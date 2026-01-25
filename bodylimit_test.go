package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestDefaultBodyLimitConfig(t *testing.T) {
	cfg := DefaultBodyLimitConfig()

	assert.Equal(t, int64(4*1024*1024), cfg.MaxSize)
	assert.Equal(t, []string{"GET", "HEAD", "OPTIONS"}, cfg.SkipMethods)
	assert.Empty(t, cfg.SkipPaths)
}

func TestBodyLimit_Fiber(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 1024, // 1KB
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 500) // 500 bytes
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", "500")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("blocks requests over limit via Content-Length", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 100,
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 200)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", "200")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	t.Run("skips GET requests", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 10,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("skips HEAD requests", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 10,
		}))
		app.Head("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("HEAD", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("skip paths are not checked", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize:   10,
			SkipPaths: []string{"/upload"},
		}))
		app.Post("/upload", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 1000)
		req := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 10,
			ErrorHandler: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"custom": "error",
				})
			},
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 100)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "100")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("default max size is 4MB", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{})) // Use default
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		// 3MB should be allowed
		body := bytes.Repeat([]byte("a"), 3*1024*1024)
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := app.Test(req, -1)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("skips OPTIONS requests", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 10,
		}))
		app.Options("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("OPTIONS", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestBodyLimitStd(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 1024,
		})(handler)

		body := strings.Repeat("a", 500)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "500")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 100,
		})(handler)

		body := strings.Repeat("a", 200)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "200")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("skips GET requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 10,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("skip paths are not checked", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize:   10,
			SkipPaths: []string{"/upload"},
		})(handler)

		body := strings.Repeat("a", 1000)
		req := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("blocks over limit with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize:            100,
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		})(handler)

		body := strings.Repeat("a", 200)
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		req.Header.Set("Content-Length", "200")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
		assert.Contains(t, buf.String(), "Request body size exceeds limit")
	})

	t.Run("default max size when zero", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 0, // Should default to 4MB
		})(handler)

		body := strings.Repeat("a", 1000)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "1000")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("default skip methods when empty", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize:     10,
			SkipMethods: nil, // Should use default
		})(handler)

		req := httptest.NewRequest("HEAD", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestBodyLimit_FiberWithLogger(t *testing.T) {
	t.Run("blocks over limit via Content-Length with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize:            100,
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 200)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "200")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusRequestEntityTooLarge, resp.StatusCode)
		assert.Contains(t, buf.String(), "Request body size exceeds limit")
	})

	t.Run("blocks over limit via actual body with custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 50,
			ErrorHandler: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "too large"})
			},
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		// Send body with correct Content-Length that exceeds limit
		body := strings.Repeat("a", 100)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "100")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})

	t.Run("default skip methods used when empty", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize:     10,
			SkipMethods: nil, // Should default to GET, HEAD, OPTIONS
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("blocks via Content-Length with custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 50,
			ErrorHandler: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{"custom": "error"})
			},
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 100)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "100")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusPaymentRequired, resp.StatusCode)
	})

	t.Run("default max size when zero", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 0, // Should default to 4MB
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := strings.Repeat("a", 1000)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "1000")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}
