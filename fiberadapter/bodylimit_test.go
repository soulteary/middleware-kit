package fiberadapter

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v3"
	"github.com/stretchr/testify/assert"
)

func TestBodyLimit_Fiber(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 1024, // 1KB
		}))
		app.Post("/", func(c fiber.Ctx) error {
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
		app.Post("/", func(c fiber.Ctx) error {
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
		app.Get("/", func(c fiber.Ctx) error {
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
		app.Head("/", func(c fiber.Ctx) error {
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
		app.Post("/upload", func(c fiber.Ctx) error {
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
			ErrorHandler: func(c fiber.Ctx) error {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"custom": "error",
				})
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
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
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// 3MB should be allowed
		body := bytes.Repeat([]byte("a"), 3*1024*1024)
		req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := app.Test(req, fiber.TestConfig{Timeout: 0})
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("skips OPTIONS requests", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			MaxSize: 10,
		}))
		app.Options("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("OPTIONS", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
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
			TrustedProxyConfig: middleware.DefaultTrustedProxyConfig(),
		}))
		app.Post("/", func(c fiber.Ctx) error {
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
			ErrorHandler: func(c fiber.Ctx) error {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "too large"})
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
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
		app.Get("/", func(c fiber.Ctx) error {
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
			ErrorHandler: func(c fiber.Ctx) error {
				return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{"custom": "error"})
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
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
		app.Post("/", func(c fiber.Ctx) error {
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

// TestBodyLimit_Fiber_NoContentLength covers the body-size check that runs when
// the Content-Length branch cannot: a chunked request advertises no length, so
// fasthttp reports Content-Length as -1 and only the decoded body reveals the
// size. Every test above sends a measured body, so this second check -- and the
// logger and ErrorHandler inside it -- had no coverage at all.
func TestBodyLimit_Fiber_NoContentLength(t *testing.T) {
	oversized := strings.Repeat("a", 2048)

	t.Run("rejects an unsized body over the limit", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{BodyLimitConfig: middleware.BodyLimitConfig{MaxSize: 1024}}))
		app.Post("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := postChunked(t, app, "/", []byte(oversized))
		assert.Equal(t, fiber.StatusRequestEntityTooLarge, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "request_entity_too_large")
	})

	t.Run("allows an unsized body under the limit", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{BodyLimitConfig: middleware.BodyLimitConfig{MaxSize: 1024}}))
		app.Post("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		assert.Equal(t, fiber.StatusOK, postChunked(t, app, "/", []byte("small")).StatusCode)
	})

	t.Run("logs the rejection with the decoded body size", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{BodyLimitConfig: middleware.BodyLimitConfig{
			MaxSize: 1024,
			Logger:  &logger,
		}}))
		app.Post("/upload", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := postChunked(t, app, "/upload", []byte(oversized))
		assert.Equal(t, fiber.StatusRequestEntityTooLarge, resp.StatusCode)
		assert.Contains(t, buf.String(), "Request body size exceeds limit")
		assert.Contains(t, buf.String(), `"body_size":2048`)
		assert.Contains(t, buf.String(), "/upload")
	})

	t.Run("custom ErrorHandler is used", func(t *testing.T) {
		app := fiber.New()
		app.Use(BodyLimit(BodyLimitConfig{
			BodyLimitConfig: middleware.BodyLimitConfig{MaxSize: 1024},
			ErrorHandler: func(c fiber.Ctx) error {
				return c.Status(fiber.StatusBadRequest).SendString("too big")
			},
		}))
		app.Post("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := postChunked(t, app, "/", []byte(oversized))
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	})
}
