package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestRequestLogging_Fiber(t *testing.T) {
	t.Run("logs request with default config", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger: &logger,
		}))
		app.Get("/test", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", "test-agent")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "/test")
		assert.Contains(t, logOutput, "GET")
	})

	t.Run("skips paths in skip list", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger:    &logger,
			SkipPaths: []string{"/health"},
		}))
		app.Get("/health", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})
		app.Get("/api", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		// Health endpoint should not be logged
		req := httptest.NewRequest("GET", "/health", nil)
		_, err := app.Test(req)
		assert.NoError(t, err)
		assert.Empty(t, buf.String())

		// API endpoint should be logged
		req = httptest.NewRequest("GET", "/api", nil)
		_, err = app.Test(req)
		assert.NoError(t, err)
		assert.Contains(t, buf.String(), "/api")
	})

	t.Run("logs latency when enabled", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger:         &logger,
			IncludeLatency: true,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "latency")
	})

	t.Run("no-op when logger is nil", func(t *testing.T) {
		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger: nil, // nil logger
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("logs headers when enabled", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger:     &logger,
			LogHeaders: true,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Custom-Header", "custom-value")
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "headers")
	})

	t.Run("redacts sensitive headers", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger:           &logger,
			LogHeaders:       true,
			SensitiveHeaders: []string{"Authorization", "X-API-Key"},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer secret-token")
		req.Header.Set("X-API-Key", "secret-key")
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "[REDACTED]")
		assert.NotContains(t, logOutput, "secret-token")
		assert.NotContains(t, logOutput, "secret-key")
	})
}

func TestRequestLoggingStd(t *testing.T) {
	t.Run("logs request with default config", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "/test")
	})

	t.Run("skips paths in skip list", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger:    &logger,
			SkipPaths: []string{"/health"},
		})(handler)

		// Health endpoint should not be logged
		req := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Empty(t, buf.String())
	})

	t.Run("captures status code", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "404")
	})

	t.Run("no-op when logger is nil", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: nil,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestDefaultLoggingConfig(t *testing.T) {
	cfg := DefaultLoggingConfig()

	assert.Equal(t, 1024, cfg.MaxBodyLogSize)
	assert.NotEmpty(t, cfg.SensitiveHeaders)
	assert.Contains(t, cfg.SensitiveHeaders, "Authorization")
	assert.Contains(t, cfg.SensitiveHeaders, "X-API-Key")
	assert.True(t, cfg.IncludeLatency)
}
