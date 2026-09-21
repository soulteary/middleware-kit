package fiberadapter

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v3"
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
		app.Get("/test", func(c fiber.Ctx) error {
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
		app.Get("/health", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})
		app.Get("/api", func(c fiber.Ctx) error {
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
		app.Get("/", func(c fiber.Ctx) error {
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
		app.Get("/", func(c fiber.Ctx) error {
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
		app.Get("/", func(c fiber.Ctx) error {
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
		app.Get("/", func(c fiber.Ctx) error {
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

	t.Run("logs request body when enabled", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger:         &logger,
			LogRequestBody: true,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"test": "data"}`))
		req.Header.Set("Content-Type", "application/json")
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "request_body")
	})

	t.Run("truncates large request body", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger:         &logger,
			LogRequestBody: true,
			MaxBodyLogSize: 10, // Very small limit
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		largeBody := "This is a very long request body that should be truncated"
		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(largeBody))
		req.Header.Set("Content-Type", "application/json")
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "truncated")
	})

	t.Run("logs custom fields", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger: &logger,
			CustomFields: func(c fiber.Ctx) map[string]interface{} {
				return map[string]interface{}{
					"custom_field": "custom_value",
				}
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "custom_field")
	})

	t.Run("logs query parameters", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger: &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/?foo=bar", nil)
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "query")
	})

	t.Run("logs errors from handler", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(RequestLogging(LoggingConfig{
			Logger: &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return fiber.ErrInternalServerError
		})

		req := httptest.NewRequest("GET", "/", nil)
		_, err := app.Test(req)
		assert.NoError(t, err)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "error")
	})
}

// TestRequestLogging_Fiber_ErrorLogLevel covers the level switch for responses
// at 400 and above, which no test above triggers.
func TestRequestLogging_Fiber_ErrorLogLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf).Level(zerolog.DebugLevel)

	app := fiber.New()
	app.Use(RequestLogging(LoggingConfig{LoggingConfig: middleware.LoggingConfig{
		Logger:        &logger,
		LogLevel:      zerolog.DebugLevel,
		ErrorLogLevel: zerolog.ErrorLevel,
	}}))
	app.Get("/boom", func(c fiber.Ctx) error {
		return c.Status(fiber.StatusInternalServerError).SendString("boom")
	})

	req := httptest.NewRequest("GET", "/boom", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	assert.Contains(t, buf.String(), `"level":"error"`)
}
