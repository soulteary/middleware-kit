package fiberadapter

import (
	"bytes"
	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v2"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyAuth_Fiber(t *testing.T) {
	t.Run("valid API key in header", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("invalid API key", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing API key", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("API key from Authorization header with Bearer scheme", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:     "test-api-key",
			AuthScheme: "Bearer",
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer test-api-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("API key from query parameter", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:         "test-api-key",
			QueryParamName: "api_key",
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/?api_key=test-api-key", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("custom header name", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:     "test-api-key",
			HeaderName: "X-Custom-Key",
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Custom-Key", "test-api-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("allow empty key in development mode", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:        "",
			AllowEmptyKey: true,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("reject when no API key configured and AllowEmptyKey is false", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:        "",
			AllowEmptyKey: false,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
			ErrorHandler: func(c fiber.Ctx, err error) error {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"custom": "error",
				})
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})
}

func TestAPIKeyAuth_FiberWithLogger(t *testing.T) {
	t.Run("invalid key with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:             "test-api-key",
			Logger:             &logger,
			TrustedProxyConfig: middleware.DefaultTrustedProxyConfig(),
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "API key authentication failed")
	})

	t.Run("success with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
			Logger: &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Contains(t, buf.String(), "API key authentication successful")
	})

	t.Run("success with success handler", func(t *testing.T) {
		successCalled := false

		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
			SuccessHandler: func(c fiber.Ctx) {
				successCalled = true
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.True(t, successCalled)
	})

	t.Run("allow empty key with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:        "",
			AllowEmptyKey: true,
			Logger:        &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Contains(t, buf.String(), "API key authentication disabled")
	})

	t.Run("default header name when empty", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey:     "test-api-key",
			HeaderName: "", // Should default to X-API-Key
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}
