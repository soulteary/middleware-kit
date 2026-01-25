package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestAPIKeyAuth_Fiber(t *testing.T) {
	t.Run("valid API key in header", func(t *testing.T) {
		app := fiber.New()
		app.Use(APIKeyAuth(APIKeyConfig{
			APIKey: "test-api-key",
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"custom": "error",
				})
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})
}

func TestAPIKeyAuthStd(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey: "test-api-key",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid API key", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey: "test-api-key",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Authorization header with scheme", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:     "test-api-key",
			AuthScheme: "Bearer",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("query parameter", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:         "test-api-key",
			QueryParamName: "key",
		})(handler)

		req := httptest.NewRequest("GET", "/?key=test-api-key", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
