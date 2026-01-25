package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders_Fiber(t *testing.T) {
	t.Run("default security headers", func(t *testing.T) {
		app := fiber.New()
		app.Use(SecurityHeaders(DefaultSecurityHeadersConfig()))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	})

	t.Run("strict security headers", func(t *testing.T) {
		app := fiber.New()
		app.Use(SecurityHeaders(StrictSecurityHeadersConfig()))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.NotEmpty(t, resp.Header.Get("Content-Security-Policy"))
		assert.Equal(t, "max-age=31536000; includeSubDomains", resp.Header.Get("Strict-Transport-Security"))
		assert.Equal(t, "same-origin", resp.Header.Get("Cross-Origin-Opener-Policy"))
		assert.Equal(t, "same-origin", resp.Header.Get("Cross-Origin-Resource-Policy"))
	})

	t.Run("custom headers", func(t *testing.T) {
		cfg := DefaultSecurityHeadersConfig()
		cfg.CustomHeaders = map[string]string{
			"X-Custom-Header": "custom-value",
		}

		app := fiber.New()
		app.Use(SecurityHeaders(cfg))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)

		assert.Equal(t, "custom-value", resp.Header.Get("X-Custom-Header"))
	})

	t.Run("empty config sets nothing", func(t *testing.T) {
		app := fiber.New()
		app.Use(SecurityHeaders(SecurityHeadersConfig{}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)

		assert.Empty(t, resp.Header.Get("X-Content-Type-Options"))
		assert.Empty(t, resp.Header.Get("X-Frame-Options"))
	})
}

func TestSecurityHeadersStd(t *testing.T) {
	t.Run("default security headers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := SecurityHeadersStd(DefaultSecurityHeadersConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
		assert.Equal(t, "1; mode=block", rr.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", rr.Header().Get("Referrer-Policy"))
	})

	t.Run("strict security headers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := SecurityHeadersStd(StrictSecurityHeadersConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotEmpty(t, rr.Header().Get("Content-Security-Policy"))
		assert.Equal(t, "max-age=31536000; includeSubDomains", rr.Header().Get("Strict-Transport-Security"))
	})
}

func TestNoCacheHeaders_Fiber(t *testing.T) {
	app := fiber.New()
	app.Use(NoCacheHeaders())
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)

	assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", resp.Header.Get("Pragma"))
	assert.Equal(t, "0", resp.Header.Get("Expires"))
}

func TestNoCacheHeadersStd(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := NoCacheHeadersStd()(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware.ServeHTTP(rr, req)

	assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	assert.Equal(t, "0", rr.Header().Get("Expires"))
}
