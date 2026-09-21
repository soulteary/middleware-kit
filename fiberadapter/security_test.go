package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v3"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_Fiber(t *testing.T) {
	t.Run("default security headers", func(t *testing.T) {
		app := fiber.New()
		app.Use(SecurityHeaders(middleware.DefaultSecurityHeadersConfig()))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		// X-XSS-Protection is deprecated; "0" (disable the auditor) is the current
		// guidance. The legacy "1; mode=block" filter introduced XSS and info-leak
		// bugs of its own in the browsers that shipped it.
		assert.Equal(t, "0", resp.Header.Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	})

	t.Run("strict security headers", func(t *testing.T) {
		app := fiber.New()
		app.Use(SecurityHeaders(middleware.StrictSecurityHeadersConfig()))
		app.Get("/", func(c fiber.Ctx) error {
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
		cfg := middleware.DefaultSecurityHeadersConfig()
		cfg.CustomHeaders = map[string]string{
			"X-Custom-Header": "custom-value",
		}

		app := fiber.New()
		app.Use(SecurityHeaders(cfg))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)

		assert.Equal(t, "custom-value", resp.Header.Get("X-Custom-Header"))
	})

	t.Run("empty config sets nothing", func(t *testing.T) {
		app := fiber.New()
		app.Use(SecurityHeaders(middleware.SecurityHeadersConfig{}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)

		assert.Empty(t, resp.Header.Get("X-Content-Type-Options"))
		assert.Empty(t, resp.Header.Get("X-Frame-Options"))
	})
}

func TestSecurityHeaders_FiberAllHeaders(t *testing.T) {
	t.Run("all optional headers", func(t *testing.T) {
		cfg := middleware.SecurityHeadersConfig{
			XContentTypeOptions:       "nosniff",
			XFrameOptions:             "SAMEORIGIN",
			XXSSProtection:            "1",
			ReferrerPolicy:            "no-referrer",
			ContentSecurityPolicy:     "default-src 'self'",
			StrictTransportSecurity:   "max-age=3600",
			PermissionsPolicy:         "camera=()",
			CrossOriginOpenerPolicy:   "same-origin",
			CrossOriginResourcePolicy: "same-site",
			CrossOriginEmbedderPolicy: "require-corp",
			CacheControl:              "no-cache",
			Pragma:                    "no-cache",
		}

		app := fiber.New()
		app.Use(SecurityHeaders(cfg))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)

		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "SAMEORIGIN", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "require-corp", resp.Header.Get("Cross-Origin-Embedder-Policy"))
		assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
		assert.Equal(t, "no-cache", resp.Header.Get("Pragma"))
	})
}

func TestNoCacheHeaders_Fiber(t *testing.T) {
	app := fiber.New()
	app.Use(NoCacheHeaders())
	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)

	assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", resp.Header.Get("Pragma"))
	assert.Equal(t, "0", resp.Header.Get("Expires"))
}
