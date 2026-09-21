package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

func TestGetClientIPFiber(t *testing.T) {
	t.Run("returns IP from context", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, nil)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		// Should return some IP (even if it's 0.0.0.0 in test)
		assert.NotEmpty(t, capturedIP)
	})

	t.Run("X-Real-IP from trusted proxy", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		// Use trust all proxies for testing
		cfg := &middleware.TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.1")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, "203.0.113.1", capturedIP)
	})

	t.Run("X-Forwarded-For from trusted proxy", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &middleware.TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.1, 10.0.0.2")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, "203.0.113.2", capturedIP)
	})

	t.Run("X-Forwarded-For chain preferred over X-Real-IP", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &middleware.TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.1")
		req.Header.Set("X-Forwarded-For", "203.0.113.2")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, "203.0.113.2", capturedIP)
	})

	t.Run("with nil config uses default", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, nil)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, capturedIP)
	})

	t.Run("invalid X-Real-IP header ignored", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &middleware.TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "not-an-ip")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		// Should fall back to connection IP
		assert.NotEmpty(t, capturedIP)
	})

	t.Run("invalid X-Forwarded-For header ignored", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &middleware.TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "invalid-ip, also-invalid")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, capturedIP)
	})
}
