package fiberadapter

import (
	"bytes"
	"errors"
	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v2"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

func TestMTLSAuth_Fiber_NotHTTPS(t *testing.T) {
	t.Run("no TLS with RequireCert=true returns error", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert: true,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("no TLS with RequireCert=false allows through", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert: false,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("no TLS with RequireCert=true and logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert: true,
			Logger:      &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "not a TLS connection")
	})

	t.Run("no TLS with custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert: true,
			ErrorHandler: func(c fiber.Ctx, err error) error {
				return c.Status(fiber.StatusForbidden).SendString("Custom mTLS error")
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

	t.Run("with AllowedCNs configured but no TLS", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert: false, // Allow without cert
			AllowedCNs:  []string{"client1", "client2"},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("with AllowedOUs configured but no TLS", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert: false,
			AllowedOUs:  []string{"Engineering"},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("with AllowedDNSSANs configured but no TLS", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			RequireCert:    false,
			AllowedDNSSANs: []string{"client.example.com"},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestHandleMTLSError(t *testing.T) {
	t.Run("certificate missing error", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			return handleMTLSError(c, MTLSConfig{}, middleware.ErrMTLSCertificateMissing)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("certificate invalid error", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			return handleMTLSError(c, MTLSConfig{}, middleware.ErrMTLSCertificateInvalid)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			return handleMTLSError(c, MTLSConfig{
				ErrorHandler: func(c fiber.Ctx, err error) error {
					return c.Status(fiber.StatusForbidden).SendString("Custom mTLS error")
				},
			}, middleware.ErrMTLSCertificateMissing)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})

	t.Run("other error uses default reason", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			return handleMTLSError(c, MTLSConfig{}, errors.New("some other error"))
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}
