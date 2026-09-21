package fiberadapter

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v2"
	"github.com/stretchr/testify/assert"
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

// TestMTLSAuth_Fiber_OverTLS exercises the verification path: everything past
// the certificate-presence check. Before the scheme pre-check was removed this
// whole path was unreachable under Fiber v3, so none of these cases had a test.
func TestMTLSAuth_Fiber_OverTLS(t *testing.T) {
	t.Run("verified certificate passes and reaches the handler", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf).Level(zerolog.DebugLevel)

		var handed *x509.Certificate
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{
			MTLSConfig: middleware.MTLSConfig{
				RequireCert: true,
				AllowedCNs:  []string{"svc-a"},
				Logger:      &logger,
			},
			SuccessHandler: func(_ fiber.Ctx, cert *x509.Certificate) { handed = cert },
		}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("svc-a", nil, nil)), "/")
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.NotNil(t, handed, "SuccessHandler must receive the verified certificate")
		assert.Equal(t, "svc-a", handed.Subject.CommonName)
		assert.Contains(t, buf.String(), "mTLS authentication successful")
	})

	t.Run("CN outside AllowedCNs is rejected as certificate_invalid", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert: true,
			AllowedCNs:  []string{"svc-a"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("intruder", nil, nil)), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "certificate_invalid")
	})

	t.Run("OU outside AllowedOUs is rejected", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert: true,
			AllowedOUs:  []string{"Engineering"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("svc-a", []string{"Marketing"}, nil)), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("DNS SAN outside AllowedDNSSANs is rejected", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert:    true,
			AllowedDNSSANs: []string{"client.example.com"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("svc-a", nil, []string{"other.example.com"})), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("allow-listed OU and SAN pass", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert:    true,
			AllowedCNs:     []string{"svc-a"},
			AllowedOUs:     []string{"Engineering"},
			AllowedDNSSANs: []string{"client.example.com"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		state := verifiedState(testCert("svc-a", []string{"Engineering"}, []string{"client.example.com"}))
		assert.Equal(t, fiber.StatusOK, serveOverTLSState(t, app, state, "/").StatusCode)
	})

	t.Run("CertValidator rejection is honoured", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert:   true,
			CertValidator: func(*x509.Certificate) error { return errors.New("revoked") },
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("svc-a", nil, nil)), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("certificate the TLS layer did not verify is rejected", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert: true,
			AllowedCNs:  []string{"svc-a"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		// Subject says svc-a, but no chain validated against ClientCAs: a
		// self-signed certificate can claim any Subject it likes.
		resp := serveOverTLSState(t, app, unverifiedState(testCert("svc-a", nil, nil)), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "certificate_unverified")
	})

	t.Run("RequireCert=false still rejects a certificate that fails the allow-list", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert: false,
			AllowedCNs:  []string{"svc-a"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		// RequireCert=false waves through the ABSENCE of a certificate, not a
		// certificate that was presented and rejected.
		resp := serveOverTLSState(t, app, verifiedState(testCert("intruder", nil, nil)), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("RequireCert=false allows a TLS connection with no certificate", func(t *testing.T) {
		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert: false,
			AllowedCNs:  []string{"svc-a"},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		state := tls.ConnectionState{HandshakeComplete: true}
		assert.Equal(t, fiber.StatusOK, serveOverTLSState(t, app, state, "/").StatusCode)
	})

	t.Run("failure is logged with the client IP and path", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(MTLSAuth(MTLSConfig{MTLSConfig: middleware.MTLSConfig{
			RequireCert: true,
			AllowedCNs:  []string{"svc-a"},
			Logger:      &logger,
		}}))
		app.Get("/guarded", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("intruder", nil, nil)), "/guarded")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "mTLS authentication failed")
		assert.Contains(t, buf.String(), "/guarded")
	})

	t.Run("custom ErrorHandler sees the verification error", func(t *testing.T) {
		app := fiber.New()
		var seen error
		app.Use(MTLSAuth(MTLSConfig{
			MTLSConfig: middleware.MTLSConfig{RequireCert: true, AllowedCNs: []string{"svc-a"}},
			ErrorHandler: func(c fiber.Ctx, err error) error {
				seen = err
				return c.Status(fiber.StatusForbidden).SendString("denied")
			},
		}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("intruder", nil, nil)), "/")
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
		assert.ErrorIs(t, seen, middleware.ErrMTLSCertificateInvalid)
	})
}

func TestHandleMTLSError_UnverifiedReason(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return handleMTLSError(c, MTLSConfig{}, middleware.ErrMTLSCertificateUnverified)
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "certificate_unverified")
}
