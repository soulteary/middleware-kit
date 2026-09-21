package fiberadapter

import (
	"errors"
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

func MTLSAuth(cfg MTLSConfig) fiber.Handler {
	lists := middleware.NewCertAllowLists(cfg.MTLSConfig)

	return func(c fiber.Ctx) error {
		// Check if connection is TLS
		if c.Protocol() != "https" {
			if cfg.RequireCert {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("mTLS authentication failed: not a TLS connection")
				}
				return handleMTLSError(c, cfg, middleware.ErrMTLSCertificateMissing)
			}
			return c.Next()
		}

		// Validate the certificate: it must be verified by the TLS layer and
		// satisfy every restriction in cfg.
		cert, err := middleware.AuthenticateMTLS(c.RequestCtx().TLSConnectionState(), cfg.MTLSConfig, lists)
		if err != nil {
			if !cfg.RequireCert && middleware.CertificateAbsent(err) {
				return c.Next()
			}
			if cfg.Logger != nil {
				clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
				cfg.Logger.Warn().
					Str("ip", clientIP).
					Str("path", c.Path()).
					Err(err).
					Msg("mTLS authentication failed")
			}
			return handleMTLSError(c, cfg, err)
		}

		// Authentication successful
		if cfg.Logger != nil {
			cfg.Logger.Debug().
				Str("cn", cert.Subject.CommonName).
				Str("issuer", cert.Issuer.CommonName).
				Msg("mTLS authentication successful")
		}

		if cfg.SuccessHandler != nil {
			cfg.SuccessHandler(c, cert)
		}

		return c.Next()
	}
}

func handleMTLSError(c fiber.Ctx, cfg MTLSConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	reason := "unauthorized"
	switch {
	case errors.Is(err, middleware.ErrMTLSCertificateMissing):
		reason = "certificate_required"
	case errors.Is(err, middleware.ErrMTLSCertificateUnverified):
		reason = "certificate_unverified"
	case errors.Is(err, middleware.ErrMTLSCertificateInvalid):
		reason = "certificate_invalid"
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": reason,
	})
}
