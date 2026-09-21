package fiberadapter

import (
	"errors"
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v3"
)

// MTLSAuth returns a Fiber middleware that authenticates requests by their
// client certificate. It is the Fiber half of the pair whose net/http half is
// middleware.MTLSAuthStd, and runs the same middleware.AuthenticateMTLS check:
// the certificate must have been verified by the TLS layer AND satisfy every
// restriction in cfg.
//
// TLS is expected to be configured with tls.RequireAndVerifyClientCert (or
// VerifyClientCertIfGiven together with RequireCert=false). A connection whose
// certificate the TLS layer did not verify is rejected, whatever Subject it
// carries.
func MTLSAuth(cfg MTLSConfig) fiber.Handler {
	lists := middleware.NewCertAllowLists(cfg.MTLSConfig)

	return func(c fiber.Ctx) error {
		// Validate the certificate: it must be verified by the TLS layer and
		// satisfy every restriction in cfg.
		//
		// The TLS connection state is the only thing consulted, exactly as
		// MTLSAuthStd consults r.TLS, and there is deliberately no scheme
		// pre-check in front of it.
		//
		// A `c.Protocol() != "https"` guard used to stand here. In Fiber v3
		// Protocol reports the HTTP VERSION -- "HTTP/1.1" -- so it never
		// equalled "https" and the guard matched EVERY request, including
		// genuine mTLS ones: with RequireCert set, a fully verified
		// allow-listed certificate was answered 401, and without it, every
		// request was waved through with AllowedCNs, AllowedOUs,
		// AllowedDNSSANs and CertValidator never consulted at all.
		//
		// Fiber's c.Scheme() would not be a safe replacement either: it
		// answers "https" for a plaintext request carrying
		// X-Forwarded-Proto from a trusted proxy, and a forwarded header
		// cannot establish that a client certificate was presented to THIS
		// process. A plaintext connection simply has no TLS state, which
		// AuthenticateMTLS already reports as an absent certificate -- the
		// one condition RequireCert=false is meant to wave through.
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
