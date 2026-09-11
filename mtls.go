package middleware

import (
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
)

// MTLSConfig configures the mTLS (mutual TLS) authentication middleware.
type MTLSConfig struct {
	// RequireCert requires a valid client certificate.
	// If false, requests without certificates are allowed through.
	// Default: true
	RequireCert bool

	// AllowedCNs is a list of allowed Common Names.
	// If empty, any valid certificate is accepted.
	AllowedCNs []string

	// AllowedOUs is a list of allowed Organizational Units.
	// If empty, any valid certificate is accepted.
	AllowedOUs []string

	// AllowedDNSSANs is a list of allowed DNS Subject Alternative Names.
	// If empty, any valid certificate is accepted.
	AllowedDNSSANs []string

	// CertValidator is a custom function to validate the client certificate.
	// If set, it's called after the built-in validation.
	// Return nil to accept the certificate, or an error to reject it.
	CertValidator func(cert *x509.Certificate) error

	// ErrorHandler is called when authentication fails.
	ErrorHandler func(c fiber.Ctx, err error) error

	// SuccessHandler is called when authentication succeeds.
	// The verified certificate is passed to this handler.
	SuccessHandler func(c fiber.Ctx, cert *x509.Certificate)

	// Logger for logging authentication events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection in logs.
	TrustedProxyConfig *TrustedProxyConfig
}

// DefaultMTLSConfig returns the default mTLS configuration.
func DefaultMTLSConfig() MTLSConfig {
	return MTLSConfig{
		RequireCert: true,
	}
}

// MTLSAuth creates a Fiber middleware for mTLS client certificate authentication.
// Note: This middleware requires TLS to be properly configured with ClientAuth.
func MTLSAuth(cfg MTLSConfig) fiber.Handler {
	lists := newCertAllowLists(cfg)

	return func(c fiber.Ctx) error {
		// Check if connection is TLS
		if c.Protocol() != "https" {
			if cfg.RequireCert {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("mTLS authentication failed: not a TLS connection")
				}
				return handleMTLSError(c, cfg, ErrMTLSCertificateMissing)
			}
			return c.Next()
		}

		// Validate the certificate: it must be verified by the TLS layer and
		// satisfy every restriction in cfg.
		cert, err := authenticateMTLS(c.RequestCtx().TLSConnectionState(), cfg, lists)
		if err != nil {
			if !cfg.RequireCert && errors.Is(err, ErrMTLSCertificateMissing) {
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

// MTLSAuthStd creates a standard net/http middleware for mTLS authentication.
func MTLSAuthStd(cfg MTLSConfig) func(http.Handler) http.Handler {
	lists := newCertAllowLists(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cert, err := authenticateMTLS(r.TLS, cfg, lists)
			if err != nil {
				if !cfg.RequireCert && errors.Is(err, ErrMTLSCertificateMissing) {
					next.ServeHTTP(w, r)
					return
				}
				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Str("ip", GetClientIP(r, cfg.TrustedProxyConfig)).
						Str("path", r.URL.Path).
						Err(err).
						Msg("mTLS authentication failed")
				}
				http.Error(w, "Unauthorized: client certificate required", http.StatusUnauthorized)
				return
			}

			// Authentication successful
			if cfg.Logger != nil {
				cfg.Logger.Debug().
					Str("cn", cert.Subject.CommonName).
					Str("issuer", cert.Issuer.CommonName).
					Msg("mTLS authentication successful")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// handleMTLSError handles mTLS authentication errors.
func handleMTLSError(c fiber.Ctx, cfg MTLSConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	reason := "unauthorized"
	switch {
	case errors.Is(err, ErrMTLSCertificateMissing):
		reason = "certificate_required"
	case errors.Is(err, ErrMTLSCertificateUnverified):
		reason = "certificate_unverified"
	case errors.Is(err, ErrMTLSCertificateInvalid):
		reason = "certificate_invalid"
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": reason,
	})
}
