package middleware

import (
	"crypto/x509"
	"net/http"

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
// MTLSAuthStd creates a standard net/http middleware for mTLS authentication.
func MTLSAuthStd(cfg MTLSConfig) func(http.Handler) http.Handler {
	lists := NewCertAllowLists(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cert, err := AuthenticateMTLS(r.TLS, cfg, lists)
			if err != nil {
				if !cfg.RequireCert && CertificateAbsent(err) {
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
