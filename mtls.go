package middleware

import (
	"crypto/x509"
	"net/http"

	"github.com/gofiber/fiber/v2"
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
	ErrorHandler func(c *fiber.Ctx, err error) error

	// SuccessHandler is called when authentication succeeds.
	// The verified certificate is passed to this handler.
	SuccessHandler func(c *fiber.Ctx, cert *x509.Certificate)

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
	// Build lookup maps for faster checking
	allowedCNs := make(map[string]bool)
	for _, cn := range cfg.AllowedCNs {
		allowedCNs[cn] = true
	}

	allowedOUs := make(map[string]bool)
	for _, ou := range cfg.AllowedOUs {
		allowedOUs[ou] = true
	}

	allowedDNSSANs := make(map[string]bool)
	for _, san := range cfg.AllowedDNSSANs {
		allowedDNSSANs[san] = true
	}

	return func(c *fiber.Ctx) error {
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

		// Get TLS connection state
		tlsConn := c.Context().TLSConnectionState()
		if tlsConn == nil {
			if cfg.RequireCert {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("mTLS authentication failed: TLS state not available")
				}
				return handleMTLSError(c, cfg, ErrMTLSCertificateMissing)
			}
			return c.Next()
		}

		// Check if client certificate is present
		if len(tlsConn.PeerCertificates) == 0 {
			if cfg.RequireCert {
				if cfg.Logger != nil {
					clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
					cfg.Logger.Warn().
						Str("ip", clientIP).
						Str("path", c.Path()).
						Msg("mTLS authentication failed: no client certificate")
				}
				return handleMTLSError(c, cfg, ErrMTLSCertificateMissing)
			}
			return c.Next()
		}

		// Get the first (leaf) certificate
		cert := tlsConn.PeerCertificates[0]

		// Validate Common Name if restrictions are set
		if len(allowedCNs) > 0 {
			if !allowedCNs[cert.Subject.CommonName] {
				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Str("cn", cert.Subject.CommonName).
						Msg("mTLS authentication failed: CN not allowed")
				}
				return handleMTLSError(c, cfg, ErrMTLSCertificateInvalid)
			}
		}

		// Validate Organizational Unit if restrictions are set
		if len(allowedOUs) > 0 {
			ouMatch := false
			for _, ou := range cert.Subject.OrganizationalUnit {
				if allowedOUs[ou] {
					ouMatch = true
					break
				}
			}
			if !ouMatch {
				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Strs("ou", cert.Subject.OrganizationalUnit).
						Msg("mTLS authentication failed: OU not allowed")
				}
				return handleMTLSError(c, cfg, ErrMTLSCertificateInvalid)
			}
		}

		// Validate DNS SANs if restrictions are set
		if len(allowedDNSSANs) > 0 {
			sanMatch := false
			for _, san := range cert.DNSNames {
				if allowedDNSSANs[san] {
					sanMatch = true
					break
				}
			}
			if !sanMatch {
				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Strs("dns_sans", cert.DNSNames).
						Msg("mTLS authentication failed: DNS SAN not allowed")
				}
				return handleMTLSError(c, cfg, ErrMTLSCertificateInvalid)
			}
		}

		// Run custom validator if provided
		if cfg.CertValidator != nil {
			if err := cfg.CertValidator(cert); err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Err(err).
						Str("cn", cert.Subject.CommonName).
						Msg("mTLS authentication failed: custom validation failed")
				}
				return handleMTLSError(c, cfg, err)
			}
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
	// Build lookup maps for faster checking
	allowedCNs := make(map[string]bool)
	for _, cn := range cfg.AllowedCNs {
		allowedCNs[cn] = true
	}

	allowedOUs := make(map[string]bool)
	for _, ou := range cfg.AllowedOUs {
		allowedOUs[ou] = true
	}

	allowedDNSSANs := make(map[string]bool)
	for _, san := range cfg.AllowedDNSSANs {
		allowedDNSSANs[san] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if connection is TLS
			if r.TLS == nil {
				if cfg.RequireCert {
					if cfg.Logger != nil {
						cfg.Logger.Warn().Msg("mTLS authentication failed: not a TLS connection")
					}
					http.Error(w, "Unauthorized: TLS required", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Check if client certificate is present
			if len(r.TLS.PeerCertificates) == 0 {
				if cfg.RequireCert {
					if cfg.Logger != nil {
						clientIP := GetClientIP(r, cfg.TrustedProxyConfig)
						cfg.Logger.Warn().
							Str("ip", clientIP).
							Str("path", r.URL.Path).
							Msg("mTLS authentication failed: no client certificate")
					}
					http.Error(w, "Unauthorized: client certificate required", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Get the first (leaf) certificate
			cert := r.TLS.PeerCertificates[0]

			// Validate Common Name if restrictions are set
			if len(allowedCNs) > 0 {
				if !allowedCNs[cert.Subject.CommonName] {
					if cfg.Logger != nil {
						cfg.Logger.Warn().
							Str("cn", cert.Subject.CommonName).
							Msg("mTLS authentication failed: CN not allowed")
					}
					http.Error(w, "Unauthorized: certificate not allowed", http.StatusUnauthorized)
					return
				}
			}

			// Validate Organizational Unit if restrictions are set
			if len(allowedOUs) > 0 {
				ouMatch := false
				for _, ou := range cert.Subject.OrganizationalUnit {
					if allowedOUs[ou] {
						ouMatch = true
						break
					}
				}
				if !ouMatch {
					if cfg.Logger != nil {
						cfg.Logger.Warn().
							Strs("ou", cert.Subject.OrganizationalUnit).
							Msg("mTLS authentication failed: OU not allowed")
					}
					http.Error(w, "Unauthorized: certificate not allowed", http.StatusUnauthorized)
					return
				}
			}

			// Validate DNS SANs if restrictions are set
			if len(allowedDNSSANs) > 0 {
				sanMatch := false
				for _, san := range cert.DNSNames {
					if allowedDNSSANs[san] {
						sanMatch = true
						break
					}
				}
				if !sanMatch {
					if cfg.Logger != nil {
						cfg.Logger.Warn().
							Strs("dns_sans", cert.DNSNames).
							Msg("mTLS authentication failed: DNS SAN not allowed")
					}
					http.Error(w, "Unauthorized: certificate not allowed", http.StatusUnauthorized)
					return
				}
			}

			// Run custom validator if provided
			if cfg.CertValidator != nil {
				if err := cfg.CertValidator(cert); err != nil {
					if cfg.Logger != nil {
						cfg.Logger.Warn().
							Err(err).
							Str("cn", cert.Subject.CommonName).
							Msg("mTLS authentication failed: custom validation failed")
					}
					http.Error(w, "Unauthorized: certificate validation failed", http.StatusUnauthorized)
					return
				}
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
func handleMTLSError(c *fiber.Ctx, cfg MTLSConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	reason := "unauthorized"
	switch err {
	case ErrMTLSCertificateMissing:
		reason = "certificate_required"
	case ErrMTLSCertificateInvalid:
		reason = "certificate_invalid"
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": reason,
	})
}
