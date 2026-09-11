package middleware

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
)

// AuthConfig configures the combined authentication middleware.
// It supports multiple authentication methods with priority:
// mTLS > HMAC > API Key
type AuthConfig struct {
	// MTLSConfig for mTLS authentication (highest priority)
	MTLSConfig *MTLSConfig

	// HMACConfig for HMAC signature authentication
	HMACConfig *HMACConfig

	// APIKeyConfig for API key authentication (lowest priority)
	APIKeyConfig *APIKeyConfig

	// AllowNoAuth allows requests when no authentication method is configured.
	// This is useful for development mode but NOT recommended for production.
	// Default: false
	AllowNoAuth bool

	// ErrorHandler is called when all authentication methods fail.
	ErrorHandler func(c fiber.Ctx, err error) error

	// Logger for logging authentication events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection.
	TrustedProxyConfig *TrustedProxyConfig
}

// CombinedAuth creates a Fiber middleware that tries multiple authentication methods.
// Authentication methods are tried in order: mTLS > HMAC > API Key.
// The first successful authentication allows the request through.
func CombinedAuth(cfg AuthConfig) fiber.Handler {
	var mtlsLists certAllowLists
	if cfg.MTLSConfig != nil {
		mtlsLists = newCertAllowLists(*cfg.MTLSConfig)
	}

	return func(c fiber.Ctx) error {
		// Check if any authentication method is configured
		hasMTLS := cfg.MTLSConfig != nil
		hasHMAC := cfg.HMACConfig != nil && (cfg.HMACConfig.Secret != "" || cfg.HMACConfig.KeyProvider != nil)
		hasAPIKey := cfg.APIKeyConfig != nil && cfg.APIKeyConfig.APIKey != ""

		if !hasMTLS && !hasHMAC && !hasAPIKey {
			if cfg.AllowNoAuth {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("No authentication method configured, allowing request (development mode)")
				}
				return c.Next()
			}
			return handleCombinedAuthError(c, cfg, ErrUnauthorized)
		}

		// Try mTLS first (if TLS connection with a verified client certificate).
		//
		// This runs the same authenticateMTLS check as the dedicated MTLSAuth
		// middleware. Previously it only tested len(PeerCertificates) > 0 and
		// returned c.Next(), which meant AllowedCNs, AllowedOUs,
		// AllowedDNSSANs and CertValidator were all silently ignored here --
		// any client certificate, including a self-signed one, authenticated.
		if hasMTLS && c.Protocol() == "https" {
			cert, err := authenticateMTLS(c.RequestCtx().TLSConnectionState(), *cfg.MTLSConfig, mtlsLists)
			if err == nil {
				if cfg.Logger != nil {
					cfg.Logger.Debug().
						Str("cn", cert.Subject.CommonName).
						Msg("Request authenticated via mTLS")
				}
				return c.Next()
			}
			if cfg.Logger != nil {
				cfg.Logger.Debug().Err(err).Msg("mTLS authentication did not apply")
			}
			// Fall through to the remaining methods.
		}

		// Try HMAC signature
		if hasHMAC {
			signature := c.Get(getHeaderOrDefault(cfg.HMACConfig.SignatureHeader, "X-Signature"))
			timestamp := c.Get(getHeaderOrDefault(cfg.HMACConfig.TimestampHeader, "X-Timestamp"))

			if signature != "" && timestamp != "" {
				// Create a temporary HMACConfig with logger
				hmacCfg := *cfg.HMACConfig
				if hmacCfg.Logger == nil && cfg.Logger != nil {
					hmacCfg.Logger = cfg.Logger
				}
				if hmacCfg.TrustedProxyConfig == nil && cfg.TrustedProxyConfig != nil {
					hmacCfg.TrustedProxyConfig = cfg.TrustedProxyConfig
				}

				// Try HMAC validation inline
				if validateHMAC(c, hmacCfg) {
					if cfg.Logger != nil {
						cfg.Logger.Debug().Msg("Request authenticated via HMAC")
					}
					return c.Next()
				}
				// HMAC was provided but failed, we should still check API key
			}
		}

		// Try API Key
		if hasAPIKey {
			apiKeyCfg := *cfg.APIKeyConfig
			if apiKeyCfg.Logger == nil && cfg.Logger != nil {
				apiKeyCfg.Logger = cfg.Logger
			}
			if apiKeyCfg.TrustedProxyConfig == nil && cfg.TrustedProxyConfig != nil {
				apiKeyCfg.TrustedProxyConfig = cfg.TrustedProxyConfig
			}

			if validateAPIKey(c, apiKeyCfg) {
				if cfg.Logger != nil {
					cfg.Logger.Debug().Msg("Request authenticated via API Key")
				}
				return c.Next()
			}
		}

		// No authentication method succeeded
		return handleCombinedAuthError(c, cfg, ErrUnauthorized)
	}
}

// validateHMAC performs inline HMAC validation without middleware chaining.
func validateHMAC(c fiber.Ctx, cfg HMACConfig) bool {
	signature := c.Get(getHeaderOrDefault(cfg.SignatureHeader, "X-Signature"))
	timestamp := c.Get(getHeaderOrDefault(cfg.TimestampHeader, "X-Timestamp"))
	keyID := c.Get(getHeaderOrDefault(cfg.KeyIDHeader, "X-Key-Id"))
	service := c.Get(getHeaderOrDefault(cfg.ServiceHeader, "X-Service"))

	if signature == "" || timestamp == "" {
		return false
	}

	// Get the HMAC secret
	secret := cfg.Secret
	if cfg.KeyProvider != nil {
		secret = cfg.KeyProvider(keyID)
	}

	if secret == "" {
		return false
	}

	// Validate timestamp
	ts, err := parseTimestamp(timestamp)
	if err != nil {
		return false
	}

	maxDrift := cfg.MaxTimeDrift
	if maxDrift == 0 {
		// 5 * 60 here was a time.Duration of 300 NANOSECONDS, not five
		// minutes: int64(maxDrift.Seconds()) then rounded to 0, so the
		// documented zero value demanded a timestamp matching the current
		// second exactly, and the replay guard retained entries for 600ns.
		maxDrift = 5 * time.Minute
	}

	if !isTimestampValid(ts, int64(maxDrift.Seconds())) {
		return false
	}

	if !cfg.serviceAllowed(service) {
		return false
	}

	expectedSig := cfg.expectedSignature(SignatureInput{
		Method: c.Method(),
		// The ESCAPED path: see SignatureInput.Path.
		Path:      string(c.RequestCtx().URI().PathOriginal()),
		RawQuery:  string(c.RequestCtx().URI().QueryString()),
		Timestamp: timestamp,
		Service:   service,
		Body:      string(c.Body()),
		Secret:    secret,
	})

	if !constantTimeEqual(signature, expectedSig) {
		return false
	}

	// The NORMALIZED drift, not cfg.MaxTimeDrift. With the documented zero
	// value, validation above computed a five-minute default while this call
	// passed 0, so MemoryReplayGuard expired the entry on the very next
	// request and enabling ReplayGuard prevented no replay at all.
	if cfg.ReplayGuard != nil && cfg.ReplayGuard.Seen(signature, replayRetention(maxDrift)) {
		return false
	}

	return true
}

// validateAPIKey performs inline API key validation.
func validateAPIKey(c fiber.Ctx, cfg APIKeyConfig) bool {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}

	// Try to get API key from various sources
	providedKey := c.Get(headerName)

	// Check Authorization header with scheme
	if providedKey == "" && cfg.AuthScheme != "" {
		authHeader := c.Get("Authorization")
		prefix := cfg.AuthScheme + " "
		if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
			providedKey = authHeader[len(prefix):]
		}
	}

	// Check query parameter
	if providedKey == "" && cfg.QueryParamName != "" {
		providedKey = c.Query(cfg.QueryParamName)
	}

	if providedKey == "" {
		return false
	}

	return constantTimeEqual(providedKey, cfg.APIKey)
}

// handleCombinedAuthError handles combined auth errors.
func handleCombinedAuthError(c fiber.Ctx, cfg AuthConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": "unauthorized",
	})
}

// getHeaderOrDefault returns the header name or a default value.
func getHeaderOrDefault(header, defaultValue string) string {
	if header == "" {
		return defaultValue
	}
	return header
}
