package middleware

import (
	"github.com/gofiber/fiber/v2"
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
	ErrorHandler func(c *fiber.Ctx, err error) error

	// Logger for logging authentication events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection.
	TrustedProxyConfig *TrustedProxyConfig
}

// CombinedAuth creates a Fiber middleware that tries multiple authentication methods.
// Authentication methods are tried in order: mTLS > HMAC > API Key.
// The first successful authentication allows the request through.
func CombinedAuth(cfg AuthConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
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

		// Try mTLS first (if TLS connection with verified client certificate)
		if hasMTLS && c.Protocol() == "https" {
			tlsConn := c.Context().TLSConnectionState()
			if tlsConn != nil && len(tlsConn.PeerCertificates) > 0 {
				// Client certificate is present and verified (by TLS layer)
				if cfg.Logger != nil {
					cfg.Logger.Debug().Msg("Request authenticated via mTLS")
				}
				return c.Next()
			}
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
func validateHMAC(c *fiber.Ctx, cfg HMACConfig) bool {
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
		maxDrift = 5 * 60 // 5 minutes in seconds
	}

	if !isTimestampValid(ts, int64(maxDrift.Seconds())) {
		return false
	}

	// Compute expected signature
	signFunc := cfg.SignatureFunc
	if signFunc == nil {
		signFunc = ComputeHMAC
	}

	body := string(c.Body())
	expectedSig := signFunc(timestamp, service, body, secret)

	return constantTimeEqual(signature, expectedSig)
}

// validateAPIKey performs inline API key validation.
func validateAPIKey(c *fiber.Ctx, cfg APIKeyConfig) bool {
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
func handleCombinedAuthError(c *fiber.Ctx, cfg AuthConfig, err error) error {
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
