package middleware

import (
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

	// Logger for logging authentication events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection.
	TrustedProxyConfig *TrustedProxyConfig
}

// CombinedAuth creates a Fiber middleware that tries multiple authentication methods.
// Authentication methods are tried in order: mTLS > HMAC > API Key.
// The first successful authentication allows the request through.
// validateHMAC performs inline HMAC validation without middleware chaining.
// validateAPIKey performs inline API key validation.
// handleCombinedAuthError handles combined auth errors.
// HeaderOrDefault returns the header name or a default value.
// HeaderOrDefault returns value when non-empty, otherwise fallback.
// Exported for framework adapters.
func HeaderOrDefault(header, defaultValue string) string {
	if header == "" {
		return defaultValue
	}
	return header
}
