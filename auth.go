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

// HeaderOrDefault returns header when non-empty, otherwise defaultValue.
//
// Exported so a framework adapter resolves a configured header name to the same
// default the net/http middlewares use.
func HeaderOrDefault(header, defaultValue string) string {
	if header == "" {
		return defaultValue
	}
	return header
}
