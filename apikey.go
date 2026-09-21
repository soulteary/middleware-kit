package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
)

// APIKeyConfig configures the API Key authentication middleware.
type APIKeyConfig struct {
	// APIKey is the expected API key value.
	// If empty, authentication will fail for all requests (secure by default).
	APIKey string

	// HeaderName is the header name to look for the API key.
	// Default: "X-API-Key"
	HeaderName string

	// QueryParamName is the query parameter name to look for the API key.
	// If set, the middleware will also check query parameters.
	// Default: "" (disabled)
	//
	// Enable this only when a client genuinely cannot set headers. A key in
	// the query string is recorded by access logs, proxy logs, browser
	// history, and is sent onwards in the Referer header of any outbound link.
	QueryParamName string

	// AuthScheme is the Authorization header scheme (e.g., "Bearer", "ApiKey").
	// If set, the middleware will also check Authorization header.
	// Default: "" (disabled)
	AuthScheme string

	// AllowEmptyKey allows requests when no API key is configured.
	// This is useful for development mode but NOT recommended for production.
	// Default: false
	AllowEmptyKey bool

	// Logger for logging authentication events.
	// If nil, no logging is performed.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection in logs.
	TrustedProxyConfig *TrustedProxyConfig
}

// DefaultAPIKeyConfig returns the default API key configuration.
func DefaultAPIKeyConfig() APIKeyConfig {
	return APIKeyConfig{
		HeaderName:    "X-API-Key",
		AllowEmptyKey: false,
	}
}

// APIKeyAuth creates a Fiber middleware for API key authentication.
// APIKeyAuthStd creates a standard net/http middleware for API key authentication.
func APIKeyAuthStd(cfg APIKeyConfig) func(http.Handler) http.Handler {
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-API-Key"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if API key is configured
			if cfg.APIKey == "" {
				if cfg.AllowEmptyKey {
					if cfg.Logger != nil {
						cfg.Logger.Warn().Msg("API key authentication disabled (no key configured)")
					}
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Try to get API key from various sources
			providedKey := ""

			// 1. Check header
			providedKey = r.Header.Get(cfg.HeaderName)

			// 2. Check Authorization header with scheme
			if providedKey == "" && cfg.AuthScheme != "" {
				authHeader := r.Header.Get("Authorization")
				prefix := cfg.AuthScheme + " "
				if strings.HasPrefix(authHeader, prefix) {
					providedKey = strings.TrimPrefix(authHeader, prefix)
				}
			}

			// 3. Check query parameter
			if providedKey == "" && cfg.QueryParamName != "" {
				providedKey = r.URL.Query().Get(cfg.QueryParamName)
			}

			// Validate API key
			if providedKey == "" {
				if cfg.Logger != nil {
					clientIP := GetClientIP(r, cfg.TrustedProxyConfig)
					cfg.Logger.Warn().
						Str("ip", clientIP).
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Msg("API key authentication failed: missing key")
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Use constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(providedKey), []byte(cfg.APIKey)) != 1 {
				if cfg.Logger != nil {
					clientIP := GetClientIP(r, cfg.TrustedProxyConfig)
					cfg.Logger.Warn().
						Str("ip", clientIP).
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Msg("API key authentication failed: invalid key")
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Authentication successful
			if cfg.Logger != nil {
				cfg.Logger.Debug().Msg("API key authentication successful")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// handleAPIKeyError handles API key authentication errors.
