package middleware

import (
	"net/http"

	"github.com/rs/zerolog"
)

// BodyLimitConfig configures the body limit middleware.
type BodyLimitConfig struct {
	// MaxSize is the maximum allowed request body size in bytes.
	// Default: 4MB (4 * 1024 * 1024)
	MaxSize int64

	// SkipMethods is a list of HTTP methods to skip body limit check.
	// Default: ["GET", "HEAD", "OPTIONS"]
	SkipMethods []string

	// SkipPaths is a list of paths to skip body limit check.
	SkipPaths []string

	// Logger for logging body limit events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection in logs.
	TrustedProxyConfig *TrustedProxyConfig
}

// DefaultBodyLimitConfig returns the default body limit configuration.
func DefaultBodyLimitConfig() BodyLimitConfig {
	return BodyLimitConfig{
		MaxSize:     4 * 1024 * 1024, // 4MB
		SkipMethods: []string{"GET", "HEAD", "OPTIONS"},
	}
}

// BodyLimit creates a Fiber middleware that limits request body size.
// BodyLimitStd creates a standard net/http middleware that limits request body size.
func BodyLimitStd(cfg BodyLimitConfig) func(http.Handler) http.Handler {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 4 * 1024 * 1024 // 4MB default
	}

	skipMethodMap := make(map[string]bool)
	if len(cfg.SkipMethods) == 0 {
		cfg.SkipMethods = []string{"GET", "HEAD", "OPTIONS"}
	}
	for _, m := range cfg.SkipMethods {
		skipMethodMap[m] = true
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip certain methods
			if skipMethodMap[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			// Skip certain paths
			if skipPathMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Check Content-Length header
			if r.ContentLength > cfg.MaxSize {
				if cfg.Logger != nil {
					clientIP := GetClientIP(r, cfg.TrustedProxyConfig)
					cfg.Logger.Warn().
						Str("ip", clientIP).
						Str("path", r.URL.Path).
						Int64("content_length", r.ContentLength).
						Int64("max_size", cfg.MaxSize).
						Msg("Request body size exceeds limit")
				}
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}

			// Limit request body size (MaxBytesReader will check when reading)
			r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxSize)

			next.ServeHTTP(w, r)
		})
	}
}
