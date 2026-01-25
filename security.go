package middleware

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// SecurityHeadersConfig configures security headers middleware.
type SecurityHeadersConfig struct {
	// XContentTypeOptions sets X-Content-Type-Options header.
	// Prevents MIME type sniffing.
	// Default: "nosniff"
	XContentTypeOptions string

	// XFrameOptions sets X-Frame-Options header.
	// Prevents clickjacking.
	// Default: "DENY"
	XFrameOptions string

	// XXSSProtection sets X-XSS-Protection header.
	// Enables browser XSS filter.
	// Default: "1; mode=block"
	XXSSProtection string

	// ReferrerPolicy sets Referrer-Policy header.
	// Controls referrer information.
	// Default: "strict-origin-when-cross-origin"
	ReferrerPolicy string

	// ContentSecurityPolicy sets Content-Security-Policy header.
	// Controls resource loading policy.
	// Default: "" (not set)
	ContentSecurityPolicy string

	// StrictTransportSecurity sets Strict-Transport-Security header.
	// Enforces HTTPS connections.
	// Default: "" (not set, set to "max-age=31536000; includeSubDomains" for production)
	StrictTransportSecurity string

	// PermissionsPolicy sets Permissions-Policy header.
	// Controls browser features.
	// Default: "" (not set)
	PermissionsPolicy string

	// CrossOriginOpenerPolicy sets Cross-Origin-Opener-Policy header.
	// Default: "" (not set)
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy sets Cross-Origin-Resource-Policy header.
	// Default: "" (not set)
	CrossOriginResourcePolicy string

	// CrossOriginEmbedderPolicy sets Cross-Origin-Embedder-Policy header.
	// Default: "" (not set)
	CrossOriginEmbedderPolicy string

	// CacheControl sets Cache-Control header.
	// Default: "" (not set)
	CacheControl string

	// Pragma sets Pragma header.
	// Default: "" (not set)
	Pragma string

	// CustomHeaders allows setting additional custom headers.
	CustomHeaders map[string]string
}

// DefaultSecurityHeadersConfig returns the default security headers configuration.
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		XContentTypeOptions: "nosniff",
		XFrameOptions:       "DENY",
		XXSSProtection:      "1; mode=block",
		ReferrerPolicy:      "strict-origin-when-cross-origin",
	}
}

// StrictSecurityHeadersConfig returns a stricter security headers configuration.
// Suitable for production API servers.
func StrictSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		XContentTypeOptions:       "nosniff",
		XFrameOptions:             "DENY",
		XXSSProtection:            "1; mode=block",
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		ContentSecurityPolicy:     "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;",
		StrictTransportSecurity:   "max-age=31536000; includeSubDomains",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
		PermissionsPolicy:         "geolocation=(), microphone=(), camera=()",
	}
}

// SecurityHeaders creates a Fiber middleware that adds security headers.
func SecurityHeaders(cfg SecurityHeadersConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Set standard security headers
		if cfg.XContentTypeOptions != "" {
			c.Set("X-Content-Type-Options", cfg.XContentTypeOptions)
		}
		if cfg.XFrameOptions != "" {
			c.Set("X-Frame-Options", cfg.XFrameOptions)
		}
		if cfg.XXSSProtection != "" {
			c.Set("X-XSS-Protection", cfg.XXSSProtection)
		}
		if cfg.ReferrerPolicy != "" {
			c.Set("Referrer-Policy", cfg.ReferrerPolicy)
		}
		if cfg.ContentSecurityPolicy != "" {
			c.Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
		}
		if cfg.StrictTransportSecurity != "" {
			c.Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
		}
		if cfg.PermissionsPolicy != "" {
			c.Set("Permissions-Policy", cfg.PermissionsPolicy)
		}
		if cfg.CrossOriginOpenerPolicy != "" {
			c.Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
		}
		if cfg.CrossOriginResourcePolicy != "" {
			c.Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicy)
		}
		if cfg.CrossOriginEmbedderPolicy != "" {
			c.Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicy)
		}
		if cfg.CacheControl != "" {
			c.Set("Cache-Control", cfg.CacheControl)
		}
		if cfg.Pragma != "" {
			c.Set("Pragma", cfg.Pragma)
		}

		// Set custom headers
		for key, value := range cfg.CustomHeaders {
			c.Set(key, value)
		}

		return c.Next()
	}
}

// SecurityHeadersStd creates a standard net/http middleware that adds security headers.
func SecurityHeadersStd(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set standard security headers
			if cfg.XContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", cfg.XContentTypeOptions)
			}
			if cfg.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", cfg.XFrameOptions)
			}
			if cfg.XXSSProtection != "" {
				w.Header().Set("X-XSS-Protection", cfg.XXSSProtection)
			}
			if cfg.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", cfg.ReferrerPolicy)
			}
			if cfg.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", cfg.ContentSecurityPolicy)
			}
			if cfg.StrictTransportSecurity != "" {
				w.Header().Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
			}
			if cfg.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", cfg.PermissionsPolicy)
			}
			if cfg.CrossOriginOpenerPolicy != "" {
				w.Header().Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicy)
			}
			if cfg.CrossOriginResourcePolicy != "" {
				w.Header().Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicy)
			}
			if cfg.CrossOriginEmbedderPolicy != "" {
				w.Header().Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicy)
			}
			if cfg.CacheControl != "" {
				w.Header().Set("Cache-Control", cfg.CacheControl)
			}
			if cfg.Pragma != "" {
				w.Header().Set("Pragma", cfg.Pragma)
			}

			// Set custom headers
			for key, value := range cfg.CustomHeaders {
				w.Header().Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// NoCacheHeaders creates a middleware that sets cache-control headers to prevent caching.
func NoCacheHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Set("Pragma", "no-cache")
		c.Set("Expires", "0")
		return c.Next()
	}
}

// NoCacheHeadersStd creates a standard net/http middleware that prevents caching.
func NoCacheHeadersStd() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			next.ServeHTTP(w, r)
		})
	}
}
