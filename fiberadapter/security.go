package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

// SecurityHeaders returns a Fiber middleware that sets the response security
// headers cfg enables. It is the Fiber half of the pair whose net/http half is
// middleware.SecurityHeadersStd, and takes the root config unchanged -- it has
// no Fiber-typed hooks.
func SecurityHeaders(cfg middleware.SecurityHeadersConfig) fiber.Handler {
	return func(c fiber.Ctx) error {
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

// NoCacheHeaders returns a Fiber middleware that sets the cache-control headers
// which keep a response out of every cache. It is the Fiber half of the pair
// whose net/http half is middleware.NoCacheHeadersStd.
func NoCacheHeaders() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Set("Pragma", "no-cache")
		c.Set("Expires", "0")
		return c.Next()
	}
}
