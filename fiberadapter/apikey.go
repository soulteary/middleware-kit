// Package fiberadapter exposes middleware-kit over Fiber v3.
//
// It lives in its own package so that importing the root package does not drag
// Fiber -- and with it fasthttp -- into binaries that never use it. A service
// on net/http, Echo, Gin or chi pays nothing for Fiber support existing; only
// importing this package links it in.
//
// Every middleware here is the Fiber half of a pair whose net/http half stays
// in the root package as XxxStd. The rules they share -- what a valid key or
// signature is, which IP to trust, what counts as sensitive -- live in the
// root package and are read from there.
package fiberadapter

import (
	"crypto/subtle"
	"strings"

	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

// APIKeyAuth returns a Fiber middleware that authenticates requests by API
// key. It is the Fiber half of the pair whose net/http half is
// middleware.APIKeyAuthStd, and reads the key from the same places: the
// configured header, then the Authorization scheme, then the query parameter --
// each only where cfg enables it.
func APIKeyAuth(cfg APIKeyConfig) fiber.Handler {
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-API-Key"
	}

	return func(c fiber.Ctx) error {
		// Check if API key is configured
		if cfg.APIKey == "" {
			if cfg.AllowEmptyKey {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("API key authentication disabled (no key configured)")
				}
				return c.Next()
			}
			return handleAPIKeyError(c, cfg, middleware.ErrAPIKeyNotConfigured)
		}

		// Try to get API key from various sources
		providedKey := ""

		// 1. Check header
		providedKey = c.Get(cfg.HeaderName)

		// 2. Check Authorization header with scheme
		if providedKey == "" && cfg.AuthScheme != "" {
			authHeader := c.Get("Authorization")
			prefix := cfg.AuthScheme + " "
			if strings.HasPrefix(authHeader, prefix) {
				providedKey = strings.TrimPrefix(authHeader, prefix)
			}
		}

		// 3. Check query parameter
		if providedKey == "" && cfg.QueryParamName != "" {
			providedKey = c.Query(cfg.QueryParamName)
		}

		// Validate API key
		if providedKey == "" {
			return handleAPIKeyError(c, cfg, middleware.ErrAPIKeyMissing)
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(providedKey), []byte(cfg.APIKey)) != 1 {
			if cfg.Logger != nil {
				clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
				cfg.Logger.Warn().
					Str("ip", clientIP).
					Str("path", c.Path()).
					Str("method", c.Method()).
					Msg("API key authentication failed: invalid key")
			}
			return handleAPIKeyError(c, cfg, middleware.ErrAPIKeyInvalid)
		}

		// Authentication successful
		if cfg.Logger != nil {
			cfg.Logger.Debug().Msg("API key authentication successful")
		}

		if cfg.SuccessHandler != nil {
			cfg.SuccessHandler(c)
		}

		return c.Next()
	}
}

func handleAPIKeyError(c fiber.Ctx, cfg APIKeyConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": "unauthorized",
	})
}
