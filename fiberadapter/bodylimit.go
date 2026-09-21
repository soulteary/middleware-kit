package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
)

// BodyLimit returns a Fiber middleware that refuses requests whose body exceeds
// cfg.MaxSize (4MB by default). It is the Fiber half of the pair whose net/http
// half is middleware.BodyLimitStd.
//
// Both the advertised Content-Length and the decoded body are checked, because a
// chunked request advertises no length at all.
func BodyLimit(cfg BodyLimitConfig) fiber.Handler {
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

	return func(c fiber.Ctx) error {
		// Skip certain methods
		if skipMethodMap[c.Method()] {
			return c.Next()
		}

		// Skip certain paths
		if skipPathMap[c.Path()] {
			return c.Next()
		}

		// Check Content-Length header first
		contentLength := int64(c.Request().Header.ContentLength())
		if contentLength > cfg.MaxSize {
			if cfg.Logger != nil {
				clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
				cfg.Logger.Warn().
					Str("ip", clientIP).
					Str("path", c.Path()).
					Int64("content_length", contentLength).
					Int64("max_size", cfg.MaxSize).
					Msg("Request body size exceeds limit")
			}

			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c)
			}

			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
				"ok":     false,
				"reason": "request_entity_too_large",
			})
		}

		// Fiber automatically handles body reading, but we check actual body size
		body := c.Body()
		if int64(len(body)) > cfg.MaxSize {
			if cfg.Logger != nil {
				clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
				cfg.Logger.Warn().
					Str("ip", clientIP).
					Str("path", c.Path()).
					Int64("body_size", int64(len(body))).
					Int64("max_size", cfg.MaxSize).
					Msg("Request body size exceeds limit")
			}

			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c)
			}

			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
				"ok":     false,
				"reason": "request_entity_too_large",
			})
		}

		return c.Next()
	}
}
