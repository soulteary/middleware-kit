package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

// RateLimit returns a Fiber middleware that rate-limits requests by key. It is
// the Fiber half of the pair whose net/http half is middleware.RateLimitStd and
// shares its limiter, so one middleware.RateLimiter can bound a service serving
// both frameworks.
//
// The key comes from cfg.KeyFunc, or from GetClientIPFiber when that is nil.
func RateLimit(cfg RateLimitConfig) fiber.Handler {
	if cfg.Limiter == nil {
		cfg.Limiter = middleware.NewRateLimiter(middleware.DefaultRateLimiterConfig())
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	return func(c fiber.Ctx) error {
		// Skip if path is in skip list
		if skipPathMap[c.Path()] {
			return c.Next()
		}

		// Get the key for rate limiting
		var key string
		if cfg.KeyFunc != nil {
			key = cfg.KeyFunc(c)
		} else {
			key = GetClientIPFiber(c, cfg.TrustedProxyConfig)
		}

		// Check rate limit
		if !cfg.Limiter.Allow(key) {
			if cfg.OnLimitReached != nil {
				cfg.OnLimitReached(key)
			}

			if cfg.Logger != nil {
				cfg.Logger.Warn().
					Str("key", key).
					Str("path", c.Path()).
					Str("method", c.Method()).
					Msg("Rate limit exceeded")
			}

			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c)
			}

			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"ok":     false,
				"reason": "rate_limited",
			})
		}

		return c.Next()
	}
}
