package fiberadapter

import (
	"bytes"
	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v3"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitMiddleware_Fiber(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   5,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   2,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// First 2 requests should succeed
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		}

		// 3rd request should be rate limited
		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
	})

	t.Run("skip paths are not rate limited", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter:   limiter,
			SkipPaths: []string{"/health"},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})
		app.Get("/health", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// Health endpoint should never be rate limited
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "/health", nil)
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		}
	})

	t.Run("custom error handler", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			ErrorHandler: func(c fiber.Ctx) error {
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"custom": "rate_limited",
				})
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// First request succeeds
		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Second request uses custom error handler
		req = httptest.NewRequest("GET", "/", nil)
		resp, err = app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("custom key function", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   2,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			KeyFunc: func(c fiber.Ctx) string {
				return c.Get("X-User-ID")
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// User1 makes 2 requests
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-User-ID", "user1")
			resp, err := app.Test(req)
			assert.NoError(t, err)
			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		}

		// User1's 3rd request is blocked
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-User-ID", "user1")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)

		// User2 can still make requests
		req = httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-User-ID", "user2")
		resp, err = app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestRateLimitMiddleware_FiberWithLogger(t *testing.T) {
	t.Run("logs when rate limit exceeded", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			Logger:  &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// First request succeeds
		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		// Second request is rate limited and logged
		req = httptest.NewRequest("GET", "/", nil)
		resp, err = app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
		assert.Contains(t, buf.String(), "Rate limit exceeded")
	})

	t.Run("OnLimitReached callback called", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		var limitReachedKey string
		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			OnLimitReached: func(key string) {
				limitReachedKey = key
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// First request succeeds
		req := httptest.NewRequest("GET", "/", nil)
		_, _ = app.Test(req)

		// Second request triggers OnLimitReached
		req = httptest.NewRequest("GET", "/", nil)
		_, _ = app.Test(req)

		assert.NotEmpty(t, limitReachedKey)
	})

	t.Run("default limiter created when nil", func(t *testing.T) {
		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: nil,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}
