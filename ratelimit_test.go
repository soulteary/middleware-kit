package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestDefaultRateLimiterConfig(t *testing.T) {
	cfg := DefaultRateLimiterConfig()

	assert.Equal(t, 100, cfg.Rate)
	assert.Equal(t, time.Minute, cfg.Window)
	assert.Equal(t, 10000, cfg.MaxVisitors)
	assert.Equal(t, 100, cfg.MaxWhitelist)
	assert.Equal(t, time.Minute, cfg.CleanupInterval)
}

func TestRateLimiter(t *testing.T) {
	t.Run("allow requests under limit", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   5,
			Window: time.Minute,
		})
		defer rl.Stop()

		for i := 0; i < 5; i++ {
			assert.True(t, rl.Allow("client1"), "Request %d should be allowed", i+1)
		}
	})

	t.Run("block requests over limit", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   3,
			Window: time.Minute,
		})
		defer rl.Stop()

		for i := 0; i < 3; i++ {
			assert.True(t, rl.Allow("client1"))
		}
		assert.False(t, rl.Allow("client1"), "Request over limit should be blocked")
	})

	t.Run("different clients have separate limits", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   2,
			Window: time.Minute,
		})
		defer rl.Stop()

		assert.True(t, rl.Allow("client1"))
		assert.True(t, rl.Allow("client1"))
		assert.False(t, rl.Allow("client1"))

		assert.True(t, rl.Allow("client2"))
		assert.True(t, rl.Allow("client2"))
		assert.False(t, rl.Allow("client2"))
	})

	t.Run("window reset allows new requests", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   2,
			Window: 100 * time.Millisecond,
		})
		defer rl.Stop()

		assert.True(t, rl.Allow("client1"))
		assert.True(t, rl.Allow("client1"))
		assert.False(t, rl.Allow("client1"))

		// Wait for window to reset
		time.Sleep(150 * time.Millisecond)

		assert.True(t, rl.Allow("client1"), "Request should be allowed after window reset")
	})

	t.Run("whitelist bypass rate limit", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer rl.Stop()

		assert.True(t, rl.AddToWhitelist("vip"))

		// VIP client should not be rate limited
		for i := 0; i < 100; i++ {
			assert.True(t, rl.Allow("vip"), "Whitelisted client should always be allowed")
		}

		// Regular client should be limited
		assert.True(t, rl.Allow("regular"))
		assert.False(t, rl.Allow("regular"))
	})

	t.Run("whitelist operations", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:         10,
			Window:       time.Minute,
			MaxWhitelist: 2,
		})
		defer rl.Stop()

		assert.True(t, rl.AddToWhitelist("ip1"))
		assert.True(t, rl.AddToWhitelist("ip2"))
		assert.False(t, rl.AddToWhitelist("ip3"), "Should fail when whitelist is full")

		assert.True(t, rl.IsWhitelisted("ip1"))
		assert.True(t, rl.IsWhitelisted("ip2"))
		assert.False(t, rl.IsWhitelisted("ip3"))

		rl.RemoveFromWhitelist("ip1")
		assert.False(t, rl.IsWhitelisted("ip1"))

		// Now we can add ip3
		assert.True(t, rl.AddToWhitelist("ip3"))
	})

	t.Run("max visitors eviction", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:        10,
			Window:      time.Minute,
			MaxVisitors: 3,
		})
		defer rl.Stop()

		// Add 3 visitors
		rl.Allow("client1")
		time.Sleep(10 * time.Millisecond)
		rl.Allow("client2")
		time.Sleep(10 * time.Millisecond)
		rl.Allow("client3")
		time.Sleep(10 * time.Millisecond)

		// Add 4th visitor - should evict oldest (client1)
		rl.Allow("client4")

		// All should still work due to eviction
		assert.True(t, rl.Allow("client2"))
		assert.True(t, rl.Allow("client3"))
		assert.True(t, rl.Allow("client4"))
	})

	t.Run("concurrent access", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   1000,
			Window: time.Minute,
		})
		defer rl.Stop()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					rl.Allow("client1")
				}
			}(i)
		}
		wg.Wait()
	})

	t.Run("reset clears all data", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:   2,
			Window: time.Minute,
		})
		defer rl.Stop()

		rl.Allow("client1")
		rl.Allow("client1")
		assert.False(t, rl.Allow("client1"))

		rl.AddToWhitelist("vip")
		assert.True(t, rl.IsWhitelisted("vip"))

		rl.Reset()

		// After reset, client1 should be allowed again
		assert.True(t, rl.Allow("client1"))
		// Whitelist should be cleared
		assert.False(t, rl.IsWhitelisted("vip"))
	})
}

func TestRateLimitMiddleware_Fiber(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   5,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   2,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter:   limiter,
			SkipPaths: []string{"/health"},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})
		app.Get("/health", func(c *fiber.Ctx) error {
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
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			ErrorHandler: func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
					"custom": "rate_limited",
				})
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   2,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			KeyFunc: func(c *fiber.Ctx) string {
				return c.Get("X-User-ID")
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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

func TestRateLimitMiddlewareStd(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   3,
			Window: time.Minute,
		})
		defer limiter.Stop()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitStd(RateLimitConfig{
			Limiter: limiter,
		})(handler)

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitStd(RateLimitConfig{
			Limiter: limiter,
		})(handler)

		// First request succeeds
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)

		// Second request is blocked
		req = httptest.NewRequest("GET", "/", nil)
		rr = httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	})

	t.Run("skip paths are not rate limited", func(t *testing.T) {
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitStd(RateLimitConfig{
			Limiter:   limiter,
			SkipPaths: []string{"/health"},
		})(handler)

		// Health endpoint should never be rate limited
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest("GET", "/health", nil)
			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code)
		}
	})

	t.Run("OnLimitReached callback is called", func(t *testing.T) {
		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		var limitReachedKey string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitStd(RateLimitConfig{
			Limiter: limiter,
			OnLimitReached: func(key string) {
				limitReachedKey = key
			},
		})(handler)

		// First request succeeds
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		// Second request triggers OnLimitReached
		req = httptest.NewRequest("GET", "/", nil)
		rr = httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.NotEmpty(t, limitReachedKey)
	})

	t.Run("creates default limiter if nil", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitStd(RateLimitConfig{
			Limiter: nil, // nil limiter should be auto-created
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestCleanupVisitors(t *testing.T) {
	t.Run("cleanup removes expired entries", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:            10,
			Window:          50 * time.Millisecond,
			CleanupInterval: 30 * time.Millisecond,
		})
		defer rl.Stop()

		// Add some visitors
		rl.Allow("client1")
		rl.Allow("client2")

		// Wait for window to expire and cleanup to run
		time.Sleep(100 * time.Millisecond)

		// After cleanup, visitors should be gone and new requests allowed
		assert.True(t, rl.Allow("client1"))
		assert.True(t, rl.Allow("client2"))
	})

	t.Run("cleanup handles over limit visitors", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:            10,
			Window:          time.Hour, // Long window so entries don't expire
			MaxVisitors:     3,
			CleanupInterval: 30 * time.Millisecond,
		})
		defer rl.Stop()

		// Add more visitors than MaxVisitors
		for i := 0; i < 5; i++ {
			rl.Allow("client" + string(rune('0'+i)))
			time.Sleep(5 * time.Millisecond)
		}

		// Wait for cleanup to potentially run
		time.Sleep(50 * time.Millisecond)

		// Rate limiter should still function correctly
		assert.True(t, rl.Allow("newclient"))
	})
}

func TestRateLimiterAddToWhitelistDuplicate(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:         10,
		Window:       time.Minute,
		MaxWhitelist: 5,
	})
	defer rl.Stop()

	// Add same key twice
	assert.True(t, rl.AddToWhitelist("vip"))
	assert.True(t, rl.AddToWhitelist("vip")) // Should return true for duplicate

	assert.True(t, rl.IsWhitelisted("vip"))
}

func TestRateLimitMiddleware_FiberWithLogger(t *testing.T) {
	t.Run("logs when rate limit exceeded", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		app := fiber.New()
		app.Use(RateLimit(RateLimitConfig{
			Limiter: limiter,
			Logger:  &logger,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		limiter := NewRateLimiter(RateLimiterConfig{
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
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestRateLimitMiddlewareStd_WithLogger(t *testing.T) {
	t.Run("logs when rate limit exceeded", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		limiter := NewRateLimiter(RateLimiterConfig{
			Rate:   1,
			Window: time.Minute,
		})
		defer limiter.Stop()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RateLimitStd(RateLimitConfig{
			Limiter: limiter,
			Logger:  &logger,
		})(handler)

		// First request succeeds
		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)

		// Second request is rate limited and logged
		req = httptest.NewRequest("GET", "/", nil)
		rr = httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		assert.Contains(t, buf.String(), "Rate limit exceeded")
	})
}

func TestNewRateLimiter_Defaults(t *testing.T) {
	t.Run("uses defaults for zero values", func(t *testing.T) {
		rl := NewRateLimiter(RateLimiterConfig{
			Rate:            0,
			Window:          0,
			MaxVisitors:     0,
			MaxWhitelist:    0,
			CleanupInterval: 0,
		})
		defer rl.Stop()

		// Should use default rate of 100
		for i := 0; i < 100; i++ {
			assert.True(t, rl.Allow("client1"))
		}
		assert.False(t, rl.Allow("client1"))
	})
}
