package middleware

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// RateLimiter implements an in-memory rate limiter with sliding window.
type RateLimiter struct {
	mu           sync.RWMutex
	wg           sync.WaitGroup
	visitors     map[string]*visitor
	whitelist    map[string]bool
	rate         int
	window       time.Duration
	maxVisitors  int
	maxWhitelist int
	cleanup      *time.Ticker
	stopCh       chan struct{}
	stopOnce     sync.Once
}

// visitor tracks request counts for a single IP/key.
type visitor struct {
	count    int
	lastSeen time.Time
}

// RateLimiterConfig configures the rate limiter.
type RateLimiterConfig struct {
	// Rate is the maximum number of requests allowed per window.
	// Default: 100
	Rate int

	// Window is the time window for rate limiting.
	// Default: 1 minute
	Window time.Duration

	// MaxVisitors is the maximum number of unique visitors to track.
	// Oldest entries are evicted when this limit is reached.
	// Default: 10000
	MaxVisitors int

	// MaxWhitelist is the maximum number of whitelisted IPs.
	// Default: 100
	MaxWhitelist int

	// CleanupInterval is how often to clean up expired entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultRateLimiterConfig returns the default rate limiter configuration.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Rate:            100,
		Window:          time.Minute,
		MaxVisitors:     10000,
		MaxWhitelist:    100,
		CleanupInterval: time.Minute,
	}
}

// NewRateLimiter creates a new rate limiter with the given configuration.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	if cfg.Rate <= 0 {
		cfg.Rate = 100
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.MaxVisitors <= 0 {
		cfg.MaxVisitors = 10000
	}
	if cfg.MaxWhitelist <= 0 {
		cfg.MaxWhitelist = 100
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = time.Minute
	}

	rl := &RateLimiter{
		visitors:     make(map[string]*visitor),
		whitelist:    make(map[string]bool),
		rate:         cfg.Rate,
		window:       cfg.Window,
		maxVisitors:  cfg.MaxVisitors,
		maxWhitelist: cfg.MaxWhitelist,
		cleanup:      time.NewTicker(cfg.CleanupInterval),
		stopCh:       make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanupVisitors()

	return rl
}

// cleanupVisitors periodically removes expired visitor records.
func (rl *RateLimiter) cleanupVisitors() {
	defer rl.wg.Done()
	for {
		select {
		case <-rl.cleanup.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, v := range rl.visitors {
				if now.Sub(v.lastSeen) > rl.window {
					delete(rl.visitors, ip)
				}
			}
			// If still over limit, clean up oldest entries
			if len(rl.visitors) > rl.maxVisitors {
				rl.cleanupOldestVisitors()
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// cleanupOldestVisitors removes the oldest visitor entries when over limit.
func (rl *RateLimiter) cleanupOldestVisitors() {
	type visitorWithTime struct {
		ip       string
		lastSeen time.Time
	}

	visitors := make([]visitorWithTime, 0, len(rl.visitors))
	for ip, v := range rl.visitors {
		visitors = append(visitors, visitorWithTime{ip: ip, lastSeen: v.lastSeen})
	}

	sort.Slice(visitors, func(i, j int) bool {
		return visitors[i].lastSeen.Before(visitors[j].lastSeen)
	})

	toRemove := len(rl.visitors) - rl.maxVisitors
	for i := 0; i < toRemove && i < len(visitors); i++ {
		delete(rl.visitors, visitors[i].ip)
	}
}

// Allow checks if a request from the given key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.RLock()
	// Check whitelist first
	if rl.whitelist[key] {
		rl.mu.RUnlock()
		return true
	}
	rl.mu.RUnlock()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[key]
	now := time.Now()

	if !exists {
		// Check if we need to evict old entries
		if len(rl.visitors) >= rl.maxVisitors {
			rl.cleanupOldestVisitors()
		}
		rl.visitors[key] = &visitor{
			count:    1,
			lastSeen: now,
		}
		return true
	}

	// If window has passed, reset count
	if now.Sub(v.lastSeen) > rl.window {
		v.count = 1
		v.lastSeen = now
		return true
	}

	// Check if over limit
	if v.count >= rl.rate {
		return false
	}

	v.count++
	v.lastSeen = now
	return true
}

// AddToWhitelist adds a key to the whitelist.
func (rl *RateLimiter) AddToWhitelist(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.whitelist[key] {
		return true
	}

	if len(rl.whitelist) >= rl.maxWhitelist {
		return false
	}

	rl.whitelist[key] = true
	return true
}

// RemoveFromWhitelist removes a key from the whitelist.
func (rl *RateLimiter) RemoveFromWhitelist(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.whitelist, key)
}

// IsWhitelisted checks if a key is in the whitelist.
func (rl *RateLimiter) IsWhitelisted(key string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.whitelist[key]
}

// Reset clears all visitor data and whitelist.
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.visitors = make(map[string]*visitor)
	rl.whitelist = make(map[string]bool)
}

// Stop stops the rate limiter and its cleanup goroutine.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		rl.cleanup.Stop()
		close(rl.stopCh)
		rl.wg.Wait()
	})
}

// RateLimitConfig configures the rate limit middleware.
type RateLimitConfig struct {
	// Limiter is the rate limiter to use.
	// If nil, a new one is created with default settings.
	Limiter *RateLimiter

	// KeyFunc extracts the key to use for rate limiting from the request.
	// Default: uses client IP
	KeyFunc func(c *fiber.Ctx) string

	// ErrorHandler is called when the rate limit is exceeded.
	ErrorHandler func(c *fiber.Ctx) error

	// SkipPaths is a list of paths to skip rate limiting.
	SkipPaths []string

	// Logger for logging rate limit events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection.
	TrustedProxyConfig *TrustedProxyConfig

	// OnLimitReached is called when the rate limit is reached.
	// Useful for recording metrics.
	OnLimitReached func(key string)
}

// RateLimit creates a Fiber middleware for rate limiting.
func RateLimit(cfg RateLimitConfig) fiber.Handler {
	if cfg.Limiter == nil {
		cfg.Limiter = NewRateLimiter(DefaultRateLimiterConfig())
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	return func(c *fiber.Ctx) error {
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

// RateLimitStd creates a standard net/http middleware for rate limiting.
func RateLimitStd(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if cfg.Limiter == nil {
		cfg.Limiter = NewRateLimiter(DefaultRateLimiterConfig())
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if path is in skip list
			if skipPathMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Get client IP
			key := GetClientIP(r, cfg.TrustedProxyConfig)

			// Check rate limit
			if !cfg.Limiter.Allow(key) {
				if cfg.OnLimitReached != nil {
					cfg.OnLimitReached(key)
				}

				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Str("key", key).
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Msg("Rate limit exceeded")
				}

				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
