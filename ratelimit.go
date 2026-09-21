package middleware

import (
	"net/http"
	"sort"
	"sync"
	"time"

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

// visitor records the timestamps of a single IP/key's recent requests.
//
// An EXACT sliding window: the timestamps of the requests still inside the
// trailing Window are kept, so no interval of Window can ever exceed Rate.
//
// A fixed window -- reset the counter every Window -- admits almost twice the
// configured rate across a boundary. Weighting the previous window's count by
// how much of it still overlaps fixes the worst of that but is only an
// estimate: it assumes the previous window's requests were spread evenly, so a
// burst concentrated at its end is undercounted and more requests get through
// than Rate. Keeping the timestamps costs at most Rate int64s per visitor and
// removes the approximation entirely.
type visitor struct {
	// epoch anchors the ring. Stamps are offsets from it, measured with
	// time.Time.Sub, which subtracts Go's MONOTONIC clock readings when both
	// operands carry one -- as anything derived from time.Now() does.
	//
	// UnixNano would discard that reading and leave the ring ordered by the
	// wall clock, so a backward step (an NTP correction, a VM restore) makes
	// existing stamps look like the future: they never fall past the cutoff,
	// and the visitor stays limited long after its window should have drained
	// while its own retries keep it from being evicted.
	epoch time.Time

	// stamps is a ring buffer of up to Rate request offsets, oldest at head.
	stamps []int64
	head   int
	count  int

	// lastSeen is only used for eviction bookkeeping.
	lastSeen time.Time
}

// allow records a request at now if the trailing window has room for it.
func (v *visitor) allow(now time.Time, window time.Duration, rate int) bool {
	at := int64(now.Sub(v.epoch))
	cutoff := at - int64(window)

	// Drop the timestamps that have left the trailing window. They are in
	// ascending order, so this stops at the first one still inside it.
	for v.count > 0 && v.stamps[v.head] <= cutoff {
		v.head = (v.head + 1) % len(v.stamps)
		v.count--
	}

	if v.count >= rate {
		return false
	}

	v.stamps[(v.head+v.count)%len(v.stamps)] = at
	v.count++
	return true
}

// newVisitor allocates a visitor able to hold one full window of requests.
func newVisitor(now time.Time, rate int) *visitor {
	if rate < 1 {
		rate = 1
	}
	v := &visitor{epoch: now, stamps: make([]int64, rate), lastSeen: now}
	v.stamps[0] = 0
	v.count = 1
	return v
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
		rl.visitors[key] = newVisitor(now, rl.rate)
		return true
	}

	v.lastSeen = now

	// Requests leave the window on schedule, not only after an idle gap. The
	// original code compared against lastSeen -- refreshed on every allowed
	// request -- so a client sending faster than one request per window never
	// rolled over at all: the counter only ever grew, and "100 per minute"
	// actually meant "100 requests, then a full minute of silence". A steady
	// 1 req/s client was blocked at the 100th second.
	return v.allow(now, rl.window, rl.rate)
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

// RateLimitConfig configures the rate limit middleware.
type RateLimitConfig struct {
	// Limiter is the rate limiter to use.
	// If nil, a new one is created with default settings.
	Limiter *RateLimiter

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

// Stop stops the rate limiter and its cleanup goroutine.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		rl.cleanup.Stop()
		close(rl.stopCh)
		rl.wg.Wait()
	})
}
