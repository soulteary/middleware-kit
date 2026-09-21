package fiberadapter

import (
	"crypto/x509"

	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

// The config types below are the root package's configs plus the Fiber-typed
// hooks that used to sit on them. Fields typed func(fiber.Ctx) ... are exactly
// what pulled Fiber into the root package, so they live here; everything else
// stays shared, via the embedded config, with the net/http halves.

// APIKeyConfig is middleware.APIKeyConfig plus the Fiber hooks.
type APIKeyConfig struct {
	middleware.APIKeyConfig

	// ErrorHandler is called when authentication fails.
	// If nil, returns 401 Unauthorized with a generic message.
	ErrorHandler func(c fiber.Ctx, err error) error

	// SuccessHandler is called when authentication succeeds.
	SuccessHandler func(c fiber.Ctx)
}

// HMACConfig is middleware.HMACConfig plus the Fiber hooks.
type HMACConfig struct {
	middleware.HMACConfig

	// ErrorHandler is called when authentication fails.
	ErrorHandler func(c fiber.Ctx, err error) error

	// SuccessHandler is called when authentication succeeds.
	SuccessHandler func(c fiber.Ctx)
}

// MTLSConfig is middleware.MTLSConfig plus the Fiber hooks.
type MTLSConfig struct {
	middleware.MTLSConfig

	// ErrorHandler is called when authentication fails.
	ErrorHandler func(c fiber.Ctx, err error) error

	// SuccessHandler is called when authentication succeeds.
	SuccessHandler func(c fiber.Ctx, cert *x509.Certificate)
}

// AuthConfig is middleware.AuthConfig plus the Fiber hook.
type AuthConfig struct {
	middleware.AuthConfig

	// ErrorHandler is called when every configured scheme has failed.
	ErrorHandler func(c fiber.Ctx, err error) error
}

// BodyLimitConfig is middleware.BodyLimitConfig plus the Fiber hook.
type BodyLimitConfig struct {
	middleware.BodyLimitConfig

	// ErrorHandler is called when the body exceeds the limit.
	ErrorHandler func(c fiber.Ctx) error
}

// LoggingConfig is middleware.LoggingConfig plus the Fiber hook.
type LoggingConfig struct {
	middleware.LoggingConfig

	// CustomFields adds fields to each log entry.
	CustomFields func(c fiber.Ctx) map[string]interface{}
}

// RateLimitConfig is middleware.RateLimitConfig plus the Fiber hooks.
type RateLimitConfig struct {
	middleware.RateLimitConfig

	// KeyFunc extracts the rate-limit key from the request.
	// Default: uses client IP.
	KeyFunc func(c fiber.Ctx) string

	// ErrorHandler is called when the rate limit is exceeded.
	ErrorHandler func(c fiber.Ctx) error
}
