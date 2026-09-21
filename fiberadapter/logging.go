package fiberadapter

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
)

// RequestLogging returns a Fiber middleware that logs one entry per request. It
// is the Fiber half of the pair whose net/http half is
// middleware.RequestLoggingStd, and masks the same sensitive headers.
//
// Responses at 400 and above are logged at cfg.ErrorLogLevel, everything else at
// cfg.LogLevel.
func RequestLogging(cfg LoggingConfig) fiber.Handler {
	if cfg.Logger == nil {
		// No-op middleware if no logger is provided
		return func(c fiber.Ctx) error {
			return c.Next()
		}
	}

	cfg, skipPaths, sensitive := prepareLogging(cfg)

	return func(c fiber.Ctx) error {
		// Skip if path is in skip list
		if skipPaths[c.Path()] {
			return c.Next()
		}

		start := time.Now()

		// Process request
		err := c.Next()

		// Measured before anything else, so the figure is the handler's own
		// latency and not this middleware's bookkeeping.
		latency := time.Since(start)

		status := c.Response().StatusCode()
		logLevel := cfg.LogLevel
		if status >= 400 {
			logLevel = cfg.ErrorLogLevel
		}

		event := cfg.Logger.WithLevel(logLevel).
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", status).
			Str("ip", GetClientIPFiber(c, cfg.TrustedProxyConfig)).
			Str("user_agent", c.Get("User-Agent"))

		if cfg.IncludeLatency {
			event = event.Dur("latency", latency)
		}

		if query := c.Request().URI().QueryString(); len(query) > 0 {
			event = event.Str("query", string(query))
		}

		if cfg.LogRequestBody {
			event = appendBodyField(event, c.Body(), cfg.MaxBodyLogSize)
		}

		if cfg.LogHeaders {
			event = event.Interface("headers", maskedHeaders(c, sensitive))
		}

		if cfg.CustomFields != nil {
			for key, value := range cfg.CustomFields(c) {
				event = event.Interface(key, value)
			}
		}

		if err != nil {
			event = event.Err(err)
		}

		event.Msg("HTTP request")

		return err
	}
}

// prepareLogging fills in cfg's defaults once, at construction, and builds the
// two lookup sets the per-request path needs.
func prepareLogging(cfg LoggingConfig) (out LoggingConfig, skipPaths, sensitive map[string]bool) {
	if cfg.MaxBodyLogSize <= 0 {
		cfg.MaxBodyLogSize = 1024
	}

	skipPaths = make(map[string]bool, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipPaths[p] = true
	}

	if len(cfg.SensitiveHeaders) == 0 {
		cfg.SensitiveHeaders = []string{"Authorization", "X-API-Key", "X-Signature", "Cookie", "Set-Cookie"}
	}
	sensitive = make(map[string]bool, len(cfg.SensitiveHeaders))
	for _, h := range cfg.SensitiveHeaders {
		// Lowercase, because header names are case-insensitive.
		sensitive[strings.ToLower(h)] = true
	}

	return cfg, skipPaths, sensitive
}

// appendBodyField adds the request body, truncated to maxSize. An empty body
// adds no field at all.
func appendBodyField(event *zerolog.Event, body []byte, maxSize int) *zerolog.Event {
	switch {
	case len(body) > maxSize:
		return event.Str("request_body", string(body[:maxSize])+"...[truncated]")
	case len(body) > 0:
		return event.Str("request_body", string(body))
	default:
		return event
	}
}

// maskedHeaders returns every request header, with the values of the ones named
// in sensitive replaced rather than logged.
func maskedHeaders(c fiber.Ctx, sensitive map[string]bool) map[string]string {
	headers := make(map[string]string)
	for key, value := range c.Request().Header.All() {
		name := string(key)
		if sensitive[strings.ToLower(name)] {
			headers[name] = "[REDACTED]"
		} else {
			headers[name] = string(value)
		}
	}
	return headers
}
