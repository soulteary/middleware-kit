package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// LoggingConfig configures the request logging middleware.
type LoggingConfig struct {
	// Logger is the zerolog logger to use.
	// If nil, logging is disabled.
	Logger *zerolog.Logger

	// SkipPaths is a list of paths to skip logging.
	// Useful for health check endpoints.
	SkipPaths []string

	// LogRequestBody enables logging of request body.
	// Warning: This may log sensitive data.
	// Default: false
	LogRequestBody bool

	// LogResponseBody enables logging of response body.
	// Warning: This may log sensitive data and impact performance.
	// Default: false
	LogResponseBody bool

	// MaxBodyLogSize is the maximum body size to log (in bytes).
	// Bodies larger than this are truncated.
	// Default: 1024
	MaxBodyLogSize int

	// LogHeaders enables logging of request headers.
	// Default: false
	LogHeaders bool

	// SensitiveHeaders is a list of header names to mask in logs.
	// Default: ["Authorization", "X-API-Key", "Cookie", "Set-Cookie"]
	SensitiveHeaders []string

	// LogLevel is the log level for successful requests.
	// Default: zerolog.InfoLevel
	LogLevel zerolog.Level

	// ErrorLogLevel is the log level for failed requests (status >= 400).
	// Default: zerolog.WarnLevel
	ErrorLogLevel zerolog.Level

	// IncludeLatency includes request latency in logs.
	// Default: true
	IncludeLatency bool

	// TrustedProxyConfig for client IP detection.
	TrustedProxyConfig *TrustedProxyConfig

	// CustomFields adds custom fields to each log entry.
	CustomFields func(c *fiber.Ctx) map[string]interface{}
}

// DefaultLoggingConfig returns the default logging configuration.
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		MaxBodyLogSize: 1024,
		SensitiveHeaders: []string{
			"Authorization",
			"X-API-Key",
			"X-Signature",
			"Cookie",
			"Set-Cookie",
		},
		LogLevel:       zerolog.InfoLevel,
		ErrorLogLevel:  zerolog.WarnLevel,
		IncludeLatency: true,
	}
}

// RequestLogging creates a Fiber middleware for request logging.
func RequestLogging(cfg LoggingConfig) fiber.Handler {
	if cfg.Logger == nil {
		// No-op middleware if no logger is provided
		return func(c *fiber.Ctx) error {
			return c.Next()
		}
	}

	if cfg.MaxBodyLogSize <= 0 {
		cfg.MaxBodyLogSize = 1024
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	sensitiveHeaderMap := make(map[string]bool)
	if len(cfg.SensitiveHeaders) == 0 {
		cfg.SensitiveHeaders = []string{"Authorization", "X-API-Key", "X-Signature", "Cookie", "Set-Cookie"}
	}
	for _, h := range cfg.SensitiveHeaders {
		// Use lowercase for case-insensitive comparison
		sensitiveHeaderMap[strings.ToLower(h)] = true
	}

	return func(c *fiber.Ctx) error {
		// Skip if path is in skip list
		if skipPathMap[c.Path()] {
			return c.Next()
		}

		start := time.Now()

		// Process request
		err := c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get status code
		status := c.Response().StatusCode()

		// Determine log level
		logLevel := cfg.LogLevel
		if status >= 400 {
			logLevel = cfg.ErrorLogLevel
		}

		// Build log event
		event := cfg.Logger.WithLevel(logLevel)

		// Add standard fields
		clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
		event = event.
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", status).
			Str("ip", clientIP).
			Str("user_agent", c.Get("User-Agent"))

		// Add latency if enabled
		if cfg.IncludeLatency {
			event = event.Dur("latency", latency)
		}

		// Add query parameters if present
		if c.Request().URI().QueryString() != nil && len(c.Request().URI().QueryString()) > 0 {
			event = event.Str("query", string(c.Request().URI().QueryString()))
		}

		// Add request body if enabled
		if cfg.LogRequestBody {
			body := c.Body()
			if len(body) > cfg.MaxBodyLogSize {
				event = event.Str("request_body", string(body[:cfg.MaxBodyLogSize])+"...[truncated]")
			} else if len(body) > 0 {
				event = event.Str("request_body", string(body))
			}
		}

		// Add headers if enabled
		if cfg.LogHeaders {
			headers := make(map[string]string)
			for key, value := range c.Request().Header.All() {
				headerName := string(key)
				// Use lowercase for case-insensitive comparison
				if sensitiveHeaderMap[strings.ToLower(headerName)] {
					headers[headerName] = "[REDACTED]"
				} else {
					headers[headerName] = string(value)
				}
			}
			event = event.Interface("headers", headers)
		}

		// Add custom fields if provided
		if cfg.CustomFields != nil {
			for key, value := range cfg.CustomFields(c) {
				event = event.Interface(key, value)
			}
		}

		// Add error if present
		if err != nil {
			event = event.Err(err)
		}

		// Send log
		event.Msg("HTTP request")

		return err
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// RequestLoggingStd creates a standard net/http middleware for request logging.
func RequestLoggingStd(cfg LoggingConfig) func(http.Handler) http.Handler {
	if cfg.Logger == nil {
		// No-op middleware if no logger is provided
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	if cfg.MaxBodyLogSize <= 0 {
		cfg.MaxBodyLogSize = 1024
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	sensitiveHeaderMap := make(map[string]bool)
	if len(cfg.SensitiveHeaders) == 0 {
		cfg.SensitiveHeaders = []string{"Authorization", "X-API-Key", "X-Signature", "Cookie", "Set-Cookie"}
	}
	for _, h := range cfg.SensitiveHeaders {
		// Use lowercase for case-insensitive comparison
		sensitiveHeaderMap[strings.ToLower(h)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if path is in skip list
			if skipPathMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Wrap response writer to capture status
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			// Process request
			next.ServeHTTP(rw, r)

			// Calculate latency
			latency := time.Since(start)

			// Determine log level
			logLevel := cfg.LogLevel
			if rw.status >= 400 {
				logLevel = cfg.ErrorLogLevel
			}

			// Build log event
			event := cfg.Logger.WithLevel(logLevel)

			// Add standard fields
			clientIP := GetClientIP(r, cfg.TrustedProxyConfig)
			event = event.
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", rw.status).
				Str("ip", clientIP).
				Str("user_agent", r.UserAgent())

			// Add latency if enabled
			if cfg.IncludeLatency {
				event = event.Dur("latency", latency)
			}

			// Add query parameters if present
			if r.URL.RawQuery != "" {
				event = event.Str("query", r.URL.RawQuery)
			}

			// Add headers if enabled
			if cfg.LogHeaders {
				headers := make(map[string]string)
				for name, values := range r.Header {
					// Use lowercase for case-insensitive comparison
					if sensitiveHeaderMap[strings.ToLower(name)] {
						headers[name] = "[REDACTED]"
					} else if len(values) > 0 {
						headers[name] = values[0]
					}
				}
				event = event.Interface("headers", headers)
			}

			// Send log
			event.Msg("HTTP request")
		})
	}
}
