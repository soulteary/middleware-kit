# middleware-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/middleware-kit.svg)](https://pkg.go.dev/github.com/soulteary/middleware-kit)
[![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/middleware-kit)](https://goreportcard.com/report/github.com/soulteary/middleware-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/middleware-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/middleware-kit)

[中文文档](README_CN.md)

A comprehensive HTTP middleware toolkit for Go services. This package provides authentication (API Key, HMAC, mTLS), rate limiting, security headers, request logging, compression, and body limiting middleware for both Fiber and standard net/http.

## Features

- **Authentication Middleware**
  - API Key authentication with multiple sources (header, query, Authorization)
  - HMAC signature verification with key rotation support
  - mTLS client certificate authentication with CN/OU/SAN filtering
  - Combined authentication with priority: mTLS > HMAC > API Key
  
- **Security Middleware**
  - Security headers (XSS, clickjacking, MIME sniffing protection)
  - Configurable Content-Security-Policy
  - HSTS support
  
- **Traffic Control**
  - In-memory rate limiting with sliding window
  - IP whitelist support
  - Configurable limits per client
  
- **Request Processing**
  - Request body size limiting
  - Gzip compression with configurable thresholds
  - Request/response logging with sensitive data masking
  
- **Utilities**
  - Client IP detection with trusted proxy support
  - Sensitive data masking (email, phone)

## Installation

```bash
go get github.com/soulteary/middleware-kit
```

## Usage

### API Key Authentication

```go
import (
    "github.com/gofiber/fiber/v2"
    middleware "github.com/soulteary/middleware-kit"
)

app := fiber.New()

// Simple API key authentication
app.Use(middleware.APIKeyAuth(middleware.APIKeyConfig{
    APIKey: "your-secret-api-key",
}))

// With multiple sources
app.Use(middleware.APIKeyAuth(middleware.APIKeyConfig{
    APIKey:         "your-secret-api-key",
    HeaderName:     "X-API-Key",           // Check this header
    AuthScheme:     "Bearer",               // Also check Authorization: Bearer <key>
    QueryParamName: "api_key",              // Also check ?api_key=<key>
}))
```

### HMAC Signature Authentication

```go
// Basic HMAC authentication
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    Secret: "your-hmac-secret",
}))

// With key rotation support
keys := map[string]string{
    "key-v1": "secret-v1",
    "key-v2": "secret-v2",
}
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    KeyProvider: func(keyID string) string {
        return keys[keyID]
    },
    MaxTimeDrift: 5 * time.Minute,
}))

// Computing HMAC signature on client side
timestamp := strconv.FormatInt(time.Now().Unix(), 10)
signature := middleware.ComputeHMAC(timestamp, "service-name", requestBody, secret)
// Set headers: X-Signature, X-Timestamp, X-Service, X-Key-Id (optional)
```

### mTLS Client Certificate Authentication

```go
// Basic mTLS
app.Use(middleware.MTLSAuth(middleware.MTLSConfig{
    RequireCert: true,
}))

// With CN/OU restrictions
app.Use(middleware.MTLSAuth(middleware.MTLSConfig{
    RequireCert: true,
    AllowedCNs:  []string{"service-a", "service-b"},
    AllowedOUs:  []string{"engineering"},
}))

// With custom validator
app.Use(middleware.MTLSAuth(middleware.MTLSConfig{
    RequireCert: true,
    CertValidator: func(cert *x509.Certificate) error {
        // Custom validation logic
        if cert.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
            return errors.New("certificate expires too soon")
        }
        return nil
    },
}))
```

### Combined Authentication

```go
// Try multiple authentication methods in order: mTLS > HMAC > API Key
app.Use(middleware.CombinedAuth(middleware.AuthConfig{
    MTLSConfig: &middleware.MTLSConfig{
        RequireCert: false, // Optional mTLS
    },
    HMACConfig: &middleware.HMACConfig{
        Secret: "hmac-secret",
    },
    APIKeyConfig: &middleware.APIKeyConfig{
        APIKey: "api-key",
    },
}))
```

### Rate Limiting

```go
// Create rate limiter
limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
    Rate:   100,              // 100 requests
    Window: time.Minute,      // per minute
})
defer limiter.Stop()

// Add to middleware
app.Use(middleware.RateLimit(middleware.RateLimitConfig{
    Limiter:   limiter,
    SkipPaths: []string{"/health", "/metrics"},
}))

// Whitelist IPs
limiter.AddToWhitelist("10.0.0.1")

// Custom key function (e.g., rate limit by user ID)
app.Use(middleware.RateLimit(middleware.RateLimitConfig{
    Limiter: limiter,
    KeyFunc: func(c *fiber.Ctx) string {
        return c.Get("X-User-ID")
    },
}))
```

### Security Headers

```go
// Default security headers
app.Use(middleware.SecurityHeaders(middleware.DefaultSecurityHeadersConfig()))

// Strict security headers (recommended for production)
app.Use(middleware.SecurityHeaders(middleware.StrictSecurityHeadersConfig()))

// Custom configuration
app.Use(middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
    XContentTypeOptions:     "nosniff",
    XFrameOptions:           "DENY",
    ContentSecurityPolicy:   "default-src 'self'",
    StrictTransportSecurity: "max-age=31536000; includeSubDomains",
}))

// No-cache headers for sensitive endpoints
app.Use("/api/sensitive", middleware.NoCacheHeaders())
```

### Request Body Limiting

```go
app.Use(middleware.BodyLimit(middleware.BodyLimitConfig{
    MaxSize:     4 * 1024 * 1024, // 4MB
    SkipMethods: []string{"GET", "HEAD"},
    SkipPaths:   []string{"/upload"}, // Allow larger uploads
}))
```

### Gzip Compression (Standard HTTP)

```go
import "net/http"

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
})

compressed := middleware.CompressStd(middleware.DefaultCompressConfig())(handler)
http.ListenAndServe(":8080", compressed)
```

### Request Logging

```go
import "github.com/rs/zerolog"

logger := zerolog.New(os.Stdout)

app.Use(middleware.RequestLogging(middleware.LoggingConfig{
    Logger:     &logger,
    SkipPaths:  []string{"/health", "/metrics"},
    LogHeaders: true,
    SensitiveHeaders: []string{
        "Authorization",
        "X-API-Key",
        "Cookie",
    },
}))
```

### Client IP Detection

```go
// With trusted proxy configuration
trustedProxies := middleware.NewTrustedProxyConfig([]string{
    "10.0.0.0/8",
    "192.168.1.1",
})

// In Fiber handler
app.Get("/", func(c *fiber.Ctx) error {
    clientIP := middleware.GetClientIPFiber(c, trustedProxies)
    return c.SendString("Your IP: " + clientIP)
})

// In standard HTTP handler
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    clientIP := middleware.GetClientIP(r, trustedProxies)
    fmt.Fprintf(w, "Your IP: %s", clientIP)
})
```

### Data Masking Utilities

```go
// Mask email for logging
masked := middleware.MaskEmail("john.doe@example.com")
// Output: jo***@example.com

// Mask phone for logging
masked := middleware.MaskPhone("+1234567890")
// Output: +12***7890
```

## Standard net/http Support

All middleware support both Fiber and standard net/http:

```go
import (
    "net/http"
    middleware "github.com/soulteary/middleware-kit"
)

// API Key authentication
handler := middleware.APIKeyAuthStd(middleware.APIKeyConfig{
    APIKey: "your-api-key",
})(yourHandler)

// HMAC authentication
handler = middleware.HMACAuthStd(middleware.HMACConfig{
    Secret: "your-secret",
})(handler)

// Rate limiting
limiter := middleware.NewRateLimiter(middleware.DefaultRateLimiterConfig())
handler = middleware.RateLimitStd(middleware.RateLimitConfig{
    Limiter: limiter,
})(handler)

// Security headers
handler = middleware.SecurityHeadersStd(middleware.DefaultSecurityHeadersConfig())(handler)

// Body limit
handler = middleware.BodyLimitStd(middleware.BodyLimitConfig{
    MaxSize: 4 * 1024 * 1024,
})(handler)

// Compression
handler = middleware.CompressStd(middleware.DefaultCompressConfig())(handler)

// Logging
handler = middleware.RequestLoggingStd(middleware.LoggingConfig{
    Logger: &logger,
})(handler)

http.ListenAndServe(":8080", handler)
```

## Project Structure

```
middleware-kit/
├── apikey.go           # API Key authentication
├── hmac.go             # HMAC signature authentication
├── mtls.go             # mTLS client certificate authentication
├── auth.go             # Combined authentication middleware
├── ratelimit.go        # Rate limiting
├── security.go         # Security headers
├── bodylimit.go        # Request body size limiting
├── compress.go         # Gzip compression
├── logging.go          # Request logging
├── clientip.go         # Client IP detection
├── helpers.go          # Utility functions
├── errors.go           # Error definitions
└── *_test.go           # Comprehensive tests
```

## Requirements

- Go 1.25 or later
- github.com/gofiber/fiber/v2 v2.52.6+ (for Fiber middleware)
- github.com/rs/zerolog v1.34.0+ (for logging)

## Test Coverage

Run tests:

```bash
go test ./... -v

# With coverage
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -html=coverage.out -o coverage.html
go tool cover -func=coverage.out
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

See [LICENSE](LICENSE) file for details.
