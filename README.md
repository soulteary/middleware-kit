# middleware-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/middleware-kit/v2.svg)](https://pkg.go.dev/github.com/soulteary/middleware-kit/v2)
[![Go Report Card](.github/goreportcard.svg)](.github/goreportcard-report.md)
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
go get github.com/soulteary/middleware-kit/v2
```

## Usage

### API Key Authentication

```go
import (
    "github.com/gofiber/fiber/v3"
    middleware "github.com/soulteary/middleware-kit/v2"
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

// Computing the signature on the client side
timestamp := strconv.FormatInt(time.Now().Unix(), 10)
signature := middleware.ComputeHMAC(timestamp, "service-name", requestBody, secret)
// Headers: X-Signature, X-Timestamp, X-Service, X-Key-Id (optional)
```

#### Binding the signature to the request

The default signed message is `timestamp:service:body`. It covers **neither the
method nor the path**, so a signature minted for `POST /transfer` is equally
valid on `POST /delete-account` with the same body.

`ComputeHMACBound` signs the method, path and query as well, and length-prefixes
every field so the encoding is injective. Changing the signed bytes breaks every
deployed signer at once, so it is opt-in:

```go
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    Secret:               "your-hmac-secret",
    RequestSignatureFunc: middleware.ComputeHMACBound,
}))
```

Clients sign the same way:

```go
signature := middleware.ComputeHMACBound(middleware.SignatureInput{
    Timestamp: timestamp,
    Service:   "service-name",
    Method:    req.Method,
    Path:      req.URL.Path,
    RawQuery:  req.URL.RawQuery,
    Body:      string(body),
    Secret:    secret,
})
```

The legacy encoding is made safe in place: because `service` comes from a
client-supplied header and the old format is not injective, a signature for
(`service` `"a"`, `body` `"b:c"`) could be presented as (`service` `"a:b"`,
`body` `"c"`). A service identifier containing the delimiter is now rejected. Set
`AllowDelimitersInService` only if you have a deployed signer that needs it.

#### Replay protection

The timestamp window bounds how long a captured request stays useful — it does
not stop the request being replayed inside that window. Without a guard, every
signed request is replayable for `MaxTimeDrift`:

```go
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    Secret:      "your-hmac-secret",
    ReplayGuard: middleware.NewMemoryReplayGuard(), // single instance
}))
```

`ReplayGuard` is an interface, so a multi-instance deployment can back it with
shared storage:

```go
type ReplayGuard interface {
    // Seen reports whether id has been accepted before, and records it for ttl.
    Seen(id string, ttl time.Duration) bool
}
```

### mTLS Client Certificate Authentication

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

**A certificate must have been verified by the TLS layer.**
`tls.ConnectionState.PeerCertificates` is populated whenever the peer *sends* a
certificate, and with `tls.RequestClientCert` or `tls.RequireAnyClientCert` the
server verifies nothing — so a self-signed certificate would pass, and since its
Subject is chosen by whoever generated it, a CN allow-list on top gives no
protection either. Authentication requires a non-empty `VerifiedChains`; configure
your `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert` and a
`ClientCAs` pool.

An unverified certificate is rejected with `ErrMTLSCertificateUnverified`.
Failure reasons are wrapped, so logs keep naming the specific cause.

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

`CombinedAuth`'s mTLS branch runs the same check as the dedicated `MTLSAuth`
middleware, including `AllowedCNs`, `AllowedOUs`, `AllowedDNSSANs` and
`CertValidator`, so the combined middleware cannot accept what the dedicated one
rejects.

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
    KeyFunc: func(c fiber.Ctx) string {
        return c.Get("X-User-ID")
    },
}))
```

The in-memory limiter tracks the window start separately from the eviction
timestamp, so an active client rolls over on schedule: "100 per minute" means
100 requests in any minute, not "100 requests then a full minute of silence".

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
// Always build the config with the constructor
trustedProxies := middleware.NewTrustedProxyConfig([]string{
    "10.0.0.0/8",
    "192.168.1.1",
})

// In a Fiber handler
app.Get("/", func(c fiber.Ctx) error {
    clientIP := middleware.GetClientIPFiber(c, trustedProxies)
    return c.SendString("Your IP: " + clientIP)
})

// In a standard HTTP handler
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    clientIP := middleware.GetClientIP(r, trustedProxies)
    fmt.Fprintf(w, "Your IP: %s", clientIP)
})
```

`X-Forwarded-For` is **walked from the right**, skipping hops that are themselves
trusted proxies, and stops at the first untrusted address. That is the only
reading that is not spoofable: a client sends `X-Forwarded-For: 1.2.3.4`, the
proxy *appends* the real address to the right of it, and the forged value stays
leftmost. `X-Real-IP` is used only when no usable chain is present.

Every control keyed on this function — the IP allow-list, per-IP rate limiting,
audit logs — is only as trustworthy as `TrustedProxies`, so set it to your actual
proxies. With nothing configured, private addresses are trusted.

IPv6 unique local addresses (`fc00::/7`) count as private, so an all-IPv6
deployment trusts its own proxies.

### Data Masking Utilities
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
    middleware "github.com/soulteary/middleware-kit/v2"
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

## Upgrade Notes (v2.2.0)

**Three of these reject requests that previously authenticated.** Read the mTLS
and HMAC items before upgrading a live deployment.

- **mTLS requires a TLS-verified certificate.** Both `MTLSAuth` and
  `CombinedAuth` accepted any certificate the peer *sent*, because
  `PeerCertificates` is populated regardless of verification — with
  `tls.RequestClientCert` or `tls.RequireAnyClientCert` the server verifies
  nothing, so a self-signed certificate passed and the CN allow-list on top gave
  no protection. A non-empty `VerifiedChains` is now required. **If your
  `tls.Config` does not use `RequireAndVerifyClientCert` with a `ClientCAs` pool,
  mTLS clients will start failing with `ErrMTLSCertificateUnverified`.**
- **`CombinedAuth` now enforces the mTLS allow-lists.** Its mTLS branch tested
  only `len(PeerCertificates) > 0` and returned `c.Next()`, so `AllowedCNs`,
  `AllowedOUs`, `AllowedDNSSANs` and `CertValidator` were never consulted —
  configuring them there had no effect and any client certificate authenticated.
- **An HMAC `service` containing the delimiter is rejected.** The legacy signed
  message `timestamp:service:body` is not injective and `service` comes from a
  client-supplied header, so a signature for (`"a"`, `"b:c"`) could be presented
  as (`"a:b"`, `"c"`). Set `AllowDelimitersInService` if a deployed signer needs
  the old behaviour.
- **`X-Forwarded-For` is read from the right, and `X-Real-IP` no longer wins.**
  Taking the leftmost entry is spoofable by design — the proxy appends the real
  address to the right of whatever the client sent — so every control keyed on
  `GetClientIP` was bypassable even behind a correctly configured proxy. **Client
  IPs in your logs and rate-limit buckets will change**, to the correct values.
- **`TrustedProxyConfig` parses its lists lazily.** Parsing happened only in
  `NewTrustedProxyConfig`, while `TrustedProxies` is an exported field and
  `DefaultTrustedProxyConfig` returns a literal — so a config built as a struct
  literal had empty parsed lists and fell through to "nothing configured",
  trusting every private address instead of the one asked for. Tightening the
  policy silently loosened it.
- **IPv6 unique local addresses (`fc00::/7`) count as private.** An all-IPv6
  deployment never trusted its own proxies.
- **The rate-limit window rolls over for active clients.** The in-memory limiter
  compared the window against `lastSeen`, refreshed on every allowed request, so
  the counter only grew: "100 per minute" meant "100 requests, then a full minute
  of silence", and a steady 1 req/s client was blocked at the 100th second. **Some
  clients you were blocking will now be allowed** — correctly.
- **`X-XSS-Protection` defaults to `"0"`.** The header is deprecated, and the
  filter that `"1; mode=block"` enabled introduced XSS and info-leak bugs of its
  own.
- **Secret comparison no longer leaks length.** `constantTimeEqual` called
  `subtle.ConstantTimeCompare` directly, which returns early on a length mismatch.
- **New API**: `ReplayGuard` and `NewMemoryReplayGuard` for HMAC replay
  protection; `ComputeHMACBound`, `SignatureInput` and `RequestSignatureFunc` for
  signatures that cover the method, path and query;
  `HMACConfig.AllowDelimitersInService`; `ErrMTLSCertificateUnverified`.

## Requirements

- **Go 1.27+** (`go.mod` declares `go 1.27.0`)
- github.com/gofiber/fiber/v3 v3.4.0+ (for Fiber middleware)
- github.com/rs/zerolog v1.34.0+ (for logging)

This v2 module line targets Fiber v3. Applications that still use Fiber v2 should remain on `github.com/soulteary/middleware-kit` v1.

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
