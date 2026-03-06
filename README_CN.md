# middleware-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/middleware-kit.svg)](https://pkg.go.dev/github.com/soulteary/middleware-kit)
[![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/middleware-kit)](https://goreportcard.com/report/github.com/soulteary/middleware-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/middleware-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/middleware-kit)

[English](README.md)

一个全面的 Go 服务 HTTP 中间件工具包。提供认证（API Key、HMAC、mTLS）、限流、安全头、请求日志、压缩和请求体限制等中间件，同时支持 Fiber 和标准 net/http。

## 功能特性

- **认证中间件**
  - API Key 认证，支持多种来源（Header、Query、Authorization）
  - HMAC 签名验证，支持密钥轮换
  - mTLS 客户端证书认证，支持 CN/OU/SAN 过滤
  - 组合认证，优先级：mTLS > HMAC > API Key
  
- **安全中间件**
  - 安全头（XSS、点击劫持、MIME 嗅探防护）
  - 可配置的 Content-Security-Policy
  - HSTS 支持
  
- **流量控制**
  - 基于滑动窗口的内存限流
  - IP 白名单支持
  - 可配置的客户端限制
  
- **请求处理**
  - 请求体大小限制
  - Gzip 压缩，可配置阈值
  - 请求/响应日志，敏感数据脱敏
  
- **工具函数**
  - 客户端 IP 检测，支持可信代理
  - 敏感数据脱敏（邮箱、手机号）

## 安装

```bash
go get github.com/soulteary/middleware-kit
```

## 使用方法

### API Key 认证

```go
import (
    "github.com/gofiber/fiber/v2"
    middleware "github.com/soulteary/middleware-kit"
)

app := fiber.New()

// 简单的 API Key 认证
app.Use(middleware.APIKeyAuth(middleware.APIKeyConfig{
    APIKey: "your-secret-api-key",
}))

// 支持多种来源
app.Use(middleware.APIKeyAuth(middleware.APIKeyConfig{
    APIKey:         "your-secret-api-key",
    HeaderName:     "X-API-Key",           // 检查此 Header
    AuthScheme:     "Bearer",               // 也检查 Authorization: Bearer <key>
    QueryParamName: "api_key",              // 也检查 ?api_key=<key>
}))
```

### HMAC 签名认证

```go
// 基础 HMAC 认证
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    Secret: "your-hmac-secret",
}))

// 支持密钥轮换
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

// 客户端计算 HMAC 签名
timestamp := strconv.FormatInt(time.Now().Unix(), 10)
signature := middleware.ComputeHMAC(timestamp, "service-name", requestBody, secret)
// 设置 Headers: X-Signature, X-Timestamp, X-Service, X-Key-Id (可选)
```

### mTLS 客户端证书认证

```go
// 基础 mTLS
app.Use(middleware.MTLSAuth(middleware.MTLSConfig{
    RequireCert: true,
}))

// 限制 CN/OU
app.Use(middleware.MTLSAuth(middleware.MTLSConfig{
    RequireCert: true,
    AllowedCNs:  []string{"service-a", "service-b"},
    AllowedOUs:  []string{"engineering"},
}))

// 自定义验证器
app.Use(middleware.MTLSAuth(middleware.MTLSConfig{
    RequireCert: true,
    CertValidator: func(cert *x509.Certificate) error {
        // 自定义验证逻辑
        if cert.NotAfter.Before(time.Now().Add(24 * time.Hour)) {
            return errors.New("证书即将过期")
        }
        return nil
    },
}))
```

### 组合认证

```go
// 按顺序尝试多种认证方式：mTLS > HMAC > API Key
app.Use(middleware.CombinedAuth(middleware.AuthConfig{
    MTLSConfig: &middleware.MTLSConfig{
        RequireCert: false, // 可选 mTLS
    },
    HMACConfig: &middleware.HMACConfig{
        Secret: "hmac-secret",
    },
    APIKeyConfig: &middleware.APIKeyConfig{
        APIKey: "api-key",
    },
}))
```

### 限流

```go
// 创建限流器
limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{
    Rate:   100,              // 100 次请求
    Window: time.Minute,      // 每分钟
})
defer limiter.Stop()

// 添加中间件
app.Use(middleware.RateLimit(middleware.RateLimitConfig{
    Limiter:   limiter,
    SkipPaths: []string{"/health", "/metrics"},
}))

// IP 白名单
limiter.AddToWhitelist("10.0.0.1")

// 自定义 Key 函数（例如按用户 ID 限流）
app.Use(middleware.RateLimit(middleware.RateLimitConfig{
    Limiter: limiter,
    KeyFunc: func(c *fiber.Ctx) string {
        return c.Get("X-User-ID")
    },
}))
```

### 安全头

```go
// 默认安全头
app.Use(middleware.SecurityHeaders(middleware.DefaultSecurityHeadersConfig()))

// 严格安全头（推荐生产环境使用）
app.Use(middleware.SecurityHeaders(middleware.StrictSecurityHeadersConfig()))

// 自定义配置
app.Use(middleware.SecurityHeaders(middleware.SecurityHeadersConfig{
    XContentTypeOptions:     "nosniff",
    XFrameOptions:           "DENY",
    ContentSecurityPolicy:   "default-src 'self'",
    StrictTransportSecurity: "max-age=31536000; includeSubDomains",
}))

// 敏感端点禁止缓存
app.Use("/api/sensitive", middleware.NoCacheHeaders())
```

### 请求体限制

```go
app.Use(middleware.BodyLimit(middleware.BodyLimitConfig{
    MaxSize:     4 * 1024 * 1024, // 4MB
    SkipMethods: []string{"GET", "HEAD"},
    SkipPaths:   []string{"/upload"}, // 允许大文件上传
}))
```

### Gzip 压缩（标准 HTTP）

```go
import "net/http"

handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello, World!"))
})

compressed := middleware.CompressStd(middleware.DefaultCompressConfig())(handler)
http.ListenAndServe(":8080", compressed)
```

### 请求日志

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

### 客户端 IP 检测

```go
// 配置可信代理
trustedProxies := middleware.NewTrustedProxyConfig([]string{
    "10.0.0.0/8",
    "192.168.1.1",
})

// Fiber 处理器中
app.Get("/", func(c *fiber.Ctx) error {
    clientIP := middleware.GetClientIPFiber(c, trustedProxies)
    return c.SendString("Your IP: " + clientIP)
})

// 标准 HTTP 处理器中
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    clientIP := middleware.GetClientIP(r, trustedProxies)
    fmt.Fprintf(w, "Your IP: %s", clientIP)
})
```

### 数据脱敏工具

```go
// 邮箱脱敏
masked := middleware.MaskEmail("john.doe@example.com")
// 输出: jo***@example.com

// 手机号脱敏
masked := middleware.MaskPhone("+1234567890")
// 输出: +12***7890
```

## 标准 net/http 支持

所有中间件同时支持 Fiber 和标准 net/http：

```go
import (
    "net/http"
    middleware "github.com/soulteary/middleware-kit"
)

// API Key 认证
handler := middleware.APIKeyAuthStd(middleware.APIKeyConfig{
    APIKey: "your-api-key",
})(yourHandler)

// HMAC 认证
handler = middleware.HMACAuthStd(middleware.HMACConfig{
    Secret: "your-secret",
})(handler)

// 限流
limiter := middleware.NewRateLimiter(middleware.DefaultRateLimiterConfig())
handler = middleware.RateLimitStd(middleware.RateLimitConfig{
    Limiter: limiter,
})(handler)

// 安全头
handler = middleware.SecurityHeadersStd(middleware.DefaultSecurityHeadersConfig())(handler)

// 请求体限制
handler = middleware.BodyLimitStd(middleware.BodyLimitConfig{
    MaxSize: 4 * 1024 * 1024,
})(handler)

// 压缩
handler = middleware.CompressStd(middleware.DefaultCompressConfig())(handler)

// 日志
handler = middleware.RequestLoggingStd(middleware.LoggingConfig{
    Logger: &logger,
})(handler)

http.ListenAndServe(":8080", handler)
```

## 项目结构

```
middleware-kit/
├── apikey.go           # API Key 认证
├── hmac.go             # HMAC 签名认证
├── mtls.go             # mTLS 客户端证书认证
├── auth.go             # 组合认证中间件
├── ratelimit.go        # 限流
├── security.go         # 安全头
├── bodylimit.go        # 请求体大小限制
├── compress.go         # Gzip 压缩
├── logging.go          # 请求日志
├── clientip.go         # 客户端 IP 检测
├── helpers.go          # 工具函数
├── errors.go           # 错误定义
└── *_test.go           # 完整测试
```

## 依赖要求

- Go 1.26 或更高版本
- github.com/gofiber/fiber/v2 v2.52.6+（Fiber 中间件）
- github.com/rs/zerolog v1.34.0+（日志）

## 测试覆盖

运行测试：

```bash
go test ./... -v

# 带覆盖率
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -html=coverage.out -o coverage.html
go tool cover -func=coverage.out
```

## 贡献

1. Fork 此仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

## 许可证

详见 [LICENSE](LICENSE) 文件。
