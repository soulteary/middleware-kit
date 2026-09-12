# middleware-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/middleware-kit/v2.svg)](https://pkg.go.dev/github.com/soulteary/middleware-kit/v2)
[![Go Report Card](.github/goreportcard.svg)](.github/goreportcard-report.md)
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
go get github.com/soulteary/middleware-kit/v2
```

## 使用方法

### API Key 认证

```go
import (
    "github.com/gofiber/fiber/v3"
    middleware "github.com/soulteary/middleware-kit/v2"
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

// 客户端侧计算签名
timestamp := strconv.FormatInt(time.Now().Unix(), 10)
signature := middleware.ComputeHMAC(timestamp, "service-name", requestBody, secret)
// 请求头：X-Signature、X-Timestamp、X-Service、X-Key-Id（可选）
```

#### 把签名绑定到请求上

默认被签名的消息是 `timestamp:service:body`。它**既不覆盖方法也不覆盖路径**，因此为
`POST /transfer` 签出的签名，在 body 相同的 `POST /delete-account` 上同样有效。

`ComputeHMACBound` 会把方法、路径和查询串一并签进去，并给每个字段加长度前缀，使编码
成为单射。改变被签名的字节会一次性让所有已部署的签名方失效，所以这是可选项：

```go
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    Secret:               "your-hmac-secret",
    RequestSignatureFunc: middleware.ComputeHMACBound,
}))
```

客户端用同样的方式签名：

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

旧编码就地变安全了：由于 `service` 来自客户端提供的请求头、而旧格式不是单射的，
（`service` 为 `"a"`、`body` 为 `"b:c"`）的签名可以被当成（`service` 为 `"a:b"`、
`body` 为 `"c"`）提交。现在含分隔符的 service 标识会被拒绝。只有在确实有已部署的签名方
依赖它时，才设置 `AllowDelimitersInService`。

#### 重放保护

时间戳窗口只限定被截获的请求还能用多久——它并不阻止请求在窗口内被重放。没有守卫时，
每个已签名的请求在 `MaxTimeDrift` 期间都是可重放的：

```go
app.Use(middleware.HMACAuth(middleware.HMACConfig{
    Secret:      "your-hmac-secret",
    ReplayGuard: middleware.NewMemoryReplayGuard(), // 单实例
}))
```

`ReplayGuard` 是接口，多实例部署可以用共享存储实现：

```go
type ReplayGuard interface {
    // Seen 报告 id 是否此前已被接受过，并把它记录 ttl 时长。
    Seen(id string, ttl time.Duration) bool
}
```

### mTLS 客户端证书认证

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

**证书必须已由 TLS 层校验通过。** 只要对端*发送了*证书，
`tls.ConnectionState.PeerCertificates` 就会被填充，而在 `tls.RequestClientCert` 或
`tls.RequireAnyClientCert` 下服务端什么都不校验——于是自签名证书可以通过，而由于它的
Subject 由生成者自己决定，上层的 CN 白名单也提供不了保护。现在认证要求
`VerifiedChains` 非空；请把 `tls.Config` 配置为
`ClientAuth: tls.RequireAndVerifyClientCert` 并提供 `ClientCAs` 池。

未经校验的证书会以 `ErrMTLSCertificateUnverified` 被拒绝。失败原因会被包装，因此日志
仍能指出具体成因。

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

`CombinedAuth` 的 mTLS 分支执行与独立 `MTLSAuth` 中间件完全相同的检查，包括
`AllowedCNs`、`AllowedOUs`、`AllowedDNSSANs` 和 `CertValidator`，因此组合中间件不会
接受独立中间件会拒绝的请求。

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
    KeyFunc: func(c fiber.Ctx) string {
        return c.Get("X-User-ID")
    },
}))
```

内存限流器把窗口起点与淘汰时间戳分开记录，因此活跃客户端会按时滚动窗口："每分钟 100
次"意味着任意一分钟内 100 次，而不是"100 次之后必须安静整整一分钟"。

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
// 一定要用构造函数来建这个配置
trustedProxies := middleware.NewTrustedProxyConfig([]string{
    "10.0.0.0/8",
    "192.168.1.1",
})

// Fiber 处理器中
app.Get("/", func(c fiber.Ctx) error {
    clientIP := middleware.GetClientIPFiber(c, trustedProxies)
    return c.SendString("Your IP: " + clientIP)
})

// 标准 HTTP 处理器中
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    clientIP := middleware.GetClientIP(r, trustedProxies)
    fmt.Fprintf(w, "Your IP: %s", clientIP)
})
```

`X-Forwarded-For` 是**从右往左**遍历的，跳过本身属于可信代理的跳数，在第一个不可信的
地址处停下。这是唯一不可伪造的读法：客户端发送 `X-Forwarded-For: 1.2.3.4`，代理把真实
地址*追加*到它右边，于是伪造的值仍然在最左。只有在没有可用链路时才会使用
`X-Real-IP`。

所有以这个函数为基础的管控——IP 白名单、按 IP 限流、审计日志——可信程度都取决于
`TrustedProxies`，所以请把它设成你实际的代理。什么都不配置时，私有地址会被信任。

IPv6 唯一本地地址（`fc00::/7`）算作私有地址，因此纯 IPv6 部署也能信任自己的代理。

### 数据脱敏工具
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
    middleware "github.com/soulteary/middleware-kit/v2"
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

## 升级说明（v2.2.0）

**其中三条会拒绝此前能通过认证的请求。** 升级线上部署前请先读 mTLS 和 HMAC 两条。

- **mTLS 要求证书已通过 TLS 校验。** `MTLSAuth` 和 `CombinedAuth` 此前接受对端*发送*
  的任何证书，因为 `PeerCertificates` 无论是否校验都会被填充——在
  `tls.RequestClientCert` 或 `tls.RequireAnyClientCert` 下服务端什么都不校验，于是
  自签名证书能通过，上层的 CN 白名单也提供不了保护。现在要求 `VerifiedChains` 非空。
  **如果你的 `tls.Config` 没有使用 `RequireAndVerifyClientCert` 并配置 `ClientCAs`
  池，mTLS 客户端会开始以 `ErrMTLSCertificateUnverified` 失败。**
- **`CombinedAuth` 现在会执行 mTLS 白名单。** 它的 mTLS 分支此前只检查
  `len(PeerCertificates) > 0` 就 `c.Next()`，于是 `AllowedCNs`、`AllowedOUs`、
  `AllowedDNSSANs` 和 `CertValidator` 从未被查阅——在那里配置它们毫无作用，任何客户端
  证书都能通过认证。
- **含分隔符的 HMAC `service` 会被拒绝。** 旧的被签名消息 `timestamp:service:body`
  不是单射的，而 `service` 来自客户端提供的请求头，于是（`"a"`、`"b:c"`）的签名可以被
  当成（`"a:b"`、`"c"`）提交。若有已部署的签名方需要旧行为，请设置
  `AllowDelimitersInService`。
- **`X-Forwarded-For` 从右往左读，`X-Real-IP` 不再优先。** 取最左项在设计上就是可伪造
  的——代理会把真实地址追加到客户端所发内容的右边——因此即便代理配置正确，所有以
  `GetClientIP` 为基础的管控都可被绕过。**你日志和限流桶里的客户端 IP 会发生变化**，
  变成正确的值。
- **`TrustedProxyConfig` 改为懒解析。** 解析此前只发生在 `NewTrustedProxyConfig` 里，
  而 `TrustedProxies` 是导出字段、`DefaultTrustedProxyConfig` 返回的是字面量——于是用
  结构体字面量构造的配置解析列表为空，落进"什么都没配置"的分支，信任所有私有地址而不是
  你要求的那一个。收紧策略反而静默放宽了。
- **IPv6 唯一本地地址（`fc00::/7`）算作私有。** 纯 IPv6 部署此前从不信任自己的代理。
- **限流窗口会为活跃客户端滚动。** 内存限流器此前拿窗口和 `lastSeen` 比较，而后者在每个
  被允许的请求上都会刷新，于是计数器只增不减："每分钟 100 次"变成了"100 次之后必须安静
  整整一分钟"，稳定 1 req/s 的客户端会在第 100 秒被拦住。**一些你此前在拦的客户端现在会
  被放过**——这是正确的。
- **`X-XSS-Protection` 默认为 `"0"`。** 该头已废弃，而 `"1; mode=block"` 启用的过滤器
  本身引入了 XSS 和信息泄露问题。
- **密钥比较不再泄露长度。** `constantTimeEqual` 此前直接调用
  `subtle.ConstantTimeCompare`，而它在长度不一致时会提前返回。
- **新增 API**：用于 HMAC 重放保护的 `ReplayGuard` 和 `NewMemoryReplayGuard`；用于让
  签名覆盖方法、路径和查询串的 `ComputeHMACBound`、`SignatureInput` 和
  `RequestSignatureFunc`；`HMACConfig.AllowDelimitersInService`；
  `ErrMTLSCertificateUnverified`。

## 依赖要求

- **Go 1.27+**（`go.mod` 声明 `go 1.27.0`）
- github.com/gofiber/fiber/v3 v3.4.0+（Fiber 中间件）
- github.com/rs/zerolog v1.34.0+（日志）

此 v2 模块版本面向 Fiber v3。仍使用 Fiber v2 的应用应继续使用 `github.com/soulteary/middleware-kit` v1。

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
