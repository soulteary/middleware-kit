package middleware

import (
	"net"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"loopback IPv4", "127.0.0.1", true},
		{"loopback IPv4 other", "127.0.0.2", true},
		{"private 10.x.x.x", "10.0.0.1", true},
		{"private 10.x.x.x other", "10.255.255.255", true},
		{"private 172.16.x.x", "172.16.0.1", true},
		{"private 172.31.x.x", "172.31.255.255", true},
		{"not private 172.15.x.x", "172.15.0.1", false},
		{"not private 172.32.x.x", "172.32.0.1", false},
		{"private 192.168.x.x", "192.168.0.1", true},
		{"private 192.168.x.x other", "192.168.255.255", true},
		{"public IP", "8.8.8.8", false},
		{"public IP 2", "1.1.1.1", false},
		{"loopback IPv6", "::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			assert.Equal(t, tt.expected, IsPrivateIP(ip))
		})
	}
}

func TestTrustedProxyConfig(t *testing.T) {
	t.Run("trust all proxies", func(t *testing.T) {
		cfg := &TrustedProxyConfig{TrustAllProxies: true}
		assert.True(t, cfg.IsTrusted(net.ParseIP("8.8.8.8")))
		assert.True(t, cfg.IsTrusted(net.ParseIP("192.168.1.1")))
	})

	t.Run("trust specific IPs", func(t *testing.T) {
		cfg := NewTrustedProxyConfig([]string{"192.168.1.1", "10.0.0.1"})
		assert.True(t, cfg.IsTrusted(net.ParseIP("192.168.1.1")))
		assert.True(t, cfg.IsTrusted(net.ParseIP("10.0.0.1")))
		assert.False(t, cfg.IsTrusted(net.ParseIP("8.8.8.8")))
	})

	t.Run("trust CIDR ranges", func(t *testing.T) {
		cfg := NewTrustedProxyConfig([]string{"192.168.0.0/16", "10.0.0.0/8"})
		assert.True(t, cfg.IsTrusted(net.ParseIP("192.168.1.1")))
		assert.True(t, cfg.IsTrusted(net.ParseIP("192.168.255.255")))
		assert.True(t, cfg.IsTrusted(net.ParseIP("10.0.0.1")))
		assert.False(t, cfg.IsTrusted(net.ParseIP("8.8.8.8")))
	})

	t.Run("default trusts private IPs", func(t *testing.T) {
		cfg := DefaultTrustedProxyConfig()
		assert.True(t, cfg.IsTrusted(net.ParseIP("192.168.1.1")))
		assert.True(t, cfg.IsTrusted(net.ParseIP("10.0.0.1")))
		assert.True(t, cfg.IsTrusted(net.ParseIP("127.0.0.1")))
		assert.False(t, cfg.IsTrusted(net.ParseIP("8.8.8.8")))
	})
}

func TestGetClientIP_Standard(t *testing.T) {
	t.Run("direct connection", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "8.8.8.8:12345"

		ip := GetClientIP(req, nil)
		assert.Equal(t, "8.8.8.8", ip)
	})

	t.Run("X-Real-IP from trusted proxy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.1")

		ip := GetClientIP(req, nil) // Default trusts private IPs
		assert.Equal(t, "203.0.113.1", ip)
	})

	t.Run("X-Forwarded-For from trusted proxy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.2")

		ip := GetClientIP(req, nil)
		assert.Equal(t, "203.0.113.1", ip)
	})

	t.Run("ignore headers from untrusted proxy", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "8.8.8.8:12345"
		req.Header.Set("X-Real-IP", "1.1.1.1")

		ip := GetClientIP(req, nil)
		assert.Equal(t, "8.8.8.8", ip)
	})

	t.Run("X-Real-IP preferred over X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.1")
		req.Header.Set("X-Forwarded-For", "203.0.113.2")

		ip := GetClientIP(req, nil)
		assert.Equal(t, "203.0.113.1", ip)
	})
}

func TestGetClientIPFiber(t *testing.T) {
	t.Run("returns IP from context", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, nil)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		// Should return some IP (even if it's 0.0.0.0 in test)
		assert.NotEmpty(t, capturedIP)
	})

	t.Run("X-Real-IP from trusted proxy", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		// Use trust all proxies for testing
		cfg := &TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.1")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, "203.0.113.1", capturedIP)
	})

	t.Run("X-Forwarded-For from trusted proxy", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.1, 10.0.0.2")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, "203.0.113.2", capturedIP)
	})

	t.Run("X-Real-IP preferred over X-Forwarded-For", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.1")
		req.Header.Set("X-Forwarded-For", "203.0.113.2")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, "203.0.113.1", capturedIP)
	})

	t.Run("with nil config uses default", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, nil)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, capturedIP)
	})

	t.Run("invalid X-Real-IP header ignored", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "not-an-ip")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		// Should fall back to connection IP
		assert.NotEmpty(t, capturedIP)
	})

	t.Run("invalid X-Forwarded-For header ignored", func(t *testing.T) {
		app := fiber.New()
		var capturedIP string

		cfg := &TrustedProxyConfig{TrustAllProxies: true}

		app.Use(func(c *fiber.Ctx) error {
			capturedIP = GetClientIPFiber(c, cfg)
			return c.Next()
		})

		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "invalid-ip, also-invalid")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, capturedIP)
	})
}

func TestGetRemoteIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{"with port", "192.168.1.1:12345", "192.168.1.1"},
		{"IPv6 with port", "[::1]:12345", "::1"},
		{"just IP", "192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := getRemoteIP(tt.remoteAddr)
			if ip != nil {
				assert.Equal(t, tt.expected, ip.String())
			}
		})
	}
}

func TestGetClientIP_EdgeCases(t *testing.T) {
	t.Run("invalid remote address returns raw", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "invalid-address"

		ip := GetClientIP(req, nil)
		assert.Equal(t, "invalid-address", ip)
	})

	t.Run("invalid X-Real-IP falls back to X-Forwarded-For", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Real-IP", "invalid-ip")
		req.Header.Set("X-Forwarded-For", "203.0.113.1")

		ip := GetClientIP(req, nil)
		assert.Equal(t, "203.0.113.1", ip)
	})

	t.Run("invalid X-Forwarded-For falls back to remote IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		req.Header.Set("X-Real-IP", "invalid-ip")
		req.Header.Set("X-Forwarded-For", "also-invalid")

		ip := GetClientIP(req, nil)
		assert.Equal(t, "192.168.1.1", ip)
	})
}

func TestTrustedProxyConfig_Parse(t *testing.T) {
	t.Run("empty proxy string is skipped", func(t *testing.T) {
		cfg := NewTrustedProxyConfig([]string{"192.168.1.1", "", "  ", "10.0.0.1"})
		assert.Equal(t, 2, len(cfg.parsedIPs))
	})

	t.Run("invalid CIDR falls back to IP parsing", func(t *testing.T) {
		cfg := NewTrustedProxyConfig([]string{"192.168.1.0/invalid"})
		// Should not parse as CIDR or IP
		assert.Equal(t, 0, len(cfg.parsedCIDRs))
		assert.Equal(t, 0, len(cfg.parsedIPs))
	})
}

func TestIsPrivateIP_LinkLocal(t *testing.T) {
	t.Run("IPv6 link-local is private", func(t *testing.T) {
		ip := net.ParseIP("fe80::1")
		assert.True(t, IsPrivateIP(ip))
	})

	t.Run("nil IP is not private", func(t *testing.T) {
		assert.False(t, IsPrivateIP(nil))
	})
}
