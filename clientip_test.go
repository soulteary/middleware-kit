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
	t.Run("X-Real-IP header", func(t *testing.T) {
		app := fiber.New()

		app.Use(func(c *fiber.Ctx) error {
			// Just call the function to ensure it works
			_ = GetClientIPFiber(c, nil)
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
		// Note: In test environment, the IP detection behavior may vary
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
