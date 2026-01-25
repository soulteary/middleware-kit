// Package middleware provides HTTP middleware functionality for Go services.
// Includes authentication (API Key, HMAC, mTLS), rate limiting, compression,
// request body limiting, security headers, and logging middleware.
package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// TrustedProxyConfig configures trusted proxy settings for client IP detection.
type TrustedProxyConfig struct {
	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges.
	// If empty, private IP addresses are trusted by default.
	TrustedProxies []string

	// TrustAllProxies trusts all proxies (not recommended for production).
	TrustAllProxies bool

	// parsedCIDRs holds parsed CIDR networks for efficient matching
	parsedCIDRs []*net.IPNet

	// parsedIPs holds parsed IP addresses for efficient matching
	parsedIPs []net.IP
}

// DefaultTrustedProxyConfig returns a default configuration that trusts private IPs.
func DefaultTrustedProxyConfig() *TrustedProxyConfig {
	return &TrustedProxyConfig{
		TrustedProxies:  []string{},
		TrustAllProxies: false,
	}
}

// NewTrustedProxyConfig creates a TrustedProxyConfig from a list of IP addresses or CIDR ranges.
func NewTrustedProxyConfig(proxies []string) *TrustedProxyConfig {
	cfg := &TrustedProxyConfig{
		TrustedProxies: proxies,
	}
	cfg.parse()
	return cfg
}

// parse parses the trusted proxy list into IP addresses and CIDR networks.
func (c *TrustedProxyConfig) parse() {
	for _, proxy := range c.TrustedProxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}

		// Try to parse as CIDR
		if strings.Contains(proxy, "/") {
			_, network, err := net.ParseCIDR(proxy)
			if err == nil {
				c.parsedCIDRs = append(c.parsedCIDRs, network)
				continue
			}
		}

		// Try to parse as IP
		if ip := net.ParseIP(proxy); ip != nil {
			c.parsedIPs = append(c.parsedIPs, ip)
		}
	}
}

// IsTrusted checks if an IP address is from a trusted proxy.
func (c *TrustedProxyConfig) IsTrusted(ip net.IP) bool {
	if c.TrustAllProxies {
		return true
	}

	// Check parsed IPs
	for _, trustedIP := range c.parsedIPs {
		if trustedIP.Equal(ip) {
			return true
		}
	}

	// Check parsed CIDRs
	for _, network := range c.parsedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}

	// If no trusted proxies configured, trust private IPs by default
	if len(c.parsedIPs) == 0 && len(c.parsedCIDRs) == 0 {
		return IsPrivateIP(ip)
	}

	return false
}

// IsPrivateIP checks if an IP address is a private IP address.
func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip4[0] == 127 {
			return true
		}
	}

	// IPv6 loopback
	if ip.Equal(net.IPv6loopback) {
		return true
	}

	// IPv6 link-local
	if ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}

// GetClientIP extracts the real client IP address from an HTTP request.
// It checks X-Real-IP and X-Forwarded-For headers if the request is from a trusted proxy.
func GetClientIP(r *http.Request, trustedConfig *TrustedProxyConfig) string {
	if trustedConfig == nil {
		trustedConfig = DefaultTrustedProxyConfig()
	}

	// Get the direct connection IP
	remoteIP := getRemoteIP(r.RemoteAddr)
	if remoteIP == nil {
		return r.RemoteAddr
	}

	// If not from trusted proxy, return direct IP
	if !trustedConfig.IsTrusted(remoteIP) {
		return remoteIP.String()
	}

	// Check X-Real-IP header first (usually more reliable)
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(realIP)); ip != nil {
			return ip.String()
		}
	}

	// Check X-Forwarded-For header
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP (leftmost, which is the original client)
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(ips[0])); ip != nil {
				return ip.String()
			}
		}
	}

	return remoteIP.String()
}

// GetClientIPFiber extracts the real client IP address from a Fiber context.
func GetClientIPFiber(c *fiber.Ctx, trustedConfig *TrustedProxyConfig) string {
	if trustedConfig == nil {
		trustedConfig = DefaultTrustedProxyConfig()
	}

	// Get the direct connection IP
	remoteIP := net.ParseIP(c.IP())
	if remoteIP == nil {
		return c.IP()
	}

	// If not from trusted proxy, return direct IP
	if !trustedConfig.IsTrusted(remoteIP) {
		return remoteIP.String()
	}

	// Check X-Real-IP header first
	if realIP := c.Get("X-Real-IP"); realIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(realIP)); ip != nil {
			return ip.String()
		}
	}

	// Check X-Forwarded-For header
	if forwarded := c.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(ips[0])); ip != nil {
				return ip.String()
			}
		}
	}

	return remoteIP.String()
}

// getRemoteIP extracts and parses the IP from a remote address string.
func getRemoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Maybe it's just an IP without port
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}
