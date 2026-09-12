// Package middleware provides HTTP middleware functionality for Go services.
// Includes authentication (API Key, HMAC, mTLS), rate limiting, compression,
// request body limiting, security headers, and logging middleware.
package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v3"
)

// TrustedProxyConfig configures trusted proxy settings for client IP detection.
//
// A zero value, or one built as a struct literal, is safe to use: the proxy
// list is parsed lazily on first use. Previously only NewTrustedProxyConfig
// populated the parsed fields, so a literal such as
//
//	&TrustedProxyConfig{TrustedProxies: []string{"10.0.0.1"}}
//
// left them empty and IsTrusted fell through to its "nothing configured" branch
// -- trusting every private address instead of the single one asked for. A
// tightened policy silently became a looser one.
type TrustedProxyConfig struct {
	// TrustedProxies is a list of trusted proxy IP addresses or CIDR ranges.
	// If empty, private IP addresses are trusted by default.
	TrustedProxies []string

	// TrustAllProxies trusts all proxies (not recommended for production).
	TrustAllProxies bool

	// parseOnce guards lazy parsing of TrustedProxies.
	parseOnce sync.Once

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
// It runs at most once per config, whether triggered by NewTrustedProxyConfig
// or lazily by the first IsTrusted call on a struct literal.
func (c *TrustedProxyConfig) parse() {
	c.parseOnce.Do(c.parseLocked)
}

func (c *TrustedProxyConfig) parseLocked() {
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

	c.parse()

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

	// IPv6 unique local addresses (fc00::/7). Without this an all-IPv6
	// deployment's proxies are never trusted, so forwarded headers from a
	// legitimate proxy are silently ignored.
	if ip.IsPrivate() {
		return true
	}

	return false
}

// clientIPFromForwarded resolves the client address from a forwarded chain,
// assuming the direct peer has already been established as a trusted proxy.
//
// The chain is walked from the RIGHT: every well-behaved hop appends the
// address it received the request from, so the rightmost entries are the
// proxies nearest to us. Entries that are themselves trusted proxies are
// skipped; the first untrusted address is the client.
//
// Taking the leftmost entry instead -- the previous behaviour -- is spoofable
// by design. A client sends "X-Forwarded-For: 1.2.3.4"; the proxy appends the
// real address to the right of it; the forged value is still first. That made
// every control keyed on this function (IP allow-list, per-IP rate limiting,
// audit logs) trivially bypassable even behind a correctly configured proxy.
func (c *TrustedProxyConfig) clientIPFromForwarded(forwarded, realIP string, peer net.IP) string {
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		chainBroken := false
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip == nil {
				// An unparseable hop breaks the chain of custody: nothing to
				// its left can be attributed to a trusted proxy.
				chainBroken = true
				break
			}
			if !c.IsTrusted(ip) {
				return ip.String()
			}
		}

		// Only when the walk actually reached the left end. Returning
		// parts[0] after a BROKEN chain handed back the very value an
		// attacker prepends: "X-Forwarded-For: 10.0.0.9, unknown" made the
		// forged 10.0.0.9 the answer as soon as one hop failed to parse --
		// and it won over a trustworthy X-Real-IP, because this returned
		// before that was consulted. A broken chain falls through instead.
		if !chainBroken {
			// Every hop is a trusted proxy (internal traffic): the leftmost
			// entry is the closest thing to a client address available.
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip.String()
			}
		}
	}

	// No usable chain. X-Real-IP is set by the immediate proxy, which we have
	// already established is trusted.
	if realIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(realIP)); ip != nil {
			return ip.String()
		}
	}

	return peer.String()
}

// GetClientIP extracts the real client IP address from an HTTP request.
// It honours X-Forwarded-For and X-Real-IP only when the direct peer is a
// trusted proxy, and resolves the chain from the right so a client cannot
// prepend an address of its choosing.
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

	return trustedConfig.clientIPFromForwarded(
		joinForwarded(r.Header.Values("X-Forwarded-For")),
		lastHeaderValue(r.Header.Values("X-Real-IP")),
		remoteIP,
	)
}

// GetClientIPFiber extracts the real client IP address from a Fiber context.
// It applies the same trusted-proxy and right-to-left chain resolution as
// GetClientIP.
func GetClientIPFiber(c fiber.Ctx, trustedConfig *TrustedProxyConfig) string {
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

	return trustedConfig.clientIPFromForwarded(
		joinForwarded(peekAllStrings(c, "X-Forwarded-For")),
		lastHeaderValue(peekAllStrings(c, "X-Real-IP")),
		remoteIP,
	)
}

// joinForwarded splices every X-Forwarded-For field into one chain, in wire
// order.
//
// The header may legitimately appear more than once: a proxy that APPENDS its
// own line instead of coalescing into the client's is compliant, and RFC 9110
// says the two forms are equivalent. Header.Get returns only the FIRST line,
// so in that deployment the resolver walked a chain consisting of nothing but
// the client's own fabrication -- the proxy-added address was never in it, and
// the right-to-left rule that makes this function spoof-resistant had nothing
// to work with. Every control keyed on it (allow-lists, per-IP rate limits)
// was bypassable by sending a single X-Forwarded-For header.
func joinForwarded(values []string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, ",")
}

// lastHeaderValue returns the last non-empty value of a single-valued header.
//
// The LAST, for the same reason: a proxy that appends rather than overwrites
// puts its own value after whatever the client sent, so the final line is the
// one attributable to the trusted hop. Where the proxy overwrites, there is
// only one and this is the same value Get would return.
func lastHeaderValue(values []string) string {
	for i := len(values) - 1; i >= 0; i-- {
		if strings.TrimSpace(values[i]) != "" {
			return values[i]
		}
	}
	return ""
}

// peekAllStrings returns every value of a request header from a Fiber context.
// fasthttp's Peek -- which c.Get uses -- returns only the first.
func peekAllStrings(c fiber.Ctx, name string) []string {
	raw := c.RequestCtx().Request.Header.PeekAll(name)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, string(v))
	}
	return out
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
