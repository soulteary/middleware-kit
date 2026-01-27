// Package middleware provides IP allowlist middleware for net/http.
// Only requests whose client IP is in the allowlist are permitted; others receive 403 Forbidden.
package middleware

import (
	"net"
	"net/http"
	"strings"
)

// IPAllowlistConfig configures IP allowlist middleware.
type IPAllowlistConfig struct {
	// Allowlist is a comma-separated list of IP addresses and/or CIDR networks (e.g. "127.0.0.1,10.0.0.0/8").
	// If empty, all requests are allowed (pass-through).
	Allowlist string
	// OnDenied is called when the client IP is not in the allowlist. If nil, http.Error(w, "Forbidden", 403) is used.
	// Use this to log and then respond (e.g. log and http.Error).
	OnDenied func(w http.ResponseWriter, r *http.Request)
	// TrustedProxyConfig for client IP resolution. If nil, DefaultTrustedProxyConfig() is used.
	TrustedProxyConfig *TrustedProxyConfig
}

// IPAllowlistMiddleware returns an http.Handler that allows only requests from IPs or CIDR ranges in allowlist.
// allowlist is comma-separated (e.g. "127.0.0.1,10.0.0.0/8,192.168.1.1").
// If allowlist is empty, the returned handler is a pass-through (all requests allowed).
// Client IP is resolved via GetClientIP(r, nil); use IPAllowlistMiddlewareFromConfig when you need OnDenied or TrustedProxyConfig.
func IPAllowlistMiddleware(allowlist string) func(http.Handler) http.Handler {
	return IPAllowlistMiddlewareFromConfig(IPAllowlistConfig{Allowlist: allowlist})
}

// IPAllowlistMiddlewareFromConfig returns an http.Handler that allows only requests from IPs or CIDR ranges in cfg.Allowlist.
// If cfg.Allowlist is empty, the returned handler is a pass-through. When access is denied, cfg.OnDenied is called if set,
// otherwise http.Error(w, "Forbidden", 403) is used. Client IP is resolved via GetClientIP(r, cfg.TrustedProxyConfig).
func IPAllowlistMiddlewareFromConfig(cfg IPAllowlistConfig) func(http.Handler) http.Handler {
	allowlist := strings.TrimSpace(cfg.Allowlist)
	if allowlist == "" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	allowedIPs, allowedNetworks := parseIPAllowlist(allowlist)
	onDenied := cfg.OnDenied
	if onDenied == nil {
		onDenied = func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
	trusted := cfg.TrustedProxyConfig
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := GetClientIP(r, trusted)
			if isIPInAllowlist(clientIP, allowedIPs, allowedNetworks) {
				next.ServeHTTP(w, r)
				return
			}
			onDenied(w, r)
		})
	}
}

// parseIPAllowlist parses a comma-separated allowlist into single IPs and CIDR networks.
func parseIPAllowlist(allowlist string) (map[string]bool, []*net.IPNet) {
	allowedIPs := make(map[string]bool)
	var allowedNetworks []*net.IPNet
	for _, s := range strings.Split(allowlist, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			allowedNetworks = append(allowedNetworks, n)
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			allowedIPs[ip.String()] = true
		}
	}
	return allowedIPs, allowedNetworks
}

// isIPInAllowlist reports whether ipStr is in allowedIPs or any of allowedNetworks.
func isIPInAllowlist(ipStr string, allowedIPs map[string]bool, allowedNetworks []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if allowedIPs[ip.String()] {
		return true
	}
	for _, n := range allowedNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
