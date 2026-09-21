package fiberadapter

import (
	"net"

	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

// GetClientIPFiber resolves the client IP of a Fiber request. It applies the
// same trusted-proxy rules and the same right-to-left chain walk as
// middleware.GetClientIP: forwarded headers are read only when the direct peer
// is a trusted proxy, and the chain is walked from the right so a client-
// supplied prefix cannot win.
//
// A nil trustedConfig means middleware.DefaultTrustedProxyConfig.
func GetClientIPFiber(c fiber.Ctx, trustedConfig *middleware.TrustedProxyConfig) string {
	if trustedConfig == nil {
		trustedConfig = middleware.DefaultTrustedProxyConfig()
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

	return trustedConfig.ClientIPFromForwarded(
		middleware.JoinForwarded(peekAllStrings(c, "X-Forwarded-For")),
		middleware.LastHeaderValue(peekAllStrings(c, "X-Real-IP")),
		remoteIP,
	)
}

// peekAllStrings returns every value of a request header. fasthttp's Peek --
// which c.Get uses -- returns only the first, which would hide the proxy-added
// address in a deployment whose proxy appends its own header line.
func peekAllStrings(c fiber.Ctx, name string) []string {
	raw := c.RequestCtx().Request.Header.PeekAll(name)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, string(v))
	}
	return out
}
