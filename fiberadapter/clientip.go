package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
	"net"
)

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

func peekAllStrings(c fiber.Ctx, name string) []string {
	raw := c.RequestCtx().Request.Header.PeekAll(name)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, string(v))
	}
	return out
}
