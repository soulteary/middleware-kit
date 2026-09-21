package fiberadapter

import (
	"time"

	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
)

// CombinedAuth returns a Fiber middleware that tries every configured
// authentication scheme in order of decreasing strength -- mTLS, then HMAC, then
// API key -- and admits the request on the first that succeeds.
//
// Each scheme runs the same check its dedicated middleware runs, so a request
// this middleware admits is one MTLSAuth, HMACAuth or APIKeyAuth would admit
// too. With no scheme configured the request is refused unless AllowNoAuth is
// set.
func CombinedAuth(cfg AuthConfig) fiber.Handler {
	var mtlsLists middleware.CertAllowLists
	if cfg.MTLSConfig != nil {
		mtlsLists = middleware.NewCertAllowLists(*cfg.MTLSConfig)
	}

	return func(c fiber.Ctx) error {
		// Check if any authentication method is configured
		hasMTLS := cfg.MTLSConfig != nil
		hasHMAC := cfg.HMACConfig != nil && (cfg.HMACConfig.Secret != "" || cfg.HMACConfig.KeyProvider != nil)
		hasAPIKey := cfg.APIKeyConfig != nil && cfg.APIKeyConfig.APIKey != ""

		if !hasMTLS && !hasHMAC && !hasAPIKey {
			if cfg.AllowNoAuth {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("No authentication method configured, allowing request (development mode)")
				}
				return c.Next()
			}
			return handleCombinedAuthError(c, cfg, middleware.ErrUnauthorized)
		}

		// Try mTLS first (if TLS connection with a verified client certificate).
		//
		// This runs the same middleware.AuthenticateMTLS check as the dedicated MTLSAuth
		// middleware. Previously it only tested len(PeerCertificates) > 0 and
		// returned c.Next(), which meant AllowedCNs, AllowedOUs,
		// AllowedDNSSANs and CertValidator were all silently ignored here --
		// any client certificate, including a self-signed one, authenticated.
		//
		// There is no `c.Protocol() == "https"` guard in front of it: in Fiber
		// v3 Protocol reports the HTTP VERSION ("HTTP/1.1"), so such a guard
		// was never satisfied and this scheme was never attempted -- an
		// mTLS-only AuthConfig rejected every request, and a mixed one
		// silently demanded HMAC or an API key from clients that had already
		// presented a valid certificate. AuthenticateMTLS reads the TLS
		// connection state itself and reports a plaintext connection as an
		// absent certificate, so a non-TLS request simply falls through to the
		// remaining methods.
		if hasMTLS {
			cert, err := middleware.AuthenticateMTLS(c.RequestCtx().TLSConnectionState(), *cfg.MTLSConfig, mtlsLists)
			if err == nil {
				if cfg.Logger != nil {
					cfg.Logger.Debug().
						Str("cn", cert.Subject.CommonName).
						Msg("Request authenticated via mTLS")
				}
				return c.Next()
			}
			if cfg.Logger != nil {
				cfg.Logger.Debug().Err(err).Msg("mTLS authentication did not apply")
			}
			// Fall through to the remaining methods.
		}

		// Try HMAC signature
		if hasHMAC {
			signature := c.Get(middleware.HeaderOrDefault(cfg.HMACConfig.SignatureHeader, "X-Signature"))
			timestamp := c.Get(middleware.HeaderOrDefault(cfg.HMACConfig.TimestampHeader, "X-Timestamp"))

			if signature != "" && timestamp != "" {
				// Create a temporary HMACConfig with logger
				hmacCfg := *cfg.HMACConfig
				if hmacCfg.Logger == nil && cfg.Logger != nil {
					hmacCfg.Logger = cfg.Logger
				}
				if hmacCfg.TrustedProxyConfig == nil && cfg.TrustedProxyConfig != nil {
					hmacCfg.TrustedProxyConfig = cfg.TrustedProxyConfig
				}

				// Try HMAC validation inline
				if validateHMAC(c, hmacCfg) {
					if cfg.Logger != nil {
						cfg.Logger.Debug().Msg("Request authenticated via HMAC")
					}
					return c.Next()
				}
				// HMAC was provided but failed, we should still check API key
			}
		}

		// Try API Key
		if hasAPIKey {
			apiKeyCfg := *cfg.APIKeyConfig
			if apiKeyCfg.Logger == nil && cfg.Logger != nil {
				apiKeyCfg.Logger = cfg.Logger
			}
			if apiKeyCfg.TrustedProxyConfig == nil && cfg.TrustedProxyConfig != nil {
				apiKeyCfg.TrustedProxyConfig = cfg.TrustedProxyConfig
			}

			if validateAPIKey(c, apiKeyCfg) {
				if cfg.Logger != nil {
					cfg.Logger.Debug().Msg("Request authenticated via API Key")
				}
				return c.Next()
			}
		}

		// No authentication method succeeded
		return handleCombinedAuthError(c, cfg, middleware.ErrUnauthorized)
	}
}

func validateHMAC(c fiber.Ctx, cfg middleware.HMACConfig) bool {
	signature := c.Get(middleware.HeaderOrDefault(cfg.SignatureHeader, "X-Signature"))
	timestamp := c.Get(middleware.HeaderOrDefault(cfg.TimestampHeader, "X-Timestamp"))
	keyID := c.Get(middleware.HeaderOrDefault(cfg.KeyIDHeader, "X-Key-Id"))
	service := c.Get(middleware.HeaderOrDefault(cfg.ServiceHeader, "X-Service"))

	if signature == "" || timestamp == "" {
		return false
	}

	// Get the HMAC secret
	secret := cfg.Secret
	if cfg.KeyProvider != nil {
		secret = cfg.KeyProvider(keyID)
	}

	if secret == "" {
		return false
	}

	// Validate timestamp
	ts, err := middleware.ParseTimestamp(timestamp)
	if err != nil {
		return false
	}

	maxDrift := cfg.MaxTimeDrift
	if maxDrift == 0 {
		// 5 * 60 here was a time.Duration of 300 NANOSECONDS, not five
		// minutes: int64(maxDrift.Seconds()) then rounded to 0, so the
		// documented zero value demanded a timestamp matching the current
		// second exactly, and the replay guard retained entries for 600ns.
		maxDrift = 5 * time.Minute
	}

	if !middleware.IsTimestampValid(ts, int64(maxDrift.Seconds())) {
		return false
	}

	if !cfg.ServiceAllowed(service) {
		return false
	}

	expectedSig := cfg.ExpectedSignature(middleware.SignatureInput{
		Method: c.Method(),
		// The ESCAPED path: see middleware.SignatureInput.Path.
		Path:      string(c.RequestCtx().URI().PathOriginal()),
		RawQuery:  string(c.RequestCtx().URI().QueryString()),
		Timestamp: timestamp,
		Service:   service,
		Body:      string(c.Body()),
		Secret:    secret,
	})

	if !middleware.ConstantTimeEqual(signature, expectedSig) {
		return false
	}

	// The NORMALIZED drift, not cfg.MaxTimeDrift. With the documented zero
	// value, validation above computed a five-minute default while this call
	// passed 0, so MemoryReplayGuard expired the entry on the very next
	// request and enabling ReplayGuard prevented no replay at all.
	if cfg.ReplayGuard != nil && cfg.ReplayGuard.Seen(signature, middleware.ReplayRetention(maxDrift)) {
		return false
	}

	return true
}

func validateAPIKey(c fiber.Ctx, cfg middleware.APIKeyConfig) bool {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}

	// Try to get API key from various sources
	providedKey := c.Get(headerName)

	// Check Authorization header with scheme
	if providedKey == "" && cfg.AuthScheme != "" {
		authHeader := c.Get("Authorization")
		prefix := cfg.AuthScheme + " "
		if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
			providedKey = authHeader[len(prefix):]
		}
	}

	// Check query parameter
	if providedKey == "" && cfg.QueryParamName != "" {
		providedKey = c.Query(cfg.QueryParamName)
	}

	if providedKey == "" {
		return false
	}

	return middleware.ConstantTimeEqual(providedKey, cfg.APIKey)
}

func handleCombinedAuthError(c fiber.Ctx, cfg AuthConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": "unauthorized",
	})
}
