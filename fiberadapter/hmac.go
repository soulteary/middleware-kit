package fiberadapter

import (
	"crypto/hmac"
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v2"
	"strconv"
	"time"
)

func HMACAuth(cfg HMACConfig) fiber.Handler {
	// Apply defaults
	if cfg.SignatureHeader == "" {
		cfg.SignatureHeader = "X-Signature"
	}
	if cfg.TimestampHeader == "" {
		cfg.TimestampHeader = "X-Timestamp"
	}
	if cfg.KeyIDHeader == "" {
		cfg.KeyIDHeader = "X-Key-Id"
	}
	if cfg.ServiceHeader == "" {
		cfg.ServiceHeader = "X-Service"
	}
	if cfg.MaxTimeDrift == 0 {
		cfg.MaxTimeDrift = 5 * time.Minute
	}
	// SignatureFunc is deliberately NOT defaulted to ComputeHMAC here.
	//
	// ExpectedSignature already falls back to it, and materializing the
	// default made ServiceAllowed see a non-nil function and mistake the
	// legacy delimiter-based signer for a caller-supplied custom one -- which
	// re-allowed ':' in the service header and reopened the collision that
	// check exists to close.

	return func(c fiber.Ctx) error {
		// Get signature and timestamp from headers
		signature := c.Get(cfg.SignatureHeader)
		timestamp := c.Get(cfg.TimestampHeader)
		keyID := c.Get(cfg.KeyIDHeader)
		service := c.Get(cfg.ServiceHeader)

		// Check if signature is provided
		if signature == "" {
			return handleHMACError(c, cfg, middleware.ErrHMACSignatureMissing)
		}

		// Check if timestamp is provided
		if timestamp == "" {
			return handleHMACError(c, cfg, middleware.ErrHMACTimestampMissing)
		}

		// Get the HMAC secret
		secret := cfg.Secret
		if cfg.KeyProvider != nil {
			secret = cfg.KeyProvider(keyID)
			if secret == "" && keyID != "" {
				return handleHMACError(c, cfg, middleware.ErrHMACKeyIDInvalid)
			}
		}

		// Check if secret is configured
		if secret == "" {
			if cfg.AllowEmptySecret {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Msg("HMAC authentication disabled (no secret configured)")
				}
				return c.Next()
			}
			return handleHMACError(c, cfg, middleware.ErrHMACSecretNotConfigured)
		}

		// Validate timestamp
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return handleHMACError(c, cfg, middleware.ErrHMACTimestampInvalid)
		}

		// Check timestamp drift
		now := time.Now().Unix()
		drift := now - ts
		if drift < 0 {
			drift = -drift
		}
		if time.Duration(drift)*time.Second > cfg.MaxTimeDrift {
			if cfg.Logger != nil {
				cfg.Logger.Warn().
					Int64("timestamp", ts).
					Int64("now", now).
					Int64("drift_seconds", drift).
					Msg("HMAC authentication failed: timestamp expired")
			}
			return handleHMACError(c, cfg, middleware.ErrHMACTimestampExpired)
		}

		// A service identifier carrying the legacy encoding's delimiter would
		// let one signature stand for two different (service, body) pairs.
		// Only the legacy encoding is ambiguous; see ServiceAllowed.
		if !cfg.ServiceAllowed(service) {
			if cfg.Logger != nil {
				cfg.Logger.Warn().Str("service", service).Msg("HMAC authentication failed: service contains a reserved character")
			}
			return handleHMACError(c, cfg, middleware.ErrHMACSignatureInvalid)
		}

		// Compute expected signature
		body := string(c.Body())
		expectedSig := cfg.ExpectedSignature(middleware.SignatureInput{
			Method: c.Method(),
			// The ESCAPED path: see middleware.SignatureInput.Path. c.Path() is decoded,
			// so "/a/b" and "/a%2Fb" sign identically while routing to
			// different handlers.
			Path:      string(c.RequestCtx().URI().PathOriginal()),
			RawQuery:  string(c.RequestCtx().URI().QueryString()),
			Timestamp: timestamp,
			Service:   service,
			Body:      body,
			Secret:    secret,
		})

		// Compare signatures using constant-time comparison
		if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
			if cfg.Logger != nil {
				clientIP := GetClientIPFiber(c, cfg.TrustedProxyConfig)
				cfg.Logger.Warn().
					Str("ip", clientIP).
					Str("path", c.Path()).
					Str("method", c.Method()).
					Str("service", service).
					Msg("HMAC authentication failed: signature mismatch")
			}
			return handleHMACError(c, cfg, middleware.ErrHMACSignatureInvalid)
		}

		// Reject a signature that has already been accepted. The timestamp
		// window bounds how long a captured request stays useful; it does not
		// stop it being replayed within that window.
		//
		// This runs AFTER the signature check, as the standard and combined
		// implementations do. Recording first meant a request carrying a valid
		// signature header but an altered body -- which is rejected anyway --
		// consumed that signature, so the legitimate request that followed was
		// refused as a replay.
		if cfg.ReplayGuard != nil && cfg.ReplayGuard.Seen(signature, middleware.ReplayRetention(cfg.MaxTimeDrift)) {
			if cfg.Logger != nil {
				cfg.Logger.Warn().
					Str("ip", GetClientIPFiber(c, cfg.TrustedProxyConfig)).
					Str("path", c.Path()).
					Msg("HMAC authentication failed: signature replayed")
			}
			return handleHMACError(c, cfg, middleware.ErrHMACSignatureInvalid)
		}

		// Authentication successful
		if cfg.Logger != nil {
			cfg.Logger.Debug().
				Str("service", service).
				Str("key_id", keyID).
				Msg("HMAC authentication successful")
		}

		if cfg.SuccessHandler != nil {
			cfg.SuccessHandler(c)
		}

		return c.Next()
	}
}

func handleHMACError(c fiber.Ctx, cfg HMACConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	reason := "unauthorized"
	switch err {
	case middleware.ErrHMACSignatureMissing:
		reason = "signature_missing"
	case middleware.ErrHMACTimestampMissing:
		reason = "timestamp_missing"
	case middleware.ErrHMACTimestampInvalid:
		reason = "invalid_timestamp"
	case middleware.ErrHMACTimestampExpired:
		reason = "timestamp_expired"
	case middleware.ErrHMACSignatureInvalid:
		reason = "invalid_signature"
	case middleware.ErrHMACKeyIDInvalid:
		reason = "invalid_key_id"
	case middleware.ErrHMACSecretNotConfigured:
		reason = "unauthorized"
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": reason,
	})
}
