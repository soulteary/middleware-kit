package fiberadapter

import (
	"crypto/hmac"
	"errors"

	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v3"
)

// HMACAuth returns a Fiber middleware that authenticates requests by their HMAC
// signature. It is the Fiber half of the pair whose net/http half is
// middleware.HMACAuthStd, and applies the same rules in the same order: the
// timestamp must be within MaxTimeDrift, the service identifier must be
// unambiguous for the configured signer, the signature must match, and only then
// is it recorded with the ReplayGuard.
func HMACAuth(cfg HMACConfig) fiber.Handler {
	// The same defaults the net/http half applies, including the deliberate
	// omission of SignatureFunc -- see middleware.HMACConfig.WithDefaults.
	cfg.HMACConfig = cfg.WithDefaults()

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
		secret, disabled, err := cfg.ResolveSecret(keyID)
		switch {
		case disabled:
			return c.Next()
		case errors.Is(err, middleware.ErrHMACKeyIDInvalid):
			return handleHMACError(c, cfg, middleware.ErrHMACKeyIDInvalid)
		case err != nil:
			return handleHMACError(c, cfg, middleware.ErrHMACSecretNotConfigured)
		}

		// Validate the timestamp and its drift
		if err := cfg.CheckTimestamp(timestamp); err != nil {
			if errors.Is(err, middleware.ErrHMACTimestampInvalid) {
				return handleHMACError(c, cfg, middleware.ErrHMACTimestampInvalid)
			}
			return handleHMACError(c, cfg, middleware.ErrHMACTimestampExpired)
		}

		// A service identifier carrying the legacy encoding's delimiter would
		// let one signature stand for two different (service, body) pairs.
		// Only the legacy encoding is ambiguous; see ServiceAllowed.
		if serviceRejected(cfg.HMACConfig, service) {
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
			logSignatureMismatch(cfg.HMACConfig, c, service)
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
		if replayed(cfg.HMACConfig, c, signature) {
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

// The three helpers below mirror the unexported ones on middleware.HMACConfig.
// They cannot be shared: an unexported method is not reachable across a package
// boundary, and what they log -- the client IP and the request path -- is
// framework-specific. What they decide is not: each defers to the exported
// policy on the embedded config.

// serviceRejected reports whether the service identifier may not be used with
// the configured signer, and logs the rejection.
func serviceRejected(cfg middleware.HMACConfig, service string) bool {
	if cfg.ServiceAllowed(service) {
		return false
	}
	if cfg.Logger != nil {
		cfg.Logger.Warn().Str("service", service).Msg("HMAC authentication failed: service contains a reserved character")
	}
	return true
}

// logSignatureMismatch records a signature that did not match.
func logSignatureMismatch(cfg middleware.HMACConfig, c fiber.Ctx, service string) {
	if cfg.Logger == nil {
		return
	}
	cfg.Logger.Warn().
		Str("ip", GetClientIPFiber(c, cfg.TrustedProxyConfig)).
		Str("path", c.Path()).
		Str("method", c.Method()).
		Str("service", service).
		Msg("HMAC authentication failed: signature mismatch")
}

// replayed reports whether signature has already been accepted, and logs the
// rejection.
func replayed(cfg middleware.HMACConfig, c fiber.Ctx, signature string) bool {
	if cfg.ReplayGuard == nil || !cfg.ReplayGuard.Seen(signature, middleware.ReplayRetention(cfg.MaxTimeDrift)) {
		return false
	}
	if cfg.Logger != nil {
		cfg.Logger.Warn().
			Str("ip", GetClientIPFiber(c, cfg.TrustedProxyConfig)).
			Str("path", c.Path()).
			Msg("HMAC authentication failed: signature replayed")
	}
	return true
}
