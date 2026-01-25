package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// HMACConfig configures the HMAC signature authentication middleware.
type HMACConfig struct {
	// Secret is the shared secret for HMAC signature verification.
	// Required if KeyProvider is not set.
	Secret string

	// KeyProvider provides HMAC secrets by key ID.
	// This allows for key rotation support.
	// If set, takes precedence over Secret.
	KeyProvider func(keyID string) string

	// SignatureHeader is the header name for the HMAC signature.
	// Default: "X-Signature"
	SignatureHeader string

	// TimestampHeader is the header name for the request timestamp.
	// Default: "X-Timestamp"
	TimestampHeader string

	// KeyIDHeader is the header name for the key ID (for key rotation).
	// Default: "X-Key-Id"
	KeyIDHeader string

	// ServiceHeader is the header name for the service identifier.
	// Default: "X-Service"
	ServiceHeader string

	// MaxTimeDrift is the maximum allowed time difference between
	// the request timestamp and server time.
	// Default: 5 minutes
	MaxTimeDrift time.Duration

	// AllowEmptySecret allows requests when no secret is configured.
	// This is useful for development mode but NOT recommended for production.
	// Default: false
	AllowEmptySecret bool

	// SignatureFunc is a custom function to compute the expected signature.
	// If nil, the default signature function is used:
	// HMAC-SHA256(secret, timestamp:service:body)
	SignatureFunc func(timestamp, service, body, secret string) string

	// ErrorHandler is called when authentication fails.
	ErrorHandler func(c *fiber.Ctx, err error) error

	// SuccessHandler is called when authentication succeeds.
	SuccessHandler func(c *fiber.Ctx)

	// Logger for logging authentication events.
	Logger *zerolog.Logger

	// TrustedProxyConfig for client IP detection in logs.
	TrustedProxyConfig *TrustedProxyConfig
}

// DefaultHMACConfig returns the default HMAC configuration.
func DefaultHMACConfig() HMACConfig {
	return HMACConfig{
		SignatureHeader: "X-Signature",
		TimestampHeader: "X-Timestamp",
		KeyIDHeader:     "X-Key-Id",
		ServiceHeader:   "X-Service",
		MaxTimeDrift:    5 * time.Minute,
	}
}

// HMACAuth creates a Fiber middleware for HMAC signature authentication.
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
	if cfg.SignatureFunc == nil {
		cfg.SignatureFunc = ComputeHMAC
	}

	return func(c *fiber.Ctx) error {
		// Get signature and timestamp from headers
		signature := c.Get(cfg.SignatureHeader)
		timestamp := c.Get(cfg.TimestampHeader)
		keyID := c.Get(cfg.KeyIDHeader)
		service := c.Get(cfg.ServiceHeader)

		// Check if signature is provided
		if signature == "" {
			return handleHMACError(c, cfg, ErrHMACSignatureMissing)
		}

		// Check if timestamp is provided
		if timestamp == "" {
			return handleHMACError(c, cfg, ErrHMACTimestampMissing)
		}

		// Get the HMAC secret
		secret := cfg.Secret
		if cfg.KeyProvider != nil {
			secret = cfg.KeyProvider(keyID)
			if secret == "" && keyID != "" {
				return handleHMACError(c, cfg, ErrHMACKeyIDInvalid)
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
			return handleHMACError(c, cfg, ErrHMACSecretNotConfigured)
		}

		// Validate timestamp
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return handleHMACError(c, cfg, ErrHMACTimestampInvalid)
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
			return handleHMACError(c, cfg, ErrHMACTimestampExpired)
		}

		// Compute expected signature
		body := string(c.Body())
		expectedSig := cfg.SignatureFunc(timestamp, service, body, secret)

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
			return handleHMACError(c, cfg, ErrHMACSignatureInvalid)
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

// HMACAuthStd creates a standard net/http middleware for HMAC signature authentication.
func HMACAuthStd(cfg HMACConfig) func(http.Handler) http.Handler {
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
	if cfg.SignatureFunc == nil {
		cfg.SignatureFunc = ComputeHMAC
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get signature and timestamp from headers
			signature := r.Header.Get(cfg.SignatureHeader)
			timestamp := r.Header.Get(cfg.TimestampHeader)
			keyID := r.Header.Get(cfg.KeyIDHeader)
			service := r.Header.Get(cfg.ServiceHeader)

			// Check if signature is provided
			if signature == "" {
				http.Error(w, "Unauthorized: signature missing", http.StatusUnauthorized)
				return
			}

			// Check if timestamp is provided
			if timestamp == "" {
				http.Error(w, "Unauthorized: timestamp missing", http.StatusUnauthorized)
				return
			}

			// Get the HMAC secret
			secret := cfg.Secret
			if cfg.KeyProvider != nil {
				secret = cfg.KeyProvider(keyID)
				if secret == "" && keyID != "" {
					http.Error(w, "Unauthorized: invalid key ID", http.StatusUnauthorized)
					return
				}
			}

			// Check if secret is configured
			if secret == "" {
				if cfg.AllowEmptySecret {
					if cfg.Logger != nil {
						cfg.Logger.Warn().Msg("HMAC authentication disabled (no secret configured)")
					}
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate timestamp
			ts, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				http.Error(w, "Unauthorized: invalid timestamp", http.StatusUnauthorized)
				return
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
				http.Error(w, "Unauthorized: timestamp expired", http.StatusUnauthorized)
				return
			}

			// Read and restore body
			bodyBytes, err := readBody(r)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			// Compute expected signature
			expectedSig := cfg.SignatureFunc(timestamp, service, string(bodyBytes), secret)

			// Compare signatures using constant-time comparison
			if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
				if cfg.Logger != nil {
					clientIP := GetClientIP(r, cfg.TrustedProxyConfig)
					cfg.Logger.Warn().
						Str("ip", clientIP).
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Str("service", service).
						Msg("HMAC authentication failed: signature mismatch")
				}
				http.Error(w, "Unauthorized: invalid signature", http.StatusUnauthorized)
				return
			}

			// Authentication successful
			if cfg.Logger != nil {
				cfg.Logger.Debug().
					Str("service", service).
					Str("key_id", keyID).
					Msg("HMAC authentication successful")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ComputeHMAC computes an HMAC-SHA256 signature.
// The message format is: timestamp:service:body
func ComputeHMAC(timestamp, service, body, secret string) string {
	message := fmt.Sprintf("%s:%s:%s", timestamp, service, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// handleHMACError handles HMAC authentication errors.
func handleHMACError(c *fiber.Ctx, cfg HMACConfig, err error) error {
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	reason := "unauthorized"
	switch err {
	case ErrHMACSignatureMissing:
		reason = "signature_missing"
	case ErrHMACTimestampMissing:
		reason = "timestamp_missing"
	case ErrHMACTimestampInvalid:
		reason = "invalid_timestamp"
	case ErrHMACTimestampExpired:
		reason = "timestamp_expired"
	case ErrHMACSignatureInvalid:
		reason = "invalid_signature"
	case ErrHMACKeyIDInvalid:
		reason = "invalid_key_id"
	case ErrHMACSecretNotConfigured:
		reason = "unauthorized"
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"ok":     false,
		"reason": reason,
	})
}
