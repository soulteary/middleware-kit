package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	//
	// Note what this form does NOT cover: the request method, path and query.
	// A signature minted for POST /transfer is equally valid on POST
	// /delete-account with the same body. Set RequestSignatureFunc to bind the
	// signature to the request target.
	SignatureFunc func(timestamp, service, body, secret string) string

	// AllowDelimitersInService permits ':' in the service identifier.
	//
	// ':' is rejected by default because ComputeHMAC -- the signer used when
	// neither function below is set -- signs "timestamp:service:body", which
	// has no field boundaries: (service "a", body "b:c") and (service "a:b",
	// body "c") produce the same bytes, so one signature stands for two
	// different requests.
	//
	// Whether a signer is safe from that cannot be inferred from the config:
	// SignatureFunc may be ComputeHMAC itself, or a wrapper around it, and a
	// custom RequestSignatureFunc may concatenate just as ambiguously. So the
	// guard stays on unless you turn it off here, having checked that your
	// signer frames its fields unambiguously. This package's own
	// ComputeHMACBound is length-prefixed and is recognised without the flag.
	AllowDelimitersInService bool

	// RequestSignatureFunc computes the expected signature over the full
	// request, including its method, path and query. When set it takes
	// precedence over SignatureFunc.
	//
	// ComputeHMACBound is the recommended implementation. Switching to it
	// changes the bytes being signed, so every signer has to be updated at the
	// same time; that is why it is opt-in rather than the default.
	RequestSignatureFunc RequestSignatureFunc

	// ReplayGuard, when set, rejects a signature that has already been
	// accepted. Without it a captured request can be replayed freely for the
	// whole MaxTimeDrift window (5 minutes by default).
	//
	// Use NewMemoryReplayGuard for a single instance, or a shared store for a
	// multi-instance deployment.
	ReplayGuard ReplayGuard

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
	// SignatureFunc is deliberately NOT defaulted to ComputeHMAC here.
	//
	// ExpectedSignature already falls back to it, and materializing the
	// default made ServiceAllowed see a non-nil function and mistake the
	// legacy delimiter-based signer for a caller-supplied custom one -- which
	// re-allowed ':' in the service header and reopened the collision that
	// check exists to close.

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

			if !cfg.ServiceAllowed(service) {
				if cfg.Logger != nil {
					cfg.Logger.Warn().Str("service", service).Msg("HMAC authentication failed: service contains a reserved character")
				}
				http.Error(w, "Unauthorized: invalid signature", http.StatusUnauthorized)
				return
			}

			// Compute expected signature
			expectedSig := cfg.ExpectedSignature(SignatureInput{
				Method: r.Method,
				// The ESCAPED path: see SignatureInput.Path.
				Path:      r.URL.EscapedPath(),
				RawQuery:  r.URL.RawQuery,
				Timestamp: timestamp,
				Service:   service,
				Body:      string(bodyBytes),
				Secret:    secret,
			})

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

			if cfg.ReplayGuard != nil && cfg.ReplayGuard.Seen(signature, ReplayRetention(cfg.MaxTimeDrift)) {
				if cfg.Logger != nil {
					cfg.Logger.Warn().
						Str("ip", GetClientIP(r, cfg.TrustedProxyConfig)).
						Str("path", r.URL.Path).
						Msg("HMAC authentication failed: signature replayed")
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
