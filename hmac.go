package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
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
// WithDefaults returns cfg with the header names and MaxTimeDrift filled in.
//
// SignatureFunc is deliberately NOT defaulted to ComputeHMAC. ExpectedSignature
// already falls back to it, and materializing the default made ServiceAllowed
// see a non-nil function and mistake the legacy delimiter-based signer for a
// caller-supplied custom one -- which re-allowed ':' in the service header and
// reopened the collision that check exists to close.
//
// Exported so a framework adapter defaults a config exactly as the net/http
// middleware does.
func (cfg HMACConfig) WithDefaults() HMACConfig {
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
	return cfg
}

// ResolveSecret picks the HMAC secret to verify a request against.
//
// KeyProvider wins when set. A provider that returns nothing for a NON-EMPTY
// key ID means that key ID is invalid, which is a different answer from "no
// secret is configured at all" and must not be reported as one.
//
// disabled is true when no secret is configured and AllowEmptySecret permits
// the request through unauthenticated; the caller should let it pass.
//
// Exported so a framework adapter resolves the secret exactly as the net/http
// middleware does.
func (cfg HMACConfig) ResolveSecret(keyID string) (secret string, disabled bool, err error) {
	secret = cfg.Secret
	if cfg.KeyProvider != nil {
		secret = cfg.KeyProvider(keyID)
		if secret == "" && keyID != "" {
			return "", false, ErrHMACKeyIDInvalid
		}
	}

	if secret == "" {
		if cfg.AllowEmptySecret {
			if cfg.Logger != nil {
				cfg.Logger.Warn().Msg("HMAC authentication disabled (no secret configured)")
			}
			return "", true, nil
		}
		return "", false, ErrHMACSecretNotConfigured
	}

	return secret, false, nil
}

// CheckTimestamp validates a request timestamp against MaxTimeDrift, and logs
// the rejection when it is outside the window.
//
// The drift is an absolute value, so a timestamp far in the FUTURE is refused
// just as one far in the past is.
//
// Exported so a framework adapter applies exactly the window the net/http
// middleware applies.
func (cfg HMACConfig) CheckTimestamp(timestamp string) error {
	ts, err := ParseTimestamp(timestamp)
	if err != nil {
		return ErrHMACTimestampInvalid
	}

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
		return ErrHMACTimestampExpired
	}

	return nil
}

// serviceRejected reports whether the service identifier may not be used with
// the configured signer, and logs the rejection.
//
// A service carrying the legacy encoding's delimiter would let one signature
// stand for two different (service, body) pairs. Only the legacy encoding is
// ambiguous; see ServiceAllowed.
func (cfg HMACConfig) serviceRejected(service string) bool {
	if cfg.ServiceAllowed(service) {
		return false
	}
	if cfg.Logger != nil {
		cfg.Logger.Warn().Str("service", service).Msg("HMAC authentication failed: service contains a reserved character")
	}
	return true
}

// replayed reports whether signature has already been accepted, and logs the
// rejection.
//
// The timestamp window bounds how long a captured request stays useful; it does
// not stop it being replayed inside that window. clientIP is a function so the
// address is resolved only when there is a log to write.
func (cfg HMACConfig) replayed(signature string, clientIP func() string, path string) bool {
	if cfg.ReplayGuard == nil || !cfg.ReplayGuard.Seen(signature, ReplayRetention(cfg.MaxTimeDrift)) {
		return false
	}
	if cfg.Logger != nil {
		cfg.Logger.Warn().
			Str("ip", clientIP()).
			Str("path", path).
			Msg("HMAC authentication failed: signature replayed")
	}
	return true
}

func HMACAuthStd(cfg HMACConfig) func(http.Handler) http.Handler {
	cfg = cfg.WithDefaults()

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
			secret, disabled, err := cfg.ResolveSecret(keyID)
			switch {
			case disabled:
				next.ServeHTTP(w, r)
				return
			case errors.Is(err, ErrHMACKeyIDInvalid):
				http.Error(w, "Unauthorized: invalid key ID", http.StatusUnauthorized)
				return
			case err != nil:
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate the timestamp and its drift
			if err := cfg.CheckTimestamp(timestamp); err != nil {
				if errors.Is(err, ErrHMACTimestampInvalid) {
					http.Error(w, "Unauthorized: invalid timestamp", http.StatusUnauthorized)
					return
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

			if cfg.serviceRejected(service) {
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

			// Reject a signature that has already been accepted. This runs
			// AFTER the signature check: recording first meant a request with
			// a valid signature header but an altered body -- rejected anyway
			// -- consumed that signature, so the legitimate request that
			// followed was refused as a replay.
			if cfg.replayed(signature, func() string { return GetClientIP(r, cfg.TrustedProxyConfig) }, r.URL.Path) {
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
