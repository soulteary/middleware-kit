package middleware

import "errors"

// Authentication errors
var (
	// ErrAPIKeyNotConfigured indicates no API key was configured on the server.
	ErrAPIKeyNotConfigured = errors.New("API key not configured")

	// ErrAPIKeyMissing indicates no API key was provided in the request.
	ErrAPIKeyMissing = errors.New("API key missing")

	// ErrAPIKeyInvalid indicates the provided API key is invalid.
	ErrAPIKeyInvalid = errors.New("API key invalid")

	// ErrHMACSecretNotConfigured indicates no HMAC secret was configured.
	ErrHMACSecretNotConfigured = errors.New("HMAC secret not configured")

	// ErrHMACSignatureMissing indicates no HMAC signature was provided.
	ErrHMACSignatureMissing = errors.New("HMAC signature missing")

	// ErrHMACSignatureInvalid indicates the HMAC signature is invalid.
	ErrHMACSignatureInvalid = errors.New("HMAC signature invalid")

	// ErrHMACTimestampMissing indicates no timestamp was provided for HMAC.
	ErrHMACTimestampMissing = errors.New("HMAC timestamp missing")

	// ErrHMACTimestampInvalid indicates the timestamp format is invalid.
	ErrHMACTimestampInvalid = errors.New("HMAC timestamp invalid")

	// ErrHMACTimestampExpired indicates the timestamp has expired.
	ErrHMACTimestampExpired = errors.New("HMAC timestamp expired")

	// ErrHMACKeyIDInvalid indicates the key ID is invalid or not found.
	ErrHMACKeyIDInvalid = errors.New("HMAC key ID invalid")

	// ErrMTLSCertificateMissing indicates no client certificate was provided.
	ErrMTLSCertificateMissing = errors.New("mTLS client certificate missing")

	// ErrMTLSCertificateInvalid indicates the client certificate is invalid.
	ErrMTLSCertificateInvalid = errors.New("mTLS client certificate invalid")

	// ErrUnauthorized is a generic unauthorized error.
	ErrUnauthorized = errors.New("unauthorized")
)

// Rate limiting errors
var (
	// ErrRateLimitExceeded indicates the rate limit has been exceeded.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// Request errors
var (
	// ErrRequestBodyTooLarge indicates the request body exceeds the size limit.
	ErrRequestBodyTooLarge = errors.New("request body too large")
)
