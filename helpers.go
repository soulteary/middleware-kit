package middleware

import (
	"bytes"
	"crypto/subtle"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ParseTimestamp parses a Unix timestamp string.
func ParseTimestamp(timestamp string) (int64, error) {
	return strconv.ParseInt(timestamp, 10, 64)
}

// IsTimestampValid checks if a timestamp is within the allowed drift.
func IsTimestampValid(timestamp, maxDriftSeconds int64) bool {
	now := time.Now().Unix()
	drift := now - timestamp
	if drift < 0 {
		drift = -drift
	}
	return drift <= maxDriftSeconds
}

// ConstantTimeEqual compares two Strings in constant time to prevent timing attacks.
// ConstantTimeEqual compares two Strings without leaking how much of them
// matched, or how long the expected value is.
//
// subtle.ConstantTimeCompare returns early when the lengths differ, so calling
// it directly on a secret and an attacker-supplied value leaks the secret's
// length through timing. Both inputs are padded to the same size first, and
// the length check is folded into the result.
func ConstantTimeEqual(a, b string) bool {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	pa := make([]byte, n)
	pb := make([]byte, n)
	copy(pa, a)
	copy(pb, b)
	return subtle.ConstantTimeCompare(pa, pb) == 1 && len(a) == len(b)
}

// readBody reads the request body and restores it for subsequent handlers.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Restore body for subsequent handlers
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}

// truncateString truncates a string to the specified length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// maskString masks a string, showing only the first and last few characters.
func maskString(s string, visibleChars int) string {
	if len(s) <= visibleChars*2 {
		return "***"
	}
	return s[:visibleChars] + "***" + s[len(s)-visibleChars:]
}

// MaskEmail masks an email address for logging.
// Example: john.doe@example.com -> jo***@example.com
func MaskEmail(email string) string {
	atIndex := -1
	for i, c := range email {
		if c == '@' {
			atIndex = i
			break
		}
	}
	if atIndex <= 0 {
		return "***"
	}

	localPart := email[:atIndex]
	domain := email[atIndex:]

	if len(localPart) <= 2 {
		return localPart + "***" + domain
	}
	return localPart[:2] + "***" + domain
}

// MaskPhone masks a phone number for logging.
// Example: +1234567890 -> +123***7890
func MaskPhone(phone string) string {
	if len(phone) <= 6 {
		return "***"
	}
	return phone[:3] + "***" + phone[len(phone)-4:]
}
