package middleware

import (
	"bytes"
	"crypto/subtle"
	"io"
	"net/http"
	"strconv"
	"time"
)

// parseTimestamp parses a Unix timestamp string.
func parseTimestamp(timestamp string) (int64, error) {
	return strconv.ParseInt(timestamp, 10, 64)
}

// isTimestampValid checks if a timestamp is within the allowed drift.
func isTimestampValid(timestamp, maxDriftSeconds int64) bool {
	now := time.Now().Unix()
	drift := now - timestamp
	if drift < 0 {
		drift = -drift
	}
	return drift <= maxDriftSeconds
}

// constantTimeEqual compares two strings in constant time to prevent timing attacks.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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
