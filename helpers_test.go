package middleware

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  int64
		expectErr bool
	}{
		{"valid timestamp", "1234567890", 1234567890, false},
		{"zero", "0", 0, false},
		{"negative", "-1234567890", -1234567890, false},
		{"invalid", "not-a-number", 0, true},
		{"empty", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTimestamp(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestIsTimestampValid(t *testing.T) {
	t.Run("within drift", func(t *testing.T) {
		result := isTimestampValid(0, 10) // 0 is way in the past
		assert.False(t, result)
	})

	t.Run("at drift boundary", func(t *testing.T) {
		result := isTimestampValid(0, 1000000000000)
		assert.True(t, result)
	})

	t.Run("current timestamp valid", func(t *testing.T) {
		now := time.Now().Unix()
		result := isTimestampValid(now, 60)
		assert.True(t, result)
	})

	t.Run("future timestamp within drift", func(t *testing.T) {
		future := time.Now().Unix() + 30 // 30 seconds in future
		result := isTimestampValid(future, 60)
		assert.True(t, result)
	})

	t.Run("future timestamp outside drift", func(t *testing.T) {
		future := time.Now().Unix() + 120 // 2 minutes in future
		result := isTimestampValid(future, 60)
		assert.False(t, result)
	})

	t.Run("past timestamp within drift", func(t *testing.T) {
		past := time.Now().Unix() - 30 // 30 seconds ago
		result := isTimestampValid(past, 60)
		assert.True(t, result)
	})

	t.Run("past timestamp outside drift", func(t *testing.T) {
		past := time.Now().Unix() - 120 // 2 minutes ago
		result := isTimestampValid(past, 60)
		assert.False(t, result)
	})
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{"equal strings", "hello", "hello", true},
		{"different strings", "hello", "world", false},
		{"different lengths", "hello", "hello!", false},
		{"empty strings", "", "", true},
		{"one empty", "hello", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := constantTimeEqual(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReadBody(t *testing.T) {
	t.Run("reads body and restores it", func(t *testing.T) {
		body := "test body content"
		req, _ := http.NewRequest("POST", "/", bytes.NewBufferString(body))

		// Read body first time
		result, err := readBody(req)
		assert.NoError(t, err)
		assert.Equal(t, body, string(result))

		// Body should still be readable
		secondRead, err := io.ReadAll(req.Body)
		assert.NoError(t, err)
		assert.Equal(t, body, string(secondRead))
	})

	t.Run("nil body", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		req.Body = nil

		result, err := readBody(req)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/", bytes.NewBufferString(""))

		result, err := readBody(req)
		assert.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("error reading body", func(t *testing.T) {
		req, _ := http.NewRequest("POST", "/", &errorReader{})

		result, err := readBody(req)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

// errorReader is a reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func (e *errorReader) Close() error {
	return nil
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello..."},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskString(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		visibleChars int
		expected     string
	}{
		{"long string", "1234567890", 3, "123***890"},
		{"short string", "123", 2, "***"},
		{"exact boundary", "1234", 2, "***"},
		{"empty", "", 2, "***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskString(tt.input, tt.visibleChars)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal email", "john.doe@example.com", "jo***@example.com"},
		{"short local part", "a@example.com", "a***@example.com"},
		{"two char local", "ab@example.com", "ab***@example.com"},
		{"no at sign", "invalid", "***"},
		{"empty", "", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskEmail(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskPhone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"US phone", "+14155551234", "+14***1234"},
		{"short phone", "123456", "***"},
		{"7 digits", "1234567", "123***4567"},
		{"empty", "", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskPhone(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
