package middleware

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestDefaultHMACConfig(t *testing.T) {
	cfg := DefaultHMACConfig()

	assert.Equal(t, "X-Signature", cfg.SignatureHeader)
	assert.Equal(t, "X-Timestamp", cfg.TimestampHeader)
	assert.Equal(t, "X-Key-Id", cfg.KeyIDHeader)
	assert.Equal(t, "X-Service", cfg.ServiceHeader)
	assert.Equal(t, 5*time.Minute, cfg.MaxTimeDrift)
	assert.Empty(t, cfg.Secret)
}

func TestComputeHMAC(t *testing.T) {
	timestamp := "1234567890"
	service := "test-service"
	body := "test body"
	secret := "test-secret"

	sig1 := ComputeHMAC(timestamp, service, body, secret)
	sig2 := ComputeHMAC(timestamp, service, body, secret)

	// Same inputs should produce same signature
	assert.Equal(t, sig1, sig2)

	// Different inputs should produce different signatures
	sig3 := ComputeHMAC(timestamp+"1", service, body, secret)
	assert.NotEqual(t, sig1, sig3)

	sig4 := ComputeHMAC(timestamp, service, body, "different-secret")
	assert.NotEqual(t, sig1, sig4)
}

func TestHMACAuthStd(t *testing.T) {
	secret := "test-secret"

	t.Run("valid HMAC signature", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", body, secret)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid signature", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"test": "data"}`))
		req.Header.Set("X-Signature", "invalid-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("missing signature", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("missing timestamp", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", "not-a-number")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("expired timestamp", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret:       secret,
			MaxTimeDrift: 5 * time.Minute,
		})(handler)

		body := `{"test": "data"}`
		// Use timestamp 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := ComputeHMAC(timestamp, "test-service", body, secret)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("allow empty secret", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret:           "",
			AllowEmptySecret: true,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("reject when no secret configured and AllowEmptySecret is false", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret:           "",
			AllowEmptySecret: false,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("key provider with valid key ID", func(t *testing.T) {
		keys := map[string]string{
			"key1": "secret1",
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			KeyProvider: func(keyID string) string {
				return keys[keyID]
			},
		})(handler)

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", body, "secret1")

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		req.Header.Set("X-Key-Id", "key1")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("key provider with invalid key ID", func(t *testing.T) {
		keys := map[string]string{
			"key1": "secret1",
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			KeyProvider: func(keyID string) string {
				return keys[keyID]
			},
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Key-Id", "unknown-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("expired timestamp with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret:       "test-secret",
			MaxTimeDrift: 60 * time.Second,
			Logger:       &logger,
		})(handler)

		// 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := ComputeHMAC(timestamp, "test-service", "", "test-secret")

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "timestamp expired")
	})

	t.Run("success with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: "test-secret",
			Logger: &logger,
		})(handler)

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", body, "test-secret")

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), "HMAC authentication successful")
	})

	t.Run("invalid signature with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret:             "test-secret",
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		})(handler)

		req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(`{"test": "data"}`))
		req.Header.Set("X-Signature", "invalid-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "HMAC authentication failed")
	})

	t.Run("allow empty secret with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret:           "",
			AllowEmptySecret: true,
			Logger:           &logger,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), "HMAC authentication disabled")
	})
}
