package middleware

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
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

// errBody is a request body that fails on read, the shape readBody returns an
// error for.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }
func (errBody) Close() error             { return nil }

// TestHMACAuthStd_UncoveredBranches covers four branches of the net/http half
// that had no test: a future timestamp, an unreadable body, the reserved
// character check on the service header, and the replay rejection. The Fiber
// half's equivalents are all covered, so a divergence in any of them would have
// gone unnoticed on this side.
func TestHMACAuthStd_UncoveredBranches(t *testing.T) {
	const secret = "test-secret"

	serve := func(cfg HMACConfig, req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		HMACAuthStd(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)
		return rec
	}

	signedReq := func(ts, service, body string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
		req.Header.Set("X-Signature", ComputeHMAC(ts, service, body, secret))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", service)
		return req
	}

	t.Run("a timestamp far in the future is expired too", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
		rec := serve(HMACConfig{Secret: secret, MaxTimeDrift: time.Minute, Logger: &logger},
			signedReq(future, "svc", "{}"))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, buf.String(), "timestamp expired")
	})

	t.Run("an unreadable body is a bad request", func(t *testing.T) {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Body = errBody{}
		req.Header.Set("X-Signature", "whatever")
		req.Header.Set("X-Timestamp", ts)

		rec := serve(HMACConfig{Secret: secret}, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("a service carrying the legacy delimiter is rejected and logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		rec := serve(HMACConfig{Secret: secret, Logger: &logger}, signedReq(ts, "svc:extra", "{}"))

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, buf.String(), "service contains a reserved character")
	})

	t.Run("a replayed signature is rejected and logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		cfg := HMACConfig{Secret: secret, Logger: &logger, ReplayGuard: NewMemoryReplayGuard()}

		assert.Equal(t, http.StatusOK, serve(cfg, signedReq(ts, "svc", "{}")).Code)

		rec := serve(cfg, signedReq(ts, "svc", "{}"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, buf.String(), "signature replayed")
	})
}

// TestExpectedSignature_LegacySignatureFunc covers the SignatureFunc branch of
// ExpectedSignature from the net/http side.
//
// It is reachable from both halves, but only a Fiber test exercised it; per-
// package coverage does not credit the root package for a call made from
// fiberadapter's tests, so moving the Fiber half out left this branch with no
// coverage attributed to the package that owns it.
func TestExpectedSignature_LegacySignatureFunc(t *testing.T) {
	const secret = "test-secret"

	custom := func(timestamp, service, body, sec string) string {
		return "sig-" + timestamp + "-" + service + "-" + body + "-" + sec
	}

	t.Run("the method dispatches to SignatureFunc", func(t *testing.T) {
		cfg := HMACConfig{SignatureFunc: custom}
		got := cfg.ExpectedSignature(SignatureInput{
			Method: http.MethodPost, Path: "/x", RawQuery: "a=1",
			Timestamp: "123", Service: "svc", Body: "{}", Secret: secret,
		})
		assert.Equal(t, custom("123", "svc", "{}", secret), got,
			"SignatureFunc receives only timestamp, service, body and secret")
	})

	t.Run("RequestSignatureFunc takes precedence", func(t *testing.T) {
		cfg := HMACConfig{
			SignatureFunc:        custom,
			RequestSignatureFunc: func(SignatureInput) string { return "bound" },
		}
		assert.Equal(t, "bound", cfg.ExpectedSignature(SignatureInput{Timestamp: "123"}))
	})

	t.Run("HMACAuthStd authenticates a request signed with SignatureFunc", func(t *testing.T) {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		body := "{}"

		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
		req.Header.Set("X-Signature", custom(ts, "svc", body, secret))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", "svc")

		rec := httptest.NewRecorder()
		HMACAuthStd(HMACConfig{
			Secret:        secret,
			SignatureFunc: custom,
			// The legacy signer is ambiguous, so ':' in the service header
			// stays refused unless this is set -- see ServiceAllowed.
			AllowDelimitersInService: false,
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestMemoryReplayGuard_SweepDropsExpiredEntries covers the delete inside the
// amortized sweep.
func TestMemoryReplayGuard_SweepDropsExpiredEntries(t *testing.T) {
	// nextSweep is left at its zero value, so the first call sweeps.
	g := &MemoryReplayGuard{seen: map[string]time.Time{
		"stale": time.Now().Add(-time.Minute),
		"live":  time.Now().Add(time.Hour),
	}}

	assert.False(t, g.Seen("fresh", time.Minute))

	g.mu.Lock()
	defer g.mu.Unlock()
	assert.NotContains(t, g.seen, "stale", "an expired entry is dropped by the sweep")
	assert.Contains(t, g.seen, "live")
	assert.Contains(t, g.seen, "fresh")
}
