package middleware

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultAPIKeyConfig(t *testing.T) {
	cfg := DefaultAPIKeyConfig()

	assert.Equal(t, "X-API-Key", cfg.HeaderName)
	assert.False(t, cfg.AllowEmptyKey)
	assert.Empty(t, cfg.APIKey)
	assert.Empty(t, cfg.AuthScheme)
	assert.Empty(t, cfg.QueryParamName)
}

func TestAPIKeyAuthStd(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey: "test-api-key",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid API key", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey: "test-api-key",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Authorization header with scheme", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:     "test-api-key",
			AuthScheme: "Bearer",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("query parameter", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:         "test-api-key",
			QueryParamName: "key",
		})(handler)

		req := httptest.NewRequest("GET", "/?key=test-api-key", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("missing API key", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey: "test-api-key",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("allow empty key in development mode", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:        "",
			AllowEmptyKey: true,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("reject when no API key configured and AllowEmptyKey is false", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:        "",
			AllowEmptyKey: false,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("custom header name", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:     "test-api-key",
			HeaderName: "X-Custom-Key",
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Custom-Key", "test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("default header name when empty", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:     "test-api-key",
			HeaderName: "", // Should default to X-API-Key
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid key with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:             "test-api-key",
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		})(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "wrong-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "API key authentication failed")
	})

	t.Run("missing key with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:             "test-api-key",
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		})(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "missing key")
	})

	t.Run("success with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey: "test-api-key",
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), "API key authentication successful")
	})

	t.Run("allow empty key with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := APIKeyAuthStd(APIKeyConfig{
			APIKey:        "",
			AllowEmptyKey: true,
			Logger:        &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), "API key authentication disabled")
	})
}
