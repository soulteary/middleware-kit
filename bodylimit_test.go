package middleware

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultBodyLimitConfig(t *testing.T) {
	cfg := DefaultBodyLimitConfig()

	assert.Equal(t, int64(4*1024*1024), cfg.MaxSize)
	assert.Equal(t, []string{"GET", "HEAD", "OPTIONS"}, cfg.SkipMethods)
	assert.Empty(t, cfg.SkipPaths)
}

func TestBodyLimitStd(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 1024,
		})(handler)

		body := strings.Repeat("a", 500)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "500")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 100,
		})(handler)

		body := strings.Repeat("a", 200)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "200")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("skips GET requests", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 10,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("skip paths are not checked", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize:   10,
			SkipPaths: []string{"/upload"},
		})(handler)

		body := strings.Repeat("a", 1000)
		req := httptest.NewRequest("POST", "/upload", strings.NewReader(body))
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("blocks over limit with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize:            100,
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		})(handler)

		body := strings.Repeat("a", 200)
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		req.Header.Set("Content-Length", "200")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
		assert.Contains(t, buf.String(), "Request body size exceeds limit")
	})

	t.Run("default max size when zero", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize: 0, // Should default to 4MB
		})(handler)

		body := strings.Repeat("a", 1000)
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Header.Set("Content-Length", "1000")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("default skip methods when empty", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := BodyLimitStd(BodyLimitConfig{
			MaxSize:     10,
			SkipMethods: nil, // Should use default
		})(handler)

		req := httptest.NewRequest("HEAD", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
