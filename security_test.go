package middleware

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersStd(t *testing.T) {
	t.Run("default security headers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := SecurityHeadersStd(DefaultSecurityHeadersConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
		assert.Equal(t, "0", rr.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "strict-origin-when-cross-origin", rr.Header().Get("Referrer-Policy"))
	})

	t.Run("strict security headers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := SecurityHeadersStd(StrictSecurityHeadersConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.NotEmpty(t, rr.Header().Get("Content-Security-Policy"))
		assert.Equal(t, "max-age=31536000; includeSubDomains", rr.Header().Get("Strict-Transport-Security"))
	})

	t.Run("all optional headers", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		cfg := SecurityHeadersConfig{
			XContentTypeOptions:       "nosniff",
			XFrameOptions:             "SAMEORIGIN",
			XXSSProtection:            "1",
			ReferrerPolicy:            "no-referrer",
			ContentSecurityPolicy:     "default-src 'self'",
			StrictTransportSecurity:   "max-age=3600",
			PermissionsPolicy:         "camera=()",
			CrossOriginOpenerPolicy:   "same-origin",
			CrossOriginResourcePolicy: "same-site",
			CrossOriginEmbedderPolicy: "require-corp",
			CacheControl:              "no-cache",
			Pragma:                    "no-cache",
			CustomHeaders: map[string]string{
				"X-Custom": "value",
			},
		}

		middleware := SecurityHeadersStd(cfg)(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "SAMEORIGIN", rr.Header().Get("X-Frame-Options"))
		assert.Equal(t, "1", rr.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "no-referrer", rr.Header().Get("Referrer-Policy"))
		assert.Equal(t, "default-src 'self'", rr.Header().Get("Content-Security-Policy"))
		assert.Equal(t, "max-age=3600", rr.Header().Get("Strict-Transport-Security"))
		assert.Equal(t, "camera=()", rr.Header().Get("Permissions-Policy"))
		assert.Equal(t, "same-origin", rr.Header().Get("Cross-Origin-Opener-Policy"))
		assert.Equal(t, "same-site", rr.Header().Get("Cross-Origin-Resource-Policy"))
		assert.Equal(t, "require-corp", rr.Header().Get("Cross-Origin-Embedder-Policy"))
		assert.Equal(t, "no-cache", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
		assert.Equal(t, "value", rr.Header().Get("X-Custom"))
	})

	t.Run("empty config sets nothing", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := SecurityHeadersStd(SecurityHeadersConfig{})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("X-Content-Type-Options"))
	})
}

func TestNoCacheHeadersStd(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := NoCacheHeadersStd()(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware.ServeHTTP(rr, req)

	assert.Equal(t, "no-store, no-cache, must-revalidate, proxy-revalidate", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	assert.Equal(t, "0", rr.Header().Get("Expires"))
}
