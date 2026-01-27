package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPAllowlistMiddleware_Empty(t *testing.T) {
	mw := IPAllowlistMiddleware("")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPAllowlistMiddleware_SingleIP(t *testing.T) {
	mw := IPAllowlistMiddleware("192.168.1.1")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	for _, tt := range []struct {
		remote   string
		wantCode int
	}{
		{"192.168.1.1:12345", http.StatusOK},
		{"192.168.1.2:12345", http.StatusForbidden},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.remote
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, tt.wantCode, w.Code, "remote=%s", tt.remote)
	}
}

func TestIPAllowlistMiddleware_MultipleIPsAndCIDR(t *testing.T) {
	mw := IPAllowlistMiddleware("192.168.1.1,10.0.0.0/8,172.16.0.1")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	for _, tt := range []struct {
		remote   string
		wantCode int
	}{
		{"192.168.1.1:0", http.StatusOK},
		{"10.0.0.1:0", http.StatusOK},
		{"172.16.0.1:0", http.StatusOK},
		{"192.168.1.2:0", http.StatusForbidden},
		{"11.0.0.1:0", http.StatusForbidden},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.remote
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, tt.wantCode, w.Code, "remote=%s", tt.remote)
	}
}

func TestIPAllowlistMiddlewareFromConfig_OnDenied(t *testing.T) {
	var denied bool
	mw := IPAllowlistMiddlewareFromConfig(IPAllowlistConfig{
		Allowlist: "127.0.0.1",
		OnDenied: func(w http.ResponseWriter, r *http.Request) {
			denied = true
			http.Error(w, "Forbidden", http.StatusForbidden)
		},
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.True(t, denied)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
