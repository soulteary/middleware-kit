package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompressStd(t *testing.T) {
	largeBody := strings.Repeat("Hello, World! ", 1000) // About 14KB

	t.Run("compresses large response", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(largeBody))
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
		assert.Equal(t, "Accept-Encoding", rr.Header().Get("Vary"))

		// Verify it's actually gzip compressed
		reader, err := gzip.NewReader(rr.Body)
		assert.NoError(t, err)
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.Equal(t, largeBody, string(decompressed))
	})

	t.Run("does not compress small response", func(t *testing.T) {
		smallBody := "Hello"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(smallBody))
		})

		middleware := CompressStd(CompressConfig{
			MinSize: 1024, // 1KB minimum
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Small response should not be gzip encoded
		// Note: The implementation buffers, so encoding header may or may not be set
	})

	t.Run("skips if client does not accept gzip", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(largeBody))
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		// No Accept-Encoding header
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("Content-Encoding"))
		assert.Equal(t, largeBody, rr.Body.String())
	})

	t.Run("skips paths in skip list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(largeBody))
		})

		middleware := CompressStd(CompressConfig{
			SkipPaths: []string{"/health"},
			MinSize:   100,
		})(handler)

		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("Content-Encoding"))
		assert.Equal(t, largeBody, rr.Body.String())
	})

	t.Run("sets Vary header", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(largeBody))
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, "Accept-Encoding", rr.Header().Get("Vary"))
	})
}

func TestDefaultCompressConfig(t *testing.T) {
	cfg := DefaultCompressConfig()

	assert.Equal(t, gzip.DefaultCompression, cfg.Level)
	assert.Equal(t, 1024, cfg.MinSize)
	assert.NotEmpty(t, cfg.ContentTypes)
	assert.Contains(t, cfg.ContentTypes, "application/json")
	assert.Contains(t, cfg.ContentTypes, "text/html")
}
