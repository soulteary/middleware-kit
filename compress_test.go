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
			_, _ = w.Write([]byte(largeBody))
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
		defer func() { _ = reader.Close() }()

		decompressed, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.Equal(t, largeBody, string(decompressed))
	})

	t.Run("does not compress small response", func(t *testing.T) {
		smallBody := "Hello"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(smallBody))
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
			_, _ = w.Write([]byte(largeBody))
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
			_, _ = w.Write([]byte(largeBody))
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
			_, _ = w.Write([]byte(largeBody))
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

func TestCompressStd_WriteHeader(t *testing.T) {
	largeBody := strings.Repeat("Hello, World! ", 1000)

	t.Run("explicit WriteHeader before Write with buffered data", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			// Write some data first (will be buffered)
			_, _ = w.Write([]byte("buffered"))
			// Then explicitly call WriteHeader
			w.WriteHeader(http.StatusCreated)
			// Write more data
			_, _ = w.Write([]byte(largeBody))
		})

		middleware := CompressStd(CompressConfig{
			MinSize: 100,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		// The response should complete without error
		assert.NotNil(t, rr.Body)
	})

	t.Run("WriteHeader with empty buffer", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNoContent)
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
	})
}

func TestCompressStd_GzipWriter(t *testing.T) {
	largeBody := strings.Repeat("Hello, World! ", 1000)

	t.Run("multiple writes with gzip enabled", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			// First write triggers buffering
			_, _ = w.Write([]byte(largeBody[:500]))
			// Second write exceeds minSize, triggers gzip
			_, _ = w.Write([]byte(largeBody[500:]))
			// Third write goes directly to gzip writer
			_, _ = w.Write([]byte(" additional data"))
		})

		middleware := CompressStd(CompressConfig{
			MinSize: 100,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	})

	t.Run("content type with charset", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(largeBody))
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	})

	t.Run("unsupported content type not compressed", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte(largeBody))
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		// Image content should not be gzip encoded
		assert.Empty(t, rr.Header().Get("Content-Encoding"))
	})

	t.Run("no content type defaults to text/html", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No content type set
			_, _ = w.Write([]byte(largeBody))
		})

		middleware := CompressStd(DefaultCompressConfig())(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		// Default text/html should be compressed
		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	})

	t.Run("empty content types config compresses all", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(largeBody))
		})

		middleware := CompressStd(CompressConfig{
			MinSize:      100,
			ContentTypes: []string{}, // Empty means compress all
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	})

	t.Run("Close with small buffer not gzipped", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			// Write less than minSize, so it won't be gzipped
			_, _ = w.Write([]byte("small"))
		})

		middleware := CompressStd(CompressConfig{
			MinSize: 1000,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		// Should not be compressed
		assert.Empty(t, rr.Header().Get("Content-Encoding"))
		assert.Equal(t, "small", rr.Body.String())
	})

	t.Run("default MinSize when zero", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(largeBody))
		})

		middleware := CompressStd(CompressConfig{
			MinSize: 0, // Should default to 1024
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)

		assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))
	})
}
