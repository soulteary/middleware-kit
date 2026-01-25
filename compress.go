package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// CompressConfig configures the compression middleware.
type CompressConfig struct {
	// Level is the gzip compression level.
	// Valid values: gzip.NoCompression (0) to gzip.BestCompression (9)
	// Default: gzip.DefaultCompression (-1)
	Level int

	// MinSize is the minimum response size to trigger compression.
	// Responses smaller than this are not compressed.
	// Default: 1024 (1KB)
	MinSize int

	// SkipPaths is a list of paths to skip compression.
	SkipPaths []string

	// ContentTypes is a list of content types to compress.
	// If empty, all text-based content types are compressed.
	// Example: ["application/json", "text/html", "text/plain"]
	ContentTypes []string
}

// DefaultCompressConfig returns the default compression configuration.
func DefaultCompressConfig() CompressConfig {
	return CompressConfig{
		Level:   gzip.DefaultCompression,
		MinSize: 1024,
		ContentTypes: []string{
			"text/html",
			"text/css",
			"text/plain",
			"text/javascript",
			"application/javascript",
			"application/json",
			"application/xml",
			"text/xml",
			"application/xhtml+xml",
		},
	}
}

// gzipWriter wraps http.ResponseWriter to support gzip compression.
type gzipWriter struct {
	http.ResponseWriter
	writer       *gzip.Writer
	minSize      int
	contentTypes map[string]bool
	buffer       []byte
	headerSent   bool
	shouldGzip   bool
}

func (gw *gzipWriter) Write(b []byte) (int, error) {
	// If header not sent yet, buffer the data
	if !gw.headerSent {
		gw.buffer = append(gw.buffer, b...)

		// Check if we have enough data to decide
		if len(gw.buffer) >= gw.minSize {
			gw.flush()
		}
		return len(b), nil
	}

	if gw.shouldGzip && gw.writer != nil {
		return gw.writer.Write(b)
	}
	return gw.ResponseWriter.Write(b)
}

func (gw *gzipWriter) flush() {
	if gw.headerSent {
		return
	}
	gw.headerSent = true

	// Check content type
	contentType := gw.Header().Get("Content-Type")
	if contentType == "" {
		contentType = "text/html"
	}
	// Extract base content type (without charset)
	if idx := strings.Index(contentType, ";"); idx > 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	// Decide if we should gzip
	gw.shouldGzip = len(gw.buffer) >= gw.minSize &&
		(len(gw.contentTypes) == 0 || gw.contentTypes[contentType])

	if gw.shouldGzip && gw.writer != nil {
		gw.Header().Set("Content-Encoding", "gzip")
		gw.Header().Del("Content-Length") // Content length changes with compression
	}

	// Write buffered data
	if len(gw.buffer) > 0 {
		if gw.shouldGzip && gw.writer != nil {
			_, _ = gw.writer.Write(gw.buffer)
		} else {
			_, _ = gw.ResponseWriter.Write(gw.buffer)
		}
	}
}

func (gw *gzipWriter) WriteHeader(statusCode int) {
	// Flush any buffered data first
	if !gw.headerSent && len(gw.buffer) > 0 {
		gw.flush()
	}
	gw.ResponseWriter.WriteHeader(statusCode)
}

func (gw *gzipWriter) Close() error {
	// Flush any remaining buffered data
	if !gw.headerSent && len(gw.buffer) > 0 {
		gw.flush()
	}
	if gw.shouldGzip && gw.writer != nil {
		return gw.writer.Close()
	}
	return nil
}

// gzipWriterPool reuses gzip.Writer objects.
var gzipWriterPool = sync.Pool{
	New: func() interface{} {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

// CompressStd creates a standard net/http middleware for gzip compression.
func CompressStd(cfg CompressConfig) func(http.Handler) http.Handler {
	if cfg.MinSize <= 0 {
		cfg.MinSize = 1024
	}

	skipPathMap := make(map[string]bool)
	for _, p := range cfg.SkipPaths {
		skipPathMap[p] = true
	}

	contentTypeMap := make(map[string]bool)
	for _, ct := range cfg.ContentTypes {
		contentTypeMap[ct] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if path is in skip list
			if skipPathMap[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Check if client supports gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Get gzip writer from pool
			gzWriter, ok := gzipWriterPool.Get().(*gzip.Writer)
			if !ok {
				gzWriter, _ = gzip.NewWriterLevel(io.Discard, cfg.Level)
			}

			// Set Vary header
			w.Header().Set("Vary", "Accept-Encoding")

			// Reset writer to point to current ResponseWriter
			gzWriter.Reset(w)

			// Wrap ResponseWriter
			gw := &gzipWriter{
				ResponseWriter: w,
				writer:         gzWriter,
				minSize:        cfg.MinSize,
				contentTypes:   contentTypeMap,
			}

			// Ensure resources are properly released
			defer func() {
				if err := gw.Close(); err != nil {
					_ = err // Explicitly ignore error
				}
				gzWriter.Reset(io.Discard)
				gzipWriterPool.Put(gzWriter)
			}()

			next.ServeHTTP(gw, r)
		})
	}
}
