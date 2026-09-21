package middleware

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestLoggingStd(t *testing.T) {
	t.Run("logs request with default config", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "HTTP request")
		assert.Contains(t, logOutput, "/test")
	})

	t.Run("skips paths in skip list", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger:    &logger,
			SkipPaths: []string{"/health"},
		})(handler)

		// Health endpoint should not be logged
		req := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)
		assert.Empty(t, buf.String())
	})

	t.Run("captures status code", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "404")
	})

	t.Run("no-op when logger is nil", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: nil,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestDefaultLoggingConfig(t *testing.T) {
	cfg := DefaultLoggingConfig()

	assert.Equal(t, 1024, cfg.MaxBodyLogSize)
	assert.NotEmpty(t, cfg.SensitiveHeaders)
	assert.Contains(t, cfg.SensitiveHeaders, "Authorization")
	assert.Contains(t, cfg.SensitiveHeaders, "X-API-Key")
	assert.True(t, cfg.IncludeLatency)
}

func TestResponseWriter(t *testing.T) {
	t.Run("Write captures response size", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write response body - this triggers responseWriter.Write
			_, _ = w.Write([]byte("Hello, World!"))
			_, _ = w.Write([]byte(" More data"))
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "Hello, World! More data", rr.Body.String())
	})

	t.Run("WriteHeader and Write together", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("Accepted"))
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("POST", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusAccepted, rr.Code)
		assert.Equal(t, "Accepted", rr.Body.String())

		logOutput := buf.String()
		assert.Contains(t, logOutput, "202")
	})
}

func TestRequestLoggingStd_Extended(t *testing.T) {
	t.Run("logs query parameters", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/api?foo=bar&baz=qux", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "query")
	})

	t.Run("logs headers when enabled", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger:     &logger,
			LogHeaders: true,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Custom", "value")
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "headers")
	})

	t.Run("redacts sensitive headers", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger:     &logger,
			LogHeaders: true,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer secret")
		req.Header.Set("X-API-Key", "secret-key")
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "[REDACTED]")
		assert.NotContains(t, logOutput, "secret")
	})

	t.Run("uses error log level for 4xx status", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Bad Request"))
		})

		middleware := RequestLoggingStd(LoggingConfig{
			Logger:        &logger,
			ErrorLogLevel: zerolog.WarnLevel,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		logOutput := buf.String()
		assert.Contains(t, logOutput, "400")
	})
}
