package middleware

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A handler that calls WriteHeader before Write must still get a response whose
// headers describe the body that was sent.
func TestCompressStd_ExplicitWriteHeader(t *testing.T) {
	large := `{"data":"` + strings.Repeat("a", 4096) + `"}`
	small := `{"ok":true}`

	tests := []struct {
		name         string
		status       int
		body         string
		preEncoded   bool
		wantEncoding string
	}{
		{name: "large body after 200", status: http.StatusOK, body: large, wantEncoding: "gzip"},
		{name: "large body after 201", status: http.StatusCreated, body: large, wantEncoding: "gzip"},
		{name: "large error body", status: http.StatusBadRequest, body: large, wantEncoding: "gzip"},
		{name: "small body keeps status", status: http.StatusNotFound, body: small},
		{name: "no content", status: http.StatusNoContent},
		{name: "not modified", status: http.StatusNotModified},
		{name: "status without body", status: http.StatusAccepted},
		{name: "already encoded body is passed through", status: http.StatusOK, body: large, preEncoded: true, wantEncoding: "br"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := CompressStd(DefaultCompressConfig())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tt.preEncoded {
					w.Header().Set("Content-Encoding", "br")
				}
				w.WriteHeader(tt.status)
				if tt.body != "" {
					_, _ = w.Write([]byte(tt.body))
				}
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", "gzip")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if got := rec.Header().Get("Content-Encoding"); got != tt.wantEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, tt.wantEncoding)
			}

			got := rec.Body.Bytes()
			if tt.wantEncoding == "gzip" {
				zr, err := gzip.NewReader(rec.Body)
				if err != nil {
					t.Fatalf("body is not gzip: %v", err)
				}
				if got, err = io.ReadAll(zr); err != nil {
					t.Fatalf("read gzip body: %v", err)
				}
			}
			if string(got) != tt.body {
				t.Fatalf("body mismatch: got %d bytes, want %d", len(got), len(tt.body))
			}
		})
	}
}

// The same case through a real server and the default client, which only
// decompresses when Content-Encoding is present.
func TestCompressStd_ExplicitWriteHeaderOverHTTP(t *testing.T) {
	body := `{"data":"` + strings.Repeat("a", 4096) + `"}`
	srv := httptest.NewServer(CompressStd(DefaultCompressConfig())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !resp.Uncompressed {
		t.Fatal("client did not decompress: Content-Encoding was missing")
	}
	if string(got) != body {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(got), len(body))
	}
}

// When the visitor table is full, one eviction pass must free room for more
// than one new key, and the table must never exceed its limit.
func TestRateLimiter_EvictionLeavesHeadroom(t *testing.T) {
	const max = 100
	rl := NewRateLimiter(RateLimiterConfig{Rate: 5, MaxVisitors: max})
	defer rl.Stop()

	for i := 0; i < max; i++ {
		rl.Allow(fmt.Sprintf("10.0.0.%d", i))
	}
	rl.Allow("new-key")

	rl.mu.RLock()
	size := len(rl.visitors)
	_, kept := rl.visitors["new-key"]
	rl.mu.RUnlock()

	if !kept {
		t.Fatal("the new key was not recorded")
	}
	if want := max - max/evictionHeadroomDivisor + 1; size != want {
		t.Fatalf("visitors after eviction = %d, want %d", size, want)
	}

	for i := 0; i < 3*max; i++ {
		rl.Allow(fmt.Sprintf("flood-%d", i))
		rl.mu.RLock()
		size = len(rl.visitors)
		rl.mu.RUnlock()
		if size > max {
			t.Fatalf("visitors = %d, exceeds limit %d", size, max)
		}
	}
}
