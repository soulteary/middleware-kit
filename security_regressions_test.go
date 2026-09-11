package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func certWithCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

// TestVerifiedPeerCertificateRequiresVerifiedChain is the regression test for
// accepting an unverified certificate: PeerCertificates alone only means the
// peer sent something, and a self-signed certificate's Subject is attacker
// chosen, so an AllowedCNs allow-list on top of it protects nothing.
func TestVerifiedPeerCertificateRequiresVerifiedChain(t *testing.T) {
	cert := certWithCN("svc-a")

	if _, err := verifiedPeerCertificate(nil); !errors.Is(err, ErrMTLSCertificateMissing) {
		t.Errorf("nil state: got %v, want ErrMTLSCertificateMissing", err)
	}
	if _, err := verifiedPeerCertificate(&tls.ConnectionState{}); !errors.Is(err, ErrMTLSCertificateMissing) {
		t.Errorf("no certificates: got %v, want ErrMTLSCertificateMissing", err)
	}

	unverified := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if _, err := verifiedPeerCertificate(unverified); !errors.Is(err, ErrMTLSCertificateUnverified) {
		t.Errorf("presented but unverified: got %v, want ErrMTLSCertificateUnverified", err)
	}

	verified := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	got, err := verifiedPeerCertificate(verified)
	if err != nil || got != cert {
		t.Errorf("verified chain: got (%v, %v), want the leaf certificate", got, err)
	}
}

// TestCombinedAuthAppliesMTLSRestrictions pins the fix for CombinedAuth
// ignoring MTLSConfig: it used to return c.Next() on any presented
// certificate, so AllowedCNs was dead configuration.
func TestCombinedAuthAppliesMTLSRestrictions(t *testing.T) {
	cfg := MTLSConfig{RequireCert: true, AllowedCNs: []string{"svc-a"}}
	lists := newCertAllowLists(cfg)

	allowed := certWithCN("svc-a")
	denied := certWithCN("attacker")

	state := func(c *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{c},
			VerifiedChains:   [][]*x509.Certificate{{c}},
		}
	}

	if _, err := authenticateMTLS(state(allowed), cfg, lists); err != nil {
		t.Errorf("allowed CN rejected: %v", err)
	}
	if _, err := authenticateMTLS(state(denied), cfg, lists); !errors.Is(err, ErrMTLSCertificateInvalid) {
		t.Errorf("CN outside the allow-list: got %v, want ErrMTLSCertificateInvalid", err)
	}
	// Verified chain absent: rejected even though the CN is allowed.
	selfSigned := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{allowed}}
	if _, err := authenticateMTLS(selfSigned, cfg, lists); !errors.Is(err, ErrMTLSCertificateUnverified) {
		t.Errorf("unverified chain with an allowed CN: got %v, want ErrMTLSCertificateUnverified", err)
	}
}

// TestRateLimiterWindowRollsOver: the window must advance on schedule, not only
// after the client goes idle. A steady client used to accumulate until blocked.
func TestRateLimiterWindowRollsOver(t *testing.T) {
	rl := NewRateLimiter(RateLimiterConfig{
		Rate:            3,
		Window:          50 * time.Millisecond,
		CleanupInterval: time.Hour,
	})
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.Allow("client") {
			t.Fatalf("request %d denied inside the limit", i+1)
		}
	}
	if rl.Allow("client") {
		t.Fatal("4th request allowed; the limit is not enforced")
	}

	// Keep the client active across the window boundary. Under the old
	// lastSeen-based check these requests kept refreshing the window start, so
	// it never rolled over and the client stayed blocked forever.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		if rl.Allow("client") {
			return // window rolled over
		}
	}
	t.Fatal("window never rolled over while the client kept sending")
}

// TestComputeHMACBoundIsUnambiguous covers both properties the legacy encoding
// lacks: the request target is signed, and fields cannot shift boundaries.
func TestComputeHMACBoundIsUnambiguous(t *testing.T) {
	base := SignatureInput{
		Method: "POST", Path: "/transfer", Timestamp: "1700000000",
		Service: "billing", Body: `{"amount":1}`, Secret: "s3cret",
	}

	other := base
	other.Path = "/delete-account"
	if ComputeHMACBound(base) == ComputeHMACBound(other) {
		t.Error("signature is identical across different paths; it is not bound to the request target")
	}

	other = base
	other.Method = "DELETE"
	if ComputeHMACBound(base) == ComputeHMACBound(other) {
		t.Error("signature is identical across different methods")
	}

	// The legacy "timestamp:service:body" form collides here; the
	// length-prefixed form must not.
	a := SignatureInput{Timestamp: "t", Service: "a", Body: "b:c", Secret: "k"}
	b := SignatureInput{Timestamp: "t", Service: "a:b", Body: "c", Secret: "k"}
	if ComputeHMACBound(a) == ComputeHMACBound(b) {
		t.Error("field boundaries are shiftable: two different (service, body) pairs sign identically")
	}
	if ComputeHMAC("t", "a", "b:c", "k") != ComputeHMAC("t", "a:b", "c", "k") {
		t.Skip("legacy encoding no longer collides; validService guard may be redundant")
	}
}

// TestValidServiceRejectsDelimiter guards the legacy encoding in place.
func TestValidServiceRejectsDelimiter(t *testing.T) {
	if validService("a:b") {
		t.Error(`validService("a:b") = true; a service carrying the delimiter can shift the signed field boundary`)
	}
	if !validService("billing") {
		t.Error(`validService("billing") = false, want true`)
	}
}

func TestMemoryReplayGuard(t *testing.T) {
	g := NewMemoryReplayGuard()

	if g.Seen("sig-1", time.Minute) {
		t.Error("first use reported as a replay")
	}
	if !g.Seen("sig-1", time.Minute) {
		t.Error("second use of the same signature was not reported as a replay")
	}
	if g.Seen("sig-2", time.Minute) {
		t.Error("a different signature reported as a replay")
	}
	// Entries expire, so a guard does not grow without bound.
	if g.Seen("sig-3", time.Nanosecond) {
		t.Error("first use of sig-3 reported as a replay")
	}
	time.Sleep(2 * time.Millisecond)
	if g.Seen("sig-1", time.Nanosecond) {
		t.Error("expired entry still reported as a replay")
	}
}

// TestConstantTimeEqualDoesNotShortCircuitOnLength documents why
// constantTimeEqual pads instead of calling subtle.ConstantTimeCompare
// directly, and checks the comparison itself is still correct.
func TestConstantTimeEqualDoesNotShortCircuitOnLength(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"secret", "secret", true},
		{"secret", "secrfx", false},
		{"secret", "sec", false},
		{"sec", "secret", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := constantTimeEqual(c.a, c.b); got != c.want {
			t.Errorf("constantTimeEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestIPAllowlistNotBypassableByForgedHeader ties the client-IP fix to the
// control that depends on it.
func TestIPAllowlistNotBypassableByForgedHeader(t *testing.T) {
	mw := IPAllowlistMiddleware("10.0.0.0/8")
	var reached bool
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:1234" // untrusted peer
	req.Header.Set("X-Forwarded-For", "10.0.0.9")
	req.Header.Set("X-Real-IP", "10.0.0.9")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if reached {
		t.Error("forged forwarded headers from an untrusted peer bypassed the IP allowlist")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}
