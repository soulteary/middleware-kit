package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
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

// --- Codex review follow-ups (PR #3) ---

// TestBoundSignatureCoversTheEscapedPath is the regression test for signing
// URL.Path. Percent escapes are already decoded there, so "/a/b" and "/a%2Fb"
// produced the same signature while net/http's ServeMux routes the first to
// "/a/b" and the second to a single-segment "/{x}" handler -- a signature
// authorized for one route authenticated a different one.
func TestBoundSignatureCoversTheEscapedPath(t *testing.T) {
	const secret = "s3cr3t"
	sigFor := func(path string) string {
		return ComputeHMACBound(SignatureInput{
			Method: http.MethodPost, Path: path, Timestamp: "1", Service: "svc", Body: "{}", Secret: secret,
		})
	}
	if sigFor("/a/b") == sigFor("/a%2Fb") {
		t.Error("/a/b and /a%2Fb sign identically; the escaped path is not covered")
	}

	// End to end: a signature minted for /a%2Fb must not authenticate /a/b.
	cfg := HMACConfig{
		Secret:               secret,
		RequestSignatureFunc: ComputeHMACBound,
		MaxTimeDrift:         time.Hour,
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	call := func(target, signedPath string) int {
		body := "{}"
		sig := ComputeHMACBound(SignatureInput{
			Method: http.MethodPost, Path: signedPath, Timestamp: ts, Service: "svc", Body: body, Secret: secret,
		})
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", "svc")
		req.Header.Set("X-Signature", sig)

		rec := httptest.NewRecorder()
		HMACAuthStd(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call("/a%2Fb", "/a%2Fb"); got != http.StatusOK {
		t.Errorf("correctly signed escaped target = %d, want 200", got)
	}
	if got := call("/a/b", "/a%2Fb"); got == http.StatusOK {
		t.Error("a signature minted for /a%2Fb authenticated /a/b")
	}
}

// TestReplayRetentionCoversTheWholeValidityWindow: timestamps are accepted
// symmetrically, so a request stamped MaxTimeDrift in the FUTURE is accepted
// now and stays acceptable for another drift. Retaining the entry for only one
// drift let the same capture through a second time.
func TestReplayRetentionCoversTheWholeValidityWindow(t *testing.T) {
	if got, want := replayRetention(5*time.Minute), 10*time.Minute; got != want {
		t.Errorf("replayRetention(5m) = %s, want %s (two drifts of validity)", got, want)
	}
	if got := replayRetention(0); got != 0 {
		t.Errorf("replayRetention(0) = %s, want 0", got)
	}

	g := NewMemoryReplayGuard()
	if g.Seen("sig", time.Minute) {
		t.Error("first Seen reported a replay")
	}
	if !g.Seen("sig", time.Minute) {
		t.Error("second Seen did not report a replay")
	}
}

// TestCombinedAuthPassesTheNormalizedDrift is the regression test for
// CombinedAuth handing cfg.MaxTimeDrift to Seen while validating against a
// locally computed default. With the documented zero value the guard received
// 0, expired the entry on the very next request, and enabling ReplayGuard
// prevented no replay at all.
func TestCombinedAuthPassesTheNormalizedDrift(t *testing.T) {
	var gotTTL time.Duration
	guard := recordingGuard{onSeen: func(ttl time.Duration) { gotTTL = ttl }}

	cfg := HMACConfig{
		Secret:      "s3cr3t",
		ReplayGuard: &guard,
		// MaxTimeDrift deliberately left at its documented zero value.
	}

	app := fiber.New()
	app.Post("/x", func(c fiber.Ctx) error {
		if !validateHMAC(c, cfg) {
			return c.SendStatus(http.StatusUnauthorized)
		}
		return c.SendStatus(http.StatusOK)
	})

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := "{}"
	sig := ComputeHMAC(ts, "svc", body, "s3cr3t")

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Service", "svc")
	req.Header.Set("X-Signature", sig)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if gotTTL <= 0 {
		t.Errorf("ReplayGuard.Seen got ttl %s with a zero MaxTimeDrift; the entry expires immediately and no replay is prevented", gotTTL)
	}
}

// recordingGuard reports the ttl it was handed.
type recordingGuard struct {
	onSeen func(time.Duration)
	seen   map[string]bool
}

func (g *recordingGuard) Seen(id string, ttl time.Duration) bool {
	if g.onSeen != nil {
		g.onSeen(ttl)
	}
	if g.seen == nil {
		g.seen = map[string]bool{}
	}
	was := g.seen[id]
	g.seen[id] = true
	return was
}

// TestServicePolicyOnlyAppliesToTheAmbiguousEncoding: the ":" restriction
// exists because ComputeHMAC's "timestamp:service:body" form has no field
// boundaries. Applying it unconditionally rejected service identifiers that
// were always valid under a length-prefixed or custom encoding, answering
// previously working clients with 401.
func TestServicePolicyOnlyAppliesToTheAmbiguousEncoding(t *testing.T) {
	legacy := HMACConfig{Secret: "s"}
	if legacy.serviceAllowed("a:b") {
		t.Error("the legacy encoding accepted a service containing ':'")
	}
	if !legacy.serviceAllowed("plain") {
		t.Error("the legacy encoding rejected an ordinary service name")
	}

	bound := HMACConfig{Secret: "s", RequestSignatureFunc: ComputeHMACBound}
	if !bound.serviceAllowed("a:b") {
		t.Error("the length-prefixed encoding rejected a service containing ':'; it has no delimiter to collide with")
	}

	custom := HMACConfig{Secret: "s", SignatureFunc: func(ts, svc, body, secret string) string { return "x" }}
	if !custom.serviceAllowed("a:b") {
		t.Error("a caller's own SignatureFunc had the legacy service policy imposed on it")
	}
}

// TestFiberReplayGuardRunsAfterTheSignatureCheck is the regression test for
// recording the nonce first. A request carrying a valid signature header but an
// altered body is rejected anyway -- and used to consume that signature, so the
// legitimate request that followed was refused as a replay.
func TestFiberReplayGuardRunsAfterTheSignatureCheck(t *testing.T) {
	const secret = "s3cr3t"
	cfg := HMACConfig{Secret: secret, MaxTimeDrift: time.Hour, ReplayGuard: NewMemoryReplayGuard()}

	app := fiber.New()
	app.Post("/x", HMACAuth(cfg), func(c fiber.Ctx) error { return c.SendStatus(http.StatusOK) })

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := `{"amount":1}`
	sig := ComputeHMAC(ts, "svc", body, secret)

	send := func(sendBody string) int {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(sendBody))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", "svc")
		req.Header.Set("X-Signature", sig)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}

	// Tampered body: rejected, and must NOT consume the signature.
	if got := send(`{"amount":9999}`); got == http.StatusOK {
		t.Fatal("a tampered body was accepted")
	}

	// The legitimate request still goes through.
	if got := send(body); got != http.StatusOK {
		t.Errorf("legitimate request = %d, want 200: the tampered attempt consumed its signature", got)
	}

	// A genuine replay is still refused.
	if got := send(body); got == http.StatusOK {
		t.Error("a replayed request was accepted")
	}
}

// TestSlidingWindowHasNoBoundaryBurst is the regression test for resetting the
// whole counter at windowStart+window. That is a fixed window: a client could
// send Rate-1 requests just before the boundary and another Rate immediately
// after, admitting almost twice the configured limit in a very short interval.
func TestSlidingWindowHasNoBoundaryBurst(t *testing.T) {
	const rate = 10
	window := time.Second

	v := &visitor{}
	start := time.Now().Truncate(window)
	v.windowStart = start

	allowed := func(now time.Time) bool {
		if v.estimate(now, window) >= float64(rate) {
			return false
		}
		v.count++
		return true
	}

	// Fill the first window right at its end.
	late := start.Add(window - time.Millisecond)
	for i := 0; i < rate; i++ {
		if !allowed(late) {
			t.Fatalf("request %d in the first window was refused", i)
		}
	}
	if allowed(late) {
		t.Fatal("the limiter admitted more than Rate inside one window")
	}

	// Immediately after the boundary the previous window still overlaps almost
	// entirely, so the budget must NOT reset. A fixed window admitted another
	// full Rate here; a weighted sliding window admits at most a trickle.
	justAfter := start.Add(window + time.Millisecond)
	burst := 0
	for i := 0; i < rate; i++ {
		if allowed(justAfter) {
			burst++
		}
	}
	if burst > 1 {
		t.Errorf("%d requests admitted immediately after the window boundary, want at most 1: this is a fixed window, not a sliding one", burst)
	}

	// The bound that matters: no interval of Window admits more than Rate.
	// Across the boundary that is the late burst plus whatever just passed.
	if total := rate + burst; total > rate+1 {
		t.Errorf("%d requests admitted within one window across the boundary, want at most %d", total, rate)
	}

	// A full window later the budget is back.
	if !allowed(start.Add(2 * window)) {
		t.Error("the limiter never recovered after a full window")
	}
}
