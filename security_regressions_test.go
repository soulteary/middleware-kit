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
	// An entry expires after ITS OWN ttl, so a guard does not grow without
	// bound.
	if g.Seen("sig-3", time.Millisecond) {
		t.Error("first use of sig-3 reported as a replay")
	}
	time.Sleep(5 * time.Millisecond)
	if g.Seen("sig-3", time.Millisecond) {
		t.Error("an entry past its own ttl still reported as a replay")
	}

	// ...and only its own. A later caller passing a short ttl must not evict
	// an entry stored with a long one: this test used to assert the opposite,
	// which is the cross-contamination the per-entry expiry removes.
	if !g.Seen("sig-1", time.Nanosecond) {
		t.Error("an entry stored with a one-minute ttl was dropped by a later one-nanosecond caller; it is still replayable within its own window")
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
//
// The exact lower bound -- including the trailing second that integer-second
// validation adds -- is asserted by
// TestReplayRetentionCoversTheFinalSecondOfValidity.
func TestReplayRetentionCoversTheWholeValidityWindow(t *testing.T) {
	if got, want := replayRetention(5*time.Minute), 10*time.Minute; got < want {
		t.Errorf("replayRetention(5m) = %s, want at least %s (two drifts of validity)", got, want)
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

// TestServicePolicyIsOnUnlessTheSignerIsKnownSafe: the ":" restriction exists
// because ComputeHMAC's "timestamp:service:body" form has no field
// boundaries. It may only be lifted when the configuration positively
// establishes that the signer is unambiguous -- never by inferring it from a
// function being non-nil, which is true of ComputeHMAC itself.
func TestServicePolicyIsOnUnlessTheSignerIsKnownSafe(t *testing.T) {
	allowed := func(cfg HMACConfig) bool { return cfg.serviceAllowed("a:b") }

	if allowed(HMACConfig{Secret: "s"}) {
		t.Error("the default signer accepted a service containing ':'")
	}
	if !(HMACConfig{Secret: "s"}).serviceAllowed("plain") {
		t.Error("the default signer rejected an ordinary service name")
	}

	// The round-3 hole: the exported default, assigned by hand. It signs the
	// ambiguous bytes, so it must keep the guard.
	if allowed(HMACConfig{Secret: "s", SignatureFunc: ComputeHMAC}) {
		t.Error("an explicit SignatureFunc: ComputeHMAC turned the colon guard off")
	}
	wrapped := func(ts, svc, body, secret string) string { return ComputeHMAC(ts, svc, body, secret) }
	if allowed(HMACConfig{Secret: "s", SignatureFunc: wrapped}) {
		t.Error("a wrapper around ComputeHMAC turned the colon guard off")
	}

	// A signer whose encoding this package cannot see is not assumed safe.
	custom := func(ts, svc, body, secret string) string { return "x" }
	if allowed(HMACConfig{Secret: "s", SignatureFunc: custom}) {
		t.Error("an unknown custom SignatureFunc was assumed unambiguous")
	}
	customBound := func(in SignatureInput) string { return "x" }
	if allowed(HMACConfig{Secret: "s", RequestSignatureFunc: customBound}) {
		t.Error("an unknown custom RequestSignatureFunc was assumed unambiguous")
	}

	// The two ways out: this package's own length-prefixed signer, and the
	// caller saying so.
	if !allowed(HMACConfig{Secret: "s", RequestSignatureFunc: ComputeHMACBound}) {
		t.Error("ComputeHMACBound had the legacy service policy imposed on it")
	}
	if !allowed(HMACConfig{Secret: "s", SignatureFunc: custom, AllowDelimitersInService: true}) {
		t.Error("AllowDelimitersInService did not lift the guard")
	}
}

// TestReplayRetentionCoversTheFinalSecondOfValidity: retention has to span the
// whole time one timestamp stays acceptable. Because validation compares
// integer seconds inclusively, that span is 2*drift + 1s, not 2*drift -- and
// the missing second was a window in which a captured request replayed.
func TestReplayRetentionCoversTheFinalSecondOfValidity(t *testing.T) {
	const drift = 5 * time.Minute

	// Derived from isTimestampValid rather than restated: it accepts while
	// |floor(now) - ts| <= drift, so ts is first acceptable at ts-drift and
	// stays acceptable until floor(now) ticks to ts+drift+1.
	span := (drift + time.Second) - (-drift)

	if got := replayRetention(drift); got < span {
		t.Errorf("retention %s over a %s validity window; the last %s is replayable", got, span, span-got)
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

// TestSlidingWindowIsExact is the regression test for the window algorithm.
//
// A fixed window admitted almost 2x Rate across a boundary. The weighted
// two-bucket replacement narrowed that but was still an estimate: it assumes
// the previous window's requests were spread evenly, so a burst concentrated
// at its end is undercounted. This asserts the property directly -- NO
// interval of Window ever contains more than Rate admitted requests.
func TestSlidingWindowIsExact(t *testing.T) {
	const rate = 10
	window := time.Second

	start := time.Now()
	v := newVisitor(start, rate)
	admitted := []time.Time{start}

	allow := func(at time.Time) bool {
		if v.allow(at, window, rate) {
			admitted = append(admitted, at)
			return true
		}
		return false
	}

	// Fill the rest of the budget right at the end of the first window, the
	// burst shape the weighted estimate undercounted.
	late := start.Add(window - time.Millisecond)
	for i := 1; i < rate; i++ {
		if !allow(late) {
			t.Fatalf("request %d inside the first window was refused", i)
		}
	}
	if allow(late) {
		t.Fatal("more than Rate admitted inside one window")
	}

	// Codex's counter-example: step through the following window and keep
	// asking. The exact window must never let a trailing Window exceed Rate.
	for step := 1; step <= 20; step++ {
		allow(start.Add(window + time.Duration(step)*window/10))
	}

	// Verify the invariant directly over every admitted request.
	for i, at := range admitted {
		n := 0
		for _, other := range admitted {
			if !other.Before(at) && other.Before(at.Add(window)) {
				n++
			}
		}
		if n > rate {
			t.Fatalf("%d requests admitted in the window starting at admitted[%d]; Rate is %d", n, i, rate)
		}
	}

	// The limiter still recovers: a full window after the last admitted
	// request, the budget is back.
	last := admitted[len(admitted)-1]
	if !allow(last.Add(window)) {
		t.Error("the limiter never recovered a full window after the last request")
	}
}

// TestRateLimiterAllowsASteadyClient guards the original fix: a client sending
// faster than one request per window must still roll over.
func TestRateLimiterAllowsASteadyClient(t *testing.T) {
	const rate = 10
	window := 100 * time.Millisecond

	now := time.Now()
	v := newVisitor(now, rate)

	// One request every window/rate, sustained: exactly at the limit, so all
	// of them must pass.
	for i := 1; i <= 100; i++ {
		at := now.Add(time.Duration(i) * window / rate)
		if !v.allow(at, window, rate) {
			t.Fatalf("steady request %d refused; the window is not rolling over", i)
		}
	}
}

// TestDefaultSignerKeepsTheColonGuard is the regression test for inferring the
// encoding AFTER the constructors applied their default. HMACAuth and
// HMACAuthStd assigned ComputeHMAC to cfg.SignatureFunc before the handler
// ran, so serviceAllowed saw a non-nil function, called the plain default
// configuration a "custom signer", and let ':' back into the service header --
// reopening the collision where a signature for service "a" with body "b:c"
// also authenticates service "a:b" with body "c".
func TestDefaultSignerKeepsTheColonGuard(t *testing.T) {
	const secret = "s3cr3t"

	// The forged pair: ("a", "b:c") and ("a:b", "c") sign identically under
	// ComputeHMAC's "timestamp:service:body" form.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ComputeHMAC(ts, "a", "b:c", secret)
	if sig != ComputeHMAC(ts, "a:b", "c", secret) {
		t.Fatal("the legacy encoding is no longer ambiguous; this test needs updating")
	}

	send := func(h http.Handler) int {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("c"))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", "a:b") // the shifted service
		req.Header.Set("X-Signature", sig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Default configuration: the guard must still reject the shifted service.
	std := HMACAuthStd(HMACConfig{Secret: secret, MaxTimeDrift: time.Hour})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if got := send(std); got == http.StatusOK {
		t.Error("a service identifier containing ':' was accepted under the default signer")
	}

	// An explicitly configured unambiguous signer is still allowed to use ':'.
	bound := HMACConfig{Secret: secret, MaxTimeDrift: time.Hour, RequestSignatureFunc: ComputeHMACBound}
	if !bound.serviceAllowed("a:b") {
		t.Error("the length-prefixed encoding had the legacy service policy imposed on it")
	}
	if !bound.usesBoundEncoding() {
		t.Error("ComputeHMACBound was not recognised as the length-prefixed signer")
	}
	if (HMACConfig{Secret: secret}).usesBoundEncoding() {
		t.Error("the default configuration was reported as the length-prefixed signer")
	}

	// The same forged pair, now against a hand-written SignatureFunc:
	// ComputeHMAC. This is the default signer under another name, so the
	// guard must still reject the shifted service.
	explicit := HMACAuthStd(HMACConfig{Secret: secret, MaxTimeDrift: time.Hour, SignatureFunc: ComputeHMAC})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if got := send(explicit); got == http.StatusOK {
		t.Error("an explicit SignatureFunc: ComputeHMAC accepted the shifted service identifier")
	}
}

// TestCombinedAuthDefaultDriftIsFiveMinutes is the regression test for
// "maxDrift = 5 * 60 // 5 minutes in seconds" in validateHMAC. maxDrift is a
// time.Duration, so that literal was 300 NANOSECONDS: int64(maxDrift.Seconds())
// truncated to 0 and the documented zero value accepted only a timestamp
// landing on the current second, while the replay guard retained entries for
// 600ns. A request a few seconds old is well inside the documented default.
func TestCombinedAuthDefaultDriftIsFiveMinutes(t *testing.T) {
	const secret = "test-secret"

	app := fiber.New()
	app.Use(CombinedAuth(AuthConfig{
		// MaxTimeDrift deliberately left at its zero value.
		HMACConfig: &HMACConfig{Secret: secret},
	}))
	app.Post("/", func(c fiber.Ctx) error { return c.SendString("OK") })

	ts := strconv.FormatInt(time.Now().Add(-5*time.Second).Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", ComputeHMAC(ts, "", "body", secret))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("a 5s-old timestamp got %d with the default drift; the default must be 5 minutes", resp.StatusCode)
	}
}

// TestForwardedChainSpansRepeatedHeaders is the regression test for reading
// X-Forwarded-For with Header.Get.
//
// The header may legitimately appear more than once -- a proxy that APPENDS
// its own line rather than coalescing into the client's is compliant -- and
// Get returns only the first. The right-to-left resolver then walked a chain
// consisting entirely of the client's own fabrication, never saw the address
// the proxy added, and returned whatever the client asked for.
func TestForwardedChainSpansRepeatedHeaders(t *testing.T) {
	cfg := &TrustedProxyConfig{TrustedProxies: []string{"10.0.0.0/8"}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234" // the trusted proxy
	// What the client sent...
	req.Header.Add("X-Forwarded-For", "1.2.3.4")
	// ...and the line the proxy appended, carrying the real peer.
	req.Header.Add("X-Forwarded-For", "203.0.113.9")

	if got := GetClientIP(req, cfg); got != "203.0.113.9" {
		t.Errorf("GetClientIP = %q, want 203.0.113.9; the proxy-added header line was ignored", got)
	}

	// A single coalesced header is unchanged.
	one := httptest.NewRequest(http.MethodGet, "/", nil)
	one.RemoteAddr = "10.0.0.1:1234"
	one.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	if got := GetClientIP(one, cfg); got != "203.0.113.9" {
		t.Errorf("GetClientIP(coalesced) = %q, want 203.0.113.9", got)
	}

	// X-Real-IP takes the LAST line for the same reason.
	real := httptest.NewRequest(http.MethodGet, "/", nil)
	real.RemoteAddr = "10.0.0.1:1234"
	real.Header.Add("X-Real-IP", "1.2.3.4")     // the client's
	real.Header.Add("X-Real-IP", "203.0.113.9") // the proxy's
	if got := GetClientIP(real, cfg); got != "203.0.113.9" {
		t.Errorf("GetClientIP(X-Real-IP) = %q, want 203.0.113.9; the client's line won", got)
	}
}

// TestBrokenForwardedChainDoesNotTrustItsLeftEnd is the regression test for
// returning parts[0] after the walk aborted on a malformed hop.
//
// The loop breaks because nothing left of an unparseable entry can be
// attributed to a trusted proxy -- and then the fallback returned exactly that
// leftmost entry, which is the one an attacker prepends. It also returned
// before X-Real-IP was consulted, so a trustworthy proxy-set value lost to a
// forged one.
func TestBrokenForwardedChainDoesNotTrustItsLeftEnd(t *testing.T) {
	cfg := &TrustedProxyConfig{TrustedProxies: []string{"10.0.0.0/8"}}

	newReq := func(xff, realIP string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.1:1234" // the trusted proxy
		r.Header.Set("X-Forwarded-For", xff)
		if realIP != "" {
			r.Header.Set("X-Real-IP", realIP)
		}
		return r
	}

	// A forged allow-listed address, then a hop this package cannot parse.
	if got := GetClientIP(newReq("10.9.9.9, unknown", ""), cfg); got == "10.9.9.9" {
		t.Error("a forged address left of a malformed hop was returned as the client")
	}

	// And it must not beat a trustworthy X-Real-IP.
	if got := GetClientIP(newReq("10.9.9.9, unknown", "203.0.113.9"), cfg); got != "203.0.113.9" {
		t.Errorf("GetClientIP = %q, want the proxy's X-Real-IP 203.0.113.9", got)
	}

	// With no X-Real-IP either, the direct peer is the answer.
	if got := GetClientIP(newReq("10.9.9.9, unknown", ""), cfg); got != "10.0.0.1" {
		t.Errorf("GetClientIP = %q, want the direct peer 10.0.0.1", got)
	}

	// An INTACT all-trusted chain still yields its leftmost entry.
	if got := GetClientIP(newReq("10.9.9.9, 10.0.0.2", ""), cfg); got != "10.9.9.9" {
		t.Errorf("GetClientIP = %q, want 10.9.9.9 from an intact internal chain", got)
	}
}
