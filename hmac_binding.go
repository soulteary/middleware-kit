package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SignatureInput carries everything a request signature may be computed over.
//
// The legacy SignatureFunc only receives timestamp, service, body and secret,
// which is why a signature produced for one endpoint is equally valid on any
// other endpoint that accepts the same body. RequestSignatureFunc receives the
// request target as well so the signature can be bound to it.
type SignatureInput struct {
	Method string

	// Path is the request target's ESCAPED path, not the decoded one.
	//
	// Decoding first collapses distinct targets: "/a/b" and "/a%2Fb" both
	// decode to "/a/b" and would sign identically, while net/http's ServeMux
	// routes the first to "/a/b" and the second to a single-segment
	// "/{x}" handler -- so a signature authorized for one route would
	// authenticate a different one.
	Path      string
	RawQuery  string
	Timestamp string
	Service   string
	Body      string
	Secret    string
}

// RequestSignatureFunc computes the expected signature for a request.
type RequestSignatureFunc func(in SignatureInput) string

// ComputeHMACBound computes HMAC-SHA256 over a canonical, unambiguous encoding
// of the request:
//
//	len(method)  "\n" method  "\n"
//	len(path)    "\n" path    "\n"  ... and so on for query, timestamp, service, body
//
// Two properties matter here:
//
//   - The method, path and query are covered, so a signature minted for
//     POST /transfer cannot be replayed against POST /delete-account.
//   - Every field is length-prefixed, so no combination of field values can
//     produce the same byte string as a different combination. The legacy
//     "timestamp:service:body" form has no such property: service is taken
//     from a client-supplied header, so ("a", "b:c") and ("a:b", "c") sign
//     identically and a valid signature can be presented with a different
//     service than the one it was issued for.
func ComputeHMACBound(in SignatureInput) string {
	var b strings.Builder
	for _, field := range []string{in.Method, in.Path, in.RawQuery, in.Timestamp, in.Service, in.Body} {
		b.WriteString(strconv.Itoa(len(field)))
		b.WriteByte('\n')
		b.WriteString(field)
		b.WriteByte('\n')
	}
	mac := hmac.New(sha256.New, []byte(in.Secret))
	mac.Write([]byte(b.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

// expectedSignature picks the signature function configured on cfg.
//
// RequestSignatureFunc wins when set; otherwise the legacy SignatureFunc (or
// ComputeHMAC) is used with only timestamp, service and body.
func (cfg HMACConfig) expectedSignature(in SignatureInput) string {
	if cfg.RequestSignatureFunc != nil {
		return cfg.RequestSignatureFunc(in)
	}
	if cfg.SignatureFunc != nil {
		return cfg.SignatureFunc(in.Timestamp, in.Service, in.Body, in.Secret)
	}
	return ComputeHMAC(in.Timestamp, in.Service, in.Body, in.Secret)
}

// validService rejects service identifiers that could shift the field boundary
// in the legacy "timestamp:service:body" encoding.
//
// The service is read from a client-supplied header, so without this a caller
// holding a valid signature for (service "a", body "b:c") can present it as
// (service "a:b", body "c"): same signed bytes, different service seen by
// everything downstream. ComputeHMACBound is length-prefixed and immune, but
// the legacy encoding is the default and has to be made safe in place.
func validService(service string) bool {
	return !strings.Contains(service, ":")
}

// serviceAllowed reports whether service may be used with cfg's signature
// function.
//
// The guard is ON unless the configuration positively establishes that the
// signer is unambiguous. Only two things establish that: the caller setting
// AllowDelimitersInService, and this package's own length-prefixed
// ComputeHMACBound.
//
// Non-nilness does not establish it, which is what an earlier version got
// wrong. "SignatureFunc != nil means a custom signer, so the legacy encoding
// is not in use" is false for the one assignment most likely to be written by
// hand -- SignatureFunc: ComputeHMAC, the exported default -- and equally
// false for any wrapper around it, or for a custom RequestSignatureFunc that
// concatenates its fields. Each of those turned the guard off while signing
// exactly the ambiguous bytes it exists to defend.
func (cfg HMACConfig) serviceAllowed(service string) bool {
	if cfg.AllowDelimitersInService || cfg.usesBoundEncoding() {
		return true
	}
	return validService(service)
}

// usesBoundEncoding reports whether signatures are computed by this package's
// own ComputeHMACBound, whose length-prefixed framing cannot be shifted.
//
// The comparison is by function identity, so only ComputeHMACBound itself
// qualifies; a wrapper around it is a different function and keeps the guard
// on. That is the safe direction to be wrong in -- such a caller sets
// AllowDelimitersInService -- and it is why this is not generalised to "any
// RequestSignatureFunc".
func (cfg HMACConfig) usesBoundEncoding() bool {
	if cfg.RequestSignatureFunc == nil {
		return false
	}
	return reflect.ValueOf(cfg.RequestSignatureFunc).Pointer() ==
		reflect.ValueOf(ComputeHMACBound).Pointer()
}

// replayRetention is how long a ReplayGuard must remember a signature.
//
// It has to cover the whole span over which one timestamp stays acceptable.
// Timestamps are validated as integer seconds, inclusively, against
// time.Now().Unix(): a request stamped ts is accepted while
// ts-drift <= floor(now) <= ts+drift, so the first acceptance can be as early
// as ts-drift and the last as late as ts+drift+1 (a whole second past
// ts+drift, because floor(now) does not tick until then).
//
// Hence 2*drift + 1s. Retaining for one drift let a captured request through
// again as soon as the first retention elapsed; retaining for exactly two
// left the final fractional second of validity uncovered -- with the 5 minute
// default, a 0.9s window in which the same request replayed successfully.
func replayRetention(maxDrift time.Duration) time.Duration {
	if maxDrift <= 0 {
		return 0
	}
	return 2*maxDrift + time.Second
}

// ReplayGuard records request identities that have already been accepted, so a
// captured request cannot be replayed within the timestamp window.
//
// A timestamp window alone does not prevent replay: it only bounds how long a
// captured request stays useful. With MaxTimeDrift at its 5 minute default,
// every signed request is replayable an unlimited number of times for five
// minutes.
type ReplayGuard interface {
	// Seen atomically records id and reports whether it was already present.
	// Implementations must expire entries after ttl.
	Seen(id string, ttl time.Duration) bool
}

// MemoryReplayGuard is a single-process ReplayGuard.
//
// It is suitable for a single instance. A deployment behind a load balancer
// needs a shared store (Redis SET NX with a TTL, for example), otherwise a
// request replayed to a different instance is not detected.
type MemoryReplayGuard struct {
	mu sync.Mutex

	// seen maps a signature to ITS OWN expiry, not to when it was recorded.
	//
	// Storing the insertion time and comparing it against the caller's ttl
	// applied whichever ttl the CURRENT request happened to carry to every
	// stored entry, so one guard shared by middlewares with different
	// MaxTimeDrift values dropped a ten-minute entry as soon as a one-second
	// caller swept -- and that signature became replayable again while still
	// inside its own validity window.
	seen map[string]time.Time

	// nextSweep bounds how often the map is scanned. Sweeping on every call
	// made Seen O(len(seen)): at the default ten-minute retention and 1000
	// requests/second the map holds ~600k entries and every authenticated
	// request walked all of them.
	nextSweep time.Time
}

// replaySweepInterval is the minimum gap between full sweeps.
const replaySweepInterval = 30 * time.Second

// NewMemoryReplayGuard returns an empty in-process replay guard.
func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{seen: make(map[string]time.Time)}
}

// Seen records id and reports whether it had been seen before.
//
// ttl is the full retention the caller asks for -- see replayRetention, which
// doubles MaxTimeDrift to cover a signature's whole validity period rather
// than just the drift. It applies to THIS id only.
func (g *MemoryReplayGuard) Seen(id string, ttl time.Duration) bool {
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	if expires, exists := g.seen[id]; exists && now.Before(expires) {
		return true
	}

	g.seen[id] = now.Add(ttl)

	// Amortized cleanup: a full scan at most every replaySweepInterval,
	// rather than on every request.
	if now.After(g.nextSweep) {
		for k, expires := range g.seen {
			if now.After(expires) {
				delete(g.seen, k)
			}
		}
		g.nextSweep = now.Add(replaySweepInterval)
	}
	return false
}
