package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	Method    string
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
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryReplayGuard returns an empty in-process replay guard.
func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{seen: make(map[string]time.Time)}
}

// Seen records id and reports whether it had been seen before.
func (g *MemoryReplayGuard) Seen(id string, ttl time.Duration) bool {
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	// Opportunistic expiry: entries are only useful for one ttl.
	for k, t := range g.seen {
		if now.Sub(t) > ttl {
			delete(g.seen, k)
		}
	}

	if _, exists := g.seen[id]; exists {
		return true
	}
	g.seen[id] = now
	return false
}
