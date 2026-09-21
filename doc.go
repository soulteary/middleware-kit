// Package middleware provides HTTP middleware for Go services: authentication
// (API key, HMAC signatures, mTLS client certificates), rate limiting, an IP
// allowlist, security headers, request logging, gzip compression and request
// body limiting.
//
// Every middleware here serves net/http and is named XxxStd. The Fiber half of
// each pair lives in the fiberadapter subpackage, so importing this package
// does not link Fiber -- and with it fasthttp -- into a binary that never
// serves a Fiber route. The two halves share their configuration structs and
// the rules they enforce; see fiberadapter's package documentation.
//
// The exported helpers that carry those shared rules -- AuthenticateMTLS,
// ConstantTimeEqual, HMACConfig.ExpectedSignature and the rest -- exist so a
// framework adapter runs the same check the net/http middleware runs rather
// than a second copy of it.
package middleware
