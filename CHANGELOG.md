# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because this is a Go module, a major version is also a distinct import path:
`v2` is `github.com/soulteary/middleware-kit/v2`, `v3` is
`.../v3`, and upgrading across one is never automatic.

Entries for releases before this file existed were reconstructed from the git
history and the upgrade notes in the README; they summarise the releases rather
than enumerate every commit.

## [Unreleased]

## [3.0.0]

### Changed (breaking)

- **The module path is now `github.com/soulteary/middleware-kit/v3`.** Update
  every import. Go treats a major version as a separate module, so nothing
  upgrades on its own and the v2 line keeps working until you move.
- **Fiber support moved to the `fiberadapter` subpackage.** Nine functions left
  the root package: `APIKeyAuth`, `HMACAuth`, `MTLSAuth`, `CombinedAuth`,
  `RateLimit`, `BodyLimit`, `SecurityHeaders`, `NoCacheHeaders`,
  `RequestLogging`, plus `GetClientIPFiber`. Each is now
  `fiberadapter.<SameName>`. The `Std` (net/http) halves are untouched — every
  one of them is byte-identical to its v2 implementation.

  Importing the root package no longer links Fiber, and with it fasthttp. For a
  net/http service mounting `SecurityHeadersStd`: 25 fewer linked packages, 11
  fewer modules in the build list, and a 14% smaller binary (7820 KB → 6739 KB).
- **The Fiber-typed hooks moved with them.** `ErrorHandler`, `SuccessHandler`,
  `KeyFunc` and `CustomFields` were typed `func(fiber.Ctx) ...`, which is what
  pulled Fiber into the root package. They now live on
  `fiberadapter.{APIKey,HMAC,MTLS,Auth,BodyLimit,Logging,RateLimit}Config`, each
  of which embeds the corresponding root config, so every other field is
  unchanged and still shared with the `Std` half.

### Fixed (changes what a running deployment accepts)

- **The Fiber mTLS certificate check never ran under Fiber v3.** `MTLSAuth` and
  `CombinedAuth` gated it on `c.Protocol() == "https"`; in Fiber v3 `Protocol()`
  reports the HTTP *version* and returns `"HTTP/1.1"`, so the test was never
  true and everything behind it was skipped. Present in v2.0.0, v2.1.0 and
  v2.2.0, all of which require Fiber v3.

  | Config | Should be | Was |
  |---|---|---|
  | `MTLSAuth`, `RequireCert: true`, verified cert matching `AllowedCNs` | 200 | **401** — deny-all |
  | `MTLSAuth`, `RequireCert: false`, verified cert **failing** `AllowedCNs` | 401 | **200** — fail-open |
  | `CombinedAuth`, mTLS the only scheme, verified cert | 200 | **401** |

  With `RequireCert: false`, `AllowedCNs`, `AllowedOUs`, `AllowedDNSSANs` and
  `CertValidator` were never consulted, so a certificate that explicitly failed
  the allow-list was accepted. Those checks now run, which means **a certificate
  outside your allow-list starts being rejected where it used to pass.** See
  "Upgrade Notes (v3.0.0)" in the README before deploying.

  Plaintext requests are unaffected in both directions: 401 with reason
  `certificate_required` when `RequireCert` is set, pass-through when it is not.

### Added

- The checks the two framework halves share are exported, so an adapter runs the
  same code the net/http middleware runs rather than a second copy of it:
  `AuthenticateMTLS`, `NewCertAllowLists`, `CertAllowLists`,
  `CertificateAbsent`, `ConstantTimeEqual`, `HMACConfig.ExpectedSignature`,
  `HMACConfig.ServiceAllowed`, `ParseTimestamp`, `IsTimestampValid`,
  `ReplayRetention`, `TrustedProxyConfig.ClientIPFromForwarded`,
  `JoinForwarded`, `LastHeaderValue`, `HeaderOrDefault`. All additive.
- `HMACConfig.WithDefaults`, `HMACConfig.ResolveSecret` and
  `HMACConfig.CheckTimestamp`, so the Fiber and net/http halves apply one
  implementation of the header defaults, the secret/key-ID resolution and the
  timestamp window rather than a copy each.
- Doc comments on every exported `fiberadapter` function, which had none, and a
  package comment for `fiberadapter`.
- This changelog, a security policy, a Dependabot configuration, and a release
  workflow that refuses a tag whose major version does not match the module
  path.

### Internal

- Brought the four functions Go Report Card flagged for cyclomatic complexity
  under gocyclo's threshold of 15, by extraction only — no statement's behaviour
  changed, and the test suite (99.8% of statements) passes unaltered:

  | Function | Before | After |
  |---|---|---|
  | `fiberadapter.CombinedAuth` | 30 | 11 |
  | `HMACAuthStd` | 27 | 14 |
  | `fiberadapter.HMACAuth` | 27 | 13 |
  | `fiberadapter.RequestLogging` | 20 | 11 |

  `CombinedAuth` now reads as the sequence its documentation describes, one
  `tryXxx` per scheme. The two HMAC middlewares share the three new
  `HMACConfig` methods above, which removes three duplicated blocks. No
  function in the module exceeds 15.

### Documentation

- Repaired thirteen doc comments the Fiber extraction stranded. Deleting each
  Fiber function left its comment attached to the next declaration, so the
  net/http surface documented itself with the text of functions that no longer
  exist: `MTLSAuthStd` showed "MTLSAuth creates a Fiber middleware …",
  `JoinForwarded` showed "GetClientIPFiber extracts …", and `HeaderOrDefault`
  had accumulated seven stranded lines. Three dangling end-of-file comments
  removed.
- The root package had two competing `// Package middleware` comments, in
  `clientip.go` and `ipallowlist.go`. Both are replaced by a single `doc.go`.

### Tests

- `fiberadapter` reaches 100% statement coverage, the root package 99.7%,
  the module 99.8% (from 91.9% / 97.7% / 95.6%).
- `MTLSAuth`'s verification path had no test because none was reachable:
  `app.Test` serves over a plain in-memory connection, so the TLS connection
  state is always nil. Serving the app on a listener whose connections satisfy
  fasthttp's TLS interface supplies a controllable `tls.ConnectionState` with no
  certificates and no handshake — the Fiber counterpart of the net/http tests'
  `req.TLS = &tls.ConnectionState{...}`.

## [2.2.0] — 2026-09-12

### Fixed (three of these reject requests that previously authenticated)

- mTLS now requires a TLS-verified certificate. `MTLSAuth` and `CombinedAuth`
  accepted any certificate the peer *sent*, because `PeerCertificates` is
  populated regardless of verification. A non-empty `VerifiedChains` is now
  required.
- `CombinedAuth` enforces the mTLS allow-lists. Its mTLS branch tested only
  `len(PeerCertificates) > 0`, so `AllowedCNs`, `AllowedOUs`, `AllowedDNSSANs`
  and `CertValidator` were never consulted there.
- An HMAC `service` containing the `:` delimiter is rejected, because the legacy
  signed message `timestamp:service:body` is not injective. Opt out with
  `AllowDelimitersInService`.
- `X-Forwarded-For` is read from the right and every header line is joined;
  `X-Real-IP` no longer wins. Taking the leftmost entry is spoofable by design.
- `TrustedProxyConfig` parses its lists lazily, so a config built as a struct
  literal no longer falls through to trusting every private address.
- IPv6 unique local addresses (`fc00::/7`) count as private.
- The rate-limit window rolls over for active clients instead of requiring a
  full window of silence.
- `X-XSS-Protection` defaults to `"0"`; the header is deprecated.
- Secret comparison no longer leaks length through timing.

### Added

- `ReplayGuard` and `NewMemoryReplayGuard` for HMAC replay protection.
- `ComputeHMACBound`, `SignatureInput` and `RequestSignatureFunc`, for
  signatures that cover the method, path and query.
- `HMACConfig.AllowDelimitersInService`, `ErrMTLSCertificateUnverified`.

## [2.1.0] — 2026-08-27

- Raised the Go requirement to 1.27.0.

## [2.0.0] — 2026-08-26

First release of the `/v2` module path. Tagged at the same commit as v1.3.0;
see that entry for the contents.

> Note: because that commit already declares the `/v2` module path, the v1.3.0
> tag is not fetchable — a module path must carry the major version suffix
> matching the tag. Use v2.0.0.

## [1.3.0] — 2026-08-26

- Migrated the Fiber integration to Fiber v3 (breaking).
- Added a Go Report Card badge and workflow.
- Dependency and Go toolchain updates.

## [1.2.0] — 2026-03-06

- CI updates and dependency upgrades.

## [1.1.0] — 2026-01-27

- Added the IP allowlist middleware.

## [1.0.0] — 2026-01-25

- Initial release: API key, HMAC and mTLS authentication, rate limiting,
  security headers, request logging, compression and body limiting, for both
  Fiber and net/http.

[Unreleased]: https://github.com/soulteary/middleware-kit/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/soulteary/middleware-kit/compare/v2.2.0...v3.0.0
[2.2.0]: https://github.com/soulteary/middleware-kit/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/soulteary/middleware-kit/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/soulteary/middleware-kit/compare/v1.2.0...v2.0.0
[1.3.0]: https://github.com/soulteary/middleware-kit/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/soulteary/middleware-kit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/soulteary/middleware-kit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/soulteary/middleware-kit/releases/tag/v1.0.0
