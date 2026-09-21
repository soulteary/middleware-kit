# Security Policy

This is an authentication and request-filtering library, so a bug here is
usually a bug in somebody's access control. Reports are welcome and taken
seriously.

## Reporting a vulnerability

Please report privately, not in a public issue.

Use GitHub's private vulnerability reporting on this repository:
**[Security → Advisories → Report a vulnerability](https://github.com/soulteary/middleware-kit/security/advisories/new)**.
That opens a private thread visible only to you and the maintainers.

Useful things to include, as far as you have them:

- the affected version or commit, and which middleware is involved;
- the configuration that exhibits it — a `Config` literal is ideal;
- what a request has to look like to exploit it, and what should have happened
  instead;
- whether it is reachable with the documented defaults, or only with a
  particular option set.

A failing test against this repository is the most useful report of all: the
test suite is internal to each package, so a reproduction usually fits in one
`func Test...`.

## Supported versions

| Version | Status |
|---|---|
| v3.x (`github.com/soulteary/middleware-kit/v3`) | Supported — fixes land in the latest v3 minor |
| v2.x (`.../v2`) | See the note below |
| v1.x, v0.x | Not supported |

Each major version is a separate Go import path, so a fix on one line never
reaches another automatically.

### Known issue in v2.0.0 – v2.2.0

All three v2 releases target Fiber v3 and contain a client-certificate check
that never executes. `MTLSAuth` and `CombinedAuth` gate it on
`c.Protocol() == "https"`, but Fiber v3's `Protocol()` returns the HTTP version
(`"HTTP/1.1"`), so the condition is never satisfied:

- with `RequireCert: false`, every request is admitted without any certificate
  verification — `AllowedCNs`, `AllowedOUs`, `AllowedDNSSANs` and
  `CertValidator` are never consulted, so a certificate that fails the
  allow-list is accepted;
- with `RequireCert: true` (the default), every request is rejected, including
  one presenting a valid allow-listed certificate;
- `CombinedAuth` never attempts its mTLS scheme at all.

This is fixed in **v3.0.0**. If you rely on Fiber mTLS, treat an upgrade as
urgent, and read "Upgrade Notes (v3.0.0)" in the README first — the fix changes
which requests are accepted.

The net/http (`MTLSAuthStd`) path is not affected: it reads `r.TLS` directly and
has always performed the check.

## Scope

In scope: anything that makes one of these middlewares admit a request it should
refuse, refuse one it should admit, leak a secret, or be bypassed by
attacker-controlled input — headers, request bodies, certificates, forwarded
addresses.

Out of scope: vulnerabilities in the dependencies themselves (report those
upstream; `govulncheck` runs in CI here), and configurations the documentation
explicitly warns against, such as `AllowEmptySecret` or `AllowNoAuth` in
production.
