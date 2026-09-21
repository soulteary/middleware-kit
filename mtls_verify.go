package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// CertAllowLists holds the CN/OU/SAN allow lists of an MTLSConfig in lookup
// form, so the per-request path does not rebuild them.
//
// Exported so a framework adapter builds them once, as the net/http middleware
// does.
type CertAllowLists struct {
	cns  map[string]bool
	ous  map[string]bool
	sans map[string]bool
}

// NewCertAllowLists builds the lookup sets AuthenticateMTLS matches against.
//
// Exported for framework adapters.
func NewCertAllowLists(cfg MTLSConfig) CertAllowLists {
	l := CertAllowLists{
		cns:  make(map[string]bool, len(cfg.AllowedCNs)),
		ous:  make(map[string]bool, len(cfg.AllowedOUs)),
		sans: make(map[string]bool, len(cfg.AllowedDNSSANs)),
	}
	for _, cn := range cfg.AllowedCNs {
		l.cns[cn] = true
	}
	for _, ou := range cfg.AllowedOUs {
		l.ous[ou] = true
	}
	for _, san := range cfg.AllowedDNSSANs {
		l.sans[san] = true
	}
	return l
}

// errNoClientCertificate marks the errors produced by the peer-certificate
// PRESENCE check, and only those.
type errNoClientCertificate struct{ error }

func (e errNoClientCertificate) Unwrap() error { return e.error }

// CertificateAbsent reports whether err says the client presented no
// certificate at all -- the one condition RequireCert=false is meant to wave
// through.
//
// Deliberately NOT errors.Is(err, ErrMTLSCertificateMissing). A CertValidator
// is caller-supplied code, and one that returns or wraps that exported
// sentinel made a certificate which explicitly FAILED validation read as an
// absent one, so the request was let through whenever RequireCert was false.
// This type is unexported, so only the presence check above can produce it.
func CertificateAbsent(err error) bool {
	var absent errNoClientCertificate
	return errors.As(err, &absent)
}

// verifiedPeerCertificate returns the leaf client certificate only when the TLS
// layer actually verified it against the server's ClientCAs.
//
// Checking len(PeerCertificates) > 0 is not enough: it only says the peer *sent*
// a certificate. With tls.RequestClientCert or tls.RequireAnyClientCert the
// server performs no verification at all, so a self-signed certificate is
// accepted -- and since its Subject is chosen by whoever generated it, an
// AllowedCNs allow-list checked against that Subject provides no protection
// either. VerifiedChains is non-empty only when a chain validated against
// ClientCAs, which is the property callers actually mean by "mTLS".
func verifiedPeerCertificate(state *tls.ConnectionState) (*x509.Certificate, error) {
	if state == nil {
		return nil, errNoClientCertificate{fmt.Errorf("%w: not a TLS connection", ErrMTLSCertificateMissing)}
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errNoClientCertificate{fmt.Errorf("%w: no client certificate", ErrMTLSCertificateMissing)}
	}
	if len(state.VerifiedChains) == 0 {
		return nil, ErrMTLSCertificateUnverified
	}
	return state.PeerCertificates[0], nil
}

// checkCertificate applies the configured Subject/SAN allow-lists and the
// custom validator to an already verified certificate.
func (l CertAllowLists) checkCertificate(cert *x509.Certificate, cfg MTLSConfig) error {
	if len(l.cns) > 0 && !l.cns[cert.Subject.CommonName] {
		return fmt.Errorf("%w: CN not allowed: %q", ErrMTLSCertificateInvalid, cert.Subject.CommonName)
	}

	if len(l.ous) > 0 {
		match := false
		for _, ou := range cert.Subject.OrganizationalUnit {
			if l.ous[ou] {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("%w: OU not allowed: %q", ErrMTLSCertificateInvalid, cert.Subject.OrganizationalUnit)
		}
	}

	if len(l.sans) > 0 {
		match := false
		for _, san := range cert.DNSNames {
			if l.sans[san] {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("%w: DNS SAN not allowed: %q", ErrMTLSCertificateInvalid, cert.DNSNames)
		}
	}

	if cfg.CertValidator != nil {
		if err := cfg.CertValidator(cert); err != nil {
			return fmt.Errorf("custom validation failed: %w", err)
		}
	}

	return nil
}

// AuthenticateMTLS runs the complete mTLS check for a connection state: the
// certificate must be verified by the TLS layer AND satisfy every restriction
// in cfg -- chain presence, then the CN, OU and DNS SAN allow lists, then
// CertValidator.
//
// This is the single entry point for every middleware that authenticates a
// client certificate, net/http and Fiber alike, so no combined middleware can
// accept a certificate that a dedicated one would reject. Two copies of a
// certificate check is how one framework ends up accepting what the other
// rejects; that is also why it is exported rather than reimplemented in the
// adapter.
func AuthenticateMTLS(state *tls.ConnectionState, cfg MTLSConfig, lists CertAllowLists) (*x509.Certificate, error) {
	cert, err := verifiedPeerCertificate(state)
	if err != nil {
		return nil, err
	}
	if err := lists.checkCertificate(cert, cfg); err != nil {
		return nil, err
	}
	return cert, nil
}
