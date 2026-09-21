package fiberadapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
)

// The helpers below serve a Fiber app over a connection that fasthttp reports
// as TLS, with a tls.ConnectionState the test supplies.
//
// This is the Fiber counterpart of the net/http tests' `req.TLS = &tls.
// ConnectionState{...}`. Fiber's app.Test drives the handler over a plain
// in-memory connection, so c.RequestCtx().TLSConnectionState() is nil there and
// nothing past the certificate-presence check can be reached -- which is why
// MTLSAuth's verification path had no test of its own. fasthttp decides both
// RequestCtx.IsTLS and RequestCtx.TLSConnectionState by type-asserting the
// accepted net.Conn to `interface{ Handshake() error; ConnectionState() tls.
// ConnectionState }`, so a connection satisfying those two methods is all it
// takes; no certificates, no handshake, no real TLS.

// fakeTLSConn is a net.Conn that fasthttp accepts as a TLS connection.
type fakeTLSConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *fakeTLSConn) Handshake() error                     { return nil }
func (c *fakeTLSConn) ConnectionState() tls.ConnectionState { return c.state }

// fakeTLSListener hands every accepted connection to fasthttp as a fakeTLSConn.
type fakeTLSListener struct {
	net.Listener
	state tls.ConnectionState
}

func (l *fakeTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fakeTLSConn{Conn: c, state: l.state}, nil
}

// serveApp runs app on a loopback listener and returns a client and the base
// URL. state, when non-nil, is reported to fasthttp as the connection's TLS
// state. The app is shut down when the test finishes.
//
// A real listener is used rather than app.Test because two things cannot be
// reached through app.Test: a TLS connection state, and a request whose length
// is not known up front (Go's client sends those chunked, which is the only way
// fasthttp reports Content-Length as -1).
func serveApp(t *testing.T, app *fiber.App, state *tls.ConnectionState) (*http.Client, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var served net.Listener = ln
	if state != nil {
		served = &fakeTLSListener{Listener: ln, state: *state}
	}

	done := make(chan error, 1)
	go func() {
		done <- app.Listener(served, fiber.ListenConfig{DisableStartupMessage: true})
	}()
	t.Cleanup(func() {
		if err := app.Shutdown(); err != nil {
			t.Errorf("shutdown: %v", err)
		}
		<-done
	})

	addr := ln.Addr().String()
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			},
		},
		Timeout: 5 * time.Second,
	}
	return client, "http://" + addr
}

// serveOverTLSState runs app on a loopback listener whose connections carry
// state, and returns a GET against the given path.
func serveOverTLSState(t *testing.T, app *fiber.App, state tls.ConnectionState, path string) *http.Response {
	t.Helper()

	client, base := serveApp(t, app, &state)
	resp, err := client.Get(base + path)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// unsizedBody is an io.Reader the http client cannot measure, so the request
// goes out with Transfer-Encoding: chunked and no Content-Length.
type unsizedBody struct{ r io.Reader }

func (b unsizedBody) Read(p []byte) (int, error) { return b.r.Read(p) }

// postChunked sends body to path with no Content-Length, the shape that reaches
// a body-size check whose Content-Length branch cannot fire.
func postChunked(t *testing.T, app *fiber.App, path string, body []byte) *http.Response {
	t.Helper()

	client, base := serveApp(t, app, nil)
	req, err := http.NewRequest(http.MethodPost, base+path, unsizedBody{r: bytes.NewReader(body)})
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// verifiedState is a connection state carrying a client certificate the TLS
// layer verified: PeerCertificates AND VerifiedChains, which is what
// middleware.AuthenticateMTLS requires.
func verifiedState(cert *x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
}

// unverifiedState is a connection state where the peer sent a certificate the
// TLS layer did NOT verify -- what tls.RequireAnyClientCert produces, and what
// a self-signed certificate looks like.
func unverifiedState(cert *x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
	}
}

func testCert(cn string, ous, dnsNames []string) *x509.Certificate {
	return &x509.Certificate{
		Subject:  pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		Issuer:   pkix.Name{CommonName: "test-ca"},
		DNSNames: dnsNames,
	}
}

func ptrTLSState(state tls.ConnectionState) *tls.ConnectionState { return &state }
