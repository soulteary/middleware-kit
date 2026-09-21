package middleware

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultMTLSConfig(t *testing.T) {
	cfg := DefaultMTLSConfig()
	assert.True(t, cfg.RequireCert)
	assert.Empty(t, cfg.AllowedCNs)
	assert.Empty(t, cfg.AllowedOUs)
	assert.Empty(t, cfg.AllowedDNSSANs)
}

func TestMTLSAuthStd_NoTLS(t *testing.T) {
	t.Run("no TLS with RequireCert=true", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		// No TLS connection
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("no TLS with RequireCert=false", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: false,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestMTLSAuthStd_NoCertificate(t *testing.T) {
	t.Run("TLS but no client certificate with RequireCert=true", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{}, // Empty
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("TLS but no client certificate with RequireCert=false", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: false,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestMTLSAuthStd_WithCertificate(t *testing.T) {
	// Create a mock certificate
	mockCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test-client",
			OrganizationalUnit: []string{"Engineering", "DevOps"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		DNSNames: []string{"client.example.com", "client2.example.com"},
	}

	t.Run("valid certificate with no restrictions", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("valid CN in allowed list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			AllowedCNs:  []string{"test-client", "other-client"},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("CN not in allowed list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			AllowedCNs:  []string{"other-client"},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("valid OU in allowed list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			AllowedOUs:  []string{"Engineering"},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("OU not in allowed list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			AllowedOUs:  []string{"Sales"},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("valid DNS SAN in allowed list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert:    true,
			AllowedDNSSANs: []string{"client.example.com"},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("DNS SAN not in allowed list", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert:    true,
			AllowedDNSSANs: []string{"other.example.com"},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("custom validator success", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			CertValidator: func(cert *x509.Certificate) error {
				if cert.Subject.CommonName == "test-client" {
					return nil
				}
				return errors.New("invalid client")
			},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("custom validator failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			CertValidator: func(cert *x509.Certificate) error {
				return errors.New("custom validation failed")
			},
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestMTLSAuthStd_WithLogger(t *testing.T) {
	mockCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "test-client",
			OrganizationalUnit: []string{"Engineering"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		DNSNames: []string{"client.example.com"},
	}

	t.Run("logs no TLS connection", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			Logger:      &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "not a TLS connection")
	})

	t.Run("logs no client certificate", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert:        true,
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		})(handler)

		req := httptest.NewRequest("GET", "/test", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		}
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "no client certificate")
	})

	t.Run("logs CN not allowed", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			AllowedCNs:  []string{"other-client"},
			Logger:      &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "CN not allowed")
	})

	t.Run("logs OU not allowed", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			AllowedOUs:  []string{"Sales"},
			Logger:      &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "OU not allowed")
	})

	t.Run("logs DNS SAN not allowed", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert:    true,
			AllowedDNSSANs: []string{"other.example.com"},
			Logger:         &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "DNS SAN not allowed")
	})

	t.Run("logs custom validation failed", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			CertValidator: func(cert *x509.Certificate) error {
				return errors.New("custom validation failed")
			},
			Logger: &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Contains(t, buf.String(), "custom validation failed")
	})

	t.Run("logs successful authentication", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := MTLSAuthStd(MTLSConfig{
			RequireCert: true,
			Logger:      &logger,
		})(handler)

		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{mockCert},
			VerifiedChains:   [][]*x509.Certificate{{mockCert}},
		}
		rr := httptest.NewRecorder()
		middleware.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Contains(t, buf.String(), "mTLS authentication successful")
	})
}
