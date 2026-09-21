package fiberadapter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	middleware "github.com/soulteary/middleware-kit/v3"
	"github.com/stretchr/testify/assert"
)

func TestCombinedAuth(t *testing.T) {
	t.Run("no auth configured with AllowNoAuth=true", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			AllowNoAuth: true,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("no auth configured with AllowNoAuth=false", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			AllowNoAuth: false,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("API key auth success", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("API key auth failure", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("HMAC auth success", func(t *testing.T) {
		secret := "test-secret"
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &middleware.HMACConfig{
				Secret: secret,
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// Use empty body since we're passing nil to the request
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", "", secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("HMAC auth failure falls back to API key", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &middleware.HMACConfig{
				Secret: "secret",
			},
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Signature", "invalid")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-API-Key", "test-api-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
			ErrorHandler: func(c fiber.Ctx, err error) error {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"custom": "error",
				})
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})

	t.Run("API key auth with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
			Logger: &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("no auth with AllowNoAuth and logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			AllowNoAuth: true,
			Logger:      &logger,
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("HMAC with logger and middleware.TrustedProxyConfig", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		secret := "test-secret"

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &middleware.HMACConfig{
				Secret: secret,
			},
			Logger:             &logger,
			TrustedProxyConfig: middleware.DefaultTrustedProxyConfig(),
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", "", secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("API key with middleware.TrustedProxyConfig", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
			Logger:             &logger,
			TrustedProxyConfig: middleware.DefaultTrustedProxyConfig(),
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestValidateAPIKey(t *testing.T) {
	t.Run("valid API key in header", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey: "test-key",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-key")
		_, _ = app.Test(req)
		assert.True(t, result)
	})

	t.Run("valid API key in Authorization header", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey:     "test-key",
				AuthScheme: "Bearer",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer test-key")
		_, _ = app.Test(req)
		assert.True(t, result)
	})

	t.Run("valid API key in query parameter", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey:         "test-key",
				QueryParamName: "api_key",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/?api_key=test-key", nil)
		_, _ = app.Test(req)
		assert.True(t, result)
	})

	t.Run("missing API key", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey: "test-key",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("invalid API key", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey: "test-key",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "wrong-key")
		_, _ = app.Test(req)
		assert.False(t, result)
	})
}

func TestValidateHMAC(t *testing.T) {
	secret := "test-secret"

	t.Run("valid HMAC", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret: secret,
			})
			return c.SendString("OK")
		})

		// Use empty body since we're passing nil to the request
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", "", secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		_, _ = app.Test(req)
		assert.True(t, result)
	})

	t.Run("missing signature", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret: secret,
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("missing timestamp", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret: secret,
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("no secret configured", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret: "",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("with KeyProvider", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				KeyProvider: func(keyID string) string {
					if keyID == "key1" {
						return secret
					}
					return ""
				},
			})
			return c.SendString("OK")
		})

		body := ""
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", body, secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Key-Id", "key1")
		req.Header.Set("X-Service", "test-service")
		_, _ = app.Test(req)
		assert.True(t, result)
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret: secret,
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", "not-a-number")
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("expired timestamp", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret:       secret,
				MaxTimeDrift: 60 * time.Second,
			})
			return c.SendString("OK")
		})

		// 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := middleware.ComputeHMAC(timestamp, "", "", secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("invalid signature", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret: secret,
			})
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "wrong-signature")
		req.Header.Set("X-Timestamp", timestamp)
		_, _ = app.Test(req)
		assert.False(t, result)
	})
}

func TestHandleCombinedAuthError(t *testing.T) {
	t.Run("default error response", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			return handleCombinedAuthError(c, AuthConfig{}, middleware.ErrUnauthorized)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c fiber.Ctx) error {
			return handleCombinedAuthError(c, AuthConfig{
				ErrorHandler: func(c fiber.Ctx, err error) error {
					return c.Status(fiber.StatusForbidden).SendString("Custom error")
				},
			}, middleware.ErrUnauthorized)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})
}

func TestValidateAPIKey_AuthScheme(t *testing.T) {
	t.Run("short Authorization header", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey:     "test-key",
				AuthScheme: "Bearer",
			})
			return c.SendString("OK")
		})

		// Authorization header shorter than "Bearer "
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bear")
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("Authorization header with wrong scheme", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Get("/", func(c fiber.Ctx) error {
			result = validateAPIKey(c, middleware.APIKeyConfig{
				APIKey:     "test-key",
				AuthScheme: "Bearer",
			})
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic test-key")
		_, _ = app.Test(req)
		assert.False(t, result)
	})
}

func TestCombinedAuth_MTLSConfig(t *testing.T) {
	t.Run("mTLS config exists but not https", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			MTLSConfig: &middleware.MTLSConfig{
				RequireCert: true,
			},
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// HTTP request with API key should succeed
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("HMAC with KeyProvider", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &middleware.HMACConfig{
				KeyProvider: func(keyID string) string {
					if keyID == "key1" {
						return "secret1"
					}
					return ""
				},
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", "", "secret1")

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Key-Id", "key1")
		req.Header.Set("X-Service", "test-service")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestValidateHMAC_CustomSignatureFunc(t *testing.T) {
	t.Run("custom signature function", func(t *testing.T) {
		customSigner := func(timestamp, service, body, secret string) string {
			return "custom-" + middleware.ComputeHMAC(timestamp, service, body, secret)
		}

		app := fiber.New()
		var result bool
		app.Post("/", func(c fiber.Ctx) error {
			result = validateHMAC(c, middleware.HMACConfig{
				Secret:        "test-secret",
				SignatureFunc: customSigner,
			})
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := customSigner(timestamp, "test-service", "", "test-secret")

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		_, _ = app.Test(req)
		assert.True(t, result)
	})
}

func TestCombinedAuth_HMACWithNoHeaders(t *testing.T) {
	t.Run("HMAC config with no signature or timestamp headers", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &middleware.HMACConfig{
				Secret: "test-secret",
			},
			APIKeyConfig: &middleware.APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// No HMAC headers, falls through to API key
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("HMAC only config with missing headers", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &middleware.HMACConfig{
				Secret: "test-secret",
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// No HMAC headers, should fail
		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

func TestCombinedAuth_MTLSOnly(t *testing.T) {
	t.Run("mTLS only config with RequireCert false", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			MTLSConfig: &middleware.MTLSConfig{
				RequireCert: false,
			},
		}))
		app.Get("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// No TLS, should fail because no API key or HMAC configured
		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestCombinedAuth_MTLSScheme covers the mTLS scheme inside CombinedAuth, which
// no test could reach while the scheme was gated on c.Protocol() == "https".
func TestCombinedAuth_MTLSScheme(t *testing.T) {
	t.Run("a verified certificate authenticates the request", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf).Level(zerolog.DebugLevel)

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{AuthConfig: middleware.AuthConfig{
			MTLSConfig: &middleware.MTLSConfig{RequireCert: true, AllowedCNs: []string{"svc-a"}},
			Logger:     &logger,
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("svc-a", nil, nil)), "/")
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Contains(t, buf.String(), "Request authenticated via mTLS")
	})

	t.Run("a rejected certificate falls through to the API key", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf).Level(zerolog.DebugLevel)

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{AuthConfig: middleware.AuthConfig{
			MTLSConfig:   &middleware.MTLSConfig{RequireCert: true, AllowedCNs: []string{"svc-a"}},
			APIKeyConfig: &middleware.APIKeyConfig{APIKey: "k3y"},
			Logger:       &logger,
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		client, base := serveApp(t, app, ptrTLSState(verifiedState(testCert("intruder", nil, nil))))
		req, err := http.NewRequest(http.MethodGet, base+"/", nil)
		assert.NoError(t, err)
		req.Header.Set("X-API-Key", "k3y")
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Contains(t, buf.String(), "mTLS authentication did not apply")
		assert.Contains(t, buf.String(), "Request authenticated via API Key")
	})

	t.Run("mTLS-only config rejects a certificate outside the allow-list", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{AuthConfig: middleware.AuthConfig{
			MTLSConfig: &middleware.MTLSConfig{RequireCert: true, AllowedCNs: []string{"svc-a"}},
		}}))
		app.Get("/", func(c fiber.Ctx) error { return c.SendString("OK") })

		resp := serveOverTLSState(t, app, verifiedState(testCert("intruder", nil, nil)), "/")
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestValidateHMAC_RejectionBranches covers the two `return false` branches of
// validateHMAC that the combined-auth tests never reach.
func TestValidateHMAC_RejectionBranches(t *testing.T) {
	const secret = "s3cr3t"

	run := func(cfg middleware.HMACConfig, service string, guard middleware.ReplayGuard, times int) []int {
		cfg.Secret = secret
		cfg.ReplayGuard = guard

		app := fiber.New()
		app.Post("/x", func(c fiber.Ctx) error {
			if !validateHMAC(c, cfg) {
				return c.SendStatus(http.StatusUnauthorized)
			}
			return c.SendStatus(http.StatusOK)
		})

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		body := "{}"
		codes := make([]int, 0, times)
		for i := 0; i < times; i++ {
			req := httptest.NewRequest("POST", "/x", bytes.NewBufferString(body))
			req.Header.Set("X-Signature", middleware.ComputeHMAC(ts, service, body, secret))
			req.Header.Set("X-Timestamp", ts)
			req.Header.Set("X-Service", service)
			resp, err := app.Test(req)
			assert.NoError(t, err)
			codes = append(codes, resp.StatusCode)
		}
		return codes
	}

	t.Run("service carrying the legacy delimiter is refused", func(t *testing.T) {
		assert.Equal(t, []int{http.StatusUnauthorized}, run(middleware.HMACConfig{}, "svc:extra", nil, 1))
	})

	t.Run("a replayed signature is refused on the second request", func(t *testing.T) {
		codes := run(middleware.HMACConfig{}, "svc", middleware.NewMemoryReplayGuard(), 2)
		assert.Equal(t, []int{http.StatusOK, http.StatusUnauthorized}, codes)
	})
}
