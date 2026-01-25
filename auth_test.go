package middleware

import (
	"bytes"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestCombinedAuth(t *testing.T) {
	t.Run("no auth configured with AllowNoAuth=true", func(t *testing.T) {
		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			AllowNoAuth: true,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
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
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			HMACConfig: &HMACConfig{
				Secret: secret,
			},
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		// Use empty body since we're passing nil to the request
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", "", secret)

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
			HMACConfig: &HMACConfig{
				Secret: "secret",
			},
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
			ErrorHandler: func(c *fiber.Ctx, err error) error {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"custom": "error",
				})
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
			Logger: &logger,
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("HMAC with logger and TrustedProxyConfig", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)
		secret := "test-secret"

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			HMACConfig: &HMACConfig{
				Secret: secret,
			},
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", "", secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("API key with TrustedProxyConfig", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(CombinedAuth(AuthConfig{
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
			Logger:             &logger,
			TrustedProxyConfig: DefaultTrustedProxyConfig(),
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
				Secret: secret,
			})
			return c.SendString("OK")
		})

		// Use empty body since we're passing nil to the request
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", "", secret)

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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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
		signature := ComputeHMAC(timestamp, "test-service", body, secret)

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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
				Secret:       secret,
				MaxTimeDrift: 60 * time.Second,
			})
			return c.SendString("OK")
		})

		// 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := ComputeHMAC(timestamp, "", "", secret)

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		_, _ = app.Test(req)
		assert.False(t, result)
	})

	t.Run("invalid signature", func(t *testing.T) {
		app := fiber.New()
		var result bool
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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

func TestGetHeaderOrDefault(t *testing.T) {
	t.Run("returns header when not empty", func(t *testing.T) {
		result := getHeaderOrDefault("X-Custom-Header", "X-Default")
		assert.Equal(t, "X-Custom-Header", result)
	})

	t.Run("returns default when header is empty", func(t *testing.T) {
		result := getHeaderOrDefault("", "X-Default")
		assert.Equal(t, "X-Default", result)
	})
}

func TestHandleCombinedAuthError(t *testing.T) {
	t.Run("default error response", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c *fiber.Ctx) error {
			return handleCombinedAuthError(c, AuthConfig{}, ErrUnauthorized)
		})

		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Get("/", func(c *fiber.Ctx) error {
			return handleCombinedAuthError(c, AuthConfig{
				ErrorHandler: func(c *fiber.Ctx, err error) error {
					return c.Status(fiber.StatusForbidden).SendString("Custom error")
				},
			}, ErrUnauthorized)
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
		app.Get("/", func(c *fiber.Ctx) error {
			result = validateAPIKey(c, APIKeyConfig{
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
			MTLSConfig: &MTLSConfig{
				RequireCert: true,
			},
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			HMACConfig: &HMACConfig{
				KeyProvider: func(keyID string) string {
					if keyID == "key1" {
						return "secret1"
					}
					return ""
				},
			},
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", "", "secret1")

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
			return "custom-" + ComputeHMAC(timestamp, service, body, secret)
		}

		app := fiber.New()
		var result bool
		app.Post("/", func(c *fiber.Ctx) error {
			result = validateHMAC(c, HMACConfig{
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
			HMACConfig: &HMACConfig{
				Secret: "test-secret",
			},
			APIKeyConfig: &APIKeyConfig{
				APIKey: "test-api-key",
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			HMACConfig: &HMACConfig{
				Secret: "test-secret",
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
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
			MTLSConfig: &MTLSConfig{
				RequireCert: false,
			},
		}))
		app.Get("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		// No TLS, should fail because no API key or HMAC configured
		req := httptest.NewRequest("GET", "/", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}
