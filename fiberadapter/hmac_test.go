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

func TestHMACAuth_Fiber(t *testing.T) {
	secret := "test-secret"

	t.Run("valid HMAC signature", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: secret,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		service := "test-service"
		signature := middleware.ComputeHMAC(timestamp, service, body, secret)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", service)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("invalid signature", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: secret,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", "invalid-signature")
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing signature", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: secret,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("missing timestamp", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: secret,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("expired timestamp", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret:       secret,
			MaxTimeDrift: 5 * time.Minute,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		// Use timestamp 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", body, secret)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: secret,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", "not-a-number")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("key provider with valid key ID", func(t *testing.T) {
		keys := map[string]string{
			"key1": "secret1",
			"key2": "secret2",
		}

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			KeyProvider: func(keyID string) string {
				return keys[keyID]
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", body, "secret1")

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		req.Header.Set("X-Key-Id", "key1")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	t.Run("key provider with invalid key ID", func(t *testing.T) {
		keys := map[string]string{
			"key1": "secret1",
		}

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			KeyProvider: func(keyID string) string {
				return keys[keyID]
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Key-Id", "unknown-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("allow empty secret", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret:           "",
			AllowEmptySecret: true,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
}

func TestHMACAuth_FiberWithLogger(t *testing.T) {
	t.Run("success with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: "test-secret",
			Logger: &logger,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", body, "test-secret")

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Contains(t, buf.String(), "HMAC authentication successful")
	})

	t.Run("invalid signature with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret:             "test-secret",
			Logger:             &logger,
			TrustedProxyConfig: middleware.DefaultTrustedProxyConfig(),
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"test": "data"}`))
		req.Header.Set("X-Signature", "invalid")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "HMAC authentication failed")
	})

	t.Run("allow empty secret with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret:           "",
			AllowEmptySecret: true,
			Logger:           &logger,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Contains(t, buf.String(), "HMAC authentication disabled")
	})

	t.Run("custom error handler", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: "test-secret",
			ErrorHandler: func(c fiber.Ctx, err error) error {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "custom"})
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "invalid")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})

	t.Run("success handler called", func(t *testing.T) {
		successCalled := false

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: "test-secret",
			SuccessHandler: func(c fiber.Ctx) {
				successCalled = true
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", body, "test-secret")

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.True(t, successCalled)
	})

	t.Run("reject when no secret and AllowEmptySecret is false", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret:           "",
			AllowEmptySecret: false,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("expired timestamp with logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret:       "test-secret",
			MaxTimeDrift: 60 * time.Second,
			Logger:       &logger,
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		// 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", "", "test-secret")

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "timestamp expired")
	})

	t.Run("success with SuccessHandler", func(t *testing.T) {
		successCalled := false

		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: "test-secret",
			SuccessHandler: func(c fiber.Ctx) {
				successCalled = true
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := middleware.ComputeHMAC(timestamp, "test-service", "", "test-secret")

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.True(t, successCalled)
	})

	t.Run("KeyProvider returns empty secret for valid keyID", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			KeyProvider: func(keyID string) string {
				return "" // Always return empty
			},
		}))
		app.Post("/", func(c fiber.Ctx) error {
			return c.SendString("OK")
		})

		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("X-Signature", "some-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Key-Id", "valid-key")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	})
}

// TestHMACAuth_Fiber_UncoveredBranches covers three branches the suite above
// never reaches: a timestamp in the future, the reserved-character check on the
// service header, and the logging inside the replay rejection.
func TestHMACAuth_Fiber_UncoveredBranches(t *testing.T) {
	const secret = "test-secret"

	newApp := func(cfg HMACConfig) *fiber.App {
		app := fiber.New()
		app.Use(HMACAuth(cfg))
		app.Post("/x", func(c fiber.Ctx) error { return c.SendString("OK") })
		return app
	}

	signed := func(ts, service, body string) *http.Request {
		req := httptest.NewRequest("POST", "/x", bytes.NewBufferString(body))
		req.Header.Set("X-Signature", middleware.ComputeHMAC(ts, service, body, secret))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", service)
		return req
	}

	t.Run("a timestamp far in the future is expired too", func(t *testing.T) {
		// The drift is taken as an absolute value; without this case only the
		// past-timestamp side of that was exercised.
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
		app := newApp(HMACConfig{HMACConfig: middleware.HMACConfig{
			Secret:       secret,
			MaxTimeDrift: time.Minute,
			Logger:       &logger,
		}})

		resp, err := app.Test(signed(future, "svc", "{}"))
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "timestamp expired")
	})

	t.Run("a service carrying the legacy delimiter is rejected and logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		app := newApp(HMACConfig{HMACConfig: middleware.HMACConfig{Secret: secret, Logger: &logger}})

		// ComputeHMAC signs "timestamp:service:body", so ("a", "b:{}") and
		// ("a:b", "{}") sign identically -- which is why ':' is refused.
		resp, err := app.Test(signed(ts, "svc:extra", "{}"))
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, buf.String(), "service contains a reserved character")
	})

	t.Run("a replayed signature is rejected and logged", func(t *testing.T) {
		var buf bytes.Buffer
		logger := zerolog.New(&buf)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		app := newApp(HMACConfig{HMACConfig: middleware.HMACConfig{
			Secret:      secret,
			Logger:      &logger,
			ReplayGuard: middleware.NewMemoryReplayGuard(),
		}})

		first, err := app.Test(signed(ts, "svc", "{}"))
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, first.StatusCode)

		second, err := app.Test(signed(ts, "svc", "{}"))
		assert.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, second.StatusCode)
		assert.Contains(t, buf.String(), "signature replayed")
	})
}
