package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestComputeHMAC(t *testing.T) {
	timestamp := "1234567890"
	service := "test-service"
	body := "test body"
	secret := "test-secret"

	sig1 := ComputeHMAC(timestamp, service, body, secret)
	sig2 := ComputeHMAC(timestamp, service, body, secret)

	// Same inputs should produce same signature
	assert.Equal(t, sig1, sig2)

	// Different inputs should produce different signatures
	sig3 := ComputeHMAC(timestamp+"1", service, body, secret)
	assert.NotEqual(t, sig1, sig3)

	sig4 := ComputeHMAC(timestamp, service, body, "different-secret")
	assert.NotEqual(t, sig1, sig4)
}

func TestHMACAuth_Fiber(t *testing.T) {
	secret := "test-secret"

	t.Run("valid HMAC signature", func(t *testing.T) {
		app := fiber.New()
		app.Use(HMACAuth(HMACConfig{
			Secret: secret,
		}))
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		service := "test-service"
		signature := ComputeHMAC(timestamp, service, body, secret)

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
		app.Post("/", func(c *fiber.Ctx) error {
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
		app.Post("/", func(c *fiber.Ctx) error {
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
		app.Post("/", func(c *fiber.Ctx) error {
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
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		// Use timestamp 10 minutes ago
		timestamp := strconv.FormatInt(time.Now().Unix()-600, 10)
		signature := ComputeHMAC(timestamp, "test-service", body, secret)

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
		app.Post("/", func(c *fiber.Ctx) error {
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
		app.Post("/", func(c *fiber.Ctx) error {
			return c.SendString("OK")
		})

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", body, "secret1")

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
		app.Post("/", func(c *fiber.Ctx) error {
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
		app.Post("/", func(c *fiber.Ctx) error {
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

func TestHMACAuthStd(t *testing.T) {
	secret := "test-secret"

	t.Run("valid HMAC signature", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		body := `{"test": "data"}`
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signature := ComputeHMAC(timestamp, "test-service", body, secret)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature", signature)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("invalid signature", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := HMACAuthStd(HMACConfig{
			Secret: secret,
		})(handler)

		req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"test": "data"}`))
		req.Header.Set("X-Signature", "invalid-signature")
		req.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Service", "test-service")
		rr := httptest.NewRecorder()

		middleware.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
