package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v3"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCombinedAuthPassesTheNormalizedDrift(t *testing.T) {
	var gotTTL time.Duration
	guard := recordingGuard{onSeen: func(ttl time.Duration) { gotTTL = ttl }}

	cfg := middleware.HMACConfig{
		Secret:      "s3cr3t",
		ReplayGuard: &guard,
		// MaxTimeDrift deliberately left at its documented zero value.
	}

	app := fiber.New()
	app.Post("/x", func(c fiber.Ctx) error {
		if !validateHMAC(c, cfg) {
			return c.SendStatus(http.StatusUnauthorized)
		}
		return c.SendStatus(http.StatusOK)
	})

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := "{}"
	sig := middleware.ComputeHMAC(ts, "svc", body, "s3cr3t")

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Service", "svc")
	req.Header.Set("X-Signature", sig)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if gotTTL <= 0 {
		t.Errorf("ReplayGuard.Seen got ttl %s with a zero MaxTimeDrift; the entry expires immediately and no replay is prevented", gotTTL)
	}
}

// recordingGuard reports the ttl it was handed.
type recordingGuard struct {
	onSeen func(time.Duration)
	seen   map[string]bool
}

func TestFiberReplayGuardRunsAfterTheSignatureCheck(t *testing.T) {
	const secret = "s3cr3t"
	cfg := HMACConfig{
		HMACConfig: middleware.HMACConfig{
			Secret:       secret,
			MaxTimeDrift: time.Hour,
			ReplayGuard:  middleware.NewMemoryReplayGuard(),
		},
	}

	app := fiber.New()
	app.Post("/x", HMACAuth(cfg), func(c fiber.Ctx) error { return c.SendStatus(http.StatusOK) })

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := `{"amount":1}`
	sig := middleware.ComputeHMAC(ts, "svc", body, secret)

	send := func(sendBody string) int {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(sendBody))
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Service", "svc")
		req.Header.Set("X-Signature", sig)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}

	// Tampered body: rejected, and must NOT consume the signature.
	if got := send(`{"amount":9999}`); got == http.StatusOK {
		t.Fatal("a tampered body was accepted")
	}

	// The legitimate request still goes through.
	if got := send(body); got != http.StatusOK {
		t.Errorf("legitimate request = %d, want 200: the tampered attempt consumed its signature", got)
	}

	// A genuine replay is still refused.
	if got := send(body); got == http.StatusOK {
		t.Error("a replayed request was accepted")
	}
}

func TestCombinedAuthDefaultDriftIsFiveMinutes(t *testing.T) {
	const secret = "test-secret"

	app := fiber.New()
	app.Use(CombinedAuth(AuthConfig{
		// MaxTimeDrift deliberately left at its zero value.
		HMACConfig: &middleware.HMACConfig{Secret: secret},
	}))
	app.Post("/", func(c fiber.Ctx) error { return c.SendString("OK") })

	ts := strconv.FormatInt(time.Now().Add(-5*time.Second).Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", middleware.ComputeHMAC(ts, "", "body", secret))

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("a 5s-old timestamp got %d with the default drift; the default must be 5 minutes", resp.StatusCode)
	}
}

// Seen mirrors the root package's test double; a test helper cannot be shared
// across packages, so both copies exist.
func (g *recordingGuard) Seen(id string, ttl time.Duration) bool {
	if g.onSeen != nil {
		g.onSeen(ttl)
	}
	if g.seen == nil {
		g.seen = map[string]bool{}
	}
	was := g.seen[id]
	g.seen[id] = true
	return was
}
