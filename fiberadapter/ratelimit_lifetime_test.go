package fiberadapter

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	middleware "github.com/soulteary/middleware-kit/v3"
	"github.com/valyala/fasthttp"
)

func TestRateLimitOwnsBorrowedHeaderKeys(t *testing.T) {
	limiter := middleware.NewRateLimiter(middleware.RateLimiterConfig{Rate: 2, Window: time.Minute})
	defer limiter.Stop()
	app := fiber.New()
	app.Use(RateLimit(RateLimitConfig{Limiter: limiter, KeyFunc: func(c fiber.Ctx) string { return c.Get("X-User-ID") }}))
	app.Get("/", func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	handler := app.Handler()
	// Reuse one request's header storage, as fasthttp does across requests.
	// Mutate the same backing buffer explicitly so the regression does not
	// depend on pool scheduling or the runtime map hash seed.
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.Header.Set("X-User-ID", "user0")
	headerValue := ctx.Request.Header.Peek("X-User-ID")
	for i, tc := range []struct {
		user   string
		status int
	}{
		{"user1", 200}, {"user1", 200}, {"user1", 429},
		{"user2", 200}, {"user2", 200}, {"user2", 429},
		{"user1", 429},
	} {
		ctx.Response.Reset()
		copy(headerValue, tc.user)
		handler(ctx)
		if got := ctx.Response.StatusCode(); got != tc.status {
			t.Fatalf("request %d (%s): got %d, want %d", i+1, tc.user, got, tc.status)
		}
	}
	// A stable caller sharing this limiter must still see user2 at its quota,
	// even though the Fiber request buffer now contains user1.
	if limiter.Allow("user2") {
		t.Fatal("reusing the request header lost user2 rate-limit history")
	}

}
