package middleware

import (
	"time"
)

// Copied alongside the Fiber tests when they moved to fiberadapter/: both
// packages need this double and a test helper cannot be shared across them.
// recordingGuard reports the ttl it was handed.
type recordingGuard struct {
	onSeen func(time.Duration)
	seen   map[string]bool
}
