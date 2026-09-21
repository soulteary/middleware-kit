package middleware

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetHeaderOrDefault(t *testing.T) {
	t.Run("returns header when not empty", func(t *testing.T) {
		result := HeaderOrDefault("X-Custom-Header", "X-Default")
		assert.Equal(t, "X-Custom-Header", result)
	})

	t.Run("returns default when header is empty", func(t *testing.T) {
		result := HeaderOrDefault("", "X-Default")
		assert.Equal(t, "X-Default", result)
	})
}
