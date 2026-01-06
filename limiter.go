// Package ratelimiter provides a modular rate limiting library for Go.
// It supports multiple algorithms (Token Bucket, Sliding Window) and
// can be used as HTTP middleware with per-endpoint configuration.
package ratelimiter

import (
	"time"
)

// Limiter defines the rate limiting interface.
// Implementations must be safe for concurrent use.
type Limiter interface {
	// Allow checks if a single request is allowed for the given key.
	// Returns true if the request is allowed, false otherwise.
	Allow(key string) (bool, error)

	// AllowN checks if n requests are allowed for the given key.
	// Returns true if the requests are allowed, false otherwise.
	AllowN(key string, n int) (bool, error)

	// Reset clears the rate limit state for the given key.
	Reset(key string) error
}

// Config holds the rate limiter configuration.
type Config struct {
	// Rate is the number of requests allowed per window.
	Rate int

	// Window is the time window for rate limiting.
	Window time.Duration

	// BurstSize is the maximum burst size (used by Token Bucket algorithm).
	// If not set, defaults to Rate.
	BurstSize int
}

// DefaultConfig returns a sensible default configuration.
// 100 requests per minute with burst size of 100.
func DefaultConfig() Config {
	return Config{
		Rate:      100,
		Window:    time.Minute,
		BurstSize: 100,
	}
}

// Validate checks if the configuration is valid.
func (c Config) Validate() error {
	if c.Rate <= 0 {
		return ErrInvalidRate
	}
	if c.Window <= 0 {
		return ErrInvalidWindow
	}
	if c.BurstSize < 0 {
		return ErrInvalidBurstSize
	}
	return nil
}

// WithBurstSize returns a copy of the config with the specified burst size.
func (c Config) WithBurstSize(size int) Config {
	c.BurstSize = size
	return c
}

// Result contains detailed information about a rate limit check.
type Result struct {
	// Allowed indicates if the request was allowed.
	Allowed bool

	// Remaining is the number of requests remaining in the current window.
	Remaining int

	// ResetAt is when the rate limit will reset.
	ResetAt time.Time

	// RetryAfter is the duration to wait before retrying (if not allowed).
	RetryAfter time.Duration
}
