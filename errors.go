package ratelimiter

import "errors"

// Error variables for rate limiter operations.
var (
	// ErrInvalidRate is returned when the rate configuration is invalid.
	ErrInvalidRate = errors.New("ratelimiter: rate must be positive")

	// ErrInvalidWindow is returned when the window configuration is invalid.
	ErrInvalidWindow = errors.New("ratelimiter: window must be positive")

	// ErrInvalidBurstSize is returned when the burst size configuration is invalid.
	ErrInvalidBurstSize = errors.New("ratelimiter: burst size must be non-negative")

	// ErrLimitExceeded is returned when the rate limit has been exceeded.
	ErrLimitExceeded = errors.New("ratelimiter: rate limit exceeded")

	// ErrKeyNotFound is returned when the key is not found in the store.
	ErrKeyNotFound = errors.New("ratelimiter: key not found")
)
