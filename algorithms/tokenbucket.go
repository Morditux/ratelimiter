// Package algorithms provides rate limiting algorithm implementations.
package algorithms

import (
	"sync"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

// tokenBucketState holds the state for a token bucket.
type tokenBucketState struct {
	Tokens     float64
	LastRefill time.Time
}

// TokenBucket implements the token bucket rate limiting algorithm.
// Tokens are added at a steady rate and consumed by requests.
// This allows for controlled bursting while maintaining an average rate.
type TokenBucket struct {
	config ratelimiter.Config
	store  store.Store
	mu     sync.Mutex // Protects state updates
}

// NewTokenBucket creates a new token bucket rate limiter.
func NewTokenBucket(config ratelimiter.Config, s store.Store) (*TokenBucket, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Default burst size to rate if not set
	if config.BurstSize == 0 {
		config.BurstSize = config.Rate
	}

	return &TokenBucket{
		config: config,
		store:  s,
	}, nil
}

// Allow checks if a single request is allowed.
func (tb *TokenBucket) Allow(key string) (bool, error) {
	return tb.AllowN(key, 1)
}

// AllowN checks if n requests are allowed.
func (tb *TokenBucket) AllowN(key string, n int) (bool, error) {
	if n <= 0 {
		return true, nil
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	state := tb.getState(key, now)

	// Refill tokens based on time elapsed
	elapsed := now.Sub(state.LastRefill)
	refillRate := float64(tb.config.Rate) / tb.config.Window.Seconds()
	tokensToAdd := elapsed.Seconds() * refillRate

	state.Tokens += tokensToAdd
	if state.Tokens > float64(tb.config.BurstSize) {
		state.Tokens = float64(tb.config.BurstSize)
	}
	state.LastRefill = now

	// Check if we have enough tokens
	if state.Tokens >= float64(n) {
		state.Tokens -= float64(n)
		tb.saveState(key, state)
		return true, nil
	}

	// Not enough tokens, save state and reject
	tb.saveState(key, state)
	return false, nil
}

// Reset clears the rate limit state for the given key.
func (tb *TokenBucket) Reset(key string) error {
	return tb.store.Delete(tb.storeKey(key))
}

// Remaining returns the number of tokens remaining for the given key.
func (tb *TokenBucket) Remaining(key string) int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	state := tb.getState(key, time.Now())
	return int(state.Tokens)
}

// getState retrieves or initializes the token bucket state.
func (tb *TokenBucket) getState(key string, now time.Time) tokenBucketState {
	storeKey := tb.storeKey(key)

	if val, ok := tb.store.Get(storeKey); ok {
		if state, ok := val.(tokenBucketState); ok {
			return state
		}
	}

	// Initialize with full tokens
	return tokenBucketState{
		Tokens:     float64(tb.config.BurstSize),
		LastRefill: now,
	}
}

// saveState persists the token bucket state.
func (tb *TokenBucket) saveState(key string, state tokenBucketState) {
	storeKey := tb.storeKey(key)
	// Store with a TTL of 2x the window to allow for cleanup
	_ = tb.store.Set(storeKey, state, tb.config.Window*2)
}

// storeKey generates the storage key for a rate limit key.
func (tb *TokenBucket) storeKey(key string) string {
	return "tb:" + key
}
