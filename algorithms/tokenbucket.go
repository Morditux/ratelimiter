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

const shardCount = 256

// paddedMutex wraps a sync.Mutex with padding to prevent false sharing.
// Standard CPU cache line is 64 bytes.
// sync.Mutex is 8 bytes on 64-bit systems.
// We add 56 bytes of padding to ensure each mutex occupies its own cache line.
type paddedMutex struct {
	sync.Mutex
	_ [56]byte
}

// TokenBucket implements the token bucket rate limiting algorithm.
// Tokens are added at a steady rate and consumed by requests.
// This allows for controlled bursting while maintaining an average rate.
type TokenBucket struct {
	config     ratelimiter.Config
	store      store.Store
	nsStore    store.NamespacedStore
	mu         [shardCount]paddedMutex // Sharded mutexes with padding to reduce contention
	refillRate float64                // Pre-calculated tokens/sec to avoid repetitive division
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

	tb := &TokenBucket{
		config:     config,
		store:      s,
		refillRate: float64(config.Rate) / config.Window.Seconds(),
	}

	if ns, ok := s.(store.NamespacedStore); ok {
		tb.nsStore = ns
	}

	return tb, nil
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

	var storeKey string
	useNS := tb.nsStore != nil

	if !useNS {
		storeKey = tb.storeKey(key)
	}

	mu := tb.getLock(key)
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	state := tb.getState(key, storeKey, useNS, now)

	// Refill tokens based on time elapsed
	elapsed := now.Sub(state.LastRefill)
	tokensToAdd := elapsed.Seconds() * tb.refillRate

	state.Tokens += tokensToAdd
	if state.Tokens > float64(tb.config.BurstSize) {
		state.Tokens = float64(tb.config.BurstSize)
	}
	state.LastRefill = now

	// Check if we have enough tokens
	if state.Tokens >= float64(n) {
		state.Tokens -= float64(n)
		if err := tb.saveState(key, storeKey, useNS, state); err != nil {
			return false, err
		}
		return true, nil
	}

	// Not enough tokens, save state and reject
	// Optimization: If we reject, we can just update the TTL to keep the key alive
	// without writing the full state (which requires allocation).
	// We only fall back to full save if UpdateTTL is not supported or fails.
	if err := tb.updateTTL(key, storeKey, useNS); err != nil {
		_ = tb.saveState(key, storeKey, useNS, state)
	}
	return false, nil
}

// Reset clears the rate limit state for the given key.
func (tb *TokenBucket) Reset(key string) error {
	mu := tb.getLock(key)
	mu.Lock()
	defer mu.Unlock()

	if tb.nsStore != nil {
		return tb.nsStore.DeleteWithNamespace("tb", key)
	}
	return tb.store.Delete(tb.storeKey(key))
}

// Remaining returns the number of tokens remaining for the given key.
func (tb *TokenBucket) Remaining(key string) int {
	mu := tb.getLock(key)
	mu.Lock()
	defer mu.Unlock()

	var storeKey string
	useNS := tb.nsStore != nil
	if !useNS {
		storeKey = tb.storeKey(key)
	}

	state := tb.getState(key, storeKey, useNS, time.Now())
	return int(state.Tokens)
}

// getState retrieves or initializes the token bucket state.
func (tb *TokenBucket) getState(key, storeKey string, useNS bool, now time.Time) tokenBucketState {
	var val interface{}
	var ok bool

	if useNS {
		val, ok = tb.nsStore.GetWithNamespace("tb", key)
	} else {
		val, ok = tb.store.Get(storeKey)
	}

	if ok {
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
func (tb *TokenBucket) saveState(key, storeKey string, useNS bool, state tokenBucketState) error {
	// Store with a TTL of 2x the window to allow for cleanup
	if useNS {
		return tb.nsStore.SetWithNamespace("tb", key, state, tb.config.Window*2)
	}
	return tb.store.Set(storeKey, state, tb.config.Window*2)
}

// updateTTL updates the expiration of the key without saving the state.
func (tb *TokenBucket) updateTTL(key, storeKey string, useNS bool) error {
	ttl := tb.config.Window * 2
	if useNS {
		if ttlStore, ok := tb.nsStore.(store.NamespacedTTLStore); ok {
			return ttlStore.UpdateTTLWithNamespace("tb", key, ttl)
		}
		// Fallback for stores that don't support NamespacedTTLStore but might support TTLStore (unlikely but possible)
	} else {
		if ttlStore, ok := tb.store.(store.TTLStore); ok {
			return ttlStore.UpdateTTL(storeKey, ttl)
		}
	}
	// Return error to trigger fallback to saveState
	return ratelimiter.ErrNotSupported
}

// storeKey generates the storage key for a rate limit key.
func (tb *TokenBucket) storeKey(key string) string {
	return "tb:" + key
}

// getLock returns the mutex for the given key based on a hash.
func (tb *TokenBucket) getLock(key string) *sync.Mutex {
	idx := fnv32a(key) % shardCount
	return &tb.mu[idx].Mutex
}

// fnv32a is a local implementation of FNV-1a 32-bit hash to avoid allocation and imports
func fnv32a(s string) uint32 {
	const offset32 = 2166136261
	const prime32 = 16777619
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}
