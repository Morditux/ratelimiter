// Package algorithms provides rate limiting algorithm implementations.
package algorithms

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

// tokenBucketState holds the state for a token bucket.
type tokenBucketState struct {
	Tokens     float64
	LastRefill time.Time
	LastSave   time.Time
}

const shardCount = 256

// TokenBucket implements the token bucket rate limiting algorithm.
// Tokens are added at a steady rate and consumed by requests.
// This allows for controlled bursting while maintaining an average rate.
type TokenBucket struct {
	config           ratelimiter.Config
	store            store.Store
	nsStore          store.NamespacedStore
	timeAwareStore   store.TimeAwareStore
	nsTimeAwareStore store.NamespacedTimeAwareStore
	mu               [shardCount]paddedMutex // Sharded mutexes to reduce contention
	tokensPerNano    float64                 // Pre-calculated tokens/ns to avoid repetitive division
	seed             maphash.Seed            // Seed for sharding hash
	isPointerStore   bool                    // True if store supports pointer updates (e.g., MemoryStore)
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

	// Calculate tokens per nanosecond
	// Rate is tokens/window. Window is duration.
	// tokensPerNano = Rate / Window.Nanoseconds()
	tokensPerNano := float64(config.Rate) / float64(config.Window.Nanoseconds())

	tb := &TokenBucket{
		config:        config,
		store:         s,
		tokensPerNano: tokensPerNano,
		seed:          maphash.MakeSeed(),
	}

	// Optimization: if store is MemoryStore, we can update state in-place via pointer
	// and skip redundant writes, only saving periodically to refresh TTL.
	if _, ok := s.(*store.MemoryStore); ok {
		tb.isPointerStore = true
	}

	if ns, ok := s.(store.NamespacedStore); ok {
		tb.nsStore = ns
	}

	if tas, ok := s.(store.TimeAwareStore); ok {
		tb.timeAwareStore = tas
	}
	if nstas, ok := s.(store.NamespacedTimeAwareStore); ok {
		tb.nsTimeAwareStore = nstas
	}

	return tb, nil
}

// Allow checks if a single request is allowed.
func (tb *TokenBucket) Allow(key string) (bool, error) {
	return tb.AllowN(key, 1)
}

// AllowN checks if n requests are allowed.
func (tb *TokenBucket) AllowN(key string, n int) (bool, error) {
	result, err := tb.AllowNWithDetails(key, n)
	return result.Allowed, err
}

// AllowNWithDetails checks if n requests are allowed and returns detailed result.
func (tb *TokenBucket) AllowNWithDetails(key string, n int) (ratelimiter.Result, error) {
	if n <= 0 {
		return ratelimiter.Result{Allowed: true, Limit: tb.config.Rate, Remaining: int(tb.config.BurstSize)}, nil
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
	// Optimization: Use multiplication instead of Duration.Seconds() which involves division
	tokensToAdd := float64(elapsed) * tb.tokensPerNano

	state.Tokens += tokensToAdd
	if state.Tokens > float64(tb.config.BurstSize) {
		state.Tokens = float64(tb.config.BurstSize)
	}
	state.LastRefill = now

	result := ratelimiter.Result{
		Limit:   tb.config.Rate,
		ResetAt: now.Add(tb.config.Window),
	}

	// Check if we have enough tokens
	if state.Tokens >= float64(n) {
		state.Tokens -= float64(n)
		result.Allowed = true
		result.Remaining = int(state.Tokens)

		// Optimization: For in-memory stores, we can skip saving if the TTL is still fresh.
		// Modifications to state are already visible via pointer.
		// We save if it's a new key (LastSave is zero) or if enough time has passed.
		shouldSave := true
		if tb.isPointerStore && !state.LastSave.IsZero() {
			// Update TTL at least once per window to ensure it doesn't expire.
			// The TTL is set to 2x Window, so updating once per Window is sufficient.
			if now.Sub(state.LastSave) < tb.config.Window {
				shouldSave = false
			}
		}

		if shouldSave {
			state.LastSave = now
			if err := tb.saveState(key, storeKey, useNS, state, now); err != nil {
				return ratelimiter.Result{}, err
			}
		}
		return result, nil
	}

	// Not enough tokens
	result.Allowed = false
	result.Remaining = int(state.Tokens)
	tokensNeeded := float64(n) - state.Tokens
	if tokensNeeded > 0 {
		result.RetryAfter = time.Duration(tokensNeeded / tb.tokensPerNano)
	}

	// Not enough tokens, save state and reject
	// Optimization: If we reject, we can just update the TTL to keep the key alive
	// without writing the full state (which requires allocation).
	// We only fall back to full save if UpdateTTL is not supported or fails.
	if err := tb.updateTTL(key, storeKey, useNS, now); err != nil {
		_ = tb.saveState(key, storeKey, useNS, state, now)
	}
	return result, nil
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
// Optimization: Returns a pointer to avoid allocation when updating state in MemoryStore.
func (tb *TokenBucket) getState(key, storeKey string, useNS bool, now time.Time) *tokenBucketState {
	var val interface{}
	var ok bool

	if useNS {
		if tb.nsTimeAwareStore != nil {
			val, ok = tb.nsTimeAwareStore.GetWithNamespaceAt("tb", key, now)
		} else {
			val, ok = tb.nsStore.GetWithNamespace("tb", key)
		}
	} else {
		if tb.timeAwareStore != nil {
			val, ok = tb.timeAwareStore.GetAt(storeKey, now)
		} else {
			val, ok = tb.store.Get(storeKey)
		}
	}

	if ok {
		// Fast path: pointer (zero allocation for MemoryStore updates)
		if state, ok := val.(*tokenBucketState); ok {
			return state
		}
		// Fallback: value (handles migration or stores that return by value)
		if state, ok := val.(tokenBucketState); ok {
			return &state
		}
	}

	// Initialize with full tokens
	return &tokenBucketState{
		Tokens:     float64(tb.config.BurstSize),
		LastRefill: now,
	}
}

// saveState persists the token bucket state.
// Optimization: Takes a pointer to support zero-allocation updates in MemoryStore.
func (tb *TokenBucket) saveState(key, storeKey string, useNS bool, state *tokenBucketState, now time.Time) error {
	// Store with a TTL of 2x the window to allow for cleanup
	ttl := tb.config.Window * 2
	if useNS {
		if tb.nsTimeAwareStore != nil {
			return tb.nsTimeAwareStore.SetWithNamespaceAt("tb", key, state, ttl, now)
		}
		return tb.nsStore.SetWithNamespace("tb", key, state, ttl)
	}
	if tb.timeAwareStore != nil {
		return tb.timeAwareStore.SetAt(storeKey, state, ttl, now)
	}
	return tb.store.Set(storeKey, state, ttl)
}

// updateTTL updates the expiration of the key without saving the state.
func (tb *TokenBucket) updateTTL(key, storeKey string, useNS bool, now time.Time) error {
	ttl := tb.config.Window * 2
	if useNS {
		if tb.nsTimeAwareStore != nil {
			return tb.nsTimeAwareStore.UpdateTTLWithNamespaceAt("tb", key, ttl, now)
		}
		if ttlStore, ok := tb.nsStore.(store.NamespacedTTLStore); ok {
			return ttlStore.UpdateTTLWithNamespace("tb", key, ttl)
		}
		// Fallback for stores that don't support NamespacedTTLStore but might support TTLStore (unlikely but possible)
	} else {
		if tb.timeAwareStore != nil {
			return tb.timeAwareStore.UpdateTTLAt(storeKey, ttl, now)
		}
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
	idx := maphash.String(tb.seed, key) % shardCount
	return &tb.mu[idx].Mutex
}
