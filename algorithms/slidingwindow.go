package algorithms

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

// slidingWindowState holds the state for a sliding window.
type slidingWindowState struct {
	PrevCount   int       // Count from previous window
	CurrCount   int       // Count in current window
	WindowStart time.Time // Start of current window
}

// SlidingWindow implements the sliding window rate limiting algorithm.
// It provides a more accurate rate limit than fixed windows by considering
// a weighted count from the previous window.
type SlidingWindow struct {
	config           ratelimiter.Config
	store            store.Store
	nsStore          store.NamespacedStore
	timeAwareStore   store.TimeAwareStore
	nsTimeAwareStore store.NamespacedTimeAwareStore
	mu               [shardCount]paddedMutex // Sharded mutexes to reduce contention
	invWindow        float64                 // Pre-calculated inverse window for faster multiplication
	seed             maphash.Seed            // Seed for sharding hash
}

// NewSlidingWindow creates a new sliding window rate limiter.
func NewSlidingWindow(config ratelimiter.Config, s store.Store) (*SlidingWindow, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	sw := &SlidingWindow{
		config:    config,
		store:     s,
		invWindow: 1.0 / float64(config.Window),
		seed:      maphash.MakeSeed(),
	}

	if ns, ok := s.(store.NamespacedStore); ok {
		sw.nsStore = ns
	}

	if tas, ok := s.(store.TimeAwareStore); ok {
		sw.timeAwareStore = tas
	}
	if nstas, ok := s.(store.NamespacedTimeAwareStore); ok {
		sw.nsTimeAwareStore = nstas
	}

	return sw, nil
}

// Allow checks if a single request is allowed.
func (sw *SlidingWindow) Allow(key string) (bool, error) {
	return sw.AllowN(key, 1)
}

// AllowN checks if n requests are allowed.
func (sw *SlidingWindow) AllowN(key string, n int) (bool, error) {
	result, err := sw.AllowNWithDetails(key, n)
	return result.Allowed, err
}

// AllowNWithDetails checks if n requests are allowed and returns detailed result.
func (sw *SlidingWindow) AllowNWithDetails(key string, n int) (ratelimiter.Result, error) {
	if n <= 0 {
		return ratelimiter.Result{Allowed: true, Limit: sw.config.Rate, Remaining: sw.config.Rate}, nil
	}

	var storeKey string
	useNS := sw.nsStore != nil
	if !useNS {
		storeKey = sw.storeKey(key)
	}

	mu := sw.getLock(key)
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	state := sw.getState(key, storeKey, useNS, now)

	result := ratelimiter.Result{
		Limit:   sw.config.Rate,
		ResetAt: state.WindowStart.Add(sw.config.Window),
	}

	// Calculate the weighted count
	windowProgress := float64(now.Sub(state.WindowStart)) * sw.invWindow
	if windowProgress > 1 {
		windowProgress = 1
	}

	// Weight from previous window decreases as we progress through current window
	prevWeight := 1.0 - windowProgress
	weightedCount := float64(state.PrevCount)*prevWeight + float64(state.CurrCount)

	// Check if adding n requests would exceed the limit
	if weightedCount+float64(n) > float64(sw.config.Rate) {
		result.Allowed = false
		// Conservative retry after: wait until the start of the next window
		result.RetryAfter = sw.config.Window - now.Sub(state.WindowStart)

		remaining := float64(sw.config.Rate) - weightedCount
		if remaining < 0 {
			remaining = 0
		}
		result.Remaining = int(remaining)

		// Optimization: If we reject, we can just update the TTL to keep the key alive
		// without writing the full state (which requires allocation).
		// We only fall back to full save if UpdateTTL is not supported or fails.
		if err := sw.updateTTL(key, storeKey, useNS, now); err != nil {
			_ = sw.saveState(key, storeKey, useNS, state, now)
		}
		return result, nil
	}

	// Allow the request and increment the counter
	state.CurrCount += n

	result.Allowed = true
	remaining := float64(sw.config.Rate) - (weightedCount + float64(n))
	if remaining < 0 {
		remaining = 0
	}
	result.Remaining = int(remaining)

	if err := sw.saveState(key, storeKey, useNS, state, now); err != nil {
		return ratelimiter.Result{}, err
	}
	return result, nil
}

// updateTTL updates the expiration of the key without saving the state.
func (sw *SlidingWindow) updateTTL(key, storeKey string, useNS bool, now time.Time) error {
	ttl := sw.config.Window * 3
	if useNS {
		if sw.nsTimeAwareStore != nil {
			return sw.nsTimeAwareStore.UpdateTTLWithNamespaceAt("sw", key, ttl, now)
		}
		if ttlStore, ok := sw.nsStore.(store.NamespacedTTLStore); ok {
			return ttlStore.UpdateTTLWithNamespace("sw", key, ttl)
		}
	} else {
		if sw.timeAwareStore != nil {
			return sw.timeAwareStore.UpdateTTLAt(storeKey, ttl, now)
		}
		if ttlStore, ok := sw.store.(store.TTLStore); ok {
			return ttlStore.UpdateTTL(storeKey, ttl)
		}
	}
	// Return error to trigger fallback to saveState
	return ratelimiter.ErrNotSupported
}

// Reset clears the rate limit state for the given key.
func (sw *SlidingWindow) Reset(key string) error {
	mu := sw.getLock(key)
	mu.Lock()
	defer mu.Unlock()

	if sw.nsStore != nil {
		return sw.nsStore.DeleteWithNamespace("sw", key)
	}
	return sw.store.Delete(sw.storeKey(key))
}

// Remaining returns an estimate of remaining requests for the given key.
func (sw *SlidingWindow) Remaining(key string) int {
	mu := sw.getLock(key)
	mu.Lock()
	defer mu.Unlock()

	var storeKey string
	useNS := sw.nsStore != nil
	if !useNS {
		storeKey = sw.storeKey(key)
	}

	state := sw.getState(key, storeKey, useNS, time.Now())

	windowProgress := float64(time.Since(state.WindowStart)) * sw.invWindow
	if windowProgress > 1 {
		windowProgress = 1
	}

	prevWeight := 1.0 - windowProgress
	weightedCount := float64(state.PrevCount)*prevWeight + float64(state.CurrCount)

	remaining := float64(sw.config.Rate) - weightedCount
	if remaining < 0 {
		return 0
	}
	return int(remaining)
}

// getState retrieves or initializes the sliding window state.
// Optimization: Returns a pointer to avoid allocation when updating state in MemoryStore.
// Safety: This function and the returned pointer must only be accessed while holding the
// lock for the key (sw.getLock(key)). In-place mutation via advanceWindow is safe
// because access is serialized by the lock.
func (sw *SlidingWindow) getState(key, storeKey string, useNS bool, now time.Time) *slidingWindowState {
	var val interface{}
	var ok bool

	if useNS {
		if sw.nsTimeAwareStore != nil {
			val, ok = sw.nsTimeAwareStore.GetWithNamespaceAt("sw", key, now)
		} else {
			val, ok = sw.nsStore.GetWithNamespace("sw", key)
		}
	} else {
		if sw.timeAwareStore != nil {
			val, ok = sw.timeAwareStore.GetAt(storeKey, now)
		} else {
			val, ok = sw.store.Get(storeKey)
		}
	}

	if ok {
		// Fast path: pointer (zero allocation for MemoryStore updates)
		if state, ok := val.(*slidingWindowState); ok {
			sw.advanceWindow(state, now)
			return state
		}
		// Fallback: value (handles migration or stores that return by value)
		if state, ok := val.(slidingWindowState); ok {
			// Copy to heap to allow pointer return
			s := state
			sw.advanceWindow(&s, now)
			return &s
		}
	}

	// Initialize new state
	return &slidingWindowState{
		PrevCount:   0,
		CurrCount:   0,
		WindowStart: now,
	}
}

// advanceWindow updates the window state if time has passed.
// It mutates the state in-place. This is safe because the caller holds the lock.
func (sw *SlidingWindow) advanceWindow(state *slidingWindowState, now time.Time) {
	elapsed := now.Sub(state.WindowStart)
	if elapsed >= sw.config.Window*2 {
		// More than 2 windows have passed, reset completely
		state.PrevCount = 0
		state.CurrCount = 0
		state.WindowStart = now
	} else if elapsed >= sw.config.Window {
		// One window has passed, slide the window
		state.PrevCount = state.CurrCount
		state.CurrCount = 0
		state.WindowStart = state.WindowStart.Add(sw.config.Window)
	}
}

// saveState persists the sliding window state.
// Optimization: Takes a pointer to support zero-allocation updates in MemoryStore.
func (sw *SlidingWindow) saveState(key, storeKey string, useNS bool, state *slidingWindowState, now time.Time) error {
	// Store with a TTL of 3x the window to allow for proper sliding
	ttl := sw.config.Window * 3
	if useNS {
		if sw.nsTimeAwareStore != nil {
			return sw.nsTimeAwareStore.SetWithNamespaceAt("sw", key, state, ttl, now)
		}
		return sw.nsStore.SetWithNamespace("sw", key, state, ttl)
	}
	if sw.timeAwareStore != nil {
		return sw.timeAwareStore.SetAt(storeKey, state, ttl, now)
	}
	return sw.store.Set(storeKey, state, ttl)
}

// storeKey generates the storage key for a rate limit key.
func (sw *SlidingWindow) storeKey(key string) string {
	return "sw:" + key
}

// getLock returns the mutex for the given key based on a hash.
func (sw *SlidingWindow) getLock(key string) *sync.Mutex {
	idx := maphash.String(sw.seed, key) % shardCount
	return &sw.mu[idx].Mutex
}
