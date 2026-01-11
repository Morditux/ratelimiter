package algorithms

import (
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
	config  ratelimiter.Config
	store   store.Store
	nsStore store.NamespacedStore
	mu      [shardCount]sync.Mutex // Sharded mutexes to reduce contention
}

// NewSlidingWindow creates a new sliding window rate limiter.
func NewSlidingWindow(config ratelimiter.Config, s store.Store) (*SlidingWindow, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	sw := &SlidingWindow{
		config: config,
		store:  s,
	}

	if ns, ok := s.(store.NamespacedStore); ok {
		sw.nsStore = ns
	}

	return sw, nil
}

// Allow checks if a single request is allowed.
func (sw *SlidingWindow) Allow(key string) (bool, error) {
	return sw.AllowN(key, 1)
}

// AllowN checks if n requests are allowed.
func (sw *SlidingWindow) AllowN(key string, n int) (bool, error) {
	if n <= 0 {
		return true, nil
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

	// Calculate the weighted count
	windowProgress := now.Sub(state.WindowStart).Seconds() / sw.config.Window.Seconds()
	if windowProgress > 1 {
		windowProgress = 1
	}

	// Weight from previous window decreases as we progress through current window
	prevWeight := 1.0 - windowProgress
	weightedCount := float64(state.PrevCount)*prevWeight + float64(state.CurrCount)

	// Check if adding n requests would exceed the limit
	if weightedCount+float64(n) > float64(sw.config.Rate) {
		return false, nil
	}

	// Allow the request and increment the counter
	state.CurrCount += n
	sw.saveState(key, storeKey, useNS, state)
	return true, nil
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

	windowProgress := time.Since(state.WindowStart).Seconds() / sw.config.Window.Seconds()
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
func (sw *SlidingWindow) getState(key, storeKey string, useNS bool, now time.Time) slidingWindowState {
	var val interface{}
	var ok bool

	if useNS {
		val, ok = sw.nsStore.GetWithNamespace("sw", key)
	} else {
		val, ok = sw.store.Get(storeKey)
	}

	if ok {
		if state, ok := val.(slidingWindowState); ok {
			// Check if we need to slide to a new window
			elapsed := now.Sub(state.WindowStart)

			if elapsed >= sw.config.Window*2 {
				// More than 2 windows have passed, reset completely
				return slidingWindowState{
					PrevCount:   0,
					CurrCount:   0,
					WindowStart: now,
				}
			} else if elapsed >= sw.config.Window {
				// One window has passed, slide the window
				return slidingWindowState{
					PrevCount:   state.CurrCount,
					CurrCount:   0,
					WindowStart: state.WindowStart.Add(sw.config.Window),
				}
			}

			return state
		}
	}

	// Initialize new state
	return slidingWindowState{
		PrevCount:   0,
		CurrCount:   0,
		WindowStart: now,
	}
}

// saveState persists the sliding window state.
func (sw *SlidingWindow) saveState(key, storeKey string, useNS bool, state slidingWindowState) {
	// Store with a TTL of 3x the window to allow for proper sliding
	if useNS {
		_ = sw.nsStore.SetWithNamespace("sw", key, state, sw.config.Window*3)
	} else {
		_ = sw.store.Set(storeKey, state, sw.config.Window*3)
	}
}

// storeKey generates the storage key for a rate limit key.
func (sw *SlidingWindow) storeKey(key string) string {
	return "sw:" + key
}

// getLock returns the mutex for the given key based on a hash.
func (sw *SlidingWindow) getLock(key string) *sync.Mutex {
	idx := fnv32a(key) % shardCount
	return &sw.mu[idx]
}
