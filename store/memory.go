package store

import (
	"sync"
	"time"
)

// MemoryStore is an in-memory implementation of the Store interface.
// It provides automatic cleanup of expired entries.
type MemoryStore struct {
	mu       sync.RWMutex
	entries  map[string]Entry
	stopChan chan struct{}
	stopped  bool
}

// MemoryStoreConfig holds configuration for MemoryStore.
type MemoryStoreConfig struct {
	// CleanupInterval is how often to run the cleanup routine.
	// Default is 1 minute.
	CleanupInterval time.Duration
}

// DefaultMemoryStoreConfig returns sensible defaults for MemoryStore.
func DefaultMemoryStoreConfig() MemoryStoreConfig {
	return MemoryStoreConfig{
		CleanupInterval: time.Minute,
	}
}

// NewMemoryStore creates a new in-memory store with default configuration.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithConfig(DefaultMemoryStoreConfig())
}

// NewMemoryStoreWithConfig creates a new in-memory store with custom configuration.
func NewMemoryStoreWithConfig(config MemoryStoreConfig) *MemoryStore {
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = time.Minute
	}

	s := &MemoryStore{
		entries:  make(map[string]Entry),
		stopChan: make(chan struct{}),
	}

	go s.cleanupLoop(config.CleanupInterval)

	return s
}

// Get retrieves a value from the store.
func (s *MemoryStore) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.entries[key]
	if !exists {
		return nil, false
	}

	if entry.IsExpired() {
		return nil, false
	}

	return entry.Value, true
}

// Set stores a value with an optional TTL.
func (s *MemoryStore) Set(key string, value interface{}, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := Entry{
		Value: value,
	}

	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	s.entries[key] = entry
	return nil
}

// Delete removes a value from the store.
func (s *MemoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	return nil
}

// Close stops the cleanup routine and releases resources.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stopped {
		close(s.stopChan)
		s.stopped = true
	}

	return nil
}

// Len returns the number of entries in the store (including expired ones).
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.entries)
}

// cleanupLoop periodically removes expired entries.
func (s *MemoryStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stopChan:
			return
		}
	}
}

// cleanup removes all expired entries.
func (s *MemoryStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, entry := range s.entries {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(s.entries, key)
		}
	}
}
