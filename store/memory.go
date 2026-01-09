package store

import (
	"sync"
	"time"
)

const shardCount = 256

type shard struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// MemoryStore is an in-memory implementation of the Store interface.
// It provides automatic cleanup of expired entries.
type MemoryStore struct {
	shards       [shardCount]*shard
	stopChan     chan struct{}
	closeOnce    sync.Once
	maxShardSize int
	maxKeySize   int
}

// MemoryStoreConfig holds configuration for MemoryStore.
type MemoryStoreConfig struct {
	// CleanupInterval is how often to run the cleanup routine.
	// Default is 1 minute.
	CleanupInterval time.Duration
	// MaxEntries is the maximum number of keys to store.
	// Default is 1,000,000.
	MaxEntries int
	// MaxKeySize is the maximum length of a key in bytes.
	// Default is 4096.
	MaxKeySize int
}

// DefaultMemoryStoreConfig returns sensible defaults for MemoryStore.
func DefaultMemoryStoreConfig() MemoryStoreConfig {
	return MemoryStoreConfig{
		CleanupInterval: time.Minute,
		MaxEntries:      1_000_000,
		MaxKeySize:      4096,
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
	if config.MaxEntries <= 0 {
		config.MaxEntries = 1_000_000
	}
	if config.MaxKeySize <= 0 {
		config.MaxKeySize = 4096
	}

	s := &MemoryStore{
		stopChan:   make(chan struct{}),
		maxKeySize: config.MaxKeySize,
	}

	// Calculate approximate per-shard limit
	// Ensure at least 1 entry per shard if MaxEntries is very small
	s.maxShardSize = config.MaxEntries / shardCount
	if s.maxShardSize < 1 {
		s.maxShardSize = 1
	}

	for i := 0; i < shardCount; i++ {
		s.shards[i] = &shard{
			entries: make(map[string]Entry),
		}
	}

	go s.cleanupLoop(config.CleanupInterval)

	return s
}

// Get retrieves a value from the store.
func (s *MemoryStore) Get(key string) (interface{}, bool) {
	if len(key) > s.maxKeySize {
		return nil, false
	}

	shard := s.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.entries[key]
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
	if len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Check if key already exists to allow updates even if full
	_, exists := shard.entries[key]

	if !exists {
		// New key, check capacity
		if len(shard.entries) >= s.maxShardSize {
			// Do NOT clean up here to avoid O(N) in hot path.
			// Rely on background cleanup.
			return ErrStoreFull
		}
	}

	entry := Entry{
		Value: value,
	}

	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	shard.entries[key] = entry
	return nil
}

// Delete removes a value from the store.
func (s *MemoryStore) Delete(key string) error {
	if len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	shard := s.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	delete(shard.entries, key)
	return nil
}

// Close stops the cleanup routine and releases resources.
func (s *MemoryStore) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopChan)
	})
	return nil
}

// Len returns the number of entries in the store (including expired ones).
func (s *MemoryStore) Len() int {
	count := 0
	for _, shard := range s.shards {
		shard.mu.RLock()
		count += len(shard.entries)
		shard.mu.RUnlock()
	}
	return count
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
	for _, shard := range s.shards {
		shard.mu.Lock()
		s.cleanupShard(shard)
		shard.mu.Unlock()
	}
}

// cleanupShard removes expired entries from a specific shard.
// It assumes the caller holds the lock.
func (s *MemoryStore) cleanupShard(shard *shard) {
	now := time.Now()
	for key, entry := range shard.entries {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(shard.entries, key)
		}
	}
}

// getShard returns the shard for the given key.
func (s *MemoryStore) getShard(key string) *shard {
	idx := fnv32a(key) % shardCount
	return s.shards[idx]
}

// fnv32a is a local implementation of FNV-1a 32-bit hash
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
