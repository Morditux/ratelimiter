package store

import (
	"hash/maphash"
	"math/bits"
	"sync"
	"time"
)

const shardCount = 256

type internalKey struct {
	ns  string
	key string
}

type shard struct {
	mu      sync.RWMutex
	entries map[internalKey]Entry
}

// MemoryStore is an in-memory implementation of the Store interface.
// It provides automatic cleanup of expired entries.
type MemoryStore struct {
	shards       [shardCount]*shard
	stopChan     chan struct{}
	closeOnce    sync.Once
	maxShardSize int
	maxKeySize   int
	seed         maphash.Seed
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
		seed:       maphash.MakeSeed(),
	}

	// Calculate approximate per-shard limit
	// Ensure at least 1 entry per shard if MaxEntries is very small
	s.maxShardSize = config.MaxEntries / shardCount
	if s.maxShardSize < 1 {
		s.maxShardSize = 1
	}

	for i := 0; i < shardCount; i++ {
		s.shards[i] = &shard{
			entries: make(map[internalKey]Entry),
		}
	}

	go s.cleanupLoop(config.CleanupInterval)

	return s
}

// Get retrieves a value from the store.
func (s *MemoryStore) Get(key string) (interface{}, bool) {
	return s.GetWithNamespace("", key)
}

// GetWithNamespace retrieves a value from the store using a namespace and key.
func (s *MemoryStore) GetWithNamespace(namespace, key string) (interface{}, bool) {
	if len(namespace)+len(key) > s.maxKeySize {
		return nil, false
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.entries[k]
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
	return s.SetWithNamespace("", key, value, ttl)
}

// SetWithNamespace stores a value with namespace using an optional TTL.
func (s *MemoryStore) SetWithNamespace(namespace, key string, value interface{}, ttl time.Duration) error {
	if len(namespace)+len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry := Entry{
		Value: value,
	}

	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	// Optimization: avoid double lookup if shard is not full
	if len(shard.entries) < s.maxShardSize {
		shard.entries[k] = entry
		return nil
	}

	// Check if key already exists to allow updates even if full
	if _, exists := shard.entries[k]; exists {
		shard.entries[k] = entry
		return nil
	}

	// New key and shard is full
	return ErrStoreFull
}

// Delete removes a value from the store.
func (s *MemoryStore) Delete(key string) error {
	return s.DeleteWithNamespace("", key)
}

// DeleteWithNamespace removes a value from the store using a namespace and key.
func (s *MemoryStore) DeleteWithNamespace(namespace, key string) error {
	if len(namespace)+len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	delete(shard.entries, k)
	return nil
}

// UpdateTTL updates the expiration of a key without changing its value.
func (s *MemoryStore) UpdateTTL(key string, ttl time.Duration) error {
	return s.UpdateTTLWithNamespace("", key, ttl)
}

// UpdateTTLWithNamespace updates the expiration of a namespaced key without changing its value.
func (s *MemoryStore) UpdateTTLWithNamespace(namespace, key string, ttl time.Duration) error {
	if len(namespace)+len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, exists := shard.entries[k]
	if !exists {
		// Key doesn't exist, cannot update TTL
		return nil
	}

	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	} else {
		entry.ExpiresAt = time.Time{}
	}
	shard.entries[k] = entry
	return nil
}

// GetAt retrieves a value from the store relative to the given time.
func (s *MemoryStore) GetAt(key string, now time.Time) (interface{}, bool) {
	return s.GetWithNamespaceAt("", key, now)
}

// GetWithNamespaceAt retrieves a value from the store using a namespace and key relative to the given time.
func (s *MemoryStore) GetWithNamespaceAt(namespace, key string, now time.Time) (interface{}, bool) {
	if len(namespace)+len(key) > s.maxKeySize {
		return nil, false
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.entries[k]
	if !exists {
		return nil, false
	}

	if entry.IsExpiredAt(now) {
		return nil, false
	}

	return entry.Value, true
}

// SetAt stores a value with an optional TTL relative to the given time.
func (s *MemoryStore) SetAt(key string, value interface{}, ttl time.Duration, now time.Time) error {
	return s.SetWithNamespaceAt("", key, value, ttl, now)
}

// SetWithNamespaceAt stores a value with namespace using an optional TTL relative to the given time.
func (s *MemoryStore) SetWithNamespaceAt(namespace, key string, value interface{}, ttl time.Duration, now time.Time) error {
	if len(namespace)+len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry := Entry{
		Value: value,
	}

	if ttl > 0 {
		entry.ExpiresAt = now.Add(ttl)
	}

	// Optimization: avoid double lookup if shard is not full
	if len(shard.entries) < s.maxShardSize {
		shard.entries[k] = entry
		return nil
	}

	// Check if key already exists to allow updates even if full
	if _, exists := shard.entries[k]; exists {
		shard.entries[k] = entry
		return nil
	}

	// New key and shard is full
	return ErrStoreFull
}

// UpdateTTLAt updates the expiration of a key relative to the given time.
func (s *MemoryStore) UpdateTTLAt(key string, ttl time.Duration, now time.Time) error {
	return s.UpdateTTLWithNamespaceAt("", key, ttl, now)
}

// UpdateTTLWithNamespaceAt updates the expiration of a namespaced key relative to the given time.
func (s *MemoryStore) UpdateTTLWithNamespaceAt(namespace, key string, ttl time.Duration, now time.Time) error {
	if len(namespace)+len(key) > s.maxKeySize {
		return ErrKeyTooLong
	}

	k := internalKey{ns: namespace, key: key}
	shard := s.getShard(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, exists := shard.entries[k]
	if !exists {
		// Key doesn't exist, cannot update TTL
		return nil
	}

	if ttl > 0 {
		entry.ExpiresAt = now.Add(ttl)
	} else {
		entry.ExpiresAt = time.Time{}
	}
	shard.entries[k] = entry
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
func (s *MemoryStore) getShard(k internalKey) *shard {
	var idx uint64
	if k.ns == "" {
		// Fast path for no namespace: avoid extra hashing and rotation
		idx = maphash.String(s.seed, k.key)
	} else {
		// Combine namespace and key hashes using XOR and rotation to mix bits
		// This avoids allocating maphash.Hash struct and calling WriteString twice
		h1 := maphash.String(s.seed, k.ns)
		h2 := maphash.String(s.seed, k.key)
		idx = bits.RotateLeft64(h1, 32) ^ h2
	}
	return s.shards[idx%shardCount]
}
