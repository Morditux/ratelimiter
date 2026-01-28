// Package store provides storage backends for rate limiting data.
package store

import (
	"errors"
	"time"
)

// ErrStoreFull is returned when the storage capacity is reached.
var ErrStoreFull = errors.New("ratelimiter: store capacity exceeded")

// ErrKeyTooLong is returned when a key exceeds the maximum allowed length.
var ErrKeyTooLong = errors.New("ratelimiter: key too long")

// Store defines the storage interface for rate limiting data.
// Implementations must be safe for concurrent use.
type Store interface {
	// Get retrieves a value from the store.
	// Returns the value and true if found, nil and false otherwise.
	Get(key string) (interface{}, bool)

	// Set stores a value with an optional TTL.
	// If ttl is 0, the value never expires.
	Set(key string, value interface{}, ttl time.Duration) error

	// Delete removes a value from the store.
	Delete(key string) error

	// Close releases any resources held by the store.
	Close() error
}

// NamespacedStore extends Store with namespace support to avoid string concatenation allocations.
type NamespacedStore interface {
	Store

	// GetWithNamespace retrieves a value from the store using a namespace and key.
	GetWithNamespace(namespace, key string) (interface{}, bool)

	// SetWithNamespace stores a value with namespace using an optional TTL.
	SetWithNamespace(namespace, key string, value interface{}, ttl time.Duration) error

	// DeleteWithNamespace removes a value from the store using a namespace and key.
	DeleteWithNamespace(namespace, key string) error
}

// TimeAwareStore extends Store with time-aware methods to avoid internal time.Now() calls.
type TimeAwareStore interface {
	Store

	// GetAt retrieves a value from the store relative to the given time.
	GetAt(key string, now time.Time) (interface{}, bool)

	// SetAt stores a value with an optional TTL relative to the given time.
	SetAt(key string, value interface{}, ttl time.Duration, now time.Time) error

	// UpdateTTLAt updates the expiration of a key relative to the given time.
	UpdateTTLAt(key string, ttl time.Duration, now time.Time) error
}

// NamespacedTimeAwareStore extends NamespacedStore with time-aware methods.
type NamespacedTimeAwareStore interface {
	NamespacedStore

	// GetWithNamespaceAt retrieves a value from the store relative to the given time.
	GetWithNamespaceAt(namespace, key string, now time.Time) (interface{}, bool)

	// SetWithNamespaceAt stores a value with namespace using an optional TTL relative to the given time.
	SetWithNamespaceAt(namespace, key string, value interface{}, ttl time.Duration, now time.Time) error

	// UpdateTTLWithNamespaceAt updates the expiration of a namespaced key relative to the given time.
	UpdateTTLWithNamespaceAt(namespace, key string, ttl time.Duration, now time.Time) error
}

// Entry represents a stored value with its expiration time.
type Entry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// IsExpired checks if the entry has expired.
func (e Entry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

// IsExpiredAt checks if the entry has expired at the given time.
func (e Entry) IsExpiredAt(now time.Time) bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return now.After(e.ExpiresAt)
}
