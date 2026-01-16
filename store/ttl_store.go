package store

import "time"

// TTLStore extends Store with the ability to update TTL without changing value.
type TTLStore interface {
	Store
	// UpdateTTL updates the expiration of a key without changing its value.
	UpdateTTL(key string, ttl time.Duration) error
}

// NamespacedTTLStore extends NamespacedStore with UpdateTTL support.
type NamespacedTTLStore interface {
	NamespacedStore
	// UpdateTTLWithNamespace updates the expiration of a namespaced key.
	UpdateTTLWithNamespace(namespace, key string, ttl time.Duration) error
}
