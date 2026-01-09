package store

import (
	"strings"
	"testing"
	"time"
)

func TestMemoryStore_LargeKey(t *testing.T) {
	// Create a store with default config
	store := NewMemoryStore()
	defer store.Close()

	// Create a huge key (1MB)
	hugeKey := strings.Repeat("a", 1024*1024)

	// Attempt to set the key
	err := store.Set(hugeKey, "value", time.Minute)
	if err == nil {
		t.Fatalf("Expected Set to fail with ErrKeyTooLong, but succeeded")
	}
	if err != ErrKeyTooLong {
		t.Fatalf("Expected ErrKeyTooLong, got: %v", err)
	}

	// Verify we can't retrieve it
	_, ok := store.Get(hugeKey)
	if ok {
		t.Errorf("Expected Get to fail (not found) for huge key")
	}

	// Verify normal key still works
	normalKey := "normal-key"
	err = store.Set(normalKey, "value", time.Minute)
	if err != nil {
		t.Errorf("Expected normal Set to succeed, got: %v", err)
	}

	val, ok := store.Get(normalKey)
	if !ok || val != "value" {
		t.Errorf("Expected to get value, got %v, %v", val, ok)
	}
}
