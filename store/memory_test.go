package store

import (
	"sync"
	"testing"
	"time"
)

func TestMemoryStore_SetAndGet(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	// Test basic set and get
	err := s.Set("key1", "value1", 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	val, ok := s.Get("key1")
	if !ok {
		t.Fatal("Get returned false for existing key")
	}
	if val != "value1" {
		t.Errorf("Expected 'value1', got '%v'", val)
	}
}

func TestMemoryStore_GetNonExistent(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	val, ok := s.Get("nonexistent")
	if ok {
		t.Error("Get returned true for non-existent key")
	}
	if val != nil {
		t.Errorf("Expected nil, got '%v'", val)
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	s.Set("key1", "value1", 0)

	err := s.Delete("key1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, ok := s.Get("key1")
	if ok {
		t.Error("Get returned true after delete")
	}
}

func TestMemoryStore_DeleteNonExistent(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	// Should not error when deleting non-existent key
	err := s.Delete("nonexistent")
	if err != nil {
		t.Errorf("Delete non-existent key returned error: %v", err)
	}
}

func TestMemoryStore_TTL(t *testing.T) {
	s := NewMemoryStoreWithConfig(MemoryStoreConfig{
		CleanupInterval: 100 * time.Millisecond,
	})
	defer s.Close()

	// Set with short TTL
	err := s.Set("key1", "value1", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should exist immediately
	_, ok := s.Get("key1")
	if !ok {
		t.Error("Key should exist immediately after set")
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired (Get returns false for expired entries)
	_, ok = s.Get("key1")
	if ok {
		t.Error("Key should be expired after TTL")
	}
}

func TestMemoryStore_TTLZero(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	// TTL of 0 means no expiration
	err := s.Set("key1", "value1", 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Should still exist
	_, ok := s.Get("key1")
	if !ok {
		t.Error("Key with TTL=0 should not expire")
	}
}

func TestMemoryStore_Overwrite(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	s.Set("key1", "value1", 0)
	s.Set("key1", "value2", 0)

	val, ok := s.Get("key1")
	if !ok {
		t.Fatal("Get returned false for existing key")
	}
	if val != "value2" {
		t.Errorf("Expected 'value2', got '%v'", val)
	}
}

func TestMemoryStore_DifferentTypes(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	// String
	s.Set("string", "hello", 0)
	if val, _ := s.Get("string"); val != "hello" {
		t.Errorf("String: expected 'hello', got '%v'", val)
	}

	// Int
	s.Set("int", 42, 0)
	if val, _ := s.Get("int"); val != 42 {
		t.Errorf("Int: expected 42, got '%v'", val)
	}

	// Struct
	type testStruct struct {
		Name  string
		Value int
	}
	s.Set("struct", testStruct{"test", 123}, 0)
	if val, _ := s.Get("struct"); val != (testStruct{"test", 123}) {
		t.Errorf("Struct: expected {test 123}, got '%v'", val)
	}
}

func TestMemoryStore_Len(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	if s.Len() != 0 {
		t.Errorf("Expected Len() = 0, got %d", s.Len())
	}

	s.Set("key1", "value1", 0)
	s.Set("key2", "value2", 0)

	if s.Len() != 2 {
		t.Errorf("Expected Len() = 2, got %d", s.Len())
	}

	s.Delete("key1")

	if s.Len() != 1 {
		t.Errorf("Expected Len() = 1, got %d", s.Len())
	}
}

func TestMemoryStore_Cleanup(t *testing.T) {
	s := NewMemoryStoreWithConfig(MemoryStoreConfig{
		CleanupInterval: 50 * time.Millisecond,
	})
	defer s.Close()

	// Set multiple keys with short TTL
	s.Set("key1", "value1", 30*time.Millisecond)
	s.Set("key2", "value2", 30*time.Millisecond)
	s.Set("key3", "value3", 0) // No expiration

	if s.Len() != 3 {
		t.Errorf("Expected Len() = 3, got %d", s.Len())
	}

	// Wait for cleanup
	time.Sleep(150 * time.Millisecond)

	// Only key3 should remain (after cleanup removes expired entries)
	if s.Len() != 1 {
		t.Errorf("Expected Len() = 1 after cleanup, got %d", s.Len())
	}

	_, ok := s.Get("key3")
	if !ok {
		t.Error("key3 should still exist")
	}
}

func TestMemoryStore_Concurrent(t *testing.T) {
	s := NewMemoryStore()
	defer s.Close()

	var wg sync.WaitGroup
	numGoroutines := 100
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key" + string(rune(id)) + string(rune(j))
				s.Set(key, j, time.Second)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key" + string(rune(id)) + string(rune(j))
				s.Get(key)
			}
		}(i)
	}

	// Concurrent deletes
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := "key" + string(rune(id)) + string(rune(j))
				s.Delete(key)
			}
		}(i)
	}

	wg.Wait()
}

func TestMemoryStore_Close(t *testing.T) {
	s := NewMemoryStore()

	err := s.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}

	// Double close should not panic
	err = s.Close()
	if err != nil {
		t.Errorf("Double close returned error: %v", err)
	}
}

func TestEntry_IsExpired(t *testing.T) {
	// Zero time = never expires
	entry := Entry{Value: "test", ExpiresAt: time.Time{}}
	if entry.IsExpired() {
		t.Error("Entry with zero ExpiresAt should not be expired")
	}

	// Future time = not expired
	entry = Entry{Value: "test", ExpiresAt: time.Now().Add(time.Hour)}
	if entry.IsExpired() {
		t.Error("Entry with future ExpiresAt should not be expired")
	}

	// Past time = expired
	entry = Entry{Value: "test", ExpiresAt: time.Now().Add(-time.Hour)}
	if !entry.IsExpired() {
		t.Error("Entry with past ExpiresAt should be expired")
	}
}
