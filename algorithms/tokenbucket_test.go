package algorithms

import (
	"sync"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

func TestTokenBucket_Allow(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      10,
		Window:    time.Second,
		BurstSize: 10,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// First 10 requests should be allowed
	for i := 0; i < 10; i++ {
		allowed, err := tb.Allow("test")
		if err != nil {
			t.Fatalf("Allow returned error: %v", err)
		}
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 11th request should be rejected
	allowed, err := tb.Allow("test")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("11th request should be rejected")
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      10,
		Window:    time.Second,
		BurstSize: 10,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Request 5 tokens
	allowed, err := tb.AllowN("test", 5)
	if err != nil {
		t.Fatalf("AllowN returned error: %v", err)
	}
	if !allowed {
		t.Error("AllowN(5) should be allowed")
	}

	// Request 5 more tokens
	allowed, err = tb.AllowN("test", 5)
	if err != nil {
		t.Fatalf("AllowN returned error: %v", err)
	}
	if !allowed {
		t.Error("Second AllowN(5) should be allowed")
	}

	// Request 1 more token - should be rejected
	allowed, err = tb.AllowN("test", 1)
	if err != nil {
		t.Fatalf("AllowN returned error: %v", err)
	}
	if allowed {
		t.Error("AllowN(1) should be rejected when tokens exhausted")
	}
}

func TestTokenBucket_AllowNZeroOrNegative(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:   10,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Zero or negative n should always be allowed
	allowed, _ := tb.AllowN("test", 0)
	if !allowed {
		t.Error("AllowN(0) should be allowed")
	}

	allowed, _ = tb.AllowN("test", -1)
	if !allowed {
		t.Error("AllowN(-1) should be allowed")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      10,
		Window:    time.Second,
		BurstSize: 10,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		tb.Allow("test")
	}

	// Should be rejected
	allowed, _ := tb.Allow("test")
	if allowed {
		t.Error("Should be rejected after exhausting tokens")
	}

	// Wait for refill (100ms should give ~1 token)
	time.Sleep(150 * time.Millisecond)

	// Should be allowed after refill
	allowed, _ = tb.Allow("test")
	if !allowed {
		t.Error("Should be allowed after token refill")
	}
}

func TestTokenBucket_Reset(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      10,
		Window:    time.Second,
		BurstSize: 10,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		tb.Allow("test")
	}

	// Should be rejected
	allowed, _ := tb.Allow("test")
	if allowed {
		t.Error("Should be rejected after exhausting tokens")
	}

	// Reset
	err = tb.Reset("test")
	if err != nil {
		t.Fatalf("Reset returned error: %v", err)
	}

	// Should be allowed after reset
	allowed, _ = tb.Allow("test")
	if !allowed {
		t.Error("Should be allowed after reset")
	}
}

func TestTokenBucket_DifferentKeys(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      2,
		Window:    time.Second,
		BurstSize: 2,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Exhaust tokens for key1
	tb.Allow("key1")
	tb.Allow("key1")

	// key1 should be rejected
	allowed, _ := tb.Allow("key1")
	if allowed {
		t.Error("key1 should be rejected")
	}

	// key2 should still have tokens
	allowed, _ = tb.Allow("key2")
	if !allowed {
		t.Error("key2 should be allowed")
	}
}

func TestTokenBucket_InvalidConfig(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	// Invalid rate
	_, err := NewTokenBucket(ratelimiter.Config{
		Rate:   0,
		Window: time.Second,
	}, s)
	if err == nil {
		t.Error("Expected error for Rate=0")
	}

	// Invalid window
	_, err = NewTokenBucket(ratelimiter.Config{
		Rate:   10,
		Window: 0,
	}, s)
	if err == nil {
		t.Error("Expected error for Window=0")
	}
}

func TestTokenBucket_DefaultBurstSize(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	// BurstSize not set, should default to Rate
	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:   5,
		Window: time.Second,
		// BurstSize not set
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Should allow 5 requests (defaulted burst size)
	for i := 0; i < 5; i++ {
		allowed, _ := tb.Allow("test")
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th should be rejected
	allowed, _ := tb.Allow("test")
	if allowed {
		t.Error("6th request should be rejected")
	}
}

func TestTokenBucket_Remaining(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      10,
		Window:    time.Second,
		BurstSize: 10,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	// Initially should have 10 tokens
	remaining := tb.Remaining("test")
	if remaining != 10 {
		t.Errorf("Expected 10 remaining, got %d", remaining)
	}

	// Use 3 tokens
	tb.Allow("test")
	tb.Allow("test")
	tb.Allow("test")

	remaining = tb.Remaining("test")
	if remaining != 7 {
		t.Errorf("Expected 7 remaining, got %d", remaining)
	}
}

func TestTokenBucket_Concurrent(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, err := NewTokenBucket(ratelimiter.Config{
		Rate:      100,
		Window:    time.Second,
		BurstSize: 100,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create TokenBucket: %v", err)
	}

	var wg sync.WaitGroup
	allowedCount := int32(0)
	var mu sync.Mutex

	// Launch 200 concurrent requests
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, err := tb.Allow("test")
			if err != nil {
				t.Errorf("Allow returned error: %v", err)
				return
			}
			if allowed {
				mu.Lock()
				allowedCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Should allow approximately 100 requests (burst size)
	if allowedCount > 100 {
		t.Errorf("Expected max 100 allowed, got %d", allowedCount)
	}
}
