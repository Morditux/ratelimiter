package algorithms

import (
	"sync"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

func TestSlidingWindow_Allow(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// First 10 requests should be allowed
	for i := 0; i < 10; i++ {
		allowed, err := sw.Allow("test")
		if err != nil {
			t.Fatalf("Allow returned error: %v", err)
		}
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 11th request should be rejected
	allowed, err := sw.Allow("test")
	if err != nil {
		t.Fatalf("Allow returned error: %v", err)
	}
	if allowed {
		t.Error("11th request should be rejected")
	}
}

func TestSlidingWindow_AllowN(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Request 5
	allowed, err := sw.AllowN("test", 5)
	if err != nil {
		t.Fatalf("AllowN returned error: %v", err)
	}
	if !allowed {
		t.Error("AllowN(5) should be allowed")
	}

	// Request 5 more
	allowed, err = sw.AllowN("test", 5)
	if err != nil {
		t.Fatalf("AllowN returned error: %v", err)
	}
	if !allowed {
		t.Error("Second AllowN(5) should be allowed")
	}

	// Request 1 more - should be rejected
	allowed, err = sw.AllowN("test", 1)
	if err != nil {
		t.Fatalf("AllowN returned error: %v", err)
	}
	if allowed {
		t.Error("AllowN(1) should be rejected when limit reached")
	}
}

func TestSlidingWindow_AllowNZeroOrNegative(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Zero or negative n should always be allowed
	allowed, _ := sw.AllowN("test", 0)
	if !allowed {
		t.Error("AllowN(0) should be allowed")
	}

	allowed, _ = sw.AllowN("test", -1)
	if !allowed {
		t.Error("AllowN(-1) should be allowed")
	}
}

func TestSlidingWindow_WindowSlide(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: 100 * time.Millisecond,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Use all 10 requests
	for i := 0; i < 10; i++ {
		sw.Allow("test")
	}

	// Should be rejected
	allowed, _ := sw.Allow("test")
	if allowed {
		t.Error("Should be rejected after limit reached")
	}

	// Wait for window to slide past the first window
	// After 1 full window (100ms), the previous count becomes current count
	// and current count resets to 0
	time.Sleep(120 * time.Millisecond)

	// At 20% through the new window, weighted count should be:
	// prevCount * 0.8 + currCount = 10 * 0.8 + 0 = 8
	// So we should have room for 10 - 8 = 2 requests
	allowed, _ = sw.Allow("test")
	if !allowed {
		t.Error("Should be allowed as window slides")
	}
}

func TestSlidingWindow_FullWindowReset(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: 50 * time.Millisecond,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Use all requests
	for i := 0; i < 10; i++ {
		sw.Allow("test")
	}

	// Wait for 2 full windows to pass
	time.Sleep(120 * time.Millisecond)

	// Should have full quota again
	for i := 0; i < 10; i++ {
		allowed, _ := sw.Allow("test")
		if !allowed {
			t.Errorf("Request %d should be allowed after 2 windows", i+1)
		}
	}
}

func TestSlidingWindow_Reset(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Use all tokens
	for i := 0; i < 10; i++ {
		sw.Allow("test")
	}

	// Should be rejected
	allowed, _ := sw.Allow("test")
	if allowed {
		t.Error("Should be rejected after limit reached")
	}

	// Reset
	err = sw.Reset("test")
	if err != nil {
		t.Fatalf("Reset returned error: %v", err)
	}

	// Should be allowed after reset
	allowed, _ = sw.Allow("test")
	if !allowed {
		t.Error("Should be allowed after reset")
	}
}

func TestSlidingWindow_DifferentKeys(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   2,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Use all requests for key1
	sw.Allow("key1")
	sw.Allow("key1")

	// key1 should be rejected
	allowed, _ := sw.Allow("key1")
	if allowed {
		t.Error("key1 should be rejected")
	}

	// key2 should still be allowed
	allowed, _ = sw.Allow("key2")
	if !allowed {
		t.Error("key2 should be allowed")
	}
}

func TestSlidingWindow_InvalidConfig(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	// Invalid rate
	_, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   0,
		Window: time.Second,
	}, s)
	if err == nil {
		t.Error("Expected error for Rate=0")
	}

	// Invalid window
	_, err = NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: 0,
	}, s)
	if err == nil {
		t.Error("Expected error for Window=0")
	}
}

func TestSlidingWindow_Remaining(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   10,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	// Initially should have 10 remaining
	remaining := sw.Remaining("test")
	if remaining != 10 {
		t.Errorf("Expected 10 remaining, got %d", remaining)
	}

	// Use 3
	sw.Allow("test")
	sw.Allow("test")
	sw.Allow("test")

	remaining = sw.Remaining("test")
	if remaining != 7 {
		t.Errorf("Expected 7 remaining, got %d", remaining)
	}
}

func TestSlidingWindow_Concurrent(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, err := NewSlidingWindow(ratelimiter.Config{
		Rate:   100,
		Window: time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create SlidingWindow: %v", err)
	}

	var wg sync.WaitGroup
	allowedCount := int32(0)
	var mu sync.Mutex

	// Launch 200 concurrent requests
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, err := sw.Allow("test")
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

	// Should allow max 100 requests
	if allowedCount > 100 {
		t.Errorf("Expected max 100 allowed, got %d", allowedCount)
	}
}
