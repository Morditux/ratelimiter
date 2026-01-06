package algorithms

import (
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

func BenchmarkTokenBucket_Allow(b *testing.B) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, _ := NewTokenBucket(ratelimiter.Config{
		Rate:      1000000, // High limit to avoid rate limiting during benchmark
		Window:    time.Second,
		BurstSize: 1000000,
	}, s)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tb.Allow("benchmark")
		}
	})
}

func BenchmarkSlidingWindow_Allow(b *testing.B) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, _ := NewSlidingWindow(ratelimiter.Config{
		Rate:   1000000, // High limit to avoid rate limiting during benchmark
		Window: time.Second,
	}, s)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sw.Allow("benchmark")
		}
	})
}

func BenchmarkTokenBucket_MultipleKeys(b *testing.B) {
	s := store.NewMemoryStore()
	defer s.Close()

	tb, _ := NewTokenBucket(ratelimiter.Config{
		Rate:      1000,
		Window:    time.Second,
		BurstSize: 1000,
	}, s)

	keys := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		keys[i] = string(rune(i))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			tb.Allow(keys[i%1000])
			i++
		}
	})
}

func BenchmarkSlidingWindow_MultipleKeys(b *testing.B) {
	s := store.NewMemoryStore()
	defer s.Close()

	sw, _ := NewSlidingWindow(ratelimiter.Config{
		Rate:   1000,
		Window: time.Second,
	}, s)

	keys := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		keys[i] = string(rune(i))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			sw.Allow(keys[i%1000])
			i++
		}
	})
}
