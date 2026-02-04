package store

import (
	"fmt"
	"testing"
)

func BenchmarkMemoryStore_ConcurrentGet(b *testing.B) {
	s := NewMemoryStore()
	defer s.Close()

	// Pre-generate keys to avoid allocation during benchmark
	numKeys := 1000
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = fmt.Sprintf("key-%d", i)
		s.Set(keys[i], i, 0)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Access keys in a round-robin fashion
			key := keys[i%numKeys]
			s.Get(key)
			i++
		}
	})
}

func BenchmarkMemoryStore_ConcurrentSet(b *testing.B) {
	s := NewMemoryStore()
	defer s.Close()

	// Pre-generate keys
	numKeys := 1000
	keys := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keys[i] = fmt.Sprintf("key-%d", i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := keys[i%numKeys]
			s.Set(key, i, 0)
			i++
		}
	})
}
