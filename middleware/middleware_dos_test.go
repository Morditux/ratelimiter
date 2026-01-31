package middleware

import (
	"net/http"
	"strings"
	"testing"
)

// BenchmarkLargeHeaderDoS verifies the performance impact of large headers on DefaultKeyFunc.
// While one request is fast, many can consume CPU.
func BenchmarkLargeHeaderDoS(b *testing.B) {
	// Create a 1MB header value (garbage)
	largeHeader := strings.Repeat("a", 1024*1024) // 1MB

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", largeHeader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultKeyFunc(req)
	}
}

func TestDefaultKeyFunc_LargeHeader(t *testing.T) {
	// Ensure that large headers don't crash or behave unexpectedly, just ignored
	largeHeader := strings.Repeat("a", 1024*1024) // 1MB
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", largeHeader)
	req.RemoteAddr = "127.0.0.1:1234"

	key := DefaultKeyFunc(req)
	if key != "127.0.0.1" {
		t.Errorf("Expected fallback to RemoteAddr 127.0.0.1, got %s", key)
	}
}
