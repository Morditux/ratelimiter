package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLargeHeaderDoS checks if the system handles extremely large X-Forwarded-For headers
// without excessive processing.
func TestLargeHeaderDoS(t *testing.T) {
	// specific payload size that is large enough to be a concern but not crash the test runner
	payloadSize := 10 * 1024 * 1024 // 10MB
	longString := strings.Repeat("a", payloadSize)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", longString)
	req.RemoteAddr = "1.2.3.4:1234"

	key := DefaultKeyFunc(req)

	if key != "1.2.3.4" {
		t.Errorf("Expected fallback to RemoteAddr 1.2.3.4, got %s", key)
	}
}

func TestLargeHeaderDoS_WithComma(t *testing.T) {
	payloadSize := 10 * 1024 * 1024 // 10MB
	longString := strings.Repeat("a", payloadSize) + ", 5.6.7.8"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", longString)
	req.RemoteAddr = "1.2.3.4:1234"

	key := DefaultKeyFunc(req)

	// Should fallback to RemoteAddr because first part is garbage/too long
	if key != "1.2.3.4" {
		t.Errorf("Expected fallback to RemoteAddr 1.2.3.4, got %s", key)
	}
}
