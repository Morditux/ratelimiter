package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Morditux/ratelimiter/store"
)

// MockLimiter that always fails with a specific error
type ErrorLimiter struct {
	Err error
}

func (l *ErrorLimiter) Allow(key string) (bool, error) {
	return false, l.Err
}

func (l *ErrorLimiter) AllowN(key string, n int) (bool, error) {
	return false, l.Err
}

func (l *ErrorLimiter) Reset(key string) error {
	return l.Err
}

func TestRateLimitMiddleware_BypassWithLongKey(t *testing.T) {
	// Setup a limiter that simulates the store returning ErrKeyTooLong
	// In a real scenario, this happens when the key is > MaxKeySize (4096)
	limiter := &ErrorLimiter{Err: store.ErrKeyTooLong}

	// Create middleware
	mw := RateLimitMiddleware(limiter)

	// Create a handler
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	}))

	// Create a request with a key that triggers the error
	// We simulate this by having the limiter return ErrKeyTooLong
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// If the middleware fails open, it will return 200 OK
	if w.Code == http.StatusOK {
		t.Fatalf("Security Vulnerability: Middleware failed open on ErrKeyTooLong, allowing request bypass")
	}

	// We expect 431 Request Header Fields Too Large
	if w.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("Expected status 431, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_FailOpenOnOtherErrors(t *testing.T) {
	// Setup a limiter that simulates a system error (e.g. redis down)
	limiter := &ErrorLimiter{Err: errors.New("redis connection failed")}

	// Create middleware
	mw := RateLimitMiddleware(limiter)

	// Create a handler
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should still fail open for generic errors
	if w.Code != http.StatusOK {
		t.Errorf("Middleware should fail open on system errors, got status %d", w.Code)
	}
}
