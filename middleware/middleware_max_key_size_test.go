package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

// MockLimiter is a mock implementation of Limiter.
type MockLimiter struct {
	AllowFunc func(key string) (bool, error)
	ResetFunc func(key string) error
}

var _ ratelimiter.Limiter = (*MockLimiter)(nil)

func (m *MockLimiter) Allow(key string) (bool, error) {
	if m.AllowFunc != nil {
		return m.AllowFunc(key)
	}
	return true, nil
}

func (m *MockLimiter) AllowN(key string, n int) (bool, error) {
	return m.Allow(key)
}

func (m *MockLimiter) Reset(key string) error {
	if m.ResetFunc != nil {
		return m.ResetFunc(key)
	}
	return nil
}

func TestRateLimitMiddleware_MaxKeySize(t *testing.T) {
	called := false
	limiter := &MockLimiter{
		AllowFunc: func(key string) (bool, error) {
			called = true
			return true, nil
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a key larger than default 4096
	largeKey := strings.Repeat("a", 5000)
	keyFunc := func(r *http.Request) string {
		return largeKey
	}

	// We can use WithMaxKeySize now, but default is 4096.
	// We verify default behavior first.
	middleware := RateLimitMiddleware(limiter, WithKeyFunc(keyFunc))
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// SECURE BEHAVIOR:
	// The middleware should reject the request BEFORE calling the limiter.

	if called {
		t.Error("Limiter should NOT be called for over-sized keys")
	}
	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("Expected 431 Request Header Fields Too Large, got %d", rec.Code)
	}

	// Test with custom MaxKeySize
	called = false
	middleware = RateLimitMiddleware(limiter, WithKeyFunc(keyFunc), WithMaxKeySize(6000))
	wrappedHandler = middleware(handler)

	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if !called {
		t.Error("Limiter SHOULD be called when key is within custom MaxKeySize")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rec.Code)
	}
}

func TestRouter_MaxKeySize(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	largePath := "/" + strings.Repeat("a", 5000)

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: largePath,
			Config: ratelimiter.Config{
				Rate: 1, Window: time.Minute,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}

	req := httptest.NewRequest("GET", largePath, nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("Expected 431, got %d", rec.Code)
	}
}

func TestRouter_MaxKeySize_EarlyRejection(t *testing.T) {
	// Mock store that panics if Set is called.
	// If the router rejects early, Set should not be called.
	s := &MockStore{
		SetFunc: func(key string, value interface{}, ttl time.Duration) error {
			t.Fatal("Store.Set should NOT be called")
			return nil
		},
		GetFunc: func(key string) (interface{}, bool) {
			return nil, false
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	largePath := "/" + strings.Repeat("a", 5000)

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: largePath,
			Config: ratelimiter.Config{Rate: 1, Window: time.Minute},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}

	req := httptest.NewRequest("GET", largePath, nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("Expected 431, got %d", rec.Code)
	}
}
