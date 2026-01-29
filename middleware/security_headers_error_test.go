package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

type mockStoreFullLimiter struct{}

func (m *mockStoreFullLimiter) Allow(key string) (bool, error) {
	return false, store.ErrStoreFull
}

func (m *mockStoreFullLimiter) AllowN(key string, n int) (bool, error) {
	return false, store.ErrStoreFull
}

func (m *mockStoreFullLimiter) Reset(key string) error {
	return nil
}

func TestRateLimitMiddleware_StoreFull_SecurityHeaders(t *testing.T) {
	limiter := &mockStoreFullLimiter{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mw := RateLimitMiddleware(limiter)(handler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	mw.ServeHTTP(w, req)

	// Check status code
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable, got %d", w.Code)
	}

	// Check headers
	headers := w.Header()

	// These headers should be present for security even on errors
	requiredHeaders := []string{
		"Cache-Control",
		"Content-Security-Policy",
		"X-Frame-Options",
	}

	for _, h := range requiredHeaders {
		if headers.Get(h) == "" {
			t.Errorf("missing security header %s in error response", h)
		}
	}
}

type mockFullStore struct{}

func (m *mockFullStore) Get(key string) (interface{}, bool) { return nil, false }
func (m *mockFullStore) Set(key string, value interface{}, ttl time.Duration) error {
	return store.ErrStoreFull
}
func (m *mockFullStore) Delete(key string) error { return nil }
func (m *mockFullStore) Close() error            { return nil }

func TestRouter_StoreFull_SecurityHeaders(t *testing.T) {
	s := &mockFullStore{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	config := []EndpointConfig{
		{
			Path: "/",
			Config: ratelimiter.Config{Rate: 1, Window: time.Minute},
		},
	}

	router, _ := NewRouter(handler, s, config)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Check status code
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable, got %d", w.Code)
	}

	// Check headers
	headers := w.Header()

	requiredHeaders := []string{
		"Cache-Control",
		"Content-Security-Policy",
		"X-Frame-Options",
	}

	for _, h := range requiredHeaders {
		if headers.Get(h) == "" {
			t.Errorf("missing security header %s in error response", h)
		}
	}
}
