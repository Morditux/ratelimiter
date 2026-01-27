package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/algorithms"
	"github.com/Morditux/ratelimiter/store"
)

type mockStoreFull struct{}

func (m *mockStoreFull) Get(key string) (interface{}, bool) { return nil, false }
func (m *mockStoreFull) Set(key string, value interface{}, ttl time.Duration) error {
	return store.ErrStoreFull
}
func (m *mockStoreFull) Delete(key string) error { return nil }
func (m *mockStoreFull) Close() error            { return nil }

func TestRateLimitMiddleware_SecurityHeadersOnError(t *testing.T) {
	// 1. Test Key Too Long (431)
	t.Run("KeyTooLong_Headers", func(t *testing.T) {
		s := store.NewMemoryStore()
		defer s.Close()
		limiter, _ := algorithms.NewTokenBucket(ratelimiter.Config{Rate: 1, Window: time.Minute}, s)

		// MaxKeySize very small
		mw := RateLimitMiddleware(limiter, WithMaxKeySize(5))

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		req := httptest.NewRequest("GET", "/", nil)
		// DefaultKeyFunc uses RemoteAddr. Let's force a long key via X-Forwarded-For if KeyFunc isn't changed,
		// but wait, default KeyFunc checks XFF.
		// Or just use WithKeyFunc to return a long string.
		mw = RateLimitMiddleware(limiter, WithMaxKeySize(5), WithKeyFunc(func(r *http.Request) string {
			return "very-long-key-exceeding-limit"
		}))

		rec := httptest.NewRecorder()
		mw(handler).ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("Expected 431, got %d", rec.Code)
		}

		// Check for Security Headers
		headers := []string{
			"Cache-Control",
			"X-Content-Type-Options",
			"Content-Security-Policy",
			"X-Frame-Options",
		}

		for _, h := range headers {
			if val := rec.Header().Get(h); val == "" {
				t.Errorf("Missing security header on 431 response: %s", h)
			}
		}

		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("Expected Cache-Control: no-store, got %s", rec.Header().Get("Cache-Control"))
		}
	})

	// 2. Test Store Full (503)
	t.Run("StoreFull_Headers", func(t *testing.T) {
		s := &mockStoreFull{}
		limiter, _ := algorithms.NewTokenBucket(ratelimiter.Config{Rate: 1, Window: time.Minute}, s)

		mw := RateLimitMiddleware(limiter)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		mw(handler).ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("Expected 503, got %d", rec.Code)
		}

		// Check for Security Headers
		headers := []string{
			"Cache-Control",
			"X-Content-Type-Options",
			"Content-Security-Policy",
			"X-Frame-Options",
		}

		for _, h := range headers {
			if val := rec.Header().Get(h); val == "" {
				t.Errorf("Missing security header on 503 response: %s", h)
			}
		}

		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("Expected Cache-Control: no-store, got %s", rec.Header().Get("Cache-Control"))
		}
	})
}

// Test Router as well
func TestRouter_SecurityHeadersOnError(t *testing.T) {
	t.Run("StoreFull_Headers", func(t *testing.T) {
		s := &mockStoreFull{}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})

		router, _ := NewRouter(handler, s, []EndpointConfig{
			{
				Path: "/api",
				Config: ratelimiter.Config{Rate: 1, Window: time.Minute},
			},
		})

		req := httptest.NewRequest("GET", "/api", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("Expected 503, got %d", rec.Code)
		}

		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("Expected Cache-Control: no-store on Router 503, got %s", rec.Header().Get("Cache-Control"))
		}
	})
}
