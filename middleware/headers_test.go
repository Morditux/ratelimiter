package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/algorithms"
	"github.com/Morditux/ratelimiter/store"
)

func TestRateLimitMiddleware_Headers(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	// Rate: 2 req/min. Burst: 2.
	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      2,
		Window:    time.Minute,
		BurstSize: 2,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := RateLimitMiddleware(limiter)
	server := mw(handler)

	// 1. First Request (Allowed)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Req 1 failed: %d", rec.Code)
	}

	checkHeader(t, rec, "X-RateLimit-Limit", "2")
	checkHeader(t, rec, "X-RateLimit-Remaining", "1")
	checkHeaderExists(t, rec, "X-RateLimit-Reset")

	// 2. Second Request (Allowed)
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Req 2 failed: %d", rec.Code)
	}
	checkHeader(t, rec, "X-RateLimit-Remaining", "0")

	// 3. Third Request (Limited)
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("Req 3 expected 429, got %d", rec.Code)
	}
	checkHeader(t, rec, "X-RateLimit-Remaining", "0")
	checkHeaderExists(t, rec, "Retry-After")

	retryAfter := rec.Header().Get("Retry-After")
	seconds, err := strconv.Atoi(retryAfter)
	if err != nil {
		t.Errorf("Invalid Retry-After: %s", retryAfter)
	}
	if seconds < 1 || seconds > 60 {
		t.Errorf("Retry-After out of range: %d", seconds)
	}
}

func TestRouter_Headers(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api",
			Config: ratelimiter.Config{
				Rate:      1,
				Window:    time.Minute,
				BurstSize: 1,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}

	// 1. Allowed
	req := httptest.NewRequest("GET", "/api", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	checkHeader(t, rec, "X-RateLimit-Limit", "1")
	checkHeader(t, rec, "X-RateLimit-Remaining", "0")

	// 2. Limited
	req = httptest.NewRequest("GET", "/api", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d", rec.Code)
	}
	checkHeaderExists(t, rec, "Retry-After")
}

func checkHeader(t *testing.T, rec *httptest.ResponseRecorder, key, expected string) {
	t.Helper()
	if got := rec.Header().Get(key); got != expected {
		t.Errorf("Header %s: expected %q, got %q", key, expected, got)
	}
}

func checkHeaderExists(t *testing.T, rec *httptest.ResponseRecorder, key string) {
	t.Helper()
	if got := rec.Header().Get(key); got == "" {
		t.Errorf("Header %s missing", key)
	}
}
