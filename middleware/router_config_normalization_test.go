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

func TestRouterPathNormalizationBypass(t *testing.T) {
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Configure rate limit for "/admin/" (with trailing slash)
	// Expectation: effectively dead config if input is always cleaned
	router, err := NewRouter(handler, memStore, []EndpointConfig{
		{
			Path: "/admin/",
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Minute,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}

	// Request to "/admin/"
	req := httptest.NewRequest("GET", "/admin/", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)
	// Request 1: Should be allowed and counted
	if w.Code != http.StatusOK {
		t.Errorf("First request failed: %d", w.Code)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// Request 2: Should be rejected (429) if rate limit applies
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Security Bypass: Rate limit for '/admin/' ignored. Got status %d", w.Code)
	}
}

func TestExcludePathNormalization(t *testing.T) {
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	limiter, _ := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:   1,
		Window: time.Minute,
	}, memStore)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Exclude "/health/" (trailing slash)
	mw := RateLimitMiddleware(limiter, WithExcludePaths("/health/"))(handler)

	// Request to "/health/"
	req := httptest.NewRequest("GET", "/health/", nil)

	// Request 1
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Req 1 failed: %d", w.Code)
	}

	// Request 2 (should exceed limit if NOT excluded)
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Req 2 failed (should be excluded): %d", w.Code)
	}

	// Request 3
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Exclude path bypass: /health/ was rate limited despite exclusion. Code: %d", w.Code)
	}
}
