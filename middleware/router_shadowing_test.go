package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

func TestRouter_Shadowing(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Define general route BEFORE specific route
	// If the router is naive, it will match /api/* first and ignore /api/admin
	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/*", // General
			Config: ratelimiter.Config{
				Rate:   100,
				Window: time.Minute,
			},
		},
		{
			Path: "/api/admin", // Specific (should be stricter)
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Minute,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// 1st request to /api/admin
	// Should be allowed by both
	req := httptest.NewRequest("GET", "/api/admin", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("1st request failed: %d", rec.Code)
	}

	// 2nd request to /api/admin
	// If correctly sorted/matched, this should be blocked (limit 1)
	// If shadowed, this will be allowed (limit 100)
	req = httptest.NewRequest("GET", "/api/admin", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Security Vulnerability: Specific route shadowed by general route. Expected 429, got %d", rec.Code)
	}
}

func TestRouter_ExactVsWildcard(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// /api/* (len 6) vs /api (len 4)
	// Even though /api is shorter, it is an exact match and should be prioritized over the wildcard
	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/*",
			Config: ratelimiter.Config{
				Rate:   100,
				Window: time.Minute,
			},
		},
		{
			Path: "/api",
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Minute,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// 1st request to /api
	req := httptest.NewRequest("GET", "/api", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("1st request failed: %d", rec.Code)
	}

	// 2nd request to /api
	// Should be blocked (limit 1)
	req = httptest.NewRequest("GET", "/api", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Exact match /api shadowed by wildcard /api/*. Expected 429, got %d", rec.Code)
	}
}
