package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

func TestRouter_PathNormalizationBypass(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Configure a strict limit on /api/sensitive
	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/sensitive",
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

	// 1. Normal request should be counted
	req := httptest.NewRequest("GET", "/api/sensitive", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("First request failed: %d", rec.Code)
	}

	// 2. Second normal request should be limited
	req = httptest.NewRequest("GET", "/api/sensitive", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for normal request, got %d", rec.Code)
	}

	// 3. Bypass attempt: Double slash //api/sensitive
	// Should be normalized to /api/sensitive and rate limited
	req = httptest.NewRequest("GET", "//api/sensitive", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Double slash bypass attempt: expected 429, got %d", rec.Code)
	}

	// 4. Bypass attempt: Path traversal /api/../api/sensitive
	// Should be normalized to /api/sensitive and rate limited
	req = httptest.NewRequest("GET", "/api/../api/sensitive", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Path traversal bypass attempt: expected 429, got %d", rec.Code)
	}
}
