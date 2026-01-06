package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

func TestRouter_PerEndpointLimiting(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/fast",
			Config: ratelimiter.Config{
				Rate:   10,
				Window: time.Second,
			},
			Algorithm: AlgorithmTokenBucket,
		},
		{
			Path: "/api/slow",
			Config: ratelimiter.Config{
				Rate:   2,
				Window: time.Second,
			},
			Algorithm: AlgorithmTokenBucket,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// /api/fast should allow 10 requests
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/fast", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("/api/fast request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// /api/slow should only allow 2 requests
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api/slow", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("/api/slow request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 3rd request to /api/slow should be rate limited
	req := httptest.NewRequest("GET", "/api/slow", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("/api/slow 3rd request: expected 429, got %d", rec.Code)
	}
}

func TestRouter_DifferentAlgorithms(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/bucket",
			Config: ratelimiter.Config{
				Rate:      5,
				Window:    time.Second,
				BurstSize: 5,
			},
			Algorithm: AlgorithmTokenBucket,
		},
		{
			Path: "/window",
			Config: ratelimiter.Config{
				Rate:   5,
				Window: time.Second,
			},
			Algorithm: AlgorithmSlidingWindow,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// Both endpoints should allow 5 requests
	for _, path := range []string{"/bucket", "/window"} {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("%s request %d: expected 200, got %d", path, i+1, rec.Code)
			}
		}

		// 6th request should be rate limited
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s 6th request: expected 429, got %d", path, rec.Code)
		}
	}
}

func TestRouter_MethodFiltering(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path:    "/api/resource",
			Methods: []string{"POST", "PUT"},
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Second,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// GET should not be rate limited (not in Methods)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/api/resource", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("GET request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// POST should be rate limited
	req := httptest.NewRequest("POST", "/api/resource", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("First POST: expected 200, got %d", rec.Code)
	}

	req = httptest.NewRequest("POST", "/api/resource", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Second POST: expected 429, got %d", rec.Code)
	}
}

func TestRouter_PrefixMatch(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/*",
			Config: ratelimiter.Config{
				Rate:   2,
				Window: time.Second,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// All /api/* paths should share the same rate limit
	paths := []string{"/api/users", "/api/orders", "/api/products"}
	for _, path := range paths[:2] {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", path, rec.Code)
		}
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest("GET", paths[2], nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("%s: expected 429, got %d", paths[2], rec.Code)
	}
}

func TestRouter_UnmatchedPath(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/*",
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Second,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// /other paths should not be rate limited (no matching config)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/other/path", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("/other/path request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRouter_CustomOptions(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	customOnLimited := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Custom message"))
	}

	router, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/*",
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Second,
			},
		},
	}, WithOnLimited(customOnLimited))
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}
	defer router.Close()

	// Use up rate limit
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Trigger rate limit
	req = httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503, got %d", rec.Code)
	}

	if rec.Body.String() != "Custom message" {
		t.Errorf("Unexpected body: %s", rec.Body.String())
	}
}

func TestRouter_InvalidConfig(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Invalid rate
	_, err := NewRouter(handler, s, []EndpointConfig{
		{
			Path: "/api/*",
			Config: ratelimiter.Config{
				Rate:   0, // Invalid
				Window: time.Second,
			},
		},
	})
	if err == nil {
		t.Error("Expected error for invalid config")
	}
}
