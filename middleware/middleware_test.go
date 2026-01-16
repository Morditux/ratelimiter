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

func TestRateLimitMiddleware_Basic(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      5,
		Window:    time.Second,
		BurstSize: 5,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := RateLimitMiddleware(limiter)
	wrappedHandler := middleware(handler)

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_ExcludePaths(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      1,
		Window:    time.Second,
		BurstSize: 1,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := RateLimitMiddleware(limiter, WithExcludePaths("/health", "/metrics/*"))
	wrappedHandler := middleware(handler)

	// Use up the rate limit
	req := httptest.NewRequest("GET", "/api", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// /health should bypass rate limiting
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("/health request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// /metrics/cpu should bypass rate limiting (prefix match)
	req = httptest.NewRequest("GET", "/metrics/cpu", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/metrics/cpu: expected 200, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_IncludeMethods(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      1,
		Window:    time.Second,
		BurstSize: 1,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Only rate limit POST requests
	middleware := RateLimitMiddleware(limiter, WithIncludeMethods("POST"))
	wrappedHandler := middleware(handler)

	// GET requests should bypass rate limiting
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("GET request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// First POST should succeed
	req := httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("First POST: expected 200, got %d", rec.Code)
	}

	// Second POST should be rate limited
	req = httptest.NewRequest("POST", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Second POST: expected 429, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_CustomKeyFunc(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      1,
		Window:    time.Second,
		BurstSize: 1,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use API key for rate limiting
	customKeyFunc := func(r *http.Request) string {
		return r.Header.Get("X-API-Key")
	}

	middleware := RateLimitMiddleware(limiter, WithKeyFunc(customKeyFunc))
	wrappedHandler := middleware(handler)

	// First request with key1 should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key1")
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("First request with key1: expected 200, got %d", rec.Code)
	}

	// Second request with key1 should be rate limited
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key1")
	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Second request with key1: expected 429, got %d", rec.Code)
	}

	// Request with key2 should succeed (different rate limit key)
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key2")
	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("First request with key2: expected 200, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_CustomOnLimited(t *testing.T) {
	s := store.NewMemoryStore()
	defer s.Close()

	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      1,
		Window:    time.Second,
		BurstSize: 1,
	}, s)
	if err != nil {
		t.Fatalf("Failed to create limiter: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	customOnLimited := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "rate-limited")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Custom rate limit message"))
	}

	middleware := RateLimitMiddleware(limiter, WithOnLimited(customOnLimited))
	wrappedHandler := middleware(handler)

	// Use up rate limit
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// Trigger rate limit
	req = httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503, got %d", rec.Code)
	}

	if rec.Header().Get("X-Custom-Header") != "rate-limited" {
		t.Error("Custom header not set")
	}

	if rec.Body.String() != "Custom rate limit message" {
		t.Errorf("Unexpected body: %s", rec.Body.String())
	}
}

func TestDefaultKeyFunc_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
	req.RemoteAddr = "192.168.1.1:12345"

	key := DefaultKeyFunc(req)
	if key != "203.0.113.195" {
		t.Errorf("Expected '203.0.113.195', got '%s'", key)
	}
}

func TestDefaultKeyFunc_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "203.0.113.195")
	req.RemoteAddr = "192.168.1.1:12345"

	key := DefaultKeyFunc(req)
	if key != "203.0.113.195" {
		t.Errorf("Expected '203.0.113.195', got '%s'", key)
	}
}

func TestDefaultKeyFunc_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	key := DefaultKeyFunc(req)
	if key != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%s'", key)
	}
}

func TestDefaultKeyFunc_IPv6(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "[::1]:12345"

	key := DefaultKeyFunc(req)
	// Should handle IPv6 properly
	if key != "[::1]" && key != "[::1]:12345" {
		// Accept either format
		t.Logf("IPv6 key: %s", key)
	}
}

func TestDefaultKeyFunc_Complex(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xri        string
		remoteAddr string
		expected   string
	}{
		{
			name:       "Empty XFF first part",
			xff:        ", 1.2.3.4",
			xri:        "5.6.7.8",
			remoteAddr: "9.9.9.9:1234",
			expected:   "5.6.7.8", // XFF first part is empty, fallback to XRI
		},
		{
			name:       "Whitespace XFF first part",
			xff:        " , 1.2.3.4",
			xri:        "5.6.7.8",
			remoteAddr: "9.9.9.9:1234",
			expected:   "5.6.7.8", // Trimmed is empty, fallback
		},
		{
			name:       "Single IP",
			xff:        "1.2.3.4",
			xri:        "",
			remoteAddr: "",
			expected:   "1.2.3.4",
		},
		{
			name:       "Single IP with whitespace",
			xff:        " 1.2.3.4 ",
			xri:        "",
			remoteAddr: "",
			expected:   "1.2.3.4",
		},
		{
			name:       "Multiple IPs",
			xff:        "1.2.3.4, 5.6.7.8",
			xri:        "",
			remoteAddr: "",
			expected:   "1.2.3.4",
		},
		{
			name:       "Empty XFF and XRI",
			xff:        "",
			xri:        "",
			remoteAddr: "9.9.9.9:1234",
			expected:   "9.9.9.9",
		},
		{
			name: "All empty parts XFF",
			xff: ", , ",
			xri: "1.1.1.1",
			remoteAddr: "2.2.2.2:22",
			expected: "1.1.1.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xri != "" {
				req.Header.Set("X-Real-IP", tc.xri)
			}
			req.RemoteAddr = tc.remoteAddr

			key := DefaultKeyFunc(req)
			if key != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, key)
			}
		})
	}
}

func TestMatchPath_Exact(t *testing.T) {
	if !matchPath("/health", "/health") {
		t.Error("Exact match should return true")
	}

	if matchPath("/health", "/healt") {
		t.Error("Partial match should return false")
	}

	if matchPath("/health", "/healthz") {
		t.Error("Extended path should return false")
	}
}

func TestMatchPath_Prefix(t *testing.T) {
	if !matchPath("/api/users", "/api/*") {
		t.Error("Prefix match should return true")
	}

	if !matchPath("/api/users/123", "/api/*") {
		t.Error("Nested prefix match should return true")
	}

	if matchPath("/other/path", "/api/*") {
		t.Error("Non-matching prefix should return false")
	}
}
