package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Morditux/ratelimiter/store"
)

func TestRateLimitMiddleware_SecurityHeaders_Errors(t *testing.T) {
	tests := []struct {
		name           string
		limiterErr     error
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "KeyTooLong",
			limiterErr:     store.ErrKeyTooLong,
			expectedStatus: http.StatusRequestHeaderFieldsTooLarge,
			expectedMsg:    "Rate limit key too long",
		},
		{
			name:           "StoreFull",
			limiterErr:     store.ErrStoreFull,
			expectedStatus: http.StatusServiceUnavailable,
			expectedMsg:    "Rate limit store full",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limiter := &MockLimiter{
				AllowFunc: func(key string) (bool, error) {
					return false, tc.limiterErr
				},
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
			middleware := RateLimitMiddleware(limiter)
			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", "/", nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rec.Code)
			}

			// Check security headers
			expectedHeaders := map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "DENY",
				"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
				"Cache-Control":          "no-store",
				"Pragma":                 "no-cache",
			}

			for k, v := range expectedHeaders {
				if got := rec.Header().Get(k); got != v {
					t.Errorf("Header %s: expected %q, got %q", k, v, got)
				}
			}

			// Check Retry-After for StoreFull
			if tc.expectedStatus == http.StatusServiceUnavailable {
				if got := rec.Header().Get("Retry-After"); got != "60" {
					t.Errorf("Retry-After: expected 60, got %q", got)
				}
			}
		})
	}
}

func TestRateLimitMiddleware_MaxKeySize_SecurityHeaders(t *testing.T) {
	// Test the early key length check in middleware
	limiter := &MockLimiter{
		AllowFunc: func(key string) (bool, error) {
			return true, nil
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	// Set small max key size
	middleware := RateLimitMiddleware(limiter, WithMaxKeySize(5))
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/", nil)
	// Key will be "192.0.2.1" which is > 5 chars
	req.RemoteAddr = "192.0.2.1:1234"
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("Expected status %d, got %d", http.StatusRequestHeaderFieldsTooLarge, rec.Code)
	}

	// Check security headers
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":          "no-store",
		"Pragma":                 "no-cache",
	}

	for k, v := range expectedHeaders {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("Header %s: expected %q, got %q", k, v, got)
		}
	}
}
