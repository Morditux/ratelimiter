package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

// WrappedErrorStore wraps errors to test robust error handling.
type WrappedErrorStore struct {
	store.Store
	errToReturn error
}

func (s *WrappedErrorStore) Get(key string) (interface{}, bool) {
	return nil, false
}

func (s *WrappedErrorStore) Set(key string, value interface{}, ttl time.Duration) error {
	return fmt.Errorf("wrapped: %w", s.errToReturn)
}

func TestRouterWrappedErrors(t *testing.T) {
	tests := []struct {
		name           string
		errToReturn    error
		expectedStatus int
	}{
		{
			name:           "Wrapped ErrStoreFull",
			errToReturn:    store.ErrStoreFull,
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "Wrapped ErrKeyTooLong",
			errToReturn:    store.ErrKeyTooLong,
			expectedStatus: http.StatusRequestHeaderFieldsTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &WrappedErrorStore{errToReturn: tt.errToReturn}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			// Configure router
			cfg := EndpointConfig{
				Path: "/test",
				Config: ratelimiter.Config{
					Rate:      10,
					Window:    time.Minute,
					BurstSize: 10,
				},
			}

			router, err := NewRouter(handler, s, []EndpointConfig{cfg})
			if err != nil {
				t.Fatalf("NewRouter failed: %v", err)
			}

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

func TestDefaultOnLimitedSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	DefaultOnLimited(w, req)

	headers := []struct {
		key   string
		value string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Content-Type", "application/json"},
	}

	for _, h := range headers {
		if got := w.Header().Get(h.key); got != h.value {
			t.Errorf("expected header %s: %s, got %s", h.key, h.value, got)
		}
	}
}
