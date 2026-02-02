package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/middleware"
	"github.com/Morditux/ratelimiter/store"
)

func TestRouter_RouteShadowing(t *testing.T) {
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Intention: Global limit is 100, but critical endpoint is 1.
	// Mistake: Global limit is defined FIRST.
	router, err := middleware.NewRouter(handler, memStore, []middleware.EndpointConfig{
		{
			Path: "/*", // Matches everything
			Config: ratelimiter.Config{
				Rate:   100,
				Window: time.Minute,
			},
		},
		{
			Path: "/critical", // More specific
			Config: ratelimiter.Config{
				Rate:   1,
				Window: time.Minute,
			},
		},
	})

	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}

	// Send 5 requests to /critical
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/critical", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			t.Logf("Request %d rate limited (Correct behavior if specific route matched)", i+1)
		} else {
			t.Logf("Request %d allowed (Incorrect behavior if specific route matched)", i+1)
		}

		// If the specific route was matched, request 2 should fail.
		// If the global route was matched, all 5 should pass.
		if i >= 1 && w.Code != http.StatusTooManyRequests {
			t.Errorf("Security Vulnerability: Route shadowing detected! Request %d to /critical was allowed, bypassing the specific limit of 1.", i+1)
		}
	}
}
