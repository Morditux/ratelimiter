// Example: Per-endpoint rate limiting
//
// This example demonstrates how to configure different rate limits
// for different API endpoints using the Router.
//
// Run with: go run examples/per_endpoint/main.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/middleware"
	"github.com/Morditux/ratelimiter/store"
)

func main() {
	// Create a memory store
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	// Create the main handler (simple router for demo)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{
			"path":   r.URL.Path,
			"method": r.Method,
			"status": "success",
		}
		json.NewEncoder(w).Encode(response)
	})

	// Custom response when rate limited
	onLimited := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		response := map[string]interface{}{
			"error":       "rate_limit_exceeded",
			"message":     "Too many requests, please slow down",
			"retry_after": 60,
			"path":        r.URL.Path,
		}
		json.NewEncoder(w).Encode(response)
	}

	// Configure per-endpoint rate limits
	router, err := middleware.NewRouter(handler, memStore, []middleware.EndpointConfig{
		{
			// Strict limit for authentication endpoints
			Path: "/api/auth/*",
			Config: ratelimiter.Config{
				Rate:   5, // Only 5 requests per minute
				Window: time.Minute,
			},
			Algorithm: middleware.AlgorithmSlidingWindow,
		},
		{
			// Higher limit for data endpoints
			Path: "/api/data/*",
			Config: ratelimiter.Config{
				Rate:      100,
				Window:    time.Minute,
				BurstSize: 20, // Allow bursts
			},
			Algorithm: middleware.AlgorithmTokenBucket,
		},
		{
			// File upload: limit only POST
			Path:    "/api/upload",
			Methods: []string{"POST"},
			Config: ratelimiter.Config{
				Rate:   10,
				Window: time.Minute,
			},
			Algorithm: middleware.AlgorithmTokenBucket,
		},
		{
			// Default for all other /api/* paths
			Path: "/api/*",
			Config: ratelimiter.Config{
				Rate:   50,
				Window: time.Minute,
			},
			Algorithm: middleware.AlgorithmTokenBucket,
		},
	}, middleware.WithOnLimited(onLimited))

	if err != nil {
		log.Fatal(err)
	}
	defer router.Close()

	fmt.Println("Server starting on :8080")
	fmt.Println("")
	fmt.Println("Endpoint rate limits:")
	fmt.Println("  /api/auth/*   : 5 req/min  (Sliding Window)")
	fmt.Println("  /api/data/*   : 100 req/min, burst 20 (Token Bucket)")
	fmt.Println("  /api/upload   : 10 POST req/min (Token Bucket)")
	fmt.Println("  /api/*        : 50 req/min (Token Bucket)")
	fmt.Println("  other paths   : no rate limit")
	fmt.Println("")
	fmt.Println("Test commands:")
	fmt.Println("  Auth limit:  for i in {1..10}; do curl -s http://localhost:8080/api/auth/login | jq -c; done")
	fmt.Println("  Data limit:  for i in {1..25}; do curl -s http://localhost:8080/api/data/users | jq -c; done")
	fmt.Println("  No limit:    for i in {1..20}; do curl -s http://localhost:8080/other | jq -c; done")

	log.Fatal(http.ListenAndServe(":8080", router))
}
