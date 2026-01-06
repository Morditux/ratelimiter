// Example: Basic rate limiting middleware
//
// This example demonstrates how to use the rate limiter as HTTP middleware
// with basic configuration using the Token Bucket algorithm.
//
// Run with: go run examples/basic/main.go
// Test with: for i in {1..15}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/; done
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/algorithms"
	"github.com/Morditux/ratelimiter/middleware"
	"github.com/Morditux/ratelimiter/store"
)

func main() {
	// Create a memory store for rate limiting data
	memStore := store.NewMemoryStore()
	defer memStore.Close()

	// Create a token bucket limiter: 10 requests per minute with burst of 10
	limiter, err := algorithms.NewTokenBucket(ratelimiter.Config{
		Rate:      10,
		Window:    time.Minute,
		BurstSize: 10,
	}, memStore)
	if err != nil {
		log.Fatal(err)
	}

	// Create the handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message": "Hello, World!"}`))
	})

	// Apply rate limiting middleware
	rateLimitedHandler := middleware.RateLimitMiddleware(limiter,
		middleware.WithExcludePaths("/health"),
	)(handler)

	// Health check endpoint (not rate limited)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// All other endpoints are rate limited
	http.Handle("/", rateLimitedHandler)

	fmt.Println("Server starting on :8080")
	fmt.Println("Rate limit: 10 requests per minute")
	fmt.Println("Try: for i in {1..15}; do curl -s -o /dev/null -w \"%{http_code}\\n\" http://localhost:8080/; done")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
