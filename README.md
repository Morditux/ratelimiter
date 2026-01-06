# Rate Limiter

[![Go Reference](https://pkg.go.dev/badge/github.com/Morditux/ratelimiter.svg)](https://pkg.go.dev/github.com/Morditux/ratelimiter)

A modular, high-performance rate limiting library for Go with HTTP middleware support and per-endpoint configuration.

## Features

- **Multiple Algorithms**: Token Bucket and Sliding Window
- **Pluggable Storage**: In-memory store included, extensible interface for Redis/Memcached
- **HTTP Middleware**: Ready to use with `net/http`
- **Per-Endpoint Configuration**: Different rate limits for different endpoints
- **Customizable**: Key extraction, response handling, path exclusions
- **Thread-Safe**: Safe for concurrent use
- **High Performance**: ~300-450 ns/op with parallel access

## Installation

```bash
go get github.com/Morditux/ratelimiter
```

## Quick Start

### Basic Middleware Usage

```go
package main

import (
    "net/http"
    "time"

    "github.com/Morditux/ratelimiter"
    "github.com/Morditux/ratelimiter/algorithms"
    "github.com/Morditux/ratelimiter/middleware"
    "github.com/Morditux/ratelimiter/store"
)

func main() {
    // Create a memory store
    memStore := store.NewMemoryStore()
    defer memStore.Close()

    // Create a token bucket limiter: 100 requests per minute
    limiter, _ := algorithms.NewTokenBucket(ratelimiter.Config{
        Rate:      100,
        Window:    time.Minute,
        BurstSize: 100,
    }, memStore)

    // Your handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })

    // Apply the middleware
    http.Handle("/", middleware.RateLimitMiddleware(limiter)(handler))

    http.ListenAndServe(":8080", nil)
}
```

### Per-Endpoint Configuration

```go
package main

import (
    "net/http"
    "time"

    "github.com/Morditux/ratelimiter"
    "github.com/Morditux/ratelimiter/middleware"
    "github.com/Morditux/ratelimiter/store"
)

func main() {
    memStore := store.NewMemoryStore()
    defer memStore.Close()

    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })

    // Different rate limits for different endpoints
    router, _ := middleware.NewRouter(handler, memStore, []middleware.EndpointConfig{
        {
            Path: "/api/auth/*",
            Config: ratelimiter.Config{
                Rate:   5,              // 5 requests per minute
                Window: time.Minute,
            },
            Algorithm: middleware.AlgorithmSlidingWindow,
        },
        {
            Path: "/api/data/*",
            Config: ratelimiter.Config{
                Rate:      1000,        // 1000 requests per minute
                Window:    time.Minute,
                BurstSize: 100,         // Allow bursts up to 100
            },
            Algorithm: middleware.AlgorithmTokenBucket,
        },
        {
            Path:    "/api/upload",
            Methods: []string{"POST"},  // Only limit POST
            Config: ratelimiter.Config{
                Rate:   10,
                Window: time.Minute,
            },
        },
    })
    defer router.Close()

    http.ListenAndServe(":8080", router)
}
```

### Custom Key Extraction

```go
// Rate limit by API key instead of IP
keyFunc := func(r *http.Request) string {
    return r.Header.Get("X-API-Key")
}

middleware.RateLimitMiddleware(limiter,
    middleware.WithKeyFunc(keyFunc),
)
```

### Custom Response

```go
onLimited := func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusTooManyRequests)
    w.Write([]byte(`{"error": "Rate limit exceeded", "retry_after": 60}`))
}

middleware.RateLimitMiddleware(limiter,
    middleware.WithOnLimited(onLimited),
)
```

### Exclude Paths

```go
middleware.RateLimitMiddleware(limiter,
    middleware.WithExcludePaths("/health", "/metrics/*"),
)
```

## Algorithms

### Token Bucket

Best for APIs that allow bursting but want to maintain an average rate.

- Refills tokens at a steady rate
- Allows short bursts up to `BurstSize`
- Smooth rate limiting over time

```go
limiter, _ := algorithms.NewTokenBucket(ratelimiter.Config{
    Rate:      100,         // 100 requests per window
    Window:    time.Minute, // 1 minute window
    BurstSize: 50,          // Allow bursts up to 50
}, store)
```

### Sliding Window

Best for strict rate limiting without allowing bursts.

- Uses a weighted count from previous and current windows
- More accurate than fixed windows
- No burst capability

```go
limiter, _ := algorithms.NewSlidingWindow(ratelimiter.Config{
    Rate:   100,         // 100 requests per window
    Window: time.Minute, // 1 minute window
}, store)
```

## Storage

### Memory Store

Built-in, thread-safe in-memory storage with automatic cleanup.

```go
// Default configuration
store := store.NewMemoryStore()

// Custom cleanup interval
store := store.NewMemoryStoreWithConfig(store.MemoryStoreConfig{
    CleanupInterval: 5 * time.Minute,
})
```

### Custom Store

Implement the `Store` interface for Redis, Memcached, etc.:

```go
type Store interface {
    Get(key string) (interface{}, bool)
    Set(key string, value interface{}, ttl time.Duration) error
    Delete(key string) error
    Close() error
}
```

## Benchmarks

```
goos: linux
goarch: amd64
cpu: Intel(R) Core(TM) i5-9300H CPU @ 2.40GHz
BenchmarkTokenBucket_Allow-8             2786455    421.1 ns/op
BenchmarkSlidingWindow_Allow-8           3559952    312.8 ns/op
BenchmarkTokenBucket_MultipleKeys-8      2656964    452.6 ns/op
BenchmarkSlidingWindow_MultipleKeys-8    3455830    319.4 ns/op
```

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.
