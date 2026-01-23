/*
Package ratelimiter provides a modular, high-performance rate limiting library for Go.

It features standard rate limiting algorithms like Token Bucket and Sliding Window,
support for pluggable storage backends, and ready-to-use HTTP middleware with
per-endpoint configuration.

# Architecture

The library is organized into several components:
  - Core: Defines the Limiter interface and Config structure.
  - Algorithms: Implements rate limiting logic (Token Bucket, Sliding Window).
  - Store: Provides storage backends (In-memory, extensible for Redis/Memcached).
  - Middleware: Integrates rate limiting with net/http.

# Algorithms

The library provides two main algorithms:

  - Token Bucket (algorithms.NewTokenBucket): Best for APIs that allow for short
    bursts of traffic while maintaining a steady average rate. It uses a "bucket"
    that refills with tokens over time.
  - Sliding Window (algorithms.NewSlidingWindow): Provides a stricter rate limit
    by using a weighted count from the previous and current time windows. It is
    more accurate than fixed windows and does not allow bursting.

# Storage

Rate limiting state is persisted using a Store. The library includes:

  - MemoryStore: A thread-safe, in-memory store with automatic background cleanup.
    It is ideal for single-node applications or development.

External stores like Redis or Memcached can be implemented by satisfying the
store.Store interface.

# HTTP Middleware

The middleware package provides easy integration with Go's net/http:

  - RateLimitMiddleware: A standard middleware that applies a single rate limit
    to all requests (with optional exclusions).
  - Router: A specialized handler that allows defining different rate limits
    for different URL paths and HTTP methods.

Example with Middleware Options:

	limiter, _ := algorithms.NewTokenBucket(ratelimiter.Config{
	    Rate:   100,
	    Window: time.Minute,
	}, memStore)

	handler := middleware.RateLimitMiddleware(limiter,
	    middleware.WithKeyFunc(myCustomKeyFunc),
	    middleware.WithExcludePaths("/health", "/static/*"),
	    middleware.WithOnLimited(myCustomLimitHandler),
	)(myHandler)

# Security Considerations

By default, the IP extraction logic trusts headers like X-Forwarded-For.
In production environments behind a proxy, it is highly recommended to use
middleware.TrustedIPKeyFunc to specify which proxy IPs can be trusted to
prevent IP spoofing attacks.

# Performance

The library is optimized for high-performance scenarios, utilizing sharded locks
to reduce contention and minimizing allocations in the hot path.
*/
package ratelimiter
