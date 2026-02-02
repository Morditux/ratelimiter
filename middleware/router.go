package middleware

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"path"
	"sort"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/algorithms"
	"github.com/Morditux/ratelimiter/store"
)

// Algorithm represents the rate limiting algorithm to use.
type Algorithm string

const (
	// AlgorithmTokenBucket uses the token bucket algorithm.
	AlgorithmTokenBucket Algorithm = "token_bucket"

	// AlgorithmSlidingWindow uses the sliding window algorithm.
	AlgorithmSlidingWindow Algorithm = "sliding_window"
)

// EndpointConfig holds the rate limit configuration for a specific endpoint.
type EndpointConfig struct {
	// Path is the URL path to match.
	// Supports exact match and prefix match (ending with *).
	Path string

	// Methods are the HTTP methods to match.
	// Empty means all methods.
	Methods []string

	// Config is the rate limit configuration for this endpoint.
	Config ratelimiter.Config

	// Algorithm is the rate limiting algorithm to use.
	// Default: AlgorithmTokenBucket
	Algorithm Algorithm
}

// Router is an HTTP handler that applies per-endpoint rate limiting.
type Router struct {
	endpoints []endpointLimiter
	store     store.Store
	handler   http.Handler
	options   *Options
}

// endpointLimiter holds a compiled endpoint configuration.
type endpointLimiter struct {
	config  EndpointConfig
	limiter ratelimiter.Limiter
}

// NewRouter creates a new router with per-endpoint rate limiting.
func NewRouter(handler http.Handler, s store.Store, endpoints []EndpointConfig, opts ...Option) (*Router, error) {
	options := &Options{
		KeyFunc:    DefaultKeyFunc,
		OnLimited:  DefaultOnLimited,
		MaxKeySize: 4096,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.MaxKeySize <= 0 {
		options.MaxKeySize = 4096
	}

	r := &Router{
		endpoints: make([]endpointLimiter, 0, len(endpoints)),
		store:     s,
		handler:   handler,
		options:   options,
	}

	// Sort endpoints by specificity to prevent route shadowing
	// 1. Exact match > Prefix match
	// 2. Longer path > Shorter path
	// 3. Specific methods > All methods
	sortedEndpoints := make([]EndpointConfig, len(endpoints))
	copy(sortedEndpoints, endpoints)

	sort.SliceStable(sortedEndpoints, func(i, j int) bool {
		ep1 := sortedEndpoints[i]
		ep2 := sortedEndpoints[j]

		// Check for prefix match (ending in *)
		isPrefix1 := len(ep1.Path) > 0 && ep1.Path[len(ep1.Path)-1] == '*'
		isPrefix2 := len(ep2.Path) > 0 && ep2.Path[len(ep2.Path)-1] == '*'

		// 1. Exact match takes precedence over prefix match
		if isPrefix1 != isPrefix2 {
			return !isPrefix1 // If 1 is exact (not prefix), it comes first
		}

		// 2. Longer path takes precedence (more specific)
		if len(ep1.Path) != len(ep2.Path) {
			return len(ep1.Path) > len(ep2.Path)
		}

		// 3. Specific methods take precedence over all methods
		hasMethods1 := len(ep1.Methods) > 0
		hasMethods2 := len(ep2.Methods) > 0

		if hasMethods1 != hasMethods2 {
			return hasMethods1
		}

		return false
	})

	// Create limiters for each endpoint
	for _, ep := range sortedEndpoints {
		limiter, err := r.createLimiter(ep)
		if err != nil {
			return nil, err
		}

		r.endpoints = append(r.endpoints, endpointLimiter{
			config:  ep,
			limiter: limiter,
		})
	}

	return r, nil
}

// ServeHTTP implements the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Find matching endpoint
	for _, ep := range r.endpoints {
		if r.matchEndpoint(req, ep.config) {
			key := r.options.KeyFunc(req) + ":" + ep.config.Path

			// FAIL SECURE: Check key length early to prevent DoS (memory/cpu) in the limiter/store.
			if len(key) > r.options.MaxKeySize {
				writeError(w, "Rate limit key too long", http.StatusRequestHeaderFieldsTooLarge)
				return
			}

			var allowed bool
			var err error

			if detailsLimiter, ok := ep.limiter.(ratelimiter.LimiterWithDetails); ok {
				var result ratelimiter.Result
				result, err = detailsLimiter.AllowNWithDetails(key, 1)
				allowed = result.Allowed

				// Set headers
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
				w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))

				if !allowed && result.RetryAfter > 0 {
					seconds := int(math.Ceil(result.RetryAfter.Seconds()))
					if seconds < 1 {
						seconds = 1
					}
					w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
				}
			} else {
				allowed, err = ep.limiter.Allow(key)
			}

			if err != nil {
				// FAIL SECURE: If the key is too long (likely an attack or misconfiguration),
				// reject the request with 431 Request Header Fields Too Large.
				if errors.Is(err, store.ErrKeyTooLong) {
					writeError(w, "Rate limit key too long", http.StatusRequestHeaderFieldsTooLarge)
					return
				}

				// FAIL SECURE: If the store is full, we must reject the request to prevent
				// rate limit bypass. When the store is full, we cannot persist the state,
				// so we cannot enforce the limit.
				if errors.Is(err, store.ErrStoreFull) {
					writeError(w, "Rate limit store full", http.StatusServiceUnavailable)
					return
				}

				// Fail open on other errors (e.g. redis down) to ensure system resilience
				r.handler.ServeHTTP(w, req)
				return
			}

			if !allowed {
				r.options.OnLimited(w, req)
				return
			}

			r.handler.ServeHTTP(w, req)
			return
		}
	}

	// No matching endpoint, allow request
	r.handler.ServeHTTP(w, req)
}

// matchEndpoint checks if a request matches an endpoint configuration.
func (r *Router) matchEndpoint(req *http.Request, config EndpointConfig) bool {
	// Normalize path to prevent bypasses
	// e.g. //api/sensitive -> /api/sensitive
	cleanPath := path.Clean(req.URL.Path)

	// Check path
	if !matchPath(cleanPath, config.Path) {
		return false
	}

	// Check methods if specified
	if len(config.Methods) > 0 {
		methodMatch := false
		for _, method := range config.Methods {
			if req.Method == method {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			return false
		}
	}

	return true
}

// createLimiter creates a rate limiter for an endpoint configuration.
func (r *Router) createLimiter(config EndpointConfig) (ratelimiter.Limiter, error) {
	switch config.Algorithm {
	case AlgorithmSlidingWindow:
		return algorithms.NewSlidingWindow(config.Config, r.store)
	case AlgorithmTokenBucket, "":
		return algorithms.NewTokenBucket(config.Config, r.store)
	default:
		return algorithms.NewTokenBucket(config.Config, r.store)
	}
}

// Close releases resources held by the router.
func (r *Router) Close() error {
	return r.store.Close()
}
