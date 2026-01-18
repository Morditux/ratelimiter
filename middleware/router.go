package middleware

import (
	"errors"
	"net/http"

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
		KeyFunc:   DefaultKeyFunc,
		OnLimited: DefaultOnLimited,
	}

	for _, opt := range opts {
		opt(options)
	}

	r := &Router{
		endpoints: make([]endpointLimiter, 0, len(endpoints)),
		store:     s,
		handler:   handler,
		options:   options,
	}

	// Create limiters for each endpoint
	for _, ep := range endpoints {
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

			allowed, err := ep.limiter.Allow(key)
			if err != nil {
				// FAIL SECURE: If the key is too long (likely an attack or misconfiguration),
				// reject the request with 431 Request Header Fields Too Large.
				if errors.Is(err, store.ErrKeyTooLong) {
					http.Error(w, "Rate limit key too long", http.StatusRequestHeaderFieldsTooLarge)
					return
				}

				// FAIL SECURE: If the store is full, we must reject the request to prevent
				// rate limit bypass. When the store is full, we cannot persist the state,
				// so we cannot enforce the limit.
				if errors.Is(err, store.ErrStoreFull) {
					http.Error(w, "Rate limit store full", http.StatusServiceUnavailable)
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
	// Check path
	if !matchPath(req.URL.Path, config.Path) {
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
