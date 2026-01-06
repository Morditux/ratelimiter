// Package middleware provides HTTP middleware for rate limiting.
package middleware

import (
	"net/http"
	"strings"

	"github.com/Morditux/ratelimiter"
)

// KeyFunc is a function that extracts a rate limiting key from a request.
// Common implementations include IP-based, user-based, or API key-based extraction.
type KeyFunc func(r *http.Request) string

// OnLimitedFunc is called when a request is rate limited.
// It should write the appropriate response to w.
type OnLimitedFunc func(w http.ResponseWriter, r *http.Request)

// Options configures the rate limiting middleware behavior.
type Options struct {
	// KeyFunc extracts the rate limiting key from the request.
	// Default: IP address from X-Forwarded-For or RemoteAddr.
	KeyFunc KeyFunc

	// OnLimited is called when a request is rate limited.
	// Default: Returns 429 Too Many Requests with a JSON body.
	OnLimited OnLimitedFunc

	// ExcludePaths are paths that bypass rate limiting.
	ExcludePaths []string

	// IncludeMethods limits rate limiting to specific HTTP methods.
	// Empty means all methods are rate limited.
	IncludeMethods []string
}

// Option is a function that configures Options.
type Option func(*Options)

// WithKeyFunc sets a custom key extraction function.
func WithKeyFunc(fn KeyFunc) Option {
	return func(o *Options) {
		o.KeyFunc = fn
	}
}

// WithOnLimited sets a custom rate limit exceeded handler.
func WithOnLimited(fn OnLimitedFunc) Option {
	return func(o *Options) {
		o.OnLimited = fn
	}
}

// WithExcludePaths sets paths to exclude from rate limiting.
func WithExcludePaths(paths ...string) Option {
	return func(o *Options) {
		o.ExcludePaths = paths
	}
}

// WithIncludeMethods limits rate limiting to specific HTTP methods.
func WithIncludeMethods(methods ...string) Option {
	return func(o *Options) {
		o.IncludeMethods = methods
	}
}

// DefaultKeyFunc extracts the client IP from the request.
// It checks X-Forwarded-For, X-Real-IP, and falls back to RemoteAddr.
func DefaultKeyFunc(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (strip port if present)
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		// Check if this looks like IPv6 (contains multiple colons)
		if strings.Count(addr, ":") > 1 {
			// IPv6 address, look for bracket
			if bracketIdx := strings.LastIndex(addr, "]"); bracketIdx != -1 {
				if colonIdx := strings.LastIndex(addr[bracketIdx:], ":"); colonIdx != -1 {
					return addr[:bracketIdx+1]
				}
				return addr
			}
			return addr
		}
		return addr[:idx]
	}

	return addr
}

// DefaultOnLimited returns a 429 response with a JSON body.
func DefaultOnLimited(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"rate limit exceeded","message":"too many requests, please try again later"}`))
}

// RateLimitMiddleware creates a rate limiting middleware.
func RateLimitMiddleware(limiter ratelimiter.Limiter, opts ...Option) func(http.Handler) http.Handler {
	options := &Options{
		KeyFunc:   DefaultKeyFunc,
		OnLimited: DefaultOnLimited,
	}

	for _, opt := range opts {
		opt(options)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check excluded paths
			for _, path := range options.ExcludePaths {
				if matchPath(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check included methods
			if len(options.IncludeMethods) > 0 {
				methodIncluded := false
				for _, method := range options.IncludeMethods {
					if strings.EqualFold(r.Method, method) {
						methodIncluded = true
						break
					}
				}
				if !methodIncluded {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Get the rate limiting key
			key := options.KeyFunc(r)

			// Check the rate limit
			allowed, err := limiter.Allow(key)
			if err != nil {
				// Log error but allow request on error (fail open)
				next.ServeHTTP(w, r)
				return
			}

			if !allowed {
				options.OnLimited(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// matchPath checks if a request path matches a pattern.
// Supports exact match and prefix match (pattern ending with *).
func matchPath(path, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}
