// Package middleware provides HTTP middleware for rate limiting.
package middleware

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
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
// Note: This function blindly trusts X-Forwarded-For, which can be spoofed.
// Use TrustedIPKeyFunc for a secure alternative when behind a proxy.
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

	return getRemoteIP(r)
}

// TrustedIPKeyFunc returns a KeyFunc that securely extracts the client IP
// by trusting only specific proxies. It parses X-Forwarded-For from right to left,
// skipping IPs that match the trustedProxies list.
// trustedProxies can be individual IPs or CIDR blocks (e.g., "10.0.0.0/8").
func TrustedIPKeyFunc(trustedProxies []string) (KeyFunc, error) {
	cidrs := make([]*net.IPNet, 0, len(trustedProxies))
	for _, t := range trustedProxies {
		_, network, err := net.ParseCIDR(t)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(t)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP or CIDR: %s", t)
			}
			// Convert single IP to /32 or /128 CIDR
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		cidrs = append(cidrs, network)
	}

	return func(r *http.Request) string {
		remoteIP := getRemoteIP(r)

		// Collect all IPs: [...X-Forwarded-For, RemoteAddr]
		var ips []string
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for _, p := range parts {
				ips = append(ips, strings.TrimSpace(p))
			}
		}
		ips = append(ips, remoteIP)

		// Iterate backwards
		for i := len(ips) - 1; i >= 0; i-- {
			ipStr := ips[i]
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue // Skip invalid IPs
			}

			isTrusted := false
			for _, cidr := range cidrs {
				if cidr.Contains(ip) {
					isTrusted = true
					break
				}
			}

			if !isTrusted {
				return ipStr
			}
		}

		// If all are trusted, return the first one (original client)
		// or the last one if list is empty (shouldn't happen)
		if len(ips) > 0 {
			return ips[0]
		}
		return remoteIP
	}, nil
}

// getRemoteIP extracts the IP from RemoteAddr, handling IPv6 brackets and ports.
func getRemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
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
				// FAIL SECURE: If the key is too long (likely an attack or misconfiguration),
				// reject the request with 400 Bad Request or 431 Request Header Fields Too Large.
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

				// FAIL OPEN: Log error but allow request on other errors (e.g. redis down)
				// This ensures system resilience.
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
		if strings.HasPrefix(path, prefix) {
			return true
		}
		// Also match the path without the trailing slash if the prefix ends with /
		// e.g. /api/* (prefix /api/) should match /api
		if strings.HasSuffix(prefix, "/") {
			noSlash := strings.TrimSuffix(prefix, "/")
			if path == noSlash {
				return true
			}
		}
		return false
	}
	return path == pattern
}
