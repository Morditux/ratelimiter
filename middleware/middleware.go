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
		// Optimized to avoid strings.Split (memory DoS prevention)
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			if ip := strings.TrimSpace(xff[:idx]); ip != "" {
				return ip
			}
		} else {
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
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

		// 1. Check RemoteAddr first
		ip := net.ParseIP(remoteIP)
		if ip == nil {
			// If RemoteAddr is invalid, we return it (as untrusted/raw)
			// or fallback to XFF? Original logic appended it and skipped if nil.
			// But if it's the only one, we return it.
			return remoteIP
		}

		isTrusted := false
		for _, cidr := range cidrs {
			if cidr.Contains(ip) {
				isTrusted = true
				break
			}
		}

		if !isTrusted {
			return remoteIP
		}

		// 2. RemoteAddr is trusted, check X-Forwarded-For backwards
		xff := r.Header.Get("X-Forwarded-For")
		if xff == "" {
			return remoteIP
		}

		// Iterate backwards through XFF without allocating slice
		idx := len(xff)
		for idx > 0 {
			prevComma := strings.LastIndexByte(xff[:idx], ',')
			var part string
			if prevComma == -1 {
				part = xff[:idx]
				idx = -1 // Stop after this
			} else {
				part = xff[prevComma+1 : idx]
				idx = prevComma
			}

			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			ip := net.ParseIP(part)
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
				return part
			}
		}

		// 3. If all are trusted, return the first IP (original client)
		// Use optimized extraction for first IP
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			if ip := strings.TrimSpace(xff[:idx]); ip != "" {
				return ip
			}
		} else {
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}

		return remoteIP
	}, nil
}

// getRemoteIP extracts the IP from RemoteAddr, handling IPv6 brackets and ports.
func getRemoteIP(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if len(remoteAddr) == 0 {
		return remoteAddr
	}

	// IPv6 with port [::1]:8080
	if remoteAddr[0] == '[' {
		// Find the closing bracket
		end := strings.IndexByte(remoteAddr, ']')
		if end < 0 {
			return remoteAddr // Malformed
		}
		// Check for colon after bracket
		if end+1 < len(remoteAddr) && remoteAddr[end+1] == ':' {
			return remoteAddr[1:end]
		}
		// No port or malformed, return original to match net.SplitHostPort behavior
		return remoteAddr
	}

	// IPv4 with port 1.2.3.4:8080
	// Check for multiple colons (IPv6 without brackets)
	firstColon := strings.IndexByte(remoteAddr, ':')
	if firstColon != -1 {
		lastColon := strings.LastIndexByte(remoteAddr, ':')
		if firstColon == lastColon {
			// Exactly one colon, treat as Host:Port
			return remoteAddr[:lastColon]
		}
		// Multiple colons -> IPv6 without brackets or malformed
		// Return original to match net.SplitHostPort behavior (which errors on this)
	}

	return remoteAddr
}

// DefaultOnLimited returns a 429 response with a JSON body.
func DefaultOnLimited(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "interest-cohort=()")
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
	n := len(pattern)
	if n > 0 && pattern[n-1] == '*' {
		// optimized prefix match without string manipulation allocations
		prefixLen := n - 1

		// Check if path starts with prefix (pattern without *)
		// Equivalent to strings.HasPrefix(path, pattern[:n-1])
		if len(path) >= prefixLen && path[:prefixLen] == pattern[:prefixLen] {
			return true
		}

		// Special case: pattern ends in /* (e.g. /api/*)
		// match /api as well (pattern without trailing /*)
		// This handles the "noSlash" case efficiently
		if prefixLen > 0 && pattern[prefixLen-1] == '/' {
			baseLen := prefixLen - 1
			if len(path) == baseLen && path == pattern[:baseLen] {
				return true
			}
		}
		return false
	}
	return path == pattern
}
