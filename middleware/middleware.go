// Package middleware provides HTTP middleware for rate limiting.
package middleware

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"path"
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

	// MaxKeySize is the maximum allowed length of a rate limit key.
	// Keys exceeding this length will be rejected with 431 Request Header Fields Too Large.
	// Default: 4096.
	MaxKeySize int
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

// WithMaxKeySize sets the maximum allowed length of a rate limit key.
func WithMaxKeySize(size int) Option {
	return func(o *Options) {
		o.MaxKeySize = size
	}
}

// DefaultKeyFunc extracts the client IP from the request.
// It checks X-Forwarded-For, X-Real-IP, and falls back to RemoteAddr.
// Note: This function blindly trusts X-Forwarded-For, which can be spoofed.
// It validates that the extracted value is a valid IP address to prevent
// storage exhaustion attacks with garbage keys.
// Use TrustedIPKeyFunc for a secure alternative when behind a proxy.
func DefaultKeyFunc(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Optimized to avoid strings.Split (memory DoS prevention)
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			if ip := strings.TrimSpace(xff[:idx]); ip != "" {
				cleanIP := stripIPPort(ip)
				if ipObj := net.ParseIP(cleanIP); ipObj != nil {
					return ipObj.String()
				}
			}
		} else {
			if ip := strings.TrimSpace(xff); ip != "" {
				cleanIP := stripIPPort(ip)
				if ipObj := net.ParseIP(cleanIP); ipObj != nil {
					return ipObj.String()
				}
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		cleanIP := stripIPPort(xri)
		if ipObj := net.ParseIP(cleanIP); ipObj != nil {
			return ipObj.String()
		}
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
		// Handle multiple X-Forwarded-For headers by checking all values
		xffHeaders := r.Header.Values("X-Forwarded-For")
		if len(xffHeaders) == 0 {
			return remoteIP
		}

		// Iterate backwards through all XFF headers (starting from the last header)
		for i := len(xffHeaders) - 1; i >= 0; i-- {
			xff := xffHeaders[i]
			// Iterate backwards through the current XFF header string
			idx := len(xff)
			for idx > 0 {
				prevComma := strings.LastIndexByte(xff[:idx], ',')
				var part string
				if prevComma == -1 {
					part = xff[:idx]
					idx = -1 // Stop after this in current header
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
					return ip.String()
				}
			}
		}

		// 3. If all are trusted, return the first IP (original client)
		// Use optimized extraction for first IP from the first header
		firstHeader := xffHeaders[0]
		if idx := strings.IndexByte(firstHeader, ','); idx >= 0 {
			if ip := strings.TrimSpace(firstHeader[:idx]); ip != "" {
				cleanIP := stripIPPort(ip)
				if ipObj := net.ParseIP(cleanIP); ipObj != nil {
					return ipObj.String()
				}
				return cleanIP
			}
		} else {
			if ip := strings.TrimSpace(firstHeader); ip != "" {
				cleanIP := stripIPPort(ip)
				if ipObj := net.ParseIP(cleanIP); ipObj != nil {
					return ipObj.String()
				}
				return ip
			}
		}

		return remoteIP
	}, nil
}

// getRemoteIP extracts the IP from RemoteAddr, handling IPv6 brackets and ports.
func getRemoteIP(r *http.Request) string {
	ipStr := stripIPPort(r.RemoteAddr)
	if ip := net.ParseIP(ipStr); ip != nil {
		return ip.String()
	}
	return ipStr
}

// stripIPPort removes the port from an IP address if present.
// It handles IPv6 brackets and ensures only the IP is returned.
func stripIPPort(addr string) string {
	if len(addr) == 0 {
		return addr
	}

	// IPv6 with port [::1]:8080 or just [::1]
	if addr[0] == '[' {
		// Find the closing bracket
		end := strings.IndexByte(addr, ']')
		if end < 0 {
			return addr // Malformed
		}
		// Return content inside brackets (canonicalize to IP)
		// e.g. [::1] -> ::1
		return addr[1:end]
	}

	// IPv4 with port 1.2.3.4:8080
	// Check for multiple colons (IPv6 without brackets)
	firstColon := strings.IndexByte(addr, ':')
	if firstColon != -1 {
		lastColon := strings.LastIndexByte(addr, ':')
		if firstColon == lastColon {
			// Exactly one colon, treat as Host:Port
			return addr[:lastColon]
		}
		// Multiple colons -> IPv6 without brackets or malformed
		// Return original to match net.SplitHostPort behavior
	}

	return addr
}

// writeError writes an error response with security headers.
func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	http.Error(w, msg, code)
}

// DefaultOnLimited returns a 429 response with a JSON body.
func DefaultOnLimited(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "interest-cohort=()")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"rate limit exceeded","message":"too many requests, please try again later"}`))
}

// RateLimitMiddleware creates a rate limiting middleware.
func RateLimitMiddleware(limiter ratelimiter.Limiter, opts ...Option) func(http.Handler) http.Handler {
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check excluded paths
			if len(options.ExcludePaths) > 0 {
				// Normalize path to ensure consistent matching
				cleanPath := path.Clean(r.URL.Path)
				for _, p := range options.ExcludePaths {
					if matchPath(cleanPath, p) {
						next.ServeHTTP(w, r)
						return
					}
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

			// FAIL SECURE: Check key length early to prevent DoS (memory/cpu) in the limiter/store.
			if len(key) > options.MaxKeySize {
				writeError(w, "Rate limit key too long", http.StatusRequestHeaderFieldsTooLarge)
				return
			}

			var allowed bool
			var err error

			// Check if limiter supports details
			if detailsLimiter, ok := limiter.(ratelimiter.LimiterWithDetails); ok {
				var result ratelimiter.Result
				result, err = detailsLimiter.AllowNWithDetails(key, 1)
				allowed = result.Allowed

				// Set headers
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
				w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))

				if !allowed && result.RetryAfter > 0 {
					// Round up to nearest second
					seconds := int(math.Ceil(result.RetryAfter.Seconds()))
					if seconds < 1 {
						seconds = 1
					}
					w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
				}
			} else {
				// Check the rate limit using standard interface
				allowed, err = limiter.Allow(key)
			}

			if err != nil {
				// FAIL SECURE: If the key is too long (likely an attack or misconfiguration),
				// reject the request with 400 Bad Request or 431 Request Header Fields Too Large.
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
