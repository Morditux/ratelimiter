package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestDefaultKeyFunc_Canonicalization(t *testing.T) {
	tests := []struct {
		name     string
		header   string // X-Forwarded-For
		expected string
	}{
		{
			name:     "IPv4-mapped IPv6",
			header:   "::ffff:192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 long form",
			header:   "2001:db8:0:0:0:0:0:1",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 short form",
			header:   "2001:db8::1",
			expected: "2001:db8::1",
		},
		{
			name:     "IPv6 with port",
			header:   "[2001:db8:0:0:0:0:0:1]:8080",
			expected: "2001:db8::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tc.header)
			req.RemoteAddr = "127.0.0.1:12345" // Irrelevant

			key := DefaultKeyFunc(req)
			if key != tc.expected {
				t.Errorf("Expected canonical IP %q, got %q", tc.expected, key)
			}
		})
	}
}

func TestTrustedIPKeyFunc_Canonicalization(t *testing.T) {
	// Trusted proxy is 10.0.0.1
	kf, err := TrustedIPKeyFunc([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("Failed to create key func: %v", err)
	}

	tests := []struct {
		name     string
		header   string // X-Forwarded-For
		expected string
	}{
		{
			name:     "IPv4-mapped IPv6 via Trusted Proxy",
			header:   "::ffff:192.168.1.1, 10.0.0.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 long form via Trusted Proxy",
			header:   "2001:db8:0:0:0:0:0:1, 10.0.0.1",
			expected: "2001:db8::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tc.header)
			req.RemoteAddr = "10.0.0.1:12345" // Comes from trusted proxy

			key := kf(req)
			if key != tc.expected {
				t.Errorf("Expected canonical IP %q, got %q", tc.expected, key)
			}
		})
	}
}
