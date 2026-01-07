package middleware

import (
	"net/http"
	"testing"
)

func TestGetRemoteIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "IPv4 with port",
			remoteAddr: "1.2.3.4:1234",
			want:       "1.2.3.4",
		},
		{
			name:       "IPv6 with port and brackets",
			remoteAddr: "[::1]:1234",
			want:       "::1",
		},
		{
			name:       "IPv6 with port and brackets (long)",
			remoteAddr: "[2001:db8::1]:8080",
			want:       "2001:db8::1",
		},
		{
			name:       "IPv4 only (fallback)",
			remoteAddr: "1.2.3.4",
			want:       "1.2.3.4",
		},
		{
			name:       "IPv6 only (fallback, ambiguous but returned as is)",
			remoteAddr: "::1",
			want:       "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			got := getRemoteIP(req)
			if got != tt.want {
				t.Errorf("getRemoteIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustedIPKeyFunc_IPv6_Security(t *testing.T) {
	// Ensure that untrusted IPv6 addresses are correctly identified and stop the chain
	keyFunc, err := TrustedIPKeyFunc([]string{"127.0.0.1"}) // Only trust localhost IPv4
	if err != nil {
		t.Fatalf("Failed to create key func: %v", err)
	}

	req, _ := http.NewRequest("GET", "/", nil)
	// Untrusted IPv6 address
	req.RemoteAddr = "[2001:db8::1]:12345"
	// Spoofed XFF
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	key := keyFunc(req)
	// Should be the remote IP (stripped of brackets), not the spoofed XFF
	expected := "2001:db8::1"
	if key != expected {
		t.Errorf("TrustedIPKeyFunc security bypass: got %s, want %s", key, expected)
	}
}
