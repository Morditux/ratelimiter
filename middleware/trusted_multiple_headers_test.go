package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestTrustedIPKeyFunc_MultipleHeaders(t *testing.T) {
	// Trusted proxy is 10.0.0.1
	trustedIPs := []string{"10.0.0.1"}
	keyFunc, err := TrustedIPKeyFunc(trustedIPs)
	if err != nil {
		t.Fatalf("Failed to create key func: %v", err)
	}

	// Scenario:
	// Attacker sends: X-Forwarded-For: 1.2.3.4 (Spoofed)
	// Trusted Proxy (10.0.0.1) appends: X-Forwarded-For: 203.0.113.1 (Real Client)
	// Some proxies might add a new header line instead of appending to the existing one.

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345" // Comes from trusted proxy

	// Set multiple X-Forwarded-For headers manually
	// Go's Header map is map[string][]string
	req.Header["X-Forwarded-For"] = []string{"1.2.3.4", "203.0.113.1"}

	// We expect the KeyFunc to see "1.2.3.4, 203.0.113.1" (logically)
	// And since 10.0.0.1 is trusted, it should look at the last IP in XFF chain: 203.0.113.1.
	// 203.0.113.1 is NOT trusted, so it should be the key.

	key := keyFunc(req)

	// If it returns 1.2.3.4, it means it only read the first header and missed the one added by the proxy.
	// This would be a bypass (attacker successfully spoofed IP).
	if key == "1.2.3.4" {
		t.Errorf("VULNERABILITY: TrustedIPKeyFunc used the first header value (spoofed) and ignored the second (real). Got: %s", key)
	}

	if key != "203.0.113.1" {
		t.Errorf("Expected key to be 203.0.113.1 (Real IP), got: %s", key)
	}
}

func TestTrustedIPKeyFunc_MultipleHeaders_Complex(t *testing.T) {
	trustedIPs := []string{"10.0.0.1"}
	keyFunc, err := TrustedIPKeyFunc(trustedIPs)
	if err != nil {
		t.Fatalf("Failed to create key func: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	// Multiple headers with multiple values
	req.Header["X-Forwarded-For"] = []string{"1.2.3.4, 5.6.7.8", "9.10.11.12"}

	// Chain: 1.2.3.4, 5.6.7.8, 9.10.11.12
	// RemoteAddr: 10.0.0.1 (Trusted)
	// Last XFF: 9.10.11.12. Untrusted. Should be key.

	key := keyFunc(req)
	if key != "9.10.11.12" {
		t.Errorf("Expected 9.10.11.12, got %s", key)
	}
}
