package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestTrustedIPKeyFunc(t *testing.T) {
	// Trusted proxies: 10.0.0.1 (LB1), 10.0.0.2 (LB2)
	trustedProxies := []string{"10.0.0.1", "10.0.0.2"}
	keyFunc, err := TrustedIPKeyFunc(trustedProxies)
	if err != nil {
		t.Fatalf("Failed to create trusted key func: %v", err)
	}

	// Scenario 1: Client -> LB1 -> App
	// RemoteAddr: 10.0.0.1
	// X-Forwarded-For: ClientIP
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	key := keyFunc(req)
	if key != "203.0.113.1" {
		t.Errorf("Scenario 1: Expected 203.0.113.1, got %s", key)
	}

	// Scenario 2: Client -> LB2 -> LB1 -> App
	// RemoteAddr: 10.0.0.1
	// X-Forwarded-For: ClientIP, 10.0.0.2
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.2")

	key = keyFunc(req)
	if key != "203.0.113.1" {
		t.Errorf("Scenario 2: Expected 203.0.113.1, got %s", key)
	}

	// Scenario 3: Attacker -> LB1 -> App (Spoofing)
	// Attacker sends X-Forwarded-For: SpoofedIP
	// LB1 appends AttackerIP
	// RemoteAddr: 10.0.0.1
	// X-Forwarded-For: SpoofedIP, AttackerIP
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 192.0.2.1") // Spoofed, RealAttacker

	key = keyFunc(req)
	// We trust 10.0.0.1 (RemoteAddr).
	// We look at XFF: [Spoofed, RealAttacker].
	// RealAttacker (192.0.2.1) is NOT trusted.
	// So we stop there and return RealAttacker.
	if key != "192.0.2.1" {
		t.Errorf("Scenario 3: Expected 192.0.2.1 (Attacker), got %s (Spoofed?)", key)
	}

	// Scenario 4: Direct connection (bypass LB)
	// RemoteAddr: AttackerIP
	// X-Forwarded-For: SpoofedIP
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")

	key = keyFunc(req)
	// RemoteAddr (192.0.2.1) is NOT trusted.
	// So we return RemoteAddr.
	if key != "192.0.2.1:12345" && key != "192.0.2.1" {
		// getRemoteIP strips port? Yes.
		t.Errorf("Scenario 4: Expected 192.0.2.1, got %s", key)
	}
}

func TestTrustedIPKeyFunc_CIDR(t *testing.T) {
	// Trust 10.0.0.0/24
	keyFunc, err := TrustedIPKeyFunc([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatalf("Failed to create key func: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.50:12345" // Inside CIDR
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	key := keyFunc(req)
	if key != "203.0.113.1" {
		t.Errorf("Expected 203.0.113.1, got %s", key)
	}
}
