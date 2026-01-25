package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestDefaultOnLimitedEnhancedSecurityHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	DefaultOnLimited(w, req)

	headers := w.Header()

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "interest-cohort=()",
		"Cache-Control":           "no-store",
		"Pragma":                  "no-cache",
		"Retry-After":             "60",
		"Content-Type":            "application/json",
	}

	for key, expectedValue := range expectedHeaders {
		if got := headers.Get(key); got != expectedValue {
			t.Errorf("Header %s: expected %q, got %q", key, expectedValue, got)
		}
	}
}
