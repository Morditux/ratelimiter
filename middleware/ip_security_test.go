package middleware

import (
	"net/http"
	"testing"
)

func TestDefaultKeyFunc_Security(t *testing.T) {
	// Scenario: X-Forwarded-For is present but results in empty string
	// This could happen if the header is malformed (e.g. " , 5.6.7.8" or " ")
	// We want to ensure we don't return an empty key, which could cause all such requests
	// to share a single rate limit bucket (DoS risk) or bypass limits.

	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{
			name:       "Empty XFF",
			xff:        "",
			remoteAddr: "1.2.3.4:1234",
			want:       "1.2.3.4",
		},
		{
			name:       "Whitespace XFF",
			xff:        " ",
			remoteAddr: "1.2.3.4:1234",
			want:       "1.2.3.4",
		},
		{
			name:       "Comma Leading XFF",
			xff:        " , 5.6.7.8",
			remoteAddr: "1.2.3.4:1234",
			want:       "1.2.3.4",
		},
		{
			name:       "Valid XFF",
			xff:        "10.0.0.1, 1.2.3.4",
			remoteAddr: "1.2.3.4:1234",
			want:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			key := DefaultKeyFunc(req)
			if key != tt.want {
				t.Errorf("DefaultKeyFunc() = '%v', want '%v'", key, tt.want)
			}
		})
	}
}
