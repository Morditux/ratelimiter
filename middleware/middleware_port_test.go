package middleware

import (
	"net/http"
	"testing"
)

func TestDefaultKeyFunc_StripPort(t *testing.T) {
	tests := []struct {
		name       string
		header     string // header name to test
		headerVal  string // header value
		remoteAddr string // fallback if needed
		want       string
	}{
		{
			name:      "XFF IPv4 with port",
			header:    "X-Forwarded-For",
			headerVal: "1.2.3.4:12345",
			want:      "1.2.3.4",
		},
		{
			name:      "XFF IPv4 with port and spaces",
			header:    "X-Forwarded-For",
			headerVal: " 1.2.3.4:12345 ",
			want:      "1.2.3.4",
		},
		{
			name:      "XFF IPv6 with brackets and port",
			header:    "X-Forwarded-For",
			headerVal: "[::1]:12345",
			want:      "::1",
		},
		{
			name:      "XFF multiple IPs, first has port",
			header:    "X-Forwarded-For",
			headerVal: "1.2.3.4:12345, 5.6.7.8",
			want:      "1.2.3.4",
		},
		{
			name:      "X-Real-IP IPv4 with port",
			header:    "X-Real-IP",
			headerVal: "1.2.3.4:12345",
			want:      "1.2.3.4",
		},
		{
			name:      "X-Real-IP IPv6 with brackets and port",
			header:    "X-Real-IP",
			headerVal: "[2001:db8::1]:443",
			want:      "2001:db8::1",
		},
		{
			name:      "Plain IPv4",
			header:    "X-Forwarded-For",
			headerVal: "1.2.3.4",
			want:      "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set(tt.header, tt.headerVal)
			}
			req.RemoteAddr = "10.0.0.1:9999" // distinct from test values

			got := DefaultKeyFunc(req)
			if got != tt.want {
				t.Errorf("DefaultKeyFunc() = %q, want %q", got, tt.want)
			}
		})
	}
}
