package middleware

import (
	"path"
	"testing"
)

func TestFastPathClean(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Clean paths (should be returned as is)
		{"/api/users", "/api/users"},
		{"/", "/"},
		{"/a/b/c", "/a/b/c"},
		{"/file.txt", "/file.txt"},
		{"/v1.0/api", "/v1.0/api"},

		// Dirty paths (should be cleaned)
		{"", "."},
		{"//", "/"},
		{"/api//users", "/api/users"},
		{"/api/./users", "/api/users"},
		{"/api/../users", "/users"},
		{"/api/", "/api"},
		{"/api/users/", "/api/users"},
		{"/.", "/"},
		{"/..", "/"},
		{"/...", "/..."}, // Valid directory name "..."
		{"/.hidden", "/.hidden"}, // Hidden file in root
		{"/api/.hidden", "/api/.hidden"}, // Hidden file

		// Edge cases
		{".", "."},
		{"..", ".."},
		{"foo/bar", "foo/bar"},
		{"foo//bar", "foo/bar"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := fastPathClean(tt.input)
			if got != tt.want {
				t.Errorf("fastPathClean(%q) = %q; want %q", tt.input, got, tt.want)
			}
			// Verify it matches path.Clean behavior
			stdClean := path.Clean(tt.input)
			if got != stdClean {
				t.Errorf("fastPathClean(%q) = %q; path.Clean = %q (mismatch)", tt.input, got, stdClean)
			}
		})
	}
}

func BenchmarkFastPathClean(b *testing.B) {
	p := "/api/users/123/details"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fastPathClean(p)
	}
}

func BenchmarkStdPathClean(b *testing.B) {
	p := "/api/users/123/details"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path.Clean(p)
	}
}
