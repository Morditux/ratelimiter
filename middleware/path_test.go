package middleware

import (
	"path"
	"testing"
)

func TestFastPathClean(t *testing.T) {
	tests := []string{
		// Clean paths
		"/",
		"/api",
		"/api/users",
		"/api/users/123",
		"/health",
		"/a/b/c/d",
		"/file.txt",
		"/api/v1.0/data",
		"...",
		"/...",
		"/api/.../data",

		// Dirty paths (should be cleaned)
		"",
		"//",
		"///",
		"/api/",
		"/api//users",
		"/api/./users",
		"/api/../users",
		"/api/users/.",
		"/api/users/..",
		"/.",
		"/..",
		"./api",
		"../api",
		"/a/./b",
		"/a/../b",
		"/a//b",
		"//a/b",
		"/a/b/",

		// Edge cases
		"/foo/./bar",
		"/foo/../bar",
		"/foo/..",
		"/foo/.",
		"foo/bar",
		"foo/bar/",
		"foo//bar",
		".",
		"..",
	}

	for _, p := range tests {
		want := path.Clean(p)
		got := fastPathClean(p)
		if got != want {
			t.Errorf("fastPathClean(%q) = %q, want %q", p, got, want)
		}
	}
}

func BenchmarkPathClean_Realistic(b *testing.B) {
	paths := []string{
		"/api/users/123",
		"/api/v1/products",
		"/health",
		"/metrics",
		"/login",
		"/api/orders/999/items",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			_ = path.Clean(p)
		}
	}
}

func BenchmarkFastPathClean_Realistic(b *testing.B) {
	paths := []string{
		"/api/users/123",
		"/api/v1/products",
		"/health",
		"/metrics",
		"/login",
		"/api/orders/999/items",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			_ = fastPathClean(p)
		}
	}
}

func BenchmarkPathClean_Dirty(b *testing.B) {
	paths := []string{
		"//api/users",
		"/api/../v1",
		"/api/./v1",
		"/api/v1/",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			_ = path.Clean(p)
		}
	}
}

func BenchmarkFastPathClean_Dirty(b *testing.B) {
	paths := []string{
		"//api/users",
		"/api/../v1",
		"/api/./v1",
		"/api/v1/",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			_ = fastPathClean(p)
		}
	}
}
