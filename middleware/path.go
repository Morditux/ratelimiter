package middleware

import "path"

// fastPathClean is an optimized version of path.Clean for HTTP request paths.
// It avoids allocations for paths that are already clean (which is the common case).
// It falls back to path.Clean for dirty paths.
func fastPathClean(p string) string {
	if p == "" {
		return "."
	}
	if p[0] != '/' {
		// Non-rooted paths are rare in HTTP requests but possible.
		// Safe fallback.
		return path.Clean(p)
	}

	n := len(p)
	for i := 1; i < n; i++ {
		if p[i] == '/' {
			// Check for double slash "//"
			if p[i-1] == '/' {
				return path.Clean(p)
			}
		} else if p[i] == '.' {
			// Check for "/." (covers /./ and /..)
			if p[i-1] == '/' {
				return path.Clean(p)
			}
		}
	}

	// Check for trailing slash (path.Clean removes it unless it's root)
	if n > 1 && p[n-1] == '/' {
		return path.Clean(p)
	}

	// Path is already clean
	return p
}
