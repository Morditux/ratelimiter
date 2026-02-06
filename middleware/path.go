package middleware

import "path"

// fastPathClean is a wrapper around path.Clean that avoids allocation
// for paths that are already clean.
// It checks for dirty characters (//, /./, /../) and trailing slashes
// before calling path.Clean.
//
// This provides a significant performance improvement (allocations & CPU)
// for the common case where paths are already clean (e.g. valid API requests).
func fastPathClean(p string) string {
	// Empty path becomes "."
	if p == "" {
		return "."
	}
	// Root is always clean
	if p == "/" {
		return "/"
	}

	n := len(p)

	// Check for trailing slash (unless it's just "/")
	// path.Clean removes trailing slashes
	if n > 1 && p[n-1] == '/' {
		return path.Clean(p)
	}

	// Scan for dirty sequences
	for i := 0; i < n; i++ {
		if p[i] == '/' {
			// Check for double slash "//"
			if i+1 < n && p[i+1] == '/' {
				return path.Clean(p)
			}
		} else if p[i] == '.' {
			// Check for dot components "." or ".."
			// A dot component must be surrounded by slashes or start/end of string.

			// Check if we are at the start of a component
			startOfComp := i == 0 || p[i-1] == '/'

			if startOfComp {
				// Check for single dot "."
				// Must be followed by slash or end of string
				if i+1 == n || p[i+1] == '/' {
					return path.Clean(p)
				}

				// Check for double dot ".."
				if i+1 < n && p[i+1] == '.' {
					// Must be followed by slash or end of string
					if i+2 == n || p[i+2] == '/' {
						return path.Clean(p)
					}
				}
			}
		}
	}

	// If no dirty sequences found, the path is already clean.
	// Return original string to avoid allocation.
	return p
}
