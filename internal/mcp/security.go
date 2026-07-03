package mcp

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

// resolveWithinRoot returns the absolute form of path, and — when root is
// non-empty — verifies that it does not escape root. It rejects traversal via
// "..". An empty root imposes no restriction.
func resolveWithinRoot(root, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if root == "" {
		return abs, nil
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("invalid scan root: %w", err)
	}

	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the permitted scan root", path)
	}
	return abs, nil
}

// BearerAuth wraps next so that only requests carrying "Authorization: Bearer
// <token>" are served; others receive 401. The comparison is constant-time.
func BearerAuth(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
