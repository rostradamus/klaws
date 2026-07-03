package mcp

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
)

// resolveWithinRoot returns the absolute form of path, and — when root is
// non-empty — verifies that it does not escape root. It rejects both lexical
// traversal via ".." and symlink escapes (a link inside root that resolves to a
// target outside it). An empty root imposes no restriction.
func resolveWithinRoot(root, path string) (string, error) {
	// No restriction configured: return the path unchanged so default behavior
	// (no --scan-root) matches the plain scanner — a relative path is not
	// absolutized.
	if root == "" {
		return path, nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("invalid scan root: %w", err)
	}

	outside := fmt.Errorf("path %q is outside the permitted scan root", path)
	if !within(rootAbs, abs) {
		return "", outside
	}

	// Guard against symlink escapes: if both paths can be resolved through
	// symlinks (i.e. they exist on disk), re-check containment on the real
	// paths. os.ReadFile follows symlinks, so a link inside root pointing
	// outside must be rejected here.
	if realRoot, err := filepath.EvalSymlinks(rootAbs); err == nil {
		if realAbs, err := filepath.EvalSymlinks(abs); err == nil && !within(realRoot, realAbs) {
			return "", outside
		}
	}
	return abs, nil
}

// within reports whether target is root or a descendant of it, lexically.
func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
