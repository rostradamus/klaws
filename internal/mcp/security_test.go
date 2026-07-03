package mcp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveWithinRoot(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "src", "App.java")

	t.Run("empty root returns the path unchanged", func(t *testing.T) {
		// No restriction: the path must pass through untouched — including a
		// relative path — so default behavior matches the plain scanner.
		const rel = "relative/src/App.java"
		got, err := resolveWithinRoot("", rel)
		require.NoError(t, err)
		assert.Equal(t, rel, got)
	})

	t.Run("path inside root is allowed and absolutized", func(t *testing.T) {
		got, err := resolveWithinRoot(root, inside)
		require.NoError(t, err)
		assert.Equal(t, inside, got)
	})

	t.Run("root itself is allowed", func(t *testing.T) {
		got, err := resolveWithinRoot(root, root)
		require.NoError(t, err)
		assert.Equal(t, root, got)
	})

	t.Run("path outside root is rejected", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "file.java")
		_, err := resolveWithinRoot(root, outside)
		assert.Error(t, err)
	})

	t.Run("traversal escape is rejected", func(t *testing.T) {
		_, err := resolveWithinRoot(root, filepath.Join(root, "..", "secret"))
		assert.Error(t, err)
	})

	t.Run("sibling prefix is not treated as inside", func(t *testing.T) {
		// "<root>-evil" shares a string prefix with root but is not within it.
		_, err := resolveWithinRoot(root, root+"-evil")
		assert.Error(t, err)
	})

	t.Run("symlink escaping root is rejected", func(t *testing.T) {
		outsideDir := t.TempDir()
		secret := filepath.Join(outsideDir, "secret.java")
		require.NoError(t, os.WriteFile(secret, []byte("x"), 0o600))

		link := filepath.Join(root, "link.java")
		if err := os.Symlink(secret, link); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		// Lexically the link is inside root, but it resolves outside it.
		_, err := resolveWithinRoot(root, link)
		assert.Error(t, err)
	})
}

func TestBearerAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := BearerAuth("s3cret", next)

	cases := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"missing scheme", "s3cret", http.StatusUnauthorized},
		{"correct token", "Bearer s3cret", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, tc.wantStatus, rec.Code)
		})
	}
}
