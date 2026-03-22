package scanner

import (
	"os"
	"path/filepath"
)

// FileWalker finds source files matching a glob pattern.
type FileWalker struct{}

func (fw FileWalker) Walk(root string, pattern string) ([]string, error) {
	return Walk(root, pattern)
}

func Walk(root string, pattern string) ([]string, error) {
	if pattern == "" {
		pattern = "*.java"
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	// Single file
	if !info.IsDir() {
		return []string{root}, nil
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		matched, matchErr := filepath.Match(pattern, d.Name())
		if matchErr != nil {
			return matchErr
		}
		if matched {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
