package scanner_test

import (
	"testing"

	"github.com/rostradamus/dev-lawyer/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalk_FindsJavaFiles(t *testing.T) {
	files, err := scanner.Walk("../../testdata", "*.java")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 3, "should find at least 3 .java files in testdata")
}

func TestWalk_RespectsPattern(t *testing.T) {
	files, err := scanner.Walk("../../testdata", "*.txt")
	require.NoError(t, err)
	assert.Empty(t, files, "should find no .txt files in testdata")
}

func TestWalk_InvalidDir(t *testing.T) {
	_, err := scanner.Walk("/nonexistent/path", "*.java")
	assert.Error(t, err)
}

func TestWalk_DefaultPattern(t *testing.T) {
	files, err := scanner.Walk("../../testdata", "")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 3, "empty pattern should default to *.java")
}
