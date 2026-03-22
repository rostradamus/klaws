package scanner_test

import (
	"testing"

	"github.com/rostradamus/dev-lawyer/internal/detector"
	"github.com/rostradamus/dev-lawyer/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanDirectory_FindsRisks(t *testing.T) {
	reg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
	)
	svc := scanner.NewService(reg)

	rpt, err := svc.ScanDirectory("../../testdata", "*.java")
	require.NoError(t, err)

	assert.GreaterOrEqual(t, rpt.FilesScanned, 3)
	assert.GreaterOrEqual(t, rpt.TotalFindings, 5, "should find risks across test files")
	assert.NotEmpty(t, rpt.Disclaimer)
	assert.NotEmpty(t, rpt.ScannedAt)
}

func TestScanFile_SingleFile(t *testing.T) {
	reg := detector.NewRegistry(detector.NewLoggingDetector())
	svc := scanner.NewService(reg)

	rpt, err := svc.ScanFile("../../testdata/UserService.java")
	require.NoError(t, err)

	assert.Equal(t, 1, rpt.FilesScanned)
	assert.GreaterOrEqual(t, rpt.TotalFindings, 1)
}

func TestScanDirectory_NoRisksInCleanFile(t *testing.T) {
	reg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
	)
	svc := scanner.NewService(reg)

	rpt, err := svc.ScanFile("../../testdata/CleanService.java")
	require.NoError(t, err)

	assert.Equal(t, 0, rpt.TotalFindings)
}

func TestScanDirectory_InvalidPath(t *testing.T) {
	reg := detector.NewRegistry()
	svc := scanner.NewService(reg)

	_, err := svc.ScanDirectory("/nonexistent", "*.java")
	assert.Error(t, err)
}
