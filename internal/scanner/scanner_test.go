package scanner_test

import (
	"strings"
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/rostradamus/klaws/internal/report"
	"github.com/rostradamus/klaws/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanDirectory_FindsRisks(t *testing.T) {
	reg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
		detector.NewMarketingConsentDetector(),
		detector.NewFinancialDataDetector(),
		detector.NewRetentionDetector(),
		detector.NewPersonalDataRetentionDetector(),
		detector.NewThirdPartyTransferDetector(),
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
		detector.NewMarketingConsentDetector(),
		detector.NewFinancialDataDetector(),
		detector.NewRetentionDetector(),
		detector.NewPersonalDataRetentionDetector(),
		detector.NewThirdPartyTransferDetector(),
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

func TestScanFileFindsFlowTraces(t *testing.T) {
	svc := scanner.NewService(detector.NewRegistry(detector.NewFlowDetector()))

	rpt, err := svc.ScanFile("../../testdata/flow/UserService.java")
	require.NoError(t, err)

	require.Len(t, rpt.Findings, 2)
	assert.Equal(t, rpt.TotalFindings, len(rpt.Findings))

	// UserService.java produces two findings, and both are HIGH (주민등록번호→log
	// and email→transmit), so a map keyed by risk level would collapse them and
	// silently validate the wrong one. Pick the SSN→log finding by its trace
	// instead, then assert the log trace specifically is present and well-formed.
	var ssnLog *report.Finding
	for i := range rpt.Findings {
		f := rpt.Findings[i]
		if f.RiskLevel == "HIGH" && strings.Contains(f.Snippet, "log.info") {
			ssnLog = &rpt.Findings[i]
		}
	}
	require.NotNil(t, ssnLog, "주민등록번호 reaching a log must be reported as HIGH")
	require.NotEmpty(t, ssnLog.Trace)
	assert.Equal(t, "source", ssnLog.Trace[0].Kind)
	assert.Equal(t, "sink", ssnLog.Trace[len(ssnLog.Trace)-1].Kind)
	assert.Contains(t, ssnLog.Trace[0].Note, "주민등록번호", "the source hop must be the SSN source")
}

func TestScanFileWithSanitizedAndLiteralCodeFindsNothing(t *testing.T) {
	svc := scanner.NewService(detector.NewRegistry(detector.NewFlowDetector()))

	rpt, err := svc.ScanFile("../../testdata/flow/SafeUserService.java")
	require.NoError(t, err)

	assert.Empty(t, rpt.Findings, "sanitized and literal-only code must produce no findings")
}
