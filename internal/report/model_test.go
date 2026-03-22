package report_test

import (
	"testing"

	"github.com/rostradamus/dev-lawyer/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatJSON_EmptyReport(t *testing.T) {
	r := report.Report{
		ScannedAt:     "2026-03-23T14:30:00Z",
		TargetPath:    "/tmp/test",
		FilesScanned:  0,
		TotalFindings: 0,
		Findings:      []report.Finding{},
		Disclaimer:    report.Disclaimer,
	}
	out, err := report.FormatJSON(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"total_findings":0`)
	assert.Contains(t, string(out), `"disclaimer"`)
}

func TestFormatJSON_WithFinding(t *testing.T) {
	r := report.Report{
		ScannedAt:     "2026-03-23T14:30:00Z",
		TargetPath:    "/tmp/test",
		FilesScanned:  1,
		TotalFindings: 1,
		Findings: []report.Finding{
			{
				DetectorID:  "PIPA-LOG-001",
				RiskLevel:   "MEDIUM",
				FilePath:    "Test.java",
				LineNumber:  10,
				Snippet:     `log.info("email: " + email);`,
				Message:     "Possible personal data (email) in log output",
				RelatedLaws: []string{"PIPA-29"},
			},
		},
		Disclaimer: report.Disclaimer,
	}
	out, err := report.FormatJSON(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"detector_id":"PIPA-LOG-001"`)
	assert.Contains(t, string(out), `"related_laws":["PIPA-29"]`)
}

func TestFormatText_WithFinding(t *testing.T) {
	r := report.Report{
		ScannedAt:     "2026-03-23T14:30:00Z",
		TargetPath:    "/tmp/test",
		FilesScanned:  1,
		TotalFindings: 1,
		Findings: []report.Finding{
			{
				DetectorID:  "PIPA-LOG-001",
				RiskLevel:   "MEDIUM",
				FilePath:    "Test.java",
				LineNumber:  10,
				Snippet:     `log.info("email: " + email);`,
				Message:     "Possible personal data (email) in log output",
				RelatedLaws: []string{"PIPA-29"},
			},
		},
		Disclaimer: report.Disclaimer,
	}
	out := report.FormatText(r)
	assert.Contains(t, out, "PIPA-LOG-001")
	assert.Contains(t, out, "Test.java:10")
	assert.Contains(t, out, "MEDIUM")
	assert.Contains(t, out, report.Disclaimer)
}
