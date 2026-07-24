package report_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatTextRendersTrace(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-FLOW-001",
			RiskLevel:  "HIGH",
			FilePath:   "UserService.java",
			LineNumber: 5,
			Snippet:    "log.info(msg);",
			Message:    "Possible personal data reaches log output",
			Trace: []report.TraceHop{
				{Line: 3, Expression: "String s = user.getSsn();", Kind: "source", Note: "source: 주민등록번호"},
				{Line: 4, Expression: `String msg = "id=" + s;`, Kind: "propagate", Note: "propagates via concat"},
				{Line: 5, Expression: "log.info(msg);", Kind: "sink", Note: "sink: log output"},
			},
			RelatedLaws: []string{"PIPA-29", "PIPA-24"},
		}},
	}

	out := report.FormatText(r)

	assert.Contains(t, out, "Trace:")
	assert.Contains(t, out, "①")
	assert.Contains(t, out, "③")
	assert.Contains(t, out, "UserService.java:3")
	assert.Contains(t, out, "propagates via concat")
}

func TestFormatTextOmitsTraceSectionWhenAbsent(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{DetectorID: "PIPA-LOG-001", RiskLevel: "MEDIUM", LineNumber: 1}},
	}

	assert.NotContains(t, report.FormatText(r), "Trace:", "regex findings must render exactly as before")
}

func TestFormatJSONOmitsTraceForRegexFindings(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-LOG-001", RiskLevel: "MEDIUM", FilePath: "A.java",
			LineNumber: 1, Snippet: "x", Message: "m", RelatedLaws: []string{"PIPA-29"},
		}},
	}

	out, err := report.FormatJSON(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "trace",
		"omitempty is a public contract: existing JSON output must stay byte-identical")
}

func TestFormatJSONIncludesTraceForFlowFindings(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-FLOW-001",
			Trace:      []report.TraceHop{{Line: 3, Expression: "e", Kind: "source", Note: "n"}},
		}},
	}

	out, err := report.FormatJSON(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"trace"`)
	assert.Contains(t, string(out), `"kind":"source"`)
}
