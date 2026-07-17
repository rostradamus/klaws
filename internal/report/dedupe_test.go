package report_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupePrefersFlowFindingOnSameLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 5},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, Trace: []report.TraceHop{{Line: 5}}},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 1)
	assert.Equal(t, "PIPA-FLOW-001", got[0].DetectorID, "the flow finding knows strictly more")
}

func TestDedupeKeepsRegexFindingOnDifferentLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 9},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5},
	}

	assert.Len(t, report.Dedupe(findings), 2)
}

func TestDedupeKeepsRegexFindingInDifferentFile(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "B.java", LineNumber: 5},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5},
	}

	assert.Len(t, report.Dedupe(findings), 2)
}

func TestDedupeIsOrderIndependent(t *testing.T) {
	flow := report.Finding{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5}
	regex := report.Finding{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 5}

	for _, in := range [][]report.Finding{{regex, flow}, {flow, regex}} {
		got := report.Dedupe(in)
		require.Len(t, got, 1)
		assert.Equal(t, "PIPA-FLOW-001", got[0].DetectorID)
	}
}

func TestDedupePreservesOrderOfSurvivors(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 1},
		{DetectorID: "PIPA-ENC-001", FilePath: "A.java", LineNumber: 2},
		{DetectorID: "PIPA-CON-001", FilePath: "A.java", LineNumber: 3},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 3)
	assert.Equal(t, "PIPA-LOG-001", got[0].DetectorID)
	assert.Equal(t, "PIPA-ENC-001", got[1].DetectorID)
	assert.Equal(t, "PIPA-CON-001", got[2].DetectorID)
}

func TestDedupeKeepsMultipleFlowFindingsOnOneLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, Message: "ssn"},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, Message: "email"},
	}

	assert.Len(t, report.Dedupe(findings), 2, "distinct flows to one sink are distinct risks")
}

func TestDedupeHandlesEmptyInput(t *testing.T) {
	assert.Empty(t, report.Dedupe(nil))
}

func TestDedupeAbsorbsSupersededFindingLaws(t *testing.T) {
	findings := []report.Finding{
		{
			DetectorID:  "PIPA-ENC-001",
			FilePath:    "A.java",
			LineNumber:  5,
			RelatedLaws: []string{"PIPA-24-2", "PIPA-29"},
		},
		{
			DetectorID:  "PIPA-FLOW-001",
			FilePath:    "A.java",
			LineNumber:  5,
			Trace:       []report.TraceHop{{Line: 5, Kind: "sink"}},
			RelatedLaws: []string{"PIPA-29", "PIPA-24"},
		},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 1)
	assert.Equal(t, "PIPA-FLOW-001", got[0].DetectorID)
	assert.Equal(t, []string{"PIPA-29", "PIPA-24", "PIPA-24-2"}, got[0].RelatedLaws)
	require.Len(t, got[0].Trace, 1)
	assert.Equal(t, 5, got[0].Trace[0].Line)
}

func TestDedupeAbsorbsLawsFromMultipleSupersededFindings(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 5, RelatedLaws: []string{"PIPA-29"}},
		{DetectorID: "PIPA-CON-001", FilePath: "A.java", LineNumber: 5, RelatedLaws: []string{"PIPA-17"}},
		{
			DetectorID:  "PIPA-FLOW-001",
			FilePath:    "A.java",
			LineNumber:  5,
			RelatedLaws: []string{"PIPA-29"},
		},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 1)
	assert.Equal(t, []string{"PIPA-29", "PIPA-17"}, got[0].RelatedLaws)
}

func TestDedupeDoesNotAugmentLawsFromDifferentLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 9, RelatedLaws: []string{"PIPA-17"}},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, RelatedLaws: []string{"PIPA-29"}},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 2)
	// Order preserved: the regex finding on line 9 survives unchanged.
	assert.Equal(t, "PIPA-LOG-001", got[0].DetectorID)
	assert.Equal(t, []string{"PIPA-17"}, got[0].RelatedLaws)
	assert.Equal(t, "PIPA-FLOW-001", got[1].DetectorID)
	assert.Equal(t, []string{"PIPA-29"}, got[1].RelatedLaws, "flow finding must not absorb laws from a different line")
}

func TestDedupeFlowFindingWithNoSupersededFindingKeepsLawsUnchanged(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, RelatedLaws: []string{"PIPA-29", "PIPA-24"}},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 1)
	assert.Equal(t, []string{"PIPA-29", "PIPA-24"}, got[0].RelatedLaws)
}

func TestDedupeDoesNotMutateInputBackingArray(t *testing.T) {
	original := []report.Finding{
		{DetectorID: "PIPA-ENC-001", FilePath: "A.java", LineNumber: 5, RelatedLaws: []string{"PIPA-24-2"}},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, RelatedLaws: []string{"PIPA-29"}},
	}
	// Capture the flow finding's pre-dedupe RelatedLaws slice, as a caller
	// holding onto the original findings would.
	preDedupeFlowLaws := original[1].RelatedLaws

	got := report.Dedupe(original)

	require.Len(t, got, 1)
	assert.Equal(t, []string{"PIPA-29", "PIPA-24-2"}, got[0].RelatedLaws)
	assert.Equal(t, []string{"PIPA-29"}, preDedupeFlowLaws, "Dedupe must not mutate the caller's original slice")
}
