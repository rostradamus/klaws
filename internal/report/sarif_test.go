package report_test

import (
	"encoding/json"
	"testing"

	"github.com/rostradamus/klaws/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleReport() report.Report {
	return report.Report{
		TargetPath:    "./src",
		FilesScanned:  2,
		TotalFindings: 2,
		Findings: []report.Finding{
			{
				DetectorID:  "PIPA-ENC-001",
				RiskLevel:   "HIGH",
				FilePath:    "src/MemberEntity.java",
				LineNumber:  11,
				Snippet:     "private String residentNumber;",
				Message:     "Possible unencrypted personal identifier — may require review",
				RelatedLaws: []string{"PIPA-24-2", "PIPA-29"},
			},
			{
				DetectorID:  "PIPA-LOG-001",
				RiskLevel:   "MEDIUM",
				FilePath:    "src/UserService.java",
				LineNumber:  11,
				Snippet:     "log.info(email)",
				Message:     "Possible personal data in log output — may require review",
				RelatedLaws: []string{"PIPA-29"},
			},
		},
	}
}

func detectorInfos() []report.DetectorInfo {
	return []report.DetectorInfo{
		{ID: "PIPA-ENC-001", Name: "Unencrypted Personal Data Risk", Description: "Detects unencrypted identifiers", RelatedLaws: []string{"PIPA-24-2", "PIPA-29"}},
		{ID: "PIPA-LOG-001", Name: "Personal Data Logging Risk", Description: "Detects personal data in logs", RelatedLaws: []string{"PIPA-29"}},
	}
}

func TestFormatSARIF_Structure(t *testing.T) {
	data, err := report.FormatSARIF(sampleReport(), detectorInfos())
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))

	assert.Equal(t, "2.1.0", out["version"])
	assert.Contains(t, out["$schema"], "sarif-2.1.0")

	runs := out["runs"].([]any)
	require.Len(t, runs, 1)
	run := runs[0].(map[string]any)

	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	assert.Equal(t, "klaws", driver["name"])
	assert.Len(t, driver["rules"].([]any), 2, "one rule per detector")

	results := run["results"].([]any)
	require.Len(t, results, 2, "one result per finding")
}

func TestFormatSARIF_LevelMapping(t *testing.T) {
	data, err := report.FormatSARIF(sampleReport(), detectorInfos())
	require.NoError(t, err)

	var out struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(data, &out))

	levels := map[string]string{}
	for _, r := range out.Runs[0].Results {
		levels[r.RuleID] = r.Level
	}
	assert.Equal(t, "error", levels["PIPA-ENC-001"], "HIGH maps to error")
	assert.Equal(t, "warning", levels["PIPA-LOG-001"], "MEDIUM maps to warning")
}

func TestFormatSARIF_EmptyReport(t *testing.T) {
	data, err := report.FormatSARIF(report.Report{}, nil)
	require.NoError(t, err)

	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out))
	// results/rules should serialize as [] (not null) so consumers accept it.
	run := out["runs"].([]any)[0].(map[string]any)
	assert.NotNil(t, run["results"])
	assert.NotNil(t, run["tool"].(map[string]any)["driver"].(map[string]any)["rules"])
}
