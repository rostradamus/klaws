package report_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/report"
	"github.com/stretchr/testify/assert"
)

func reportWith(levels ...string) report.Report {
	r := report.Report{}
	for _, l := range levels {
		r.Findings = append(r.Findings, report.Finding{RiskLevel: l})
	}
	return r
}

func TestExceedsThreshold(t *testing.T) {
	cases := []struct {
		name    string
		levels  []string
		failOn  string
		exceeds bool
	}{
		{"none never triggers", []string{"HIGH"}, "none", false},
		{"empty never triggers", []string{"HIGH"}, "", false},
		{"HIGH gate with HIGH finding", []string{"MEDIUM", "HIGH"}, "HIGH", true},
		{"HIGH gate with only MEDIUM", []string{"MEDIUM"}, "HIGH", false},
		{"MEDIUM gate with MEDIUM finding", []string{"MEDIUM"}, "MEDIUM", true},
		{"MEDIUM gate with only nothing", nil, "MEDIUM", false},
		{"case-insensitive gate", []string{"high"}, "high", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.exceeds, report.ExceedsThreshold(reportWith(tc.levels...), tc.failOn))
		})
	}
}

func TestValidFailOn(t *testing.T) {
	for _, v := range []string{"", "none", "NONE", "low", "MEDIUM", "high"} {
		assert.True(t, report.ValidFailOn(v), "%q should be valid", v)
	}
	for _, v := range []string{"bogus", "critical", "1"} {
		assert.False(t, report.ValidFailOn(v), "%q should be invalid", v)
	}
}
