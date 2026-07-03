package report

import "strings"

// riskRank orders risk levels for comparison. Unknown levels rank 0.
func riskRank(level string) int {
	switch strings.ToUpper(level) {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// ValidFailOn reports whether level is an accepted --fail-on value.
func ValidFailOn(level string) bool {
	switch strings.ToUpper(level) {
	case "", "NONE", "LOW", "MEDIUM", "HIGH":
		return true
	default:
		return false
	}
}

// ExceedsThreshold reports whether any finding is at or above the given severity
// level. A level of "" or "none" (case-insensitive) never triggers.
func ExceedsThreshold(r Report, level string) bool {
	if level == "" || strings.EqualFold(level, "none") {
		return false
	}
	threshold := riskRank(level)
	for _, f := range r.Findings {
		if riskRank(f.RiskLevel) >= threshold {
			return true
		}
	}
	return false
}
