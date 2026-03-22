package detector

import (
	"regexp"
	"strings"

	"github.com/rostradamus/dev-lawyer/internal/report"
)

var mappingRe = regexp.MustCompile(`@(Post|Put)Mapping`)
var personalDataParamRe = regexp.MustCompile(`(?i)(email|phone|name|ssn|이메일|전화|이름|주민)`)
var consentRe = regexp.MustCompile(`(?i)(consent|동의|agree)`)

type ConsentDetector struct{}

func NewConsentDetector() *ConsentDetector {
	return &ConsentDetector{}
}

func (d *ConsentDetector) ID() string   { return "PIPA-CST-001" }
func (d *ConsentDetector) Name() string { return "Missing Consent Check Risk" }
func (d *ConsentDetector) Description() string {
	return "Detects endpoints accepting personal data without apparent consent verification"
}
func (d *ConsentDetector) RelatedLawIDs() []string { return []string{"PIPA-15"} }

// methodEnd returns the index of the line (exclusive) where the method body ends,
// identified by tracking brace depth from the mapping annotation line.
// If no opening brace is found within 30 lines, falls back to i+31.
func methodEnd(lines []string, start int) int {
	depth := 0
	opened := false
	limit := start + 31
	if limit > len(lines) {
		limit = len(lines)
	}
	for j := start; j < limit; j++ {
		for _, ch := range lines[j] {
			if ch == '{' {
				depth++
				opened = true
			} else if ch == '}' {
				depth--
				if opened && depth == 0 {
					return j + 1
				}
			}
		}
	}
	return limit
}

func (d *ConsentDetector) Scan(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	lines := strings.Split(sourceCode, "\n")

	for i, line := range lines {
		if !mappingRe.MatchString(line) {
			continue
		}

		// Scan only the current method body to avoid bleeding into adjacent methods
		end := methodEnd(lines, i)
		window := strings.Join(lines[i:end], "\n")

		hasPersonalData := personalDataParamRe.MatchString(window)
		hasConsent := consentRe.MatchString(window)

		if hasPersonalData && !hasConsent {
			findings = append(findings, report.Finding{
				DetectorID:  d.ID(),
				RiskLevel:   "HIGH",
				FilePath:    filePath,
				LineNumber:  i + 1,
				Snippet:     strings.TrimSpace(line),
				Message:     "Endpoint accepts possible personal data without apparent consent mechanism — may require review under PIPA Article 15",
				RelatedLaws: d.RelatedLawIDs(),
			})
		}
	}
	return findings
}
