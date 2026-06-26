package detector

import (
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

// marketingSendRe matches method calls that dispatch messages to users (email,
// SMS, push, etc.). The leading "." requires a receiver, so method declarations
// such as "void sendPromotion(" do not trigger it. In an advertising context
// these dispatches are governed by the Network Act.
var marketingSendRe = regexp.MustCompile(`(?i)\.\s*(send|push|dispatch|notify)\w*\s*\(`)

// marketingIntentRe matches advertising / marketing intent near a send call.
var marketingIntentRe = regexp.MustCompile(`(?i)(marketing|advertis|promotion|newsletter|광고|마케팅|홍보|프로모션)`)

// marketingConsentRe matches evidence that opt-in consent was checked before
// sending. Broader than the PIPA consent signal — includes opt-in / 수신동의.
// "subscrib" is deliberately omitted because it also matches "unsubscribe",
// which would wrongly suppress findings.
var marketingConsentRe = regexp.MustCompile(`(?i)(consent|optin|opt_in|opt-in|동의|수신동의)`)

type MarketingConsentDetector struct{}

func NewMarketingConsentDetector() *MarketingConsentDetector {
	return &MarketingConsentDetector{}
}

func (d *MarketingConsentDetector) ID() string   { return "NIA-MKT-001" }
func (d *MarketingConsentDetector) Name() string { return "Marketing Message Consent Risk" }
func (d *MarketingConsentDetector) Description() string {
	return "Detects advertising or marketing messages sent without an apparent opt-in consent check"
}
func (d *MarketingConsentDetector) RelatedLawIDs() []string { return []string{"NIA-50"} }

// windowAround returns the source lines within radius lines of index i, joined.
func windowAround(lines []string, i, radius int) string {
	start := i - radius
	if start < 0 {
		start = 0
	}
	end := i + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}

func (d *MarketingConsentDetector) Scan(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	lines := strings.Split(sourceCode, "\n")

	for i, line := range lines {
		if lineCommentRe.MatchString(line) {
			continue
		}
		if !marketingSendRe.MatchString(line) {
			continue
		}

		// Examine the surrounding method body for advertising intent and an
		// opt-in consent check.
		window := windowAround(lines, i, 10)
		if !marketingIntentRe.MatchString(window) {
			continue
		}
		if marketingConsentRe.MatchString(window) {
			continue
		}

		findings = append(findings, report.Finding{
			DetectorID:  d.ID(),
			RiskLevel:   "MEDIUM",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     "Possible advertising message sent without an apparent opt-in consent check — may require review under Network Act Article 50",
			RelatedLaws: d.RelatedLawIDs(),
		})
	}
	return findings
}
