package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

// financialFieldRe matches personal credit / financial identifier fields
// governed by the Credit Information Act.
// English tokens are wrapped in word boundaries so substrings such as
// "accountNotes" or "cardNotice" do not match. Korean tokens are kept outside
// the boundaries because \b is ASCII-only in RE2.
var financialFieldRe = regexp.MustCompile(
	`(?i)(\b(card_?number|card_?no|account_?number|account_?no|cvv|cvc|credit_?score|credit_?rating)\b|카드번호|계좌번호|신용등급|신용점수)`,
)

// protectionEvidenceRe matches evidence that a field is encrypted, masked, or
// tokenized.
var protectionEvidenceRe = regexp.MustCompile(
	`(?i)(@Encrypted|encrypt\(|Encrypt\(|ENCRYPT|@Mask|mask\(|Mask\(|MASK|마스킹|토큰|tokeni[sz]e)`,
)

type FinancialDataDetector struct{}

func NewFinancialDataDetector() *FinancialDataDetector {
	return &FinancialDataDetector{}
}

func (d *FinancialDataDetector) ID() string   { return "CIA-ENC-001" }
func (d *FinancialDataDetector) Name() string { return "Unprotected Credit Information Risk" }
func (d *FinancialDataDetector) Description() string {
	return "Detects credit or financial identifier fields stored without apparent encryption or masking"
}
func (d *FinancialDataDetector) RelatedLawIDs() []string { return []string{"CIA-19"} }

// hasProtectionEvidence reports whether the field at line i shows encryption or
// masking evidence on the line itself, in adjacent annotations, or within a
// short forward window in the same field block. Mirrors hasEncryptionEvidence.
func hasProtectionEvidence(lines []string, i int) bool {
	if protectionEvidenceRe.MatchString(lines[i]) {
		return true
	}

	// Backward pass: adjacent annotation lines only.
	for j := i - 1; j >= 0; j-- {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || lineCommentRe.MatchString(lines[j]) {
			break
		}
		if !fieldAnnotationRe.MatchString(lines[j]) {
			break
		}
		if protectionEvidenceRe.MatchString(lines[j]) {
			return true
		}
	}

	// Forward pass: same field block only — stop at the next field or annotation.
	end := i + 11
	if end > len(lines) {
		end = len(lines)
	}
	for j := i + 1; j < end; j++ {
		l := lines[j]
		if lineCommentRe.MatchString(l) {
			continue
		}
		if fieldDeclRe.MatchString(l) || fieldAnnotationRe.MatchString(l) {
			break
		}
		if protectionEvidenceRe.MatchString(l) {
			return true
		}
	}
	return false
}

func (d *FinancialDataDetector) Scan(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	lines := strings.Split(sourceCode, "\n")

	for i, line := range lines {
		if lineCommentRe.MatchString(line) {
			continue
		}
		if !financialFieldRe.MatchString(line) {
			continue
		}
		if hasProtectionEvidence(lines, i) {
			continue
		}

		field := financialFieldRe.FindString(line)
		findings = append(findings, report.Finding{
			DetectorID:  d.ID(),
			RiskLevel:   "HIGH",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     fmt.Sprintf("Possible unprotected credit information (%s) — may require review under Credit Information Act Article 19", field),
			RelatedLaws: d.RelatedLawIDs(),
		})
	}
	return findings
}
