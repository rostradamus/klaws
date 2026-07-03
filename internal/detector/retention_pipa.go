package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

// personalDataFieldRe matches high-signal personal-data identifier fields whose
// indefinite retention is a concern under PIPA Article 21 (destruction of
// personal information once its purpose is achieved). Kept deliberately narrow
// to avoid false positives on generic names like "name" or "address".
var personalDataFieldRe = regexp.MustCompile(
	`(?i)(\b(email|e_?mail|phone_?number|mobile_?number|resident_?number|ssn)\b|이메일|전화번호|휴대폰번호|주민번호)`,
)

// destructionEvidenceRe matches evidence of a destruction / retention-limit
// policy (deletion, expiry, purge, or anonymization). "ttl" is word-bounded so
// it does not match substrings such as "settledAt".
var destructionEvidenceRe = regexp.MustCompile(
	`(?i)(retention|retain|expir|purge|destroy|deleted_?at|anonymi|pseudonymi|\bttl\b|파기|보관기간|보존기간|익명화)`,
)

// personalFieldDeclRe matches a stored field declaration (starts with an
// access/modifier keyword, ends with ";"). This scopes the detector to
// persisted fields and excludes method declarations, log statements, and other
// mentions of a personal-data term. It is charset-agnostic so Korean field
// names are still matched.
var personalFieldDeclRe = regexp.MustCompile(`^\s*(private|protected|public|final|static)\b.*;\s*$`)

type PersonalDataRetentionDetector struct{}

func NewPersonalDataRetentionDetector() *PersonalDataRetentionDetector {
	return &PersonalDataRetentionDetector{}
}

func (d *PersonalDataRetentionDetector) ID() string   { return "PIPA-RET-001" }
func (d *PersonalDataRetentionDetector) Name() string { return "Personal Data Retention Risk" }
func (d *PersonalDataRetentionDetector) Description() string {
	return "Detects personal data fields stored without apparent destruction or retention-limit handling"
}
func (d *PersonalDataRetentionDetector) RelatedLawIDs() []string { return []string{"PIPA-21"} }

func (d *PersonalDataRetentionDetector) Scan(sourceCode string, filePath string) []report.Finding {
	lines := strings.Split(sourceCode, "\n")

	// Build a comment-free view for the file-level prechecks so a comment such
	// as "// TODO: add a deletion policy" neither triggers nor suppresses.
	var code []string
	for _, line := range lines {
		if lineCommentRe.MatchString(line) {
			continue
		}
		code = append(code, line)
	}
	codeView := strings.Join(code, "\n")

	// A destruction/retention policy anywhere in the source clears the file.
	if destructionEvidenceRe.MatchString(codeView) {
		return nil
	}

	for i, line := range lines {
		if lineCommentRe.MatchString(line) {
			continue
		}
		// Only stored field declarations count — not method signatures or logs.
		if !personalFieldDeclRe.MatchString(line) || !personalDataFieldRe.MatchString(line) {
			continue
		}

		// Report once per file, at the first personal-data field.
		field := personalDataFieldRe.FindString(line)
		return []report.Finding{{
			DetectorID:  d.ID(),
			RiskLevel:   "MEDIUM",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     fmt.Sprintf("Possible personal data (%s) stored without apparent destruction or retention-limit handling — may require review under PIPA Article 21", field),
			RelatedLaws: d.RelatedLawIDs(),
		}}
	}
	return nil
}
