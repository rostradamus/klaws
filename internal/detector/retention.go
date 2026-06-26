package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

// transactionRecordRe matches fields indicating e-commerce transaction records
// subject to preservation requirements under the E-Commerce Act.
// English tokens are word-bounded so substrings such as "orderNotes" do not
// match. Korean tokens stay outside the boundaries (\b is ASCII-only in RE2).
var transactionRecordRe = regexp.MustCompile(
	`(?i)(\b(order_?id|order_?no|payment_?id|transaction_?id|txn_?id|purchase_?id)\b|주문번호|결제정보|거래내역|주문내역)`,
)

// retentionEvidenceRe matches evidence of a defined retention / preservation or
// destruction policy. Keyword stems match loosely so they catch camelCase
// identifiers (e.g. "retentionExpiresAt", "deletedAt"). Only "ttl" is
// word-bounded, so it does not match substrings such as "settledAt".
var retentionEvidenceRe = regexp.MustCompile(
	`(?i)(retention|retain|preserv|expir|deleted_?at|archive|\bttl\b|보존|보관기간|파기)`,
)

type RetentionDetector struct{}

func NewRetentionDetector() *RetentionDetector {
	return &RetentionDetector{}
}

func (d *RetentionDetector) ID() string   { return "ECA-RET-001" }
func (d *RetentionDetector) Name() string { return "Transaction Record Retention Risk" }
func (d *RetentionDetector) Description() string {
	return "Detects transaction record fields stored without apparent retention or preservation handling"
}
func (d *RetentionDetector) RelatedLawIDs() []string { return []string{"ECA-6"} }

func (d *RetentionDetector) Scan(sourceCode string, filePath string) []report.Finding {
	// Preservation requirements apply per record store. If the source already
	// shows retention handling, treat it as addressed and skip.
	if !transactionRecordRe.MatchString(sourceCode) {
		return nil
	}
	if retentionEvidenceRe.MatchString(sourceCode) {
		return nil
	}

	lines := strings.Split(sourceCode, "\n")
	for i, line := range lines {
		if lineCommentRe.MatchString(line) {
			continue
		}
		if !transactionRecordRe.MatchString(line) {
			continue
		}

		// Report once per file, at the first transaction record field.
		field := transactionRecordRe.FindString(line)
		return []report.Finding{{
			DetectorID:  d.ID(),
			RiskLevel:   "MEDIUM",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     fmt.Sprintf("Possible transaction records (%s) stored without apparent retention or preservation handling — may require review under E-Commerce Act Article 6", field),
			RelatedLaws: d.RelatedLawIDs(),
		}}
	}
	return nil
}
