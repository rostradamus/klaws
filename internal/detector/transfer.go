package detector

import (
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

// outboundTransferRe matches an outbound request/RPC call (a method invocation
// on a client, e.g. restTemplate.postForObject(...), webClient.exchange(...),
// httpClient.send(...)). The leading "." requires a receiver, so type names in
// declarations do not trigger it.
var outboundTransferRe = regexp.MustCompile(`(?i)\.\s*(post\w*|put\w*|exchange|execute|send)\s*\(`)

// externalTargetRe signals that the destination is a third party or external
// endpoint (as opposed to an internal repository/service call).
var externalTargetRe = regexp.MustCompile(
	`(?i)(https?://|third[_-]?party|external|partner|overseas|cross[_-]?border|제3자|외부|해외|국외)`,
)

// xbrPersonalDataRe matches high-signal personal-data terms whose transfer to a
// third party is governed by PIPA Article 17.
var xbrPersonalDataRe = regexp.MustCompile(
	`(?i)(\b(email|phone_?number|mobile|resident_?number|ssn|birth_?date|passport)\b|이메일|전화번호|주민번호|여권)`,
)

// xbrConsentRe matches evidence that consent to provide the data was checked.
// "agree" is anchored to a word start so that an explicit non-consent token such
// as "disagree" does not read as consent and suppress a finding.
var xbrConsentRe = regexp.MustCompile(`(?i)(consent|\bagree|동의|제공 ?동의)`)

type ThirdPartyTransferDetector struct{}

func NewThirdPartyTransferDetector() *ThirdPartyTransferDetector {
	return &ThirdPartyTransferDetector{}
}

func (d *ThirdPartyTransferDetector) ID() string   { return "PIPA-XBR-001" }
func (d *ThirdPartyTransferDetector) Name() string { return "Third-Party Data Transfer Risk" }
func (d *ThirdPartyTransferDetector) Description() string {
	return "Detects personal data sent to a third-party or external endpoint without an apparent consent check"
}
func (d *ThirdPartyTransferDetector) RelatedLawIDs() []string { return []string{"PIPA-17"} }

func (d *ThirdPartyTransferDetector) Scan(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	lines := strings.Split(sourceCode, "\n")

	for i, line := range lines {
		if lineCommentRe.MatchString(line) {
			continue
		}
		if !outboundTransferRe.MatchString(line) {
			continue
		}

		// Require all three signals near the call: an external destination,
		// personal data, and no consent check. windowAround skips comment lines.
		window := windowAround(lines, i, 10)
		if !externalTargetRe.MatchString(window) {
			continue
		}
		if !xbrPersonalDataRe.MatchString(window) {
			continue
		}
		if xbrConsentRe.MatchString(window) {
			continue
		}

		findings = append(findings, report.Finding{
			DetectorID:  d.ID(),
			RiskLevel:   "HIGH",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     "Possible transfer of personal data to a third party or external endpoint without an apparent consent check — may require review under PIPA Article 17",
			RelatedLaws: d.RelatedLawIDs(),
		})
	}
	return findings
}
