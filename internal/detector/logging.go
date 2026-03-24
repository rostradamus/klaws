package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

var logPersonalDataRe = regexp.MustCompile(
	`(?i)log\.(info|debug|warn|error)\(.*?(email|phone|ssn|password|주민|이름|전화|이메일)`,
)

type LoggingDetector struct{}

func NewLoggingDetector() *LoggingDetector {
	return &LoggingDetector{}
}

func (d *LoggingDetector) ID() string   { return "PIPA-LOG-001" }
func (d *LoggingDetector) Name() string { return "Personal Data Logging Risk" }
func (d *LoggingDetector) Description() string {
	return "Detects log statements that may contain personal data fields"
}
func (d *LoggingDetector) RelatedLawIDs() []string { return []string{"PIPA-29"} }

func (d *LoggingDetector) Scan(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	lines := strings.Split(sourceCode, "\n")

	for i, line := range lines {
		matches := logPersonalDataRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		field := matches[2]
		findings = append(findings, report.Finding{
			DetectorID:  d.ID(),
			RiskLevel:   "MEDIUM",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     fmt.Sprintf("Possible personal data (%s) in log output — may require review under PIPA Article 29", field),
			RelatedLaws: d.RelatedLawIDs(),
		})
	}
	return findings
}
