package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rostradamus/klaws/internal/report"
)

var sensitiveFieldRe = regexp.MustCompile(
	`(?i)(residentNumber|ssn|주민번호|resident.*[Nn]o)`,
)

var encryptionEvidenceRe = regexp.MustCompile(
	`(?i)(@Encrypted|encrypt\(|Encrypt\(|ENCRYPT)`,
)

type EncryptionDetector struct{}

func NewEncryptionDetector() *EncryptionDetector {
	return &EncryptionDetector{}
}

func (d *EncryptionDetector) ID() string   { return "PIPA-ENC-001" }
func (d *EncryptionDetector) Name() string { return "Unencrypted Personal Data Risk" }
func (d *EncryptionDetector) Description() string {
	return "Detects personal identifier fields stored without apparent encryption"
}
func (d *EncryptionDetector) RelatedLawIDs() []string { return []string{"PIPA-24-2", "PIPA-29"} }

// fieldAnnotationRe matches Java/Kotlin annotation lines.
var fieldAnnotationRe = regexp.MustCompile(`^\s*@\w+`)

// lineCommentRe matches single-line comment lines (// ...).
var lineCommentRe = regexp.MustCompile(`^\s*//`)

// fieldDeclRe matches a field or variable declaration line.
var fieldDeclRe = regexp.MustCompile(`^\s*(private|protected|public|final|static).*\s+\w+\s*;`)

// hasEncryptionEvidence returns true if there is encryption evidence in the
// annotations directly above the field line, on the line itself, or in a
// setter-like method block within the next 10 lines that references the same
// field name.
func hasEncryptionEvidence(lines []string, i int) bool {
	// Check the line itself (e.g. assignment with encrypt() on same line).
	if encryptionEvidenceRe.MatchString(lines[i]) {
		return true
	}

	// --- backward pass: adjacent annotations only ---
	var annotationLines []string
	for j := i - 1; j >= 0; j-- {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || lineCommentRe.MatchString(lines[j]) {
			break
		}
		if !fieldAnnotationRe.MatchString(lines[j]) {
			break
		}
		annotationLines = append(annotationLines, lines[j])
	}
	annotationContext := strings.Join(annotationLines, "\n")
	if encryptionEvidenceRe.MatchString(annotationContext) {
		return true
	}

	// --- forward pass: look for encrypt() in the next 10 lines,
	// but only accept it if we have NOT crossed into another field block.
	// Stop at: another field declaration, or an annotation line (which signals
	// the start of a new annotated field).
	end := i + 11
	if end > len(lines) {
		end = len(lines)
	}
	for j := i + 1; j < end; j++ {
		l := lines[j]
		// Skip comment lines without checking them for evidence.
		if lineCommentRe.MatchString(l) {
			continue
		}
		// Stop if we encounter another field declaration or annotation block.
		if fieldDeclRe.MatchString(l) || fieldAnnotationRe.MatchString(l) {
			break
		}
		if encryptionEvidenceRe.MatchString(l) {
			return true
		}
	}

	return false
}

func (d *EncryptionDetector) Scan(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	lines := strings.Split(sourceCode, "\n")

	for i, line := range lines {
		// Skip comment lines — they may mention field names without being declarations.
		if lineCommentRe.MatchString(line) {
			continue
		}
		if !sensitiveFieldRe.MatchString(line) {
			continue
		}

		if hasEncryptionEvidence(lines, i) {
			continue
		}

		field := sensitiveFieldRe.FindString(line)
		findings = append(findings, report.Finding{
			DetectorID:  d.ID(),
			RiskLevel:   "HIGH",
			FilePath:    filePath,
			LineNumber:  i + 1,
			Snippet:     strings.TrimSpace(line),
			Message:     fmt.Sprintf("Possible unencrypted personal identifier (%s) — may require review under PIPA Article 24-2", field),
			RelatedLaws: d.RelatedLawIDs(),
		})
	}
	return findings
}
