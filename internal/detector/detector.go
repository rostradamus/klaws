package detector

import "github.com/rostradamus/klaws/internal/report"

type Detector interface {
	ID() string
	Name() string
	Description() string
	RelatedLawIDs() []string
	Scan(sourceCode string, filePath string) []report.Finding
}
