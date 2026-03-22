package detector

import "github.com/rostradamus/dev-lawyer/internal/report"

type Registry struct {
	detectors []Detector
}

func NewRegistry(detectors ...Detector) *Registry {
	return &Registry{detectors: detectors}
}

func (r *Registry) All() []Detector {
	return r.detectors
}

func (r *Registry) ScanAll(sourceCode string, filePath string) []report.Finding {
	var findings []report.Finding
	for _, d := range r.detectors {
		findings = append(findings, d.Scan(sourceCode, filePath)...)
	}
	return findings
}

func (r *Registry) Info() []report.DetectorInfo {
	infos := make([]report.DetectorInfo, len(r.detectors))
	for i, d := range r.detectors {
		infos[i] = report.DetectorInfo{
			ID:          d.ID(),
			Name:        d.Name(),
			Description: d.Description(),
			RelatedLaws: d.RelatedLawIDs(),
		}
	}
	return infos
}
