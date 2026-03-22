package scanner

import (
	"os"
	"time"

	"github.com/rostradamus/dev-lawyer/internal/detector"
	"github.com/rostradamus/dev-lawyer/internal/report"
)

type ScannerService struct {
	Detectors []detector.Detector
	Walker    FileWalker
	registry  *detector.Registry
}

func NewService(registry *detector.Registry) *ScannerService {
	return &ScannerService{
		Detectors: registry.All(),
		Walker:    FileWalker{},
		registry:  registry,
	}
}

func (s *ScannerService) ScanDirectory(path string, pattern string) (report.Report, error) {
	files, err := Walk(path, pattern)
	if err != nil {
		return report.Report{}, err
	}

	var allFindings []report.Finding
	for _, f := range files {
		findings, err := s.scanOneFile(f)
		if err != nil {
			continue // skip unreadable files
		}
		allFindings = append(allFindings, findings...)
	}

	return report.Report{
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
		TargetPath:    path,
		FilesScanned:  len(files),
		TotalFindings: len(allFindings),
		Findings:      allFindings,
		Disclaimer:    report.Disclaimer,
	}, nil
}

func (s *ScannerService) ScanFile(path string) (report.Report, error) {
	findings, err := s.scanOneFile(path)
	if err != nil {
		return report.Report{}, err
	}

	return report.Report{
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
		TargetPath:    path,
		FilesScanned:  1,
		TotalFindings: len(findings),
		Findings:      findings,
		Disclaimer:    report.Disclaimer,
	}, nil
}

func (s *ScannerService) scanOneFile(path string) ([]report.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s.registry.ScanAll(string(data), path), nil
}
