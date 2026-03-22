package report

const Disclaimer = "This report identifies possible compliance risks for review. It does not constitute legal advice. Consult qualified legal counsel for definitive guidance."

type Finding struct {
	DetectorID  string   `json:"detector_id"`
	RiskLevel   string   `json:"risk_level"`
	FilePath    string   `json:"file_path"`
	LineNumber  int      `json:"line_number"`
	Snippet     string   `json:"snippet"`
	Message     string   `json:"message"`
	RelatedLaws []string `json:"related_laws"`
}

type Report struct {
	ScannedAt     string    `json:"scanned_at"`
	TargetPath    string    `json:"target_path"`
	FilesScanned  int       `json:"files_scanned"`
	TotalFindings int       `json:"total_findings"`
	Findings      []Finding `json:"findings"`
	Disclaimer    string    `json:"disclaimer"`
}

type DetectorInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RelatedLaws []string `json:"related_laws"`
}
