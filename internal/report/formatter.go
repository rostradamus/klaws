package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

func FormatJSON(r Report) ([]byte, error) {
	return json.Marshal(r)
}

func FormatText(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "dev-lawyer scan report\n")
	fmt.Fprintf(&b, "Scanned: %s\n", r.ScannedAt)
	fmt.Fprintf(&b, "Target:  %s\n", r.TargetPath)
	fmt.Fprintf(&b, "Files:   %d\n", r.FilesScanned)
	fmt.Fprintf(&b, "Findings: %d\n\n", r.TotalFindings)

	for i, f := range r.Findings {
		fmt.Fprintf(&b, "--- Finding %d ---\n", i+1)
		fmt.Fprintf(&b, "  Detector:  %s\n", f.DetectorID)
		fmt.Fprintf(&b, "  Risk:      %s\n", f.RiskLevel)
		fmt.Fprintf(&b, "  Location:  %s:%d\n", f.FilePath, f.LineNumber)
		fmt.Fprintf(&b, "  Snippet:   %s\n", f.Snippet)
		fmt.Fprintf(&b, "  Message:   %s\n", f.Message)
		fmt.Fprintf(&b, "  Laws:      %s\n\n", strings.Join(f.RelatedLaws, ", "))
	}

	fmt.Fprintf(&b, "%s\n", r.Disclaimer)
	return b.String()
}
