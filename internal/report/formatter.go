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
	fmt.Fprintf(&b, "klaws scan report\n")
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
		writeTrace(&b, f)
		fmt.Fprintf(&b, "  Laws:      %s\n\n", strings.Join(f.RelatedLaws, ", "))
	}

	fmt.Fprintf(&b, "%s\n", r.Disclaimer)
	return b.String()
}

// writeTrace renders a data-flow path. Findings without a trace (every regex
// detector) render exactly as they did before.
func writeTrace(b *strings.Builder, f Finding) {
	if len(f.Trace) == 0 {
		return
	}
	fmt.Fprintf(b, "  Trace:\n")
	for i, h := range f.Trace {
		fmt.Fprintf(b, "    %s %s:%d  %s   %s\n",
			stepMarker(i+1), f.FilePath, h.Line, h.Expression, h.Note)
	}
}

// circledDigits are ①–⑨; longer traces fall back to plain numbering.
var circledDigits = []string{"①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨"}

func stepMarker(n int) string {
	if n >= 1 && n <= len(circledDigits) {
		return circledDigits[n-1]
	}
	return fmt.Sprintf("%d.", n)
}
