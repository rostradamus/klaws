package report

import "fmt"

// FlowDetectorID is the data-flow detector. Its findings supersede a regex
// finding at the same location, because a trace carries strictly more
// information than a single-line pattern match.
const FlowDetectorID = "PIPA-FLOW-001"

// Dedupe drops regex findings that a flow finding already covers at the same
// file and line. The regex detectors are kept as a safety net for code the
// lexer cannot follow; this only prevents double-reporting the same risk.
// Order of the surviving findings is preserved.
func Dedupe(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	flowLines := make(map[string]bool)
	for _, f := range findings {
		if f.DetectorID == FlowDetectorID {
			flowLines[locationKey(f)] = true
		}
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.DetectorID != FlowDetectorID && flowLines[locationKey(f)] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func locationKey(f Finding) string {
	return fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
}
