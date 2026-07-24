package report

import "fmt"

// FlowDetectorID is the data-flow detector. Its findings supersede a regex
// finding at the same location, because a trace carries strictly more
// information than a single-line pattern match.
const FlowDetectorID = "PIPA-FLOW-001"

// Dedupe drops regex findings that a flow finding already covers at the same
// file and line. The regex detectors are kept as a safety net for code the
// lexer cannot follow; this only prevents double-reporting the same risk.
// A surviving flow finding absorbs the RelatedLaws of every non-flow finding
// it supersedes at that location, so a legal citation only the regex
// detector knew about is never silently lost. Order of the surviving
// findings is preserved.
func Dedupe(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	// First pass: for every location, note whether a flow finding is present
	// and accumulate the ordered, deduplicated union of RelatedLaws from all
	// non-flow findings at that location (the laws that would otherwise be
	// dropped).
	flowLines := make(map[string]bool)
	supersededLaws := make(map[string][]string)
	for _, f := range findings {
		key := locationKey(f)
		if f.DetectorID == FlowDetectorID {
			flowLines[key] = true
			continue
		}
		supersededLaws[key] = unionLaws(supersededLaws[key], f.RelatedLaws)
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := locationKey(f)
		if f.DetectorID != FlowDetectorID {
			if flowLines[key] {
				continue
			}
			out = append(out, f)
			continue
		}

		if extra, ok := supersededLaws[key]; ok {
			f.RelatedLaws = unionLaws(f.RelatedLaws, extra)
		}
		out = append(out, f)
	}
	return out
}

// unionLaws returns a new slice containing base's elements in order,
// followed by any elements of extra not already present in base, in
// first-seen order. Neither base nor extra is mutated.
func unionLaws(base, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, law := range base {
		if !seen[law] {
			seen[law] = true
			out = append(out, law)
		}
	}
	for _, law := range extra {
		if !seen[law] {
			seen[law] = true
			out = append(out, law)
		}
	}
	return out
}

func locationKey(f Finding) string {
	return fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
}
