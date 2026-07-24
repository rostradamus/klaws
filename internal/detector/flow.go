package detector

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rostradamus/klaws/internal/flow"
	"github.com/rostradamus/klaws/internal/report"
)

// FlowDetector traces personal data from its source to a logging, transmission,
// or storage sink within a single file. Unlike the regex detectors, it can see
// data that reaches a sink through intermediate variables.
type FlowDetector struct{}

func NewFlowDetector() *FlowDetector { return &FlowDetector{} }

func (d *FlowDetector) ID() string   { return "PIPA-FLOW-001" }
func (d *FlowDetector) Name() string { return "Personal Data Flow Risk" }

func (d *FlowDetector) Description() string {
	return "Traces personal data from its source to logging, transmission, or storage within a file"
}

// RelatedLawIDs is the union of every provision a flow finding may cite.
// Individual findings cite the subset relevant to their source and sink.
func (d *FlowDetector) RelatedLawIDs() []string {
	return []string{"PIPA-17", "PIPA-24", "PIPA-24-2", "PIPA-29"}
}

func (d *FlowDetector) Scan(sourceCode string, filePath string) []report.Finding {
	traces := flow.Analyze(sourceCode, flow.Options{IsTestFile: isTestFile(filePath)})

	findings := make([]report.Finding, 0, len(traces))
	for _, t := range traces {
		if len(t.Hops) == 0 {
			continue
		}
		sink := t.Hops[len(t.Hops)-1]
		findings = append(findings, report.Finding{
			DetectorID:  d.ID(),
			RiskLevel:   riskFor(t.Source.Sens, t.Sink.Kind),
			FilePath:    filePath,
			LineNumber:  sink.Line,
			Snippet:     sink.Expression,
			Message:     flowMessage(t),
			RelatedLaws: lawsFor(t),
			Trace:       toReportHops(t.Hops),
		})
	}
	return findings
}

// riskFor implements the source-sensitivity × sink-kind matrix from the spec.
// Transmission is always HIGH: data crossing the system boundary is
// unrecoverable, and PIPA 제17조 conditions provision on the subject's consent,
// which cannot be verified from one file.
func riskFor(sens flow.Sensitivity, kind flow.SinkKind) string {
	switch kind {
	case flow.SinkTransmit:
		return "HIGH"
	case flow.SinkLog:
		if sens == flow.SensGeneral {
			return "MEDIUM"
		}
		return "HIGH"
	case flow.SinkPersist:
		switch sens {
		case flow.SensUnique:
			return "HIGH"
		case flow.SensFinancial:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}
	return "LOW"
}

// lawsFor combines the sink's provisions with any the source's sensitivity adds.
// 고유식별정보 brings in PIPA 제24조 regardless of destination. PIPA 제24조의2
// governs 주민등록번호 specifically, so a sink's blanket "PIPA-24-2" citation is
// dropped unless the source actually is a resident registration number — a
// passport number is also SensUnique but is not a 주민등록번호, and general or
// financial data reaching the same sink should not cite it at all.
func lawsFor(t flow.Trace) []string {
	laws := make([]string, 0, len(t.Sink.Laws)+1)
	for _, id := range t.Sink.Laws {
		if id == "PIPA-24-2" && t.Source.ID != "ssn" {
			continue
		}
		laws = append(laws, id)
	}

	if t.Source.Sens == flow.SensUnique {
		if !contains(laws, "PIPA-24") {
			laws = append(laws, "PIPA-24")
		}
	}
	return laws
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// flowMessage renders the finding text. Language stays hedged: this tool reports
// possible risks for review, never verdicts.
func flowMessage(t flow.Trace) string {
	return fmt.Sprintf(
		"Possible personal data (%s) may reach %s after %d steps — related provisions (%s) may require review",
		t.Source.Label,
		t.Sink.Label,
		len(t.Hops),
		strings.Join(lawsFor(t), ", "),
	)
}

func toReportHops(hops []flow.Hop) []report.TraceHop {
	out := make([]report.TraceHop, 0, len(hops))
	for _, h := range hops {
		out = append(out, report.TraceHop{
			Line:       h.Line,
			Expression: h.Expression,
			Kind:       hopKindName(h.Kind),
			Note:       h.Note,
		})
	}
	return out
}

func hopKindName(k flow.Kind) string {
	switch k {
	case flow.KindSource:
		return "source"
	case flow.KindPropagate:
		return "propagate"
	case flow.KindSink:
		return "sink"
	}
	return "unknown"
}

// isTestFile reports whether a path is test code. Test fixtures are full of fake
// 주민등록번호, so storage findings there are noise rather than risk.
func isTestFile(path string) bool {
	p := filepath.ToSlash(path)
	if strings.Contains(p, "/test/") || strings.HasPrefix(p, "test/") {
		return true
	}
	base := filepath.Base(p)
	return strings.HasSuffix(base, "Test.java") ||
		strings.HasSuffix(base, "Tests.java") ||
		strings.HasSuffix(base, "IT.java")
}
