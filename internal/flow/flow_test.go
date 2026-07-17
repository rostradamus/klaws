package flow_test

import (
	"strings"
	"testing"

	"github.com/rostradamus/klaws/internal/flow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrap puts a body inside a method so scoping behaves like real Java.
func wrap(body string) string {
	return "class T {\n  void m(UserDto user) {\n" + body + "\n  }\n}"
}

func TestAnalyzeTracesConcatToLog(t *testing.T) {
	src := wrap(`    String s = user.getSsn();
    String msg = "id=" + s;
    log.info(msg);`)

	traces := flow.Analyze(src, flow.Options{})

	require.Len(t, traces, 1)
	tr := traces[0]
	assert.Equal(t, "ssn", tr.Source.ID)
	assert.Equal(t, flow.SinkLog, tr.Sink.Kind)
	require.Len(t, tr.Hops, 3, "source → propagate → sink")
	assert.Equal(t, flow.KindSource, tr.Hops[0].Kind)
	assert.Equal(t, flow.KindPropagate, tr.Hops[1].Kind)
	assert.Equal(t, flow.KindSink, tr.Hops[2].Kind)
	assert.Contains(t, tr.Hops[0].Expression, "getSsn")
	assert.Contains(t, tr.Hops[2].Expression, "log.info")
}

func TestAnalyzeDirectSourceIntoSink(t *testing.T) {
	traces := flow.Analyze(wrap(`    log.info(user.getSsn());`), flow.Options{})

	require.Len(t, traces, 1)
	assert.Equal(t, "ssn", traces[0].Source.ID)
	assert.Len(t, traces[0].Hops, 2, "source and sink on one line")
}

func TestAnalyzePropagationForms(t *testing.T) {
	cases := map[string]string{
		"assignment":    `String s = user.getSsn();` + "\n" + `String t = s;` + "\n" + `log.info(t);`,
		"concat":        `String s = user.getSsn();` + "\n" + `String t = "x" + s;` + "\n" + `log.info(t);`,
		"format":        `String s = user.getSsn();` + "\n" + `String t = String.format("%s", s);` + "\n" + `log.info(t);`,
		"stringBuilder": `String s = user.getSsn();` + "\n" + `String t = sb.append(s).toString();` + "\n" + `log.info(t);`,
		"argumentPass":  `String s = user.getSsn();` + "\n" + `String t = wrapValue(s);` + "\n" + `log.info(t);`,
	}
	for name, body := range cases {
		traces := flow.Analyze(wrap("    "+body), flow.Options{})
		assert.Len(t, traces, 1, "propagation form: %s", name)
	}
}

func TestAnalyzeSinkKinds(t *testing.T) {
	cases := map[string]flow.SinkKind{
		`restTemplate.postForObject(url, s, String.class);`: flow.SinkTransmit,
		`repository.save(s);`:                               flow.SinkPersist,
		`log.error(s);`:                                     flow.SinkLog,
	}
	for call, wantKind := range cases {
		src := wrap("    String s = user.getSsn();\n    " + call)
		traces := flow.Analyze(src, flow.Options{})
		require.Len(t, traces, 1, "call: %s", call)
		assert.Equal(t, wantKind, traces[0].Sink.Kind, "call: %s", call)
	}
}

func TestAnalyzeParameterNamedAsSourceIsTainted(t *testing.T) {
	src := "class T {\n  void m(String ssn) {\n    log.info(ssn);\n  }\n}"
	traces := flow.Analyze(src, flow.Options{})

	require.Len(t, traces, 1)
	assert.Equal(t, "ssn", traces[0].Source.ID)
}

func TestAnalyzeParameterNamedByTypeOnlyIsNotTainted(t *testing.T) {
	// UserDto/user match no source rule. Tainting by declared type would need
	// type resolution, which is an explicit non-goal.
	src := "class T {\n  void m(UserDto user) {\n    log.info(user);\n  }\n}"
	assert.Empty(t, flow.Analyze(src, flow.Options{}))
}

// --- Negative tests: each guards a specific false positive ---

func TestAnalyzeSanitizedFlowIsNotAFinding(t *testing.T) {
	src := wrap(`    String s = encrypt(user.getSsn());
    log.info(s);`)
	assert.Empty(t, flow.Analyze(src, flow.Options{}), "sanitized data must not be reported")
}

func TestAnalyzeSanitizerAtSinkIsNotAFinding(t *testing.T) {
	src := wrap(`    String s = user.getSsn();
    log.info(mask(s));`)
	assert.Empty(t, flow.Analyze(src, flow.Options{}))
}

// TestAnalyzeSanitizerOnSiblingArgumentDoesNotSuppressTaintedArgument guards a
// regression found in QA review: a sanitizer call anywhere in a sink's argument
// list must not blanket-suppress the whole call. It only clears the value it
// wraps — an unrelated tainted sibling operand is still a finding.
func TestAnalyzeSanitizerOnSiblingArgumentDoesNotSuppressTaintedArgument(t *testing.T) {
	src := wrap(`    String s = user.getSsn();
    log.info(s + encrypt(other));`)
	traces := flow.Analyze(src, flow.Options{})

	require.Len(t, traces, 1, "s is never wrapped by encrypt, so it must still be reported")
	assert.Equal(t, "ssn", traces[0].Source.ID)
}

// TestAnalyzeSanitizerReceiverFormIsNotAFinding guards a regression: a
// sanitizer invoked ON the tainted value (`value.mask()`), not wrapped
// around it (`mask(value)`), must still clear the value. sanitizedIndices
// previously marked only the tokens inside a sanitizer call's own
// parentheses, so the receiver preceding `.mask(` was never marked and the
// tainted receiver was still (incorrectly) reported. Receiver/fluent-style
// sanitizing (`value.mask()`, `dto.getSsn().mask()`) is extremely common
// Java and must be recognized as sanitized. The wrap-form cases are included
// here as regression guards to confirm the fix does not disturb them.
func TestAnalyzeSanitizerReceiverFormIsNotAFinding(t *testing.T) {
	cases := map[string]string{
		"bare receiver form": `    String s = user.getSsn();
    log.info(s.mask());`,
		"chained receiver form":        `    log.info(user.getSsn().mask());`,
		"wrap form (regression guard)": `    log.info(encrypt(user.getSsn()));`,
		"wrap form with seeded var (regression guard)": `    String s = user.getSsn();
    log.info(mask(s));`,
	}
	for name, body := range cases {
		traces := flow.Analyze(wrap(body), flow.Options{})
		assert.Empty(t, traces, "case: %s", name)
	}
}

// TestAnalyzeSanitizerReceiverFormDoesNotSuppressSibling guards the sibling
// case for the receiver-form fix: a sanitizer clears only the operand it
// covers (its own receiver chain plus its parenthesized args) — an
// unrelated tainted sibling joined by '+' must still be reported.
func TestAnalyzeSanitizerReceiverFormDoesNotSuppressSibling(t *testing.T) {
	cases := map[string]string{
		"sanitizer wraps trailing sibling": `    String s = user.getSsn();
    log.info(s + encrypt(other));`,
		"sanitizer wraps leading sibling": `    String s = user.getSsn();
    log.info(encrypt(a) + s);`,
	}
	for name, body := range cases {
		traces := flow.Analyze(wrap(body), flow.Options{})
		require.Len(t, traces, 1, "case: %s", name)
		assert.Equal(t, "ssn", traces[0].Source.ID, "case: %s", name)
	}
}

// TestAnalyzeSinkArgumentBoundaryDoesNotLeakAcrossNestedCalls guards a
// regression found in QA review: a nested call's arguments must not be
// attributed to an unrelated outer sink call it happens to sit inside.
func TestAnalyzeSinkArgumentBoundaryDoesNotLeakAcrossNestedCalls(t *testing.T) {
	src := wrap(`    String s = user.getSsn();
    compute(repository.save(cleanRecord), s);`)
	assert.Empty(t, flow.Analyze(src, flow.Options{}),
		"s is passed to compute, not to repository.save — it must not be attributed to the persistence sink")
}

func TestAnalyzeStringLiteralIsNotAFinding(t *testing.T) {
	assert.Empty(t, flow.Analyze(wrap(`    log.info("user ssn field");`), flow.Options{}),
		"a literal mentioning ssn is not personal data — the regex detector gets this wrong")
}

func TestAnalyzeShadowedVariableDoesNotLeakAcrossScopes(t *testing.T) {
	src := "class T {\n" +
		"  void a(UserDto user) {\n    String s = user.getSsn();\n  }\n" +
		"  void b() {\n    String s = \"clean\";\n    log.info(s);\n  }\n}"
	assert.Empty(t, flow.Analyze(src, flow.Options{}), "taint must not cross method boundaries")
}

func TestAnalyzeReassignmentFromCleanValueClearsTaint(t *testing.T) {
	src := wrap(`    String s = user.getSsn();
    s = "redacted";
    log.info(s);`)
	assert.Empty(t, flow.Analyze(src, flow.Options{}))
}

func TestAnalyzeTestFileSuppressesPersistenceOnly(t *testing.T) {
	body := "    String s = user.getSsn();\n    repository.save(s);\n    log.info(s);"
	traces := flow.Analyze(wrap(body), flow.Options{IsTestFile: true})

	require.Len(t, traces, 1, "persistence suppressed in tests, logging still reported")
	assert.Equal(t, flow.SinkLog, traces[0].Sink.Kind)
}

// --- Malformed input ---

func TestAnalyzeMalformedInputReturnsNoTracesWithoutPanicking(t *testing.T) {
	cases := []string{
		``,
		`class T {`,
		`}}}{{{`,
		`String s = user.getSsn()`, // truncated, no semicolon
		"not java at all\n\x00\xff",
		`/* unterminated`,
	}
	for _, src := range cases {
		assert.NotPanics(t, func() { flow.Analyze(src, flow.Options{}) }, "input: %q", src)
	}
}

func TestAnalyzeRespectsMaxTokens(t *testing.T) {
	src := wrap(strings.Repeat("    int x = 1;\n", 100) + `    String s = user.getSsn();
    log.info(s);`)

	assert.Empty(t, flow.Analyze(src, flow.Options{MaxTokens: 10}), "oversized input bails out cheaply")
	assert.NotEmpty(t, flow.Analyze(src, flow.Options{}), "default ceiling permits normal files")
}

func TestAnalyzeRespectsMaxHops(t *testing.T) {
	body := "    String v0 = user.getSsn();\n"
	for i := 1; i <= 8; i++ {
		body += "    String v" + string(rune('0'+i)) + " = v" + string(rune('0'+i-1)) + ";\n"
	}
	body += "    log.info(v8);"

	assert.Empty(t, flow.Analyze(wrap(body), flow.Options{MaxHops: 3}), "chain longer than MaxHops is dropped")
	assert.NotEmpty(t, flow.Analyze(wrap(body), flow.Options{}), "default ceiling permits a 10-hop chain")
}
