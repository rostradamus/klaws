# PII Data-Flow Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `PIPA-FLOW-001`, a taint-analysis detector that traces personal data from its source to a logging, transmission, or storage sink within a single Java file, and reports the full propagation path.

**Architecture:** A new dependency-free `internal/flow` package lexes Java into tokens, walks statements against a brace-depth scope stack, and returns `[]Trace`. Its entire public API is `flow.Analyze(src, opts)`. A thin adapter, `internal/detector/flow.go`, maps traces onto the existing `Detector` interface, applying a source-sensitivity × sink-kind risk matrix. `report.Finding` gains an `omitempty` `Trace` field that text, JSON, and SARIF formatters render.

**Tech Stack:** Go 1.23, stdlib only (no new dependencies), testify for assertions (already vendored).

**Spec:** `docs/superpowers/specs/2026-07-16-pii-flow-tracing-design.md`

## Global Constraints

These apply to every task. Do not violate them even if a task's steps don't repeat them.

- **No new dependencies.** `internal/flow` imports stdlib only. Release builds are `CGO_ENABLED=0` across 6 platforms into `distroless/static`; adding a CGO dependency breaks the build matrix, the Docker image, and `go install`.
- **Hedged language in all user-facing strings.** Use "possible risk", "may require review", "related provision". NEVER use "violation", "illegal", "non-compliant", "you must". This tool does not provide legal advice. (Source: `CLAUDE.md` Critical Rules.)
- **Only cite law IDs that exist in `internal/law/laws/pipa.yaml`.** The valid set for this feature is exactly: `PIPA-17`, `PIPA-24`, `PIPA-24-2`, `PIPA-29`. `PIPA-24-3` and `PIPA-28-2` do NOT exist — an earlier spec draft cited them in error. Task 3 adds a test that makes this class of error impossible to ship.
- **The engine never panics and never returns an error.** Malformed Java is normal input. Unparseable → zero traces.
- **`Finding.Trace` must be `omitempty`.** Existing regex detectors' JSON output stays byte-identical. This is a public contract.
- **Go 1.23**, module `github.com/rostradamus/klaws`.
- **Test package convention:** every existing test file in this repo uses an *external* test package (`package detector_test`, `package report_test`, `package scanner_test`, `package law_test`) and refers to the code under test through its import path. Follow this. The only exceptions in this plan are `internal/flow/lexer_test.go` and `internal/flow/scope_test.go`, which use `package flow` because they exercise unexported internals (`splitWords`, `scopeStack`, `taint`) that cannot be reached from outside. Go permits both packages in one directory, so this mix is legal.
- Run `gofmt -w` on every file you touch before committing.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/flow/lexer.go` | Java → `[]Token`. Discards comments, keeps string literals opaque. |
| `internal/flow/rules.go` | Sources / sinks / sanitizers as data tables + the matchers. |
| `internal/flow/flow.go` | Public API: `Kind`, `Hop`, `Trace`, `Options`, `Analyze`. |
| `internal/flow/scope.go` | Brace-depth scope stack mapping symbol → taint. Shadowing lives here. |
| `internal/flow/trace.go` | The walk: statements, assignment, propagation, sinks. |
| `internal/detector/flow.go` | Adapter: `flow.Trace` → `report.Finding`. Risk matrix, law mapping, messages. |
| `internal/report/model.go` | Add `Finding.Trace` + `TraceHop`. |
| `internal/report/formatter.go` | Render trace in text output. |
| `internal/report/sarif.go` | Render trace as SARIF `codeFlows`. |
| `internal/report/dedupe.go` | Drop regex findings that a flow finding supersedes. |
| `internal/scanner/scanner.go` | Apply `Dedupe` after `ScanAll`. |
| `cmd/klaws/main.go` | Register `NewFlowDetector()` in `buildDeps()`. |

---

### Task 1: Java Lexer

**Files:**
- Create: `internal/flow/lexer.go`
- Test: `internal/flow/lexer_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `TokenKind` (`TokenIdent`, `TokenString`, `TokenNumber`, `TokenPunct`), `Token{Kind TokenKind; Text string; Line int}`, `func Lex(src string) []Token`, `func splitWords(name string) []string`.

The single most important property: **string literals lex to `TokenString`, never `TokenIdent`**. That is what makes `log.info("user ssn field")` a non-finding, which the current regex detector gets wrong.

- [ ] **Step 1: Write the failing test**

Create `internal/flow/lexer_test.go`:

```go
package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLexIdentifiersAndPunctuation(t *testing.T) {
	toks := Lex(`String s = user.getSsn();`)

	require.Len(t, toks, 9)
	assert.Equal(t, Token{Kind: TokenIdent, Text: "String", Line: 1}, toks[0])
	assert.Equal(t, Token{Kind: TokenIdent, Text: "s", Line: 1}, toks[1])
	assert.Equal(t, Token{Kind: TokenPunct, Text: "=", Line: 1}, toks[2])
	assert.Equal(t, Token{Kind: TokenIdent, Text: "user", Line: 1}, toks[3])
	assert.Equal(t, Token{Kind: TokenPunct, Text: ".", Line: 1}, toks[4])
	assert.Equal(t, Token{Kind: TokenIdent, Text: "getSsn", Line: 1}, toks[5])
}

func TestLexStringLiteralIsNotAnIdentifier(t *testing.T) {
	toks := Lex(`log.info("user ssn field");`)

	for _, tok := range toks {
		if tok.Text == "user ssn field" {
			assert.Equal(t, TokenString, tok.Kind, "string literal must never lex as an identifier")
			return
		}
	}
	t.Fatal("string literal token not found")
}

func TestLexDiscardsComments(t *testing.T) {
	src := "// ssn comment\nString a = 1; /* block ssn\n spanning lines */ String b = 2;"
	toks := Lex(src)

	for _, tok := range toks {
		assert.NotContains(t, tok.Text, "comment")
		assert.NotContains(t, tok.Text, "spanning")
	}
}

func TestLexTracksLineNumbersAcrossComments(t *testing.T) {
	src := "String a = 1;\n/* two\nline */\nString b = 2;"
	toks := Lex(src)

	last := toks[len(toks)-1]
	assert.Equal(t, 4, last.Line, "line count must survive multi-line block comments")
}

func TestLexKoreanIdentifiers(t *testing.T) {
	toks := Lex(`String 주민등록번호 = x;`)

	require.GreaterOrEqual(t, len(toks), 2)
	assert.Equal(t, TokenIdent, toks[1].Kind)
	assert.Equal(t, "주민등록번호", toks[1].Text)
}

func TestLexMalformedInputDoesNotPanic(t *testing.T) {
	cases := []string{
		``,
		`"unterminated`,
		`/* unterminated`,
		`}}}{{{`,
		"\x00\xff binary",
		`'a`,
	}
	for _, src := range cases {
		assert.NotPanics(t, func() { Lex(src) }, "input: %q", src)
	}
}

func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		"cardNumber":   {"card", "number"},
		"SSN":          {"ssn"},
		"getSsn":       {"get", "ssn"},
		"userRRN":      {"user", "rrn"},
		"user_ssn":     {"user", "ssn"},
		"주민등록번호": {"주민등록번호"},
		"":             nil,
	}
	for in, want := range cases {
		assert.Equal(t, want, splitWords(in), "input: %q", in)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/flow/ -v`
Expected: FAIL — build error, `undefined: Lex`, `undefined: Token`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/flow/lexer.go`:

```go
package flow

import (
	"strings"
	"unicode"
)

// TokenKind classifies a lexed Java token.
type TokenKind int

const (
	TokenIdent TokenKind = iota
	TokenString
	TokenNumber
	TokenPunct
)

// Token is a single lexed token. Line is 1-indexed.
type Token struct {
	Kind TokenKind
	Text string
	Line int
}

// Lex tokenizes Java source. Comments are discarded. String and character
// literals become TokenString so their contents can never be mistaken for an
// identifier — this is what keeps log.info("user ssn field") from tainting.
//
// Lex never panics: malformed input yields whatever tokens could be read.
func Lex(src string) []Token {
	var toks []Token
	runes := []rune(src)
	n := len(runes)
	line := 1

	for i := 0; i < n; {
		c := runes[i]

		switch {
		case c == '\n':
			line++
			i++

		case unicode.IsSpace(c):
			i++

		case c == '/' && i+1 < n && runes[i+1] == '/':
			for i < n && runes[i] != '\n' {
				i++
			}

		case c == '/' && i+1 < n && runes[i+1] == '*':
			i += 2
			for i+1 < n && !(runes[i] == '*' && runes[i+1] == '/') {
				if runes[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
			if i > n {
				i = n // unterminated block comment
			}

		case c == '"':
			startLine := line
			i++
			var sb strings.Builder
			for i < n && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < n {
					if runes[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if runes[i] == '\n' {
					line++
				}
				sb.WriteRune(runes[i])
				i++
			}
			i++ // consume closing quote (or run past end if unterminated)
			if i > n {
				i = n
			}
			toks = append(toks, Token{Kind: TokenString, Text: sb.String(), Line: startLine})

		case c == '\'':
			startLine := line
			i++
			for i < n && runes[i] != '\'' {
				if runes[i] == '\\' && i+1 < n {
					if runes[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if runes[i] == '\n' {
					line++
				}
				i++
			}
			i++
			if i > n {
				i = n
			}
			toks = append(toks, Token{Kind: TokenString, Text: "", Line: startLine})

		case isIdentStart(c):
			start := i
			for i < n && isIdentPart(runes[i]) {
				i++
			}
			toks = append(toks, Token{Kind: TokenIdent, Text: string(runes[start:i]), Line: line})

		case unicode.IsDigit(c):
			start := i
			for i < n && (unicode.IsDigit(runes[i]) || runes[i] == '.' || isIdentPart(runes[i])) {
				i++
			}
			toks = append(toks, Token{Kind: TokenNumber, Text: string(runes[start:i]), Line: line})

		default:
			toks = append(toks, Token{Kind: TokenPunct, Text: string(c), Line: line})
			i++
		}
	}

	return toks
}

func isIdentStart(c rune) bool { return unicode.IsLetter(c) || c == '_' || c == '$' }
func isIdentPart(c rune) bool  { return isIdentStart(c) || unicode.IsDigit(c) }

// splitWords breaks an identifier into lowercase words on camelCase boundaries
// and underscores. Acronyms stay whole ("SSN" → ["ssn"], not ["s","s","n"]).
// Korean identifiers have no case, so they survive as a single word.
func splitWords(name string) []string {
	var words []string
	var cur []rune
	prevLower := false

	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}

	for _, r := range name {
		if r == '_' || r == '$' {
			flush()
			prevLower = false
			continue
		}
		if unicode.IsUpper(r) && prevLower {
			flush()
		}
		cur = append(cur, r)
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
	}
	flush()

	return words
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/flow/ -v`
Expected: PASS — all 7 tests.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/flow/
git add internal/flow/lexer.go internal/flow/lexer_test.go
git commit -m "feat(flow): add pure-Go Java lexer for taint analysis"
```

---

### Task 2: Rules Tables and Matchers

**Files:**
- Create: `internal/flow/rules.go`
- Test: `internal/flow/rules_test.go`

**Interfaces:**
- Consumes: `splitWords` (Task 1).
- Produces: `Sensitivity` (`SensGeneral`, `SensFinancial`, `SensUnique`), `SourceRule{ID, Label string; Sens Sensitivity; Patterns []string}`, `SinkKind` (`SinkLog`, `SinkTransmit`, `SinkPersist`), `SinkRule{Kind SinkKind; Label string; Laws []string; Patterns []string}`, `DefaultSources`, `DefaultSinks`, `DefaultSanitizers`, `MatchSource(name string) (SourceRule, bool)`, `MatchSink(callText string) (SinkRule, bool)`, `IsSanitizer(callText string) bool`.

`Label` is the human-facing name used in findings (`주민등록번호`, `log output`). legal-mapper reviews these strings.

- [ ] **Step 1: Write the failing test**

Create `internal/flow/rules_test.go`:

```go
package flow_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/flow"
	"github.com/stretchr/testify/assert"
)

func TestMatchSourceOnGetterAndField(t *testing.T) {
	cases := map[string]string{
		"getSsn":     "ssn",
		"ssn":        "ssn",
		"userSsn":    "ssn",
		"주민등록번호":  "ssn",
		"cardNumber": "card",
		"getEmail":   "email",
		"phone":      "phone",
		"passport":   "passport",
	}
	for name, wantID := range cases {
		rule, ok := flow.MatchSource(name)
		assert.True(t, ok, "expected %q to match a source", name)
		assert.Equal(t, wantID, rule.ID, "input: %q", name)
	}
}

func TestMatchSourceIsWordBoundaryAware(t *testing.T) {
	// "accountingPeriod" contains "account" as a substring but not as a word.
	// A naive strings.Contains matcher would produce a false positive here.
	_, ok := flow.MatchSource("accountingPeriod")
	assert.False(t, ok, "substring match must not seed taint")
}

func TestMatchSourceRejectsUnrelatedNames(t *testing.T) {
	for _, name := range []string{"user", "UserDto", "total", "index", "i"} {
		_, ok := flow.MatchSource(name)
		assert.False(t, ok, "input: %q", name)
	}
}

func TestSourceSensitivity(t *testing.T) {
	ssn, _ := flow.MatchSource("ssn")
	assert.Equal(t, flow.SensUnique, ssn.Sens)

	card, _ := flow.MatchSource("cardNumber")
	assert.Equal(t, flow.SensFinancial, card.Sens)

	email, _ := flow.MatchSource("email")
	assert.Equal(t, flow.SensGeneral, email.Sens)
}

func TestMatchSink(t *testing.T) {
	cases := map[string]flow.SinkKind{
		"log.info":                   flow.SinkLog,
		"logger.debug":               flow.SinkLog,
		"System.out.print":           flow.SinkLog,
		"e.printStackTrace":          flow.SinkLog,
		"restTemplate.postForObject": flow.SinkTransmit,
		"webClient.post":             flow.SinkTransmit,
		"repository.save":            flow.SinkPersist,
		"jdbcTemplate.update":        flow.SinkPersist,
	}
	for call, wantKind := range cases {
		rule, ok := flow.MatchSink(call)
		assert.True(t, ok, "expected %q to match a sink", call)
		assert.Equal(t, wantKind, rule.Kind, "input: %q", call)
	}
}

func TestMatchSinkRejectsOrdinaryCalls(t *testing.T) {
	for _, call := range []string{"list.add", "map.get", "service.compute"} {
		_, ok := flow.MatchSink(call)
		assert.False(t, ok, "input: %q", call)
	}
}

func TestIsSanitizer(t *testing.T) {
	for _, call := range []string{"encrypt", "AesUtil.encrypt", "mask", "hashPassword", "redact", "anonymize"} {
		assert.True(t, flow.IsSanitizer(call), "input: %q", call)
	}
}

func TestIsSanitizerIsWordBoundaryAware(t *testing.T) {
	// "hashMap.put" contains "hash" as a substring. Treating it as a sanitizer
	// would silently swallow real findings.
	assert.False(t, flow.IsSanitizer("hashMap.put"), "substring match must not clear taint")
}

func TestEveryLawIDInSinkRulesIsValid(t *testing.T) {
	// Guard against citing a provision the law registry cannot resolve. An early
	// spec draft cited PIPA-24-3 and PIPA-28-2, neither of which exists.
	valid := map[string]bool{
		"PIPA-17": true, "PIPA-24": true, "PIPA-24-2": true, "PIPA-29": true,
	}
	for _, sink := range flow.DefaultSinks {
		assert.NotEmpty(t, sink.Laws, "sink %v must cite at least one provision", sink.Kind)
		for _, id := range sink.Laws {
			assert.True(t, valid[id], "sink %v cites unknown law ID %q", sink.Kind, id)
		}
	}
}

func TestEverySourceRuleHasLabelAndPatterns(t *testing.T) {
	for _, src := range flow.DefaultSources {
		assert.NotEmpty(t, src.ID)
		assert.NotEmpty(t, src.Label, "source %q needs a human-facing label", src.ID)
		assert.NotEmpty(t, src.Patterns, "source %q needs patterns", src.ID)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/flow/ -run 'TestMatch|TestSource|TestIsSanitizer|TestEvery' -v`
Expected: FAIL — `undefined: MatchSource`, `undefined: DefaultSinks`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/flow/rules.go`:

```go
package flow

import "strings"

// Sensitivity grades how sensitive a category of personal data is under PIPA.
type Sensitivity int

const (
	// SensGeneral is ordinary personal data (email, phone, address, name).
	SensGeneral Sensitivity = iota
	// SensFinancial is payment and account data.
	SensFinancial
	// SensUnique is 고유식별정보 — unique identifying information under PIPA 제24조.
	SensUnique
)

// SourceRule describes a category of personal data and the identifier patterns
// that indicate it. Patterns match whole words, not substrings.
type SourceRule struct {
	ID       string
	Label    string // human-facing, appears in findings
	Sens     Sensitivity
	Patterns []string
}

// SinkKind classifies where tainted data ends up.
type SinkKind int

const (
	SinkLog SinkKind = iota
	SinkTransmit
	SinkPersist
)

// SinkRule describes a dangerous destination and the provisions it relates to.
type SinkRule struct {
	Kind     SinkKind
	Label    string // human-facing, appears in findings
	Laws     []string
	Patterns []string
}

// DefaultSources is the curated personal-data catalogue. Kept as plain data so a
// future .klaws.yaml override can extend it without touching the engine.
var DefaultSources = []SourceRule{
	{ID: "ssn", Label: "주민등록번호", Sens: SensUnique,
		Patterns: []string{"ssn", "rrn", "jumin", "주민등록번호", "주민번호", "residentRegistration"}},
	{ID: "passport", Label: "여권번호", Sens: SensUnique,
		Patterns: []string{"passport", "여권번호", "driverLicense", "운전면허"}},
	{ID: "card", Label: "카드·계좌번호", Sens: SensFinancial,
		Patterns: []string{"cardNumber", "cardNo", "카드번호", "accountNumber", "accountNo", "계좌번호", "bankAccount"}},
	{ID: "phone", Label: "전화번호", Sens: SensGeneral,
		Patterns: []string{"phone", "mobile", "전화번호", "휴대폰"}},
	{ID: "email", Label: "이메일", Sens: SensGeneral,
		Patterns: []string{"email", "이메일"}},
	{ID: "address", Label: "주소", Sens: SensGeneral,
		Patterns: []string{"address", "주소"}},
	{ID: "name", Label: "성명", Sens: SensGeneral,
		Patterns: []string{"userName", "realName", "이름", "성명",
			"firstName", "lastName", "fullName", "customerName", "middleName", "memberName"}},
}

// DefaultSinks maps destinations to the provisions they relate to. Every ID here
// must exist in internal/law/laws/pipa.yaml — see TestEveryLawIDInSinkRulesIsValid.
var DefaultSinks = []SinkRule{
	{Kind: SinkLog, Label: "log output", Laws: []string{"PIPA-29"},
		Patterns: []string{"log.info", "log.debug", "log.warn", "log.error", "logger.",
			"System.out.print", "System.err.print", "printStackTrace"}},
	{Kind: SinkTransmit, Label: "external transmission", Laws: []string{"PIPA-17"},
		Patterns: []string{"restTemplate.", "webClient.", "okHttpClient.", "httpClient.",
			"HttpEntity", "FeignClient", "URLConnection"}},
	{Kind: SinkPersist, Label: "storage without visible encryption", Laws: []string{"PIPA-24-2", "PIPA-29"},
		Patterns: []string{"repository.save", "entityManager.persist", "jdbcTemplate.update",
			"Files.write", "FileWriter", "preparedStatement.set"}},
}

// DefaultSanitizers clear taint. This is the primary false-positive defense.
var DefaultSanitizers = []string{
	"encrypt", "mask", "hash", "redact", "anonymize", "pseudonym",
	"aes", "sha", "bcrypt", "digest",
}

// MatchSource reports whether an identifier names personal data. Matching is
// word-based: "accountingPeriod" does not match the "account" pattern, because
// substring matching is the classic source of false positives.
func MatchSource(name string) (SourceRule, bool) {
	words := splitWords(name)
	if len(words) == 0 {
		return SourceRule{}, false
	}

	for _, rule := range DefaultSources {
		for _, pattern := range rule.Patterns {
			want := normalizePattern(pattern)
			if matchesWordRun(words, want) {
				return rule, true
			}
		}
	}
	return SourceRule{}, false
}

// matchesWordRun reports whether any contiguous run of words joins to want.
// This lets a multi-word pattern ("cardNumber") match ["card","number"] while a
// single-word pattern ("ssn") matches the "ssn" word in ["user","ssn"].
func matchesWordRun(words []string, want string) bool {
	for i := range words {
		joined := ""
		for j := i; j < len(words); j++ {
			joined += words[j]
			if joined == want {
				return true
			}
			if len(joined) > len(want) {
				break
			}
		}
	}
	return false
}

func normalizePattern(p string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(p))
}

// MatchSink reports whether a dotted call expression is a dangerous destination.
// Sink patterns are call fragments ("log.info", "restTemplate."), so substring
// matching is correct here — unlike source matching.
func MatchSink(callText string) (SinkRule, bool) {
	lc := strings.ToLower(callText)
	for _, rule := range DefaultSinks {
		for _, pattern := range rule.Patterns {
			if strings.Contains(lc, strings.ToLower(pattern)) {
				return rule, true
			}
		}
	}
	return SinkRule{}, false
}

// IsSanitizer reports whether a call neutralizes personal data. Matching is
// word-based against the invoked method name — the last dotted segment — so
// "hashMap.put" is not mistaken for a hash. A receiver's name sanitizes
// nothing; only the method it invokes can.
func IsSanitizer(callText string) bool {
	segments := strings.Split(callText, ".")
	method := segments[len(segments)-1]
	words := splitWords(method)
	// Object.hashCode() is an identity/content hash for use in hashmaps, not a
	// cryptographic or anonymizing operation — it must not clear taint even
	// though its word-run contains the bare "hash" sanitizer word.
	if matchesWordRun(words, "hashcode") {
		return false
	}
	for _, word := range words {
		for _, s := range DefaultSanitizers {
			if word == s {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/flow/ -v`
Expected: PASS — Task 1 and Task 2 tests.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/flow/
git add internal/flow/rules.go internal/flow/rules_test.go
git commit -m "feat(flow): add source/sink/sanitizer rule tables and matchers"
```

---

### Task 3: Public Types and Scope Stack

**Files:**
- Create: `internal/flow/flow.go` — public types only; `Analyze` arrives in Task 4
- Create: `internal/flow/scope.go`
- Test: `internal/flow/scope_test.go`

**Interfaces:**
- Consumes: `SourceRule`, `SinkRule` (Task 2).
- Produces: `Kind` (`KindSource`, `KindPropagate`, `KindSink`), `Hop{Line int; Expression string; Kind Kind; Note string}`, `Trace{Source SourceRule; Sink SinkRule; Hops []Hop}`, `Options{MaxHops, MaxTokens int; IsTestFile bool}`, `DefaultMaxHops = 10`, `DefaultMaxTokens = 200000`, and the unexported `taint`, `scopeStack` (`newScopeStack`, `push`, `pop`, `set`, `get`, `clear`), `cloneHops`.

Every type is declared once, in its final home. `flow.go` is created here holding only declarations; Task 4 adds `Analyze` to it.

`scope_test.go` uses `package flow` (not `flow_test`) because it exercises unexported internals — see the test package convention in Global Constraints.

- [ ] **Step 1: Write the failing test**

Create `internal/flow/scope_test.go`:

```go
package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeSetAndGet(t *testing.T) {
	s := newScopeStack()
	s.set("ssn", taint{Source: SourceRule{ID: "ssn"}})

	got, ok := s.get("ssn")
	assert.True(t, ok)
	assert.Equal(t, "ssn", got.Source.ID)
}

func TestScopeInnerSeesOuter(t *testing.T) {
	s := newScopeStack()
	s.set("ssn", taint{Source: SourceRule{ID: "ssn"}})
	s.push()

	_, ok := s.get("ssn")
	assert.True(t, ok, "inner scope must see outer taint")
}

func TestScopeTaintDoesNotEscapeClosedScope(t *testing.T) {
	s := newScopeStack()
	s.push()
	s.set("ssn", taint{Source: SourceRule{ID: "ssn"}})
	s.pop()

	_, ok := s.get("ssn")
	assert.False(t, ok, "taint must not survive its scope — this is the anti-false-positive guarantee")
}

func TestScopeShadowing(t *testing.T) {
	s := newScopeStack()
	s.set("x", taint{Source: SourceRule{ID: "ssn"}})
	s.push()
	s.set("x", taint{Source: SourceRule{ID: "email"}})

	got, _ := s.get("x")
	assert.Equal(t, "email", got.Source.ID, "inner declaration shadows outer")

	s.pop()
	got, _ = s.get("x")
	assert.Equal(t, "ssn", got.Source.ID, "outer taint reappears after inner scope closes")
}

func TestScopeClearRemovesNearestBinding(t *testing.T) {
	s := newScopeStack()
	s.set("x", taint{Source: SourceRule{ID: "ssn"}})
	s.clear("x")

	_, ok := s.get("x")
	assert.False(t, ok)
}

func TestScopeUnbalancedPopDegradesGracefully(t *testing.T) {
	s := newScopeStack()

	assert.NotPanics(t, func() {
		for i := 0; i < 10; i++ {
			s.pop()
		}
	}, "unbalanced braces must degrade, not panic")

	s.set("x", taint{Source: SourceRule{ID: "ssn"}})
	_, ok := s.get("x")
	assert.True(t, ok, "stack must remain usable after over-popping")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/flow/ -run TestScope -v`
Expected: FAIL — `undefined: newScopeStack`, `undefined: taint`.

- [ ] **Step 3: Create the public types**

Create `internal/flow/flow.go`. This task adds declarations only; Task 4 appends `Analyze` to this same file.

```go
// Package flow performs intra-file taint analysis on Java source: it traces
// personal data from where it enters a file to where it leaks.
//
// The package is deliberately free of any dependency on detectors, laws, or
// reports. Analyze is its entire public surface, so the lexer can be replaced
// without affecting consumers.
package flow

// Kind classifies a hop in a trace.
type Kind int

const (
	KindSource Kind = iota
	KindPropagate
	KindSink
)

// Hop is one step along a trace, anchored to a source line.
type Hop struct {
	Line       int
	Expression string
	Kind       Kind
	Note       string
}

// Trace is a complete path from a personal-data source to a sink.
type Trace struct {
	Source SourceRule
	Sink   SinkRule
	Hops   []Hop // ordered: source first, sink last
}

// Options tunes an analysis. The zero value is valid and uses the defaults.
type Options struct {
	MaxHops    int  // longest propagation chain to follow
	MaxTokens  int  // files larger than this are skipped
	IsTestFile bool // suppresses storage findings on test fixtures
}

const (
	DefaultMaxHops   = 10
	DefaultMaxTokens = 200000
)
```

- [ ] **Step 4: Write the scope stack**

Create `internal/flow/scope.go`:

```go
package flow

// taint is what a scope binds a symbol to: which source seeded it and how it
// travelled to get here.
type taint struct {
	Source SourceRule
	Hops   []Hop
}

// scopeStack tracks tainted symbols per brace-depth frame. Correct shadowing is
// the property regex detectors fundamentally cannot provide.
type scopeStack struct {
	frames []map[string]taint
}

func newScopeStack() *scopeStack {
	return &scopeStack{frames: []map[string]taint{{}}}
}

func (s *scopeStack) push() {
	s.frames = append(s.frames, map[string]taint{})
}

// pop never removes the final frame, so unbalanced braces degrade to a flatter
// scope rather than crashing the scan.
func (s *scopeStack) pop() {
	if len(s.frames) > 1 {
		s.frames = s.frames[:len(s.frames)-1]
	}
}

func (s *scopeStack) set(name string, t taint) {
	s.frames[len(s.frames)-1][name] = t
}

func (s *scopeStack) get(name string) (taint, bool) {
	for i := len(s.frames) - 1; i >= 0; i-- {
		if t, ok := s.frames[i][name]; ok {
			return t, true
		}
	}
	return taint{}, false
}

// clear removes the nearest binding for name, used when a symbol is reassigned
// from a clean value or passed through a sanitizer.
func (s *scopeStack) clear(name string) {
	for i := len(s.frames) - 1; i >= 0; i-- {
		if _, ok := s.frames[i][name]; ok {
			delete(s.frames[i], name)
			return
		}
	}
}

// cloneHops copies a hop slice so appending to one trace never mutates another
// that shares a prefix.
func cloneHops(hops []Hop) []Hop {
	out := make([]Hop, len(hops))
	copy(out, hops)
	return out
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/flow/ -v`
Expected: PASS — Tasks 1–3.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/flow/
git add internal/flow/flow.go internal/flow/scope.go internal/flow/scope_test.go
git commit -m "feat(flow): add public trace types and brace-depth scope stack"
```

---

### Task 4: The Taint Walk

**Files:**
- Create: `internal/flow/trace.go`
- Modify: `internal/flow/flow.go` — append `Analyze` (the file already holds the public types from Task 3)
- Test: `internal/flow/flow_test.go`

**Interfaces:**
- Consumes: `Lex`, `Token` (Task 1); `MatchSource`, `MatchSink`, `IsSanitizer`, `SourceRule`, `SinkRule` (Task 2); `Kind`, `Hop`, `Trace`, `Options`, `DefaultMaxHops`, `DefaultMaxTokens`, `scopeStack`, `taint`, `cloneHops` (Task 3).
- Produces: `func Analyze(src string, opts Options) []Trace`.

This is the heart of the feature. Run qa-guard after this task.

- [ ] **Step 1: Write the failing test**

Create `internal/flow/flow_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/flow/ -run TestAnalyze -v`
Expected: FAIL — `undefined: Analyze`, `undefined: Options`, `undefined: Trace`.

- [ ] **Step 3: Add Analyze to flow.go**

Append to `internal/flow/flow.go` (which already holds `Kind`, `Hop`, `Trace`, `Options`, and the ceiling constants from Task 3). Add the `strings` import:

```go
import "strings"

// Analyze returns every taint trace in src. It never returns an error and never
// panics: malformed Java is normal input and simply yields no traces.
func Analyze(src string, opts Options) []Trace {
	if opts.MaxHops <= 0 {
		opts.MaxHops = DefaultMaxHops
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = DefaultMaxTokens
	}

	toks := Lex(src)
	if len(toks) == 0 || len(toks) > opts.MaxTokens {
		return nil
	}

	a := &analyzer{
		toks:   toks,
		lines:  strings.Split(src, "\n"),
		scopes: newScopeStack(),
		opts:   opts,
	}
	a.walk()
	return a.traces
}
```

- [ ] **Step 4: Write the walk**

Create `internal/flow/trace.go`:

```go
package flow

import "strings"

type analyzer struct {
	toks   []Token
	lines  []string
	scopes *scopeStack
	opts   Options
	traces []Trace
}

// lineText returns the trimmed source text of a 1-indexed line.
func (a *analyzer) lineText(line int) string {
	if line < 1 || line > len(a.lines) {
		return ""
	}
	return strings.TrimSpace(a.lines[line-1])
}

// walk splits the token stream into statements on ';', '{' and '}', maintaining
// the scope stack as braces open and close.
func (a *analyzer) walk() {
	start := 0
	for i, tok := range a.toks {
		if tok.Kind != TokenPunct {
			continue
		}
		switch tok.Text {
		case ";":
			a.statement(a.toks[start:i])
			start = i + 1
		case "{":
			seg := a.toks[start:i]
			a.scopes.push()
			a.params(seg) // parameters belong to the scope the brace opens
			start = i + 1
		case "}":
			a.statement(a.toks[start:i])
			a.scopes.pop()
			start = i + 1
		}
	}
}

// params taints parameter names that match a source rule. A parameter taints
// only by NAME: `void f(String ssn)` taints ssn, `void f(UserDto user)` taints
// nothing — tainting by declared type would require type resolution, which is
// an explicit non-goal.
func (a *analyzer) params(seg []Token) {
	open := indexPunct(seg, "(")
	if open < 0 {
		return
	}
	close := lastIndexPunct(seg, ")")
	if close <= open {
		return
	}

	inner := seg[open+1 : close]
	for i := 1; i < len(inner); i++ {
		prev, cur := inner[i-1], inner[i]
		// A parameter is `Type name`: two adjacent identifiers.
		if prev.Kind != TokenIdent || cur.Kind != TokenIdent {
			continue
		}
		rule, ok := MatchSource(cur.Text)
		if !ok {
			continue
		}
		a.scopes.set(cur.Text, taint{
			Source: rule,
			Hops: []Hop{{
				Line:       cur.Line,
				Expression: a.lineText(cur.Line),
				Kind:       KindSource,
				Note:       "source: " + rule.Label + " (parameter)",
			}},
		})
	}
}

// statement processes one statement: first any assignment, then any sink.
// A statement can be both, as in `String r = restTemplate.post(ssn);`.
func (a *analyzer) statement(seg []Token) {
	if len(seg) == 0 {
		return
	}
	if eq := topLevelAssign(seg); eq > 0 {
		a.assign(lhsName(seg[:eq]), seg[eq+1:])
	}
	a.checkSink(seg)
}

// assign updates the taint bound to lhs based on the right-hand side.
func (a *analyzer) assign(lhs string, rhs []Token) {
	if lhs == "" || len(rhs) == 0 {
		return
	}

	// A sanitizer anywhere on the RHS produces clean data.
	if a.containsSanitizer(rhs) {
		a.scopes.clear(lhs)
		return
	}

	// Propagate from an already-tainted symbol.
	for _, tok := range rhs {
		if tok.Kind != TokenIdent {
			continue
		}
		existing, ok := a.scopes.get(tok.Text)
		if !ok {
			continue
		}
		hops := append(cloneHops(existing.Hops), Hop{
			Line:       tok.Line,
			Expression: a.lineText(tok.Line),
			Kind:       KindPropagate,
			Note:       propagateNote(rhs),
		})
		if len(hops) > a.opts.MaxHops {
			a.scopes.clear(lhs)
			return
		}
		a.scopes.set(lhs, taint{Source: existing.Source, Hops: hops})
		return
	}

	// Seed a new source from the RHS: `user.getSsn()` or `dto.ssn`.
	for _, tok := range rhs {
		if tok.Kind != TokenIdent {
			continue
		}
		if rule, ok := MatchSource(tok.Text); ok {
			a.scopes.set(lhs, taint{Source: rule, Hops: []Hop{{
				Line:       tok.Line,
				Expression: a.lineText(tok.Line),
				Kind:       KindSource,
				Note:       "source: " + rule.Label,
			}}})
			return
		}
	}

	// The RHS is clean, so any prior taint on lhs is gone.
	a.scopes.clear(lhs)
}

// checkSink emits a trace when tainted data reaches a dangerous destination.
func (a *analyzer) checkSink(seg []Token) {
	for _, call := range findCalls(seg) {
		rule, ok := MatchSink(call.text)
		if !ok {
			continue
		}
		if rule.Kind == SinkPersist && a.opts.IsTestFile {
			continue
		}

		args := seg[call.argStart:]
		if a.containsSanitizer(args) {
			continue
		}

		if a.emitFromTaintedArg(args, rule) {
			return
		}
		if a.emitFromDirectSource(args, rule) {
			return
		}
	}
}

// emitFromTaintedArg reports a tainted symbol passed to a sink.
func (a *analyzer) emitFromTaintedArg(args []Token, rule SinkRule) bool {
	for _, tok := range args {
		if tok.Kind != TokenIdent {
			continue
		}
		existing, ok := a.scopes.get(tok.Text)
		if !ok {
			continue
		}
		hops := append(cloneHops(existing.Hops), Hop{
			Line:       tok.Line,
			Expression: a.lineText(tok.Line),
			Kind:       KindSink,
			Note:       "sink: " + rule.Label,
		})
		if len(hops) > a.opts.MaxHops {
			return false
		}
		a.traces = append(a.traces, Trace{Source: existing.Source, Sink: rule, Hops: hops})
		return true
	}
	return false
}

// emitFromDirectSource reports `log.info(user.getSsn())` — a source that reaches
// a sink without ever being bound to a variable.
func (a *analyzer) emitFromDirectSource(args []Token, rule SinkRule) bool {
	for _, tok := range args {
		if tok.Kind != TokenIdent {
			continue
		}
		src, ok := MatchSource(tok.Text)
		if !ok {
			continue
		}
		a.traces = append(a.traces, Trace{Source: src, Sink: rule, Hops: []Hop{
			{Line: tok.Line, Expression: a.lineText(tok.Line), Kind: KindSource, Note: "source: " + src.Label},
			{Line: tok.Line, Expression: a.lineText(tok.Line), Kind: KindSink, Note: "sink: " + rule.Label},
		}})
		return true
	}
	return false
}

func (a *analyzer) containsSanitizer(seg []Token) bool {
	for _, call := range findCalls(seg) {
		if IsSanitizer(call.text) {
			return true
		}
	}
	return false
}

// propagateNote describes how data moved, for the trace display.
func propagateNote(rhs []Token) string {
	for _, tok := range rhs {
		if tok.Kind == TokenPunct && tok.Text == "+" {
			return "propagates via concat"
		}
	}
	for _, tok := range rhs {
		if tok.Kind != TokenIdent {
			continue
		}
		switch tok.Text {
		case "format":
			return "propagates via String.format"
		case "append":
			return "propagates via StringBuilder"
		}
	}
	return "propagates via assignment"
}

type call struct {
	text     string // dotted chain, e.g. "log.info"
	argStart int    // index just past '('
}

// findCalls extracts every `a.b.c(` chain in a statement.
func findCalls(seg []Token) []call {
	var calls []call
	for i := 0; i < len(seg); i++ {
		if seg[i].Kind != TokenPunct || seg[i].Text != "(" {
			continue
		}
		// Walk backwards over the dotted chain preceding '('.
		end := i
		j := i - 1
		for j >= 0 && (seg[j].Kind == TokenIdent || (seg[j].Kind == TokenPunct && seg[j].Text == ".")) {
			j--
		}
		if j+1 >= end {
			continue
		}
		var sb strings.Builder
		for _, tok := range seg[j+1 : end] {
			sb.WriteString(tok.Text)
		}
		if sb.Len() > 0 {
			calls = append(calls, call{text: sb.String(), argStart: i + 1})
		}
	}
	return calls
}

// topLevelAssign returns the index of the statement's '=' when it is a plain
// assignment, or -1. It ignores '==', '!=', '<=', '>=' and anything inside
// parentheses, so `if (a == b)` and `f(x = 1)` are not treated as assignments.
func topLevelAssign(seg []Token) int {
	depth := 0
	for i, tok := range seg {
		if tok.Kind != TokenPunct {
			continue
		}
		switch tok.Text {
		case "(", "[":
			depth++
		case ")", "]":
			depth--
		case "=":
			if depth != 0 {
				continue
			}
			if i > 0 && seg[i-1].Kind == TokenPunct &&
				(seg[i-1].Text == "=" || seg[i-1].Text == "!" || seg[i-1].Text == "<" ||
					seg[i-1].Text == ">" || seg[i-1].Text == "+" || seg[i-1].Text == "-") {
				continue
			}
			if i+1 < len(seg) && seg[i+1].Kind == TokenPunct && seg[i+1].Text == "=" {
				continue // this is the first '=' of '=='
			}
			return i
		}
	}
	return -1
}

// lhsName returns the assigned symbol: the last identifier before '='. This
// handles both `String s` (declaration) and `s` (reassignment).
func lhsName(lhs []Token) string {
	for i := len(lhs) - 1; i >= 0; i-- {
		if lhs[i].Kind == TokenIdent {
			return lhs[i].Text
		}
	}
	return ""
}

func indexPunct(seg []Token, text string) int {
	for i, tok := range seg {
		if tok.Kind == TokenPunct && tok.Text == text {
			return i
		}
	}
	return -1
}

func lastIndexPunct(seg []Token, text string) int {
	for i := len(seg) - 1; i >= 0; i-- {
		if seg[i].Kind == TokenPunct && seg[i].Text == text {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/flow/ -v`
Expected: PASS — all tests.

If `TestAnalyzeRespectsMaxHops` fails, check that `assign` compares `len(hops) > a.opts.MaxHops` **after** appending, and that the 9-link chain in the test exceeds 3 but not 10.

- [ ] **Step 6: Run qa-guard**

Dispatch the qa-guard agent per `CLAUDE.md` (Agent tool, `subagent_type: "feature-dev:code-reviewer"`, prompt from `agents/qa-guard.md`) against `internal/flow/`. Address anything it raises before committing.

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/flow/
go test ./internal/flow/
git add internal/flow/
git commit -m "feat(flow): add intra-file taint walk with Analyze API"
```

---

### Task 5: Detector Adapter

**Files:**
- Create: `internal/detector/flow.go`
- Test: `internal/detector/flow_test.go`

**Interfaces:**
- Consumes: `flow.Analyze` (Task 4); `flow.Options`, `flow.Trace`, `flow.Hop`, `flow.Kind` (Task 3); `flow.SensUnique/SensFinancial/SensGeneral`, `flow.SinkLog/SinkTransmit/SinkPersist` (Task 2); `report.Finding` (existing); `report.TraceHop` (Task 6 — **this task creates it**, see step 3).
- Produces: `FlowDetector` with `NewFlowDetector()`, satisfying `detector.Detector`.

**Depends on Task 6's model change.** `report.Finding.Trace` and `report.TraceHop` must exist for this task to compile, so **step 3 adds them**. Task 6 then builds the formatters on top.

- [ ] **Step 1: Write the failing test**

Create `internal/detector/flow_test.go`:

```go
package detector_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const flowSample = `class UserService {
  void register(UserDto user) {
    String s = user.getSsn();
    String msg = "id=" + s;
    log.info(msg);
  }
}`

func TestFlowDetectorMetadata(t *testing.T) {
	d := detector.NewFlowDetector()

	assert.Equal(t, "PIPA-FLOW-001", d.ID())
	assert.Equal(t, "Personal Data Flow Risk", d.Name())
	assert.NotEmpty(t, d.Description())
	assert.ElementsMatch(t, []string{"PIPA-17", "PIPA-24", "PIPA-24-2", "PIPA-29"}, d.RelatedLawIDs())
}

func TestFlowDetectorProducesFindingAnchoredAtSink(t *testing.T) {
	findings := detector.NewFlowDetector().Scan(flowSample, "UserService.java")

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "PIPA-FLOW-001", f.DetectorID)
	assert.Equal(t, "HIGH", f.RiskLevel)
	assert.Equal(t, "UserService.java", f.FilePath)
	assert.Equal(t, 5, f.LineNumber, "finding anchors at the sink — the line to change")
	assert.Contains(t, f.Snippet, "log.info")
	assert.ElementsMatch(t, []string{"PIPA-29", "PIPA-24"}, f.RelatedLaws)
}

func TestFlowDetectorAttachesTrace(t *testing.T) {
	findings := detector.NewFlowDetector().Scan(flowSample, "UserService.java")

	require.Len(t, findings, 1)
	trace := findings[0].Trace
	require.Len(t, trace, 3)
	assert.Equal(t, "source", trace[0].Kind)
	assert.Equal(t, "propagate", trace[1].Kind)
	assert.Equal(t, "sink", trace[2].Kind)
	assert.Equal(t, 3, trace[0].Line)
	assert.Equal(t, 5, trace[2].Line)
	assert.Contains(t, trace[1].Note, "concat")
}

func TestFlowDetectorMessageIsHedged(t *testing.T) {
	findings := detector.NewFlowDetector().Scan(flowSample, "UserService.java")
	msg := findings[0].Message

	assert.Contains(t, msg, "Possible")
	assert.Contains(t, msg, "may require review")
	assert.Contains(t, msg, "주민등록번호")
	for _, banned := range []string{"violation", "illegal", "non-compliant", "you must"} {
		assert.NotContains(t, msg, banned, "user-facing text must stay hedged")
	}
}

func TestFlowDetectorRiskMatrix(t *testing.T) {
	cases := []struct {
		name   string
		getter string
		sink   string
		want   string
	}{
		{"unique to log", "getSsn", "log.info(s);", "HIGH"},
		{"unique to transmit", "getSsn", "restTemplate.postForObject(s);", "HIGH"},
		{"unique to persist", "getSsn", "repository.save(s);", "HIGH"},
		{"financial to log", "getCardNumber", "log.info(s);", "HIGH"},
		{"financial to transmit", "getCardNumber", "restTemplate.postForObject(s);", "HIGH"},
		{"financial to persist", "getCardNumber", "repository.save(s);", "MEDIUM"},
		{"general to log", "getEmail", "log.info(s);", "MEDIUM"},
		{"general to transmit", "getEmail", "restTemplate.postForObject(s);", "HIGH"},
		{"general to persist", "getEmail", "repository.save(s);", "LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "class T {\n  void m(UserDto user) {\n    String s = user." + tc.getter + "();\n    " + tc.sink + "\n  }\n}"
			findings := detector.NewFlowDetector().Scan(src, "T.java")
			require.Len(t, findings, 1)
			assert.Equal(t, tc.want, findings[0].RiskLevel)
		})
	}
}

func TestFlowDetectorSuppressesPersistenceInTestFiles(t *testing.T) {
	src := "class T {\n  void m(UserDto user) {\n    String s = user.getSsn();\n    repository.save(s);\n  }\n}"

	for _, path := range []string{
		"src/test/java/UserServiceTest.java",
		"UserServiceTests.java",
		"UserServiceIT.java",
	} {
		assert.Empty(t, detector.NewFlowDetector().Scan(src, path), "path: %s", path)
	}

	assert.Len(t, detector.NewFlowDetector().Scan(src, "src/main/java/UserService.java"), 1,
		"production code is still reported")
}

func TestFlowDetectorCitesOnlyKnownLawIDs(t *testing.T) {
	valid := map[string]bool{"PIPA-17": true, "PIPA-24": true, "PIPA-24-2": true, "PIPA-29": true}

	srcs := []string{
		"class T { void m(UserDto u) { log.info(u.getSsn()); } }",
		"class T { void m(UserDto u) { restTemplate.postForObject(u.getEmail()); } }",
		"class T { void m(UserDto u) { repository.save(u.getCardNumber()); } }",
	}
	for _, src := range srcs {
		for _, f := range detector.NewFlowDetector().Scan(src, "T.java") {
			assert.NotEmpty(t, f.RelatedLaws)
			for _, id := range f.RelatedLaws {
				assert.True(t, valid[id], "finding cites unknown law ID %q", id)
			}
		}
	}
}

func TestFlowDetectorReturnsNoFindingsForCleanCode(t *testing.T) {
	src := "class T {\n  void m() {\n    int total = 1 + 2;\n    log.info(\"total=\" + total);\n  }\n}"
	assert.Empty(t, detector.NewFlowDetector().Scan(src, "T.java"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/detector/ -run TestFlow -v`
Expected: FAIL — `undefined: NewFlowDetector`.

- [ ] **Step 3: Add the report model fields**

Modify `internal/report/model.go`. Add `Trace` as the last field of `Finding` and add the `TraceHop` type after it:

```go
type Finding struct {
	DetectorID  string     `json:"detector_id"`
	RiskLevel   string     `json:"risk_level"`
	FilePath    string     `json:"file_path"`
	LineNumber  int        `json:"line_number"`
	Snippet     string     `json:"snippet"`
	Message     string     `json:"message"`
	RelatedLaws []string   `json:"related_laws"`
	Trace       []TraceHop `json:"trace,omitempty"`
}

// TraceHop is one step in a data-flow trace. Only flow findings carry these;
// omitempty keeps every existing detector's JSON output byte-identical.
type TraceHop struct {
	Line       int    `json:"line"`
	Expression string `json:"expression"`
	Kind       string `json:"kind"` // "source" | "propagate" | "sink"
	Note       string `json:"note"`
}
```

- [ ] **Step 4: Write the detector**

Create `internal/detector/flow.go`:

```go
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
// 고유식별정보 brings in PIPA 제24조 regardless of destination.
func lawsFor(t flow.Trace) []string {
	laws := make([]string, 0, len(t.Sink.Laws)+1)
	laws = append(laws, t.Sink.Laws...)

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
		"Possible personal data (%s) reaches %s after %d steps — may require review under related provisions (%s)",
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/detector/ ./internal/report/ ./internal/flow/ -v`
Expected: PASS — including existing detector and report tests, which must be unaffected.

- [ ] **Step 6: Run qa-guard and legal-mapper**

Dispatch both per `CLAUDE.md`:
- legal-mapper (Agent tool, `subagent_type: "general-purpose"`, prompt from `agents/legal-mapper.md`) — review every user-facing string in `internal/flow/rules.go` (the `Label` fields) and `internal/detector/flow.go` (`flowMessage`, `Description`). legal-mapper MUST review before this ships.
- qa-guard (`subagent_type: "feature-dev:code-reviewer"`, prompt from `agents/qa-guard.md`) — review `internal/detector/flow.go`.

Address findings before committing.

- [ ] **Step 7: Commit**

```bash
gofmt -w internal/detector/ internal/report/
git add internal/detector/flow.go internal/detector/flow_test.go internal/report/model.go
git commit -m "feat(detector): add PIPA-FLOW-001 data-flow detector"
```

---

### Task 6: Render Traces in Text and SARIF

**Files:**
- Modify: `internal/report/formatter.go` — `FormatText`
- Modify: `internal/report/sarif.go` — add `codeFlows`
- Create: `internal/report/formatter_test.go` — **this file does not exist yet**; `FormatText` currently has no dedicated test
- Test: `internal/report/sarif_test.go` (exists, `package report_test`; append cases)

**Interfaces:**
- Consumes: `report.Finding.Trace`, `report.TraceHop` (added in Task 5).
- Produces: no new exported API. `sarifResult` gains a `CodeFlows []sarifCodeFlow` field with `json:"codeFlows,omitempty"`.

The JSON formatter needs no change — `Trace` marshals automatically. The test below locks in that guarantee.

- [ ] **Step 1: Write the failing test**

Create `internal/report/formatter_test.go` (it does not exist yet):

```go
package report_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatTextRendersTrace(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-FLOW-001",
			RiskLevel:  "HIGH",
			FilePath:   "UserService.java",
			LineNumber: 5,
			Snippet:    "log.info(msg);",
			Message:    "Possible personal data reaches log output",
			Trace: []report.TraceHop{
				{Line: 3, Expression: "String s = user.getSsn();", Kind: "source", Note: "source: 주민등록번호"},
				{Line: 4, Expression: `String msg = "id=" + s;`, Kind: "propagate", Note: "propagates via concat"},
				{Line: 5, Expression: "log.info(msg);", Kind: "sink", Note: "sink: log output"},
			},
			RelatedLaws: []string{"PIPA-29", "PIPA-24"},
		}},
	}

	out := report.FormatText(r)

	assert.Contains(t, out, "Trace:")
	assert.Contains(t, out, "①")
	assert.Contains(t, out, "③")
	assert.Contains(t, out, "UserService.java:3")
	assert.Contains(t, out, "propagates via concat")
}

func TestFormatTextOmitsTraceSectionWhenAbsent(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{DetectorID: "PIPA-LOG-001", RiskLevel: "MEDIUM", LineNumber: 1}},
	}

	assert.NotContains(t, report.FormatText(r), "Trace:", "regex findings must render exactly as before")
}

func TestFormatJSONOmitsTraceForRegexFindings(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-LOG-001", RiskLevel: "MEDIUM", FilePath: "A.java",
			LineNumber: 1, Snippet: "x", Message: "m", RelatedLaws: []string{"PIPA-29"},
		}},
	}

	out, err := report.FormatJSON(r)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "trace",
		"omitempty is a public contract: existing JSON output must stay byte-identical")
}

func TestFormatJSONIncludesTraceForFlowFindings(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-FLOW-001",
			Trace:      []report.TraceHop{{Line: 3, Expression: "e", Kind: "source", Note: "n"}},
		}},
	}

	out, err := report.FormatJSON(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"trace"`)
	assert.Contains(t, string(out), `"kind":"source"`)
}
```

Append to `internal/report/sarif_test.go`:

```go
func TestFormatSARIFEmitsCodeFlowsForTracedFindings(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{
			DetectorID: "PIPA-FLOW-001",
			RiskLevel:  "HIGH",
			FilePath:   "UserService.java",
			LineNumber: 5,
			Snippet:    "log.info(msg);",
			Message:    "Possible personal data reaches log output",
			Trace: []report.TraceHop{
				{Line: 3, Expression: "String s = user.getSsn();", Kind: "source", Note: "source: 주민등록번호"},
				{Line: 5, Expression: "log.info(msg);", Kind: "sink", Note: "sink: log output"},
			},
		}},
	}

	out, err := report.FormatSARIF(r, []report.DetectorInfo{{ID: "PIPA-FLOW-001", Name: "Personal Data Flow Risk"}})
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(out, &parsed))

	runs := parsed["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	result := results[0].(map[string]any)

	codeFlows, ok := result["codeFlows"].([]any)
	require.True(t, ok, "traced findings must emit codeFlows")

	threadFlows := codeFlows[0].(map[string]any)["threadFlows"].([]any)
	locations := threadFlows[0].(map[string]any)["locations"].([]any)
	assert.Len(t, locations, 2, "one threadFlow location per hop")
}

func TestFormatSARIFOmitsCodeFlowsForRegexFindings(t *testing.T) {
	r := report.Report{
		Findings: []report.Finding{{DetectorID: "PIPA-LOG-001", RiskLevel: "MEDIUM", FilePath: "A.java", LineNumber: 1}},
	}

	out, err := report.FormatSARIF(r, []report.DetectorInfo{{ID: "PIPA-LOG-001", Name: "Logging"}})
	require.NoError(t, err)
	assert.NotContains(t, string(out), "codeFlows")
}
```

`internal/report/sarif_test.go` already declares `package report_test` and imports `encoding/json`, testify's `assert` and `require` — no import changes needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run 'Trace|CodeFlows' -v`
Expected: FAIL — `FormatText` output lacks "Trace:", SARIF lacks `codeFlows`.

- [ ] **Step 3: Implement the text formatter**

Modify `internal/report/formatter.go`. Replace the finding loop in `FormatText` with:

```go
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
```

And add these helpers to the same file:

```go
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
```

- [ ] **Step 4: Implement the SARIF code flows**

Modify `internal/report/sarif.go`.

Add `CodeFlows` as the last field of `sarifResult`:

```go
type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifText        `json:"message"`
	Locations  []sarifLocation  `json:"locations"`
	CodeFlows  []sarifCodeFlow  `json:"codeFlows,omitempty"`
	Properties sarifResultProps `json:"properties"`
}
```

Add these types after `sarifRegion`:

```go
// SARIF models taint paths as codeFlows → threadFlows → locations, which maps
// directly onto our hops. GitHub code scanning renders it as a clickable
// step-through path in the pull request.
type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}
```

Add this constructor:

```go
// codeFlowsFor converts a finding's trace into a SARIF code flow. Findings with
// no trace get no codeFlows key at all, thanks to omitempty.
func codeFlowsFor(f Finding) []sarifCodeFlow {
	if len(f.Trace) == 0 {
		return nil
	}

	locations := make([]sarifThreadFlowLocation, 0, len(f.Trace))
	for _, h := range f.Trace {
		locations = append(locations, sarifThreadFlowLocation{
			Location: sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
					Region: sarifRegion{
						StartLine: h.Line,
						Snippet:   sarifText{Text: h.Expression},
					},
				},
			},
		})
	}

	return []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{{Locations: locations}}}}
}
```

Then in `FormatSARIF`, set the field when building each result — add `CodeFlows: codeFlowsFor(f),` immediately after the `Locations:` field:

```go
		results = append(results, sarifResult{
			RuleID:  f.DetectorID,
			Level:   sarifLevel(f.RiskLevel),
			Message: sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
					Region: sarifRegion{
						StartLine: f.LineNumber,
						Snippet:   sarifText{Text: f.Snippet},
					},
				},
			}},
			CodeFlows: codeFlowsFor(f),
			Properties: sarifResultProps{
				RiskLevel:   f.RiskLevel,
				RelatedLaws: f.RelatedLaws,
			},
		})
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/report/ -v`
Expected: PASS — new tests plus every pre-existing formatter/SARIF test.

- [ ] **Step 6: Commit**

```bash
gofmt -w internal/report/
git add internal/report/
git commit -m "feat(report): render data-flow traces in text and SARIF codeFlows"
```

---

### Task 7: Dedupe Overlapping Findings

**Files:**
- Create: `internal/report/dedupe.go`
- Modify: `internal/scanner/scanner.go` — apply `Dedupe` in `ScanDirectory` and `ScanFile`
- Test: `internal/report/dedupe_test.go`

**Interfaces:**
- Consumes: `report.Finding`.
- Produces: `func Dedupe(findings []Finding) []Finding`.

`PIPA-LOG-001` and `PIPA-FLOW-001` both fire on `log.info(user.ssn)`. The flow finding strictly knows more, so it wins; the regex detectors stay as a safety net for code the lexer cannot follow.

- [ ] **Step 1: Write the failing test**

Create `internal/report/dedupe_test.go`:

```go
package report_test

import (
	"testing"

	"github.com/rostradamus/klaws/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupePrefersFlowFindingOnSameLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 5},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, Trace: []report.TraceHop{{Line: 5}}},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 1)
	assert.Equal(t, "PIPA-FLOW-001", got[0].DetectorID, "the flow finding knows strictly more")
}

func TestDedupeKeepsRegexFindingOnDifferentLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 9},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5},
	}

	assert.Len(t, report.Dedupe(findings), 2)
}

func TestDedupeKeepsRegexFindingInDifferentFile(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "B.java", LineNumber: 5},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5},
	}

	assert.Len(t, report.Dedupe(findings), 2)
}

func TestDedupeIsOrderIndependent(t *testing.T) {
	flow := report.Finding{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5}
	regex := report.Finding{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 5}

	for _, in := range [][]report.Finding{{regex, flow}, {flow, regex}} {
		got := report.Dedupe(in)
		require.Len(t, got, 1)
		assert.Equal(t, "PIPA-FLOW-001", got[0].DetectorID)
	}
}

func TestDedupePreservesOrderOfSurvivors(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-LOG-001", FilePath: "A.java", LineNumber: 1},
		{DetectorID: "PIPA-ENC-001", FilePath: "A.java", LineNumber: 2},
		{DetectorID: "PIPA-CON-001", FilePath: "A.java", LineNumber: 3},
	}

	got := report.Dedupe(findings)

	require.Len(t, got, 3)
	assert.Equal(t, "PIPA-LOG-001", got[0].DetectorID)
	assert.Equal(t, "PIPA-ENC-001", got[1].DetectorID)
	assert.Equal(t, "PIPA-CON-001", got[2].DetectorID)
}

func TestDedupeKeepsMultipleFlowFindingsOnOneLine(t *testing.T) {
	findings := []report.Finding{
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, Message: "ssn"},
		{DetectorID: "PIPA-FLOW-001", FilePath: "A.java", LineNumber: 5, Message: "email"},
	}

	assert.Len(t, report.Dedupe(findings), 2, "distinct flows to one sink are distinct risks")
}

func TestDedupeHandlesEmptyInput(t *testing.T) {
	assert.Empty(t, report.Dedupe(nil))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestDedupe -v`
Expected: FAIL — `undefined: Dedupe`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/report/dedupe.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/ -v`
Expected: PASS.

- [ ] **Step 5: Wire Dedupe into the scanner**

Modify `internal/scanner/scanner.go`.

In `ScanDirectory`, replace the report construction so findings are deduped and counted after deduping:

```go
	allFindings = report.Dedupe(allFindings)

	return report.Report{
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
		TargetPath:    path,
		FilesScanned:  len(files),
		TotalFindings: len(allFindings),
		Findings:      allFindings,
		Disclaimer:    report.Disclaimer,
	}, nil
```

In `ScanFile`, do the same:

```go
	findings, err := s.scanOneFile(path)
	if err != nil {
		return report.Report{}, err
	}
	findings = report.Dedupe(findings)

	return report.Report{
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
		TargetPath:    path,
		FilesScanned:  1,
		TotalFindings: len(findings),
		Findings:      findings,
		Disclaimer:    report.Disclaimer,
	}, nil
```

`TotalFindings` must equal `len(Findings)` — deduping before counting is what keeps that true.

- [ ] **Step 6: Run the full suite**

Run: `go test ./...`
Expected: PASS. If a pre-existing scanner test asserts a finding count that deduping now reduces, that is a real behavior change — verify the dropped finding is genuinely a flow-superseded duplicate before updating the expectation.

- [ ] **Step 7: Run qa-guard**

Dispatch qa-guard (`subagent_type: "feature-dev:code-reviewer"`, prompt from `agents/qa-guard.md`) against `internal/report/dedupe.go` and `internal/scanner/scanner.go`.

- [ ] **Step 8: Commit**

```bash
gofmt -w internal/report/ internal/scanner/
git add internal/report/dedupe.go internal/report/dedupe_test.go internal/scanner/scanner.go
git commit -m "feat(report): dedupe regex findings superseded by flow traces"
```

---

### Task 8: Register the Detector, Integration Fixtures, and Docs

**Files:**
- Modify: `cmd/klaws/main.go` — `buildDeps()`
- Create: `testdata/flow/UserService.java`
- Create: `testdata/flow/SafeUserService.java`
- Test: `internal/scanner/scanner_test.go` (exists; add cases)
- Modify: `README.md`, `README.ko.md`, `docs/roadmap.md`

**Interfaces:**
- Consumes: `detector.NewFlowDetector()` (Task 5).
- Produces: nothing new — this wires everything together.

- [ ] **Step 1: Write the failing test**

Create `testdata/flow/UserService.java`:

```java
package com.example;

public class UserService {
    private final UserRepository repository;

    public void register(UserDto user) {
        String s = user.getSsn();
        String msg = "registering id=" + s;
        log.info(msg);
    }

    public void sync(UserDto user) {
        String email = user.getEmail();
        restTemplate.postForObject("https://partner.example.com/sync", email, String.class);
    }
}
```

Create `testdata/flow/SafeUserService.java`:

```java
package com.example;

public class SafeUserService {
    public void register(UserDto user) {
        String masked = mask(user.getSsn());
        log.info("registering id=" + masked);
    }

    public void describe() {
        log.info("this method mentions ssn and email in a literal only");
    }
}
```

Append to `internal/scanner/scanner_test.go`:

```go
func TestScanDirectoryFindsFlowTraces(t *testing.T) {
	svc := scanner.NewService(detector.NewRegistry(detector.NewFlowDetector()))

	rpt, err := svc.ScanFile("../../testdata/flow/UserService.java")
	require.NoError(t, err)

	require.Len(t, rpt.Findings, 2)
	assert.Equal(t, rpt.TotalFindings, len(rpt.Findings))

	byRisk := map[string]report.Finding{}
	for _, f := range rpt.Findings {
		byRisk[f.RiskLevel] = f
	}

	high, ok := byRisk["HIGH"]
	require.True(t, ok, "주민등록번호 reaching a log is HIGH")
	assert.NotEmpty(t, high.Trace)
	assert.Equal(t, "source", high.Trace[0].Kind)
	assert.Equal(t, "sink", high.Trace[len(high.Trace)-1].Kind)
}

func TestScanFileWithSanitizedAndLiteralCodeFindsNothing(t *testing.T) {
	svc := scanner.NewService(detector.NewRegistry(detector.NewFlowDetector()))

	rpt, err := svc.ScanFile("../../testdata/flow/SafeUserService.java")
	require.NoError(t, err)

	assert.Empty(t, rpt.Findings, "sanitized and literal-only code must produce no findings")
}
```

`internal/scanner/scanner_test.go` already declares `package scanner_test` and imports `detector`, `scanner`, testify's `assert` and `require`. Add `github.com/rostradamus/klaws/internal/report` to its import block — it is not currently imported.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestScan.*Flow -v`
Expected: FAIL — fixtures/tests not yet wired, or findings empty.

- [ ] **Step 3: Register the detector**

Modify `cmd/klaws/main.go`. Add `detector.NewFlowDetector(),` to the registry in `buildDeps()`:

```go
	detReg := detector.NewRegistry(
		detector.NewLoggingDetector(),
		detector.NewEncryptionDetector(),
		detector.NewConsentDetector(),
		detector.NewMarketingConsentDetector(),
		detector.NewFinancialDataDetector(),
		detector.NewRetentionDetector(),
		detector.NewPersonalDataRetentionDetector(),
		detector.NewThirdPartyTransferDetector(),
		detector.NewFlowDetector(),
	)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./...`
Expected: PASS — every package.

- [ ] **Step 5: Verify end-to-end by hand**

Run:

```bash
go build -o klaws ./cmd/klaws/
./klaws detectors | grep PIPA-FLOW-001
./klaws scan ./testdata/flow --pattern "*.java"
```

Expected: `detectors` lists `PIPA-FLOW-001 — Personal Data Flow Risk`. The scan prints two findings for `UserService.java`, each with a `Trace:` block showing ①②③ steps, and none for `SafeUserService.java`.

Also confirm SARIF is well-formed:

```bash
./klaws scan ./testdata/flow --pattern "*.java" --format sarif | python3 -m json.tool | grep -A3 codeFlows
```

Expected: valid JSON containing a `codeFlows` array. (Check `./klaws scan --help` for the exact format flag name if `--format sarif` is rejected.)

- [ ] **Step 6: Update the docs**

In `docs/roadmap.md`, add to the v0.2 section and check it off:

```markdown
- [x] PIPA-FLOW-001: Intra-file PII data-flow tracing (source → sink with trace path)
```

In `README.md`, add to the detector list (match the surrounding table/list format exactly — read it first) an entry for:

`PIPA-FLOW-001` — Personal Data Flow Risk — traces personal data from its source to logging, transmission, or storage within a file, reporting the full path.

Then add a short subsection under Usage showing the trace output, reusing the sample from Task 6's test.

Mirror both changes in `README.ko.md`, keeping its existing tone and structure. All added prose must stay hedged: "가능성", "검토가 필요할 수 있습니다" — never assert a violation.

- [ ] **Step 7: Run legal-mapper on the docs**

Dispatch legal-mapper (`subagent_type: "general-purpose"`, prompt from `agents/legal-mapper.md`) over the README and README.ko additions. legal-mapper MUST review user-facing strings before they ship.

- [ ] **Step 8: Final verification**

Run:

```bash
gofmt -l ./cmd ./internal   # must print nothing
go vet ./...
go test ./...
go build -o klaws ./cmd/klaws/
```

Expected: no output from `gofmt -l`, clean vet, all tests pass, clean build.

- [ ] **Step 9: Commit**

```bash
git add cmd/klaws/main.go testdata/flow/ internal/scanner/scanner_test.go README.md README.ko.md docs/roadmap.md
git commit -m "feat: register PIPA-FLOW-001 detector and document data-flow tracing"
```

---

## Self-Review Notes

Checked against the spec:

- **Every spec section maps to a task.** Architecture → Tasks 1–5; Rules (sources/sinks/sanitizers/risk matrix) → Tasks 3, 5; Data flow → Task 4; Report integration (model/text/JSON/SARIF) → Tasks 5, 6; Error handling → Tasks 1, 2, 4; False-positive controls → Tasks 3, 4, 5; Overlap/dedupe → Task 7; Testing → every task; Implementation order → task order.
- **Placeholder scan:** every code step contains complete, runnable code. No TBDs.
- **Type consistency:** every type is declared exactly once, in its final home, before any task needs it — `SourceRule`/`SinkRule` in Task 2, `Kind`/`Hop`/`Trace`/`Options` in Task 3. `flow.Kind` → `report.TraceHop.Kind` crosses a string boundary via `hopKindName`, defined once in Task 5.
- **Deviation from spec's implementation order:** the spec ordered `report.Finding.Trace` at step 6, but Task 5's detector cannot compile without it. Task 5 step 3 adds the model fields; Task 6 adds the formatters. Same end state, valid intermediate builds.

Three defects were found during self-review and fixed inline. They are recorded here because each would have broken the build for whoever executes this plan:

1. **Test package convention.** Every test file in this repo uses an external test package (`package report_test`, `package detector_test`, `package scanner_test`). The first draft of every test block used the internal package and called `Finding`, `FormatText`, `NewService`, and `NewFlowDetector` unqualified. All test blocks now use the external package and qualified references, except `internal/flow/lexer_test.go` and `internal/flow/scope_test.go`, which must stay internal to reach `splitWords`, `scopeStack`, and `taint`.
2. **`internal/report/formatter_test.go` does not exist.** The first draft said "Modify (exists)". Task 6 now creates it, with the package header and imports spelled out. `FormatText` currently has no dedicated test at all.
3. **`internal/scanner/scanner_test.go` does not import `report`.** Task 8 now says to add that import rather than assuming it.

**Task order changed before execution.** The first draft had Tasks 2–4 declare placeholder types (`SourceRule` in scope.go, `Kind`/`Hop` in scope.go) that later tasks deleted. Tasks are now ordered lexer → rules → public types + scope → walk, so every type is declared once in its final home and nothing is ever deleted.

Verified against the real codebase rather than assumed: the `--format sarif` flag exists (`cmd/klaws/main.go:48`), `buildDeps()` registers 8 detectors today, and `report.Finding` has no `Trace` field yet.
