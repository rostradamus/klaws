# PII Data-Flow Tracing — Design Spec

## Goal

Add taint analysis to klaws so it can trace personal data from where it enters a file to where it leaks, instead of matching single lines with regex.

Today `PIPA-LOG-001` finds `log.info(user.ssn)`. It cannot find this:

```java
String s = user.getSsn();   // source
String msg = "id=" + s;     // propagates
log.info(msg);              // sink — invisible to regex
```

The new `PIPA-FLOW-001` detector reports that as one finding with a 3-hop trace. This is the capability that separates klaws from grep-with-a-law-table.

## Scope

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Trace reach | Within one file | Fits the existing one-file-at-a-time `Detector` interface; no call graph or type resolution needed. Catches the majority of real leaks. |
| Parser | Hand-rolled Java lexer, pure Go | Release builds are `CGO_ENABLED=0` across 6 platforms into distroless/static, plus `go install`. tree-sitter bindings need CGO and would break all of it. |
| Language | Java only | Matches the current default `*.java` pattern. The engine is language-agnostic; rules tables are per-language. |
| Sinks | Logging, external transmission, unencrypted persistence | Serialization/`toString` deferred — serializing a DTO is usually normal, so it is the noisiest sink. |
| Sources | Curated built-in list, expressed as data | Ships value now; a `.klaws.yaml` override can layer on later without touching the engine. |

### Non-goals

- Cross-file / inter-procedural tracing
- Python / TypeScript rules
- User-configurable rules via config file
- Serialization sinks

## Architecture

The engine knows nothing about detectors, laws, or reports. It takes source code and returns traces. A thin adapter maps traces onto the existing `Detector` interface.

```
internal/flow/              # new, dependency-free engine
├── lexer.go                # Java tokens: identifiers, strings, punctuation, comments
├── scope.go                # brace-depth scope stack → tainted symbol set
├── rules.go                # sources / sinks / sanitizers as plain data tables
├── trace.go                # the walk: source → propagation → sink, recording hops
├── flow.go                 # Analyze(src string, opts Options) []Trace  ← entire public API
└── *_test.go

internal/detector/
└── flow.go                 # adapter: Trace → report.Finding
```

`Analyze` is the whole surface the detector sees. Everything else is internal, so the lexer can be rewritten — or swapped for tree-sitter later — without touching a consumer.

### Public types

```go
package flow

type Kind int   // KindSource, KindPropagate, KindSink

type Hop struct {
    Line       int
    Expression string   // trimmed source text
    Kind       Kind
    Note       string   // "source: 주민등록번호", "propagates via concat", "sink: log output"
}

type Trace struct {
    Source SourceRule
    Sink   SinkRule
    Hops   []Hop        // ordered, source-first, sink-last
}

type Options struct {
    MaxHops   int   // default 10
    MaxTokens int   // default 200_000
    IsTestFile bool
}

func Analyze(src string, opts Options) []Trace
```

### One detector, not three

The three sinks map to different laws, but `Finding.RelatedLaws` is already per-finding, so a single `PIPA-FLOW-001` emits sink-specific laws and risk while lexing each file once. Three detectors would mean three passes over the same file for no gain.

```go
func (d *FlowDetector) ID() string { return "PIPA-FLOW-001" }
func (d *FlowDetector) Name() string { return "Personal Data Flow Risk" }
func (d *FlowDetector) RelatedLawIDs() []string {
    return []string{"PIPA-17", "PIPA-24", "PIPA-24-2", "PIPA-29"}   // union
}
```

## Rules

### Sources

Matched against local variables, parameters, field names, and getter names (`getSsn` → `ssn`). Case-insensitive, word-boundary aware.

```go
type Sensitivity int   // SensUnique (고유식별정보), SensFinancial, SensGeneral

var DefaultSources = []SourceRule{
    {ID: "ssn",      Sens: SensUnique,    Patterns: []string{"ssn", "rrn", "jumin", "주민등록번호", "주민번호", "residentRegistration"}},
    {ID: "passport", Sens: SensUnique,    Patterns: []string{"passport", "여권번호", "driverLicense", "운전면허"}},
    {ID: "card",     Sens: SensFinancial, Patterns: []string{"cardNumber", "cardNo", "카드번호", "account", "계좌번호"}},
    {ID: "phone",    Sens: SensGeneral,   Patterns: []string{"phone", "mobile", "전화번호", "휴대폰"}},
    {ID: "email",    Sens: SensGeneral,   Patterns: []string{"email", "이메일"}},
    {ID: "address",  Sens: SensGeneral,   Patterns: []string{"address", "주소"}},
    {ID: "name",     Sens: SensGeneral,   Patterns: []string{"userName", "realName", "이름", "성명"}},
}
```

Each tainted symbol carries the rule that seeded it, so risk can distinguish 주민등록번호 from an email address.

### Sinks

```go
type SinkKind int   // SinkLog, SinkTransmit, SinkPersist

var DefaultSinks = []SinkRule{
    {Kind: SinkLog,      Laws: []string{"PIPA-29"},
     Patterns: []string{"log.info", "log.debug", "log.warn", "log.error", "logger.",
                        "System.out.print", "System.err.print", "printStackTrace"}},
    {Kind: SinkTransmit, Laws: []string{"PIPA-17"},
     Patterns: []string{"restTemplate.", "webClient.", "okHttpClient.", "httpClient.",
                        "HttpEntity", "@FeignClient", "URLConnection"}},
    {Kind: SinkPersist,  Laws: []string{"PIPA-24-2", "PIPA-29"},
     Patterns: []string{"repository.save", "entityManager.persist", "jdbcTemplate.update",
                        "Files.write", "FileWriter", "preparedStatement.set"}},
}
```

Every ID above exists in `internal/law/laws/pipa.yaml`, and the mappings match what the existing detectors already use — `PIPA-17` from the transfer detector, `PIPA-24-2` + `PIPA-29` from the encryption detector. A finding must never cite a provision the law registry cannot resolve.

**Source sensitivity contributes a law too.** A `SensUnique` source (고유식별정보) adds `PIPA-24` to whatever the sink contributes, since 제24조 governs the processing of unique identifying information regardless of where it ends up. So 주민등록번호 → log yields `PIPA-29, PIPA-24`.

**Out of scope:** cross-border transfer (국외이전, 제28조의8) is not currently in `laws.yaml`. Adding those provisions is a separate law-data task; this spec cites only bundled IDs.

### Sanitizers

Passing tainted data through any of these clears the taint. This is the primary false-positive defense.

```go
var DefaultSanitizers = []string{
    "encrypt", "mask", "hash", "redact", "anonymize", "pseudonym",
    "AES", "SHA", "bcrypt", "digest",
}
```

### Risk matrix

Risk is a function of source sensitivity × sink kind, not a fixed level per detector.

| Source | Logging | External transmission | Unencrypted persistence |
|--------|---------|-----------------------|-------------------------|
| 고유식별정보 (주민등록번호, 여권번호) | HIGH | HIGH | HIGH |
| Financial (카드번호, 계좌번호) | HIGH | HIGH | MEDIUM |
| General (email, phone, address, name) | MEDIUM | HIGH | LOW |

Transmission is HIGH regardless of source sensitivity: personal data crossing the system boundary to a third party is unrecoverable once sent, and 제17조 conditions such provision on the data subject's consent — which the engine cannot verify from one file.

## Data flow

One pass per file:

1. **Lex** into tokens, discarding comments and preserving string literals as opaque units — so `"ssn"` in a message never taints anything.
2. **Walk statements** while maintaining a scope stack keyed on brace depth. `{` pushes, `}` pops. This is what gives correct shadowing, which regex fundamentally cannot do.
3. **Seed taint** when a symbol matches a source rule. `String s = user.getSsn()` taints `s` in the current scope — the taint is seeded by the `getSsn` getter, not by the `user` receiver.

   A parameter taints only if its **name** matches a source rule: `void f(String ssn)` taints `ssn`; `void f(UserDto user)` taints nothing, because neither `UserDto` nor `user` is in `DefaultSources`. Tainting by declared type would require the type-driven approach this spec lists as a non-goal.
4. **Propagate** across:
   - assignment — `a = b`
   - string concat — `"id=" + s`
   - `String.format(...)` / `StringBuilder.append(...)`
   - method arguments — passing a tainted symbol into a call taints the result
   Each propagation appends a `Hop` with line number and expression.
5. **Sink or sanitize.** A tainted symbol reaching a sink emits a `Trace`; reaching a sanitizer clears it from scope.

The detector anchors the `Finding` at the **sink** line — that is the line a reviewer needs to change.

## Report integration

`report.Finding` gains one field:

```go
type Finding struct {
    // ... existing fields unchanged
    Trace []TraceHop `json:"trace,omitempty"`
}

type TraceHop struct {
    Line       int    `json:"line"`
    Expression string `json:"expression"`
    Kind       string `json:"kind"`   // "source" | "propagate" | "sink"
    Note       string `json:"note"`
}
```

`omitempty` means existing regex detectors' JSON output stays byte-identical. No breaking change for anyone parsing it today.

### Text

```
--- Finding 1 ---
  Detector:  PIPA-FLOW-001
  Risk:      HIGH
  Location:  UserService.java:14
  Snippet:   log.info(msg);
  Message:   Possible personal data (주민등록번호) reaches log output after 3 steps — may require review under PIPA Article 29
  Trace:
    ① UserService.java:11  String s = user.getSsn();   source: 주민등록번호
    ② UserService.java:12  String msg = "id=" + s;     propagates via concat
    ③ UserService.java:14  log.info(msg);              sink: log output
  Laws:      PIPA-29, PIPA-24
```

### JSON / MCP

The `trace` array rides along on the finding. This is the real payoff for MCP: an AI assistant receives the whole propagation path and can fix the actual leak rather than guessing at the sink line.

### SARIF

Hops map onto SARIF `codeFlows` → `threadFlows` → `locations`, which is precisely what that schema was designed for. GitHub code scanning renders it as a clickable step-through path in the PR.

## Error handling

The engine never returns an error and never panics out. Malformed Java is normal input — a truncated file, a syntax error mid-edit, Kotlin someone pointed `--pattern` at.

- Unparseable input → zero traces, not a failure.
- Unbalanced braces → degrade to a flatter scope rather than aborting.
- `MaxHops` (default 10) and `MaxTokens` (default 200,000) ceilings prevent a pathological file from hanging a CI run.

A scanner that crashes on one weird file in a 5,000-file repo is worse than one that quietly finds less.

## False-positive controls

In priority order — this is where the feature lives or dies.

1. **Sanitizer recognition** — the main defense.
2. **String literals never taint.** `log.info("user ssn field")` is not a finding. The current regex detector gets this wrong today.
3. **Scope-correct shadowing.** An `ssn` in one method does not taint an unrelated `ssn` in the next.
4. **Test files excluded from persistence findings.** Fixtures full of fake 주민등록번호 are the biggest noise source in real Korean repos. A file is a test file if its path contains `/test/` or its name ends `Test.java` / `Tests.java` / `IT.java`.
5. **Hedged language throughout** — "possible", "may require review", per the project's critical rules. legal-mapper reviews every user-facing string before merge.

### Overlap with existing regex detectors

`PIPA-LOG-001` and `PIPA-FLOW-001` will both fire on `log.info(user.ssn)`.

**Resolution:** keep both detectors, dedupe at the report layer. When a flow finding and a regex finding land on the same `file:line`, keep the flow finding (it strictly knows more) and drop the regex one. The regex detectors stay as a safety net for code the lexer cannot follow, without double-reporting.

```go
// internal/report/dedupe.go
func Dedupe(findings []Finding) []Finding
```

Applied in `ScannerService` after `registry.ScanAll`.

## Testing

TDD per the project's test-driven-development skill: test first, watch it fail, then implement.

### internal/flow unit tests

String fixtures, no filesystem, fast and hermetic.

- One test per propagation form: assignment, concat, `String.format`, `StringBuilder`, direct argument pass
- One test per sanitizer
- Scoping: shadowed variables, nested blocks, taint not escaping a closed scope
- Each source rule seeds taint; each sink kind emits the right `SinkKind`
- Risk matrix: every source-sensitivity × sink-kind cell
- **Every law ID in `DefaultSinks` and in the sensitivity mapping resolves against `law.Registry`.** This spec's first draft cited two provisions (`PIPA-24-3`, `PIPA-28-2`) that do not exist in the bundled data; a test makes that class of error impossible to ship.

### Negative tests — equal weight

Each is a regression guard on a specific false positive:

- Sanitized flow → no finding
- String-literal-only mention → no finding
- Shadowed variable → no cross-contamination
- Test-file fixture → no persistence finding

### Malformed input suite

Truncated file, unbalanced braces, empty file, non-Java content, file exceeding `MaxTokens`. All must return zero traces without panicking.

### Integration

- `testdata/flow/` gains realistic Spring-style fixtures; end-to-end `ScannerService` tests assert findings and trace shape.
- Formatter tests assert existing JSON stays byte-identical when `Trace` is empty.
- SARIF test asserts valid `codeFlows` structure.
- Dedupe test: overlapping flow + regex finding on one line yields only the flow finding.

## Implementation order

1. `internal/flow/lexer.go` + tests — tokens, comments, string literals
2. `internal/flow/scope.go` + tests — scope stack, shadowing
3. `internal/flow/rules.go` — data tables (legal-mapper reviews source/sink naming)
4. `internal/flow/trace.go` + `flow.go` + tests — the walk
5. `internal/detector/flow.go` + tests — adapter, risk matrix, hedged messages
6. `report.Finding.Trace` + text/JSON/SARIF formatters + tests
7. `report.Dedupe` + wire into `ScannerService`
8. Register in `buildDeps()`; update README, README.ko, roadmap

Each step ships green. qa-guard runs after steps 4, 5, and 7.
