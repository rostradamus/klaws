# klaws: Korean Compliance Risk Scanner — Design Spec

## Overview

klaws is a lightweight developer tool that scans codebases for possible Korean compliance risks. It identifies potential issues and maps them to relevant Korean law provisions. It operates as an MCP server (primary) and CLI tool (secondary).

**Critical constraint:** This tool does NOT provide legal advice. It never concludes that something is definitely legal or illegal. All output uses hedged language: "possible risk", "may require review", "related provision".

## Stack

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | Go 1.22+ | Fast iteration, single binary, stdlib-rich, beginner-friendly |
| MCP | mcp-go SDK | Mature Go MCP server library |
| CLI | cobra | Standard Go CLI framework |
| JSON | encoding/json (stdlib) | No external dependency needed |
| YAML | gopkg.in/yaml.v3 | Law provision data file parsing |
| HTTP | net/http (stdlib) | For open.law.go.kr API client |
| Regex | regexp (stdlib) | Pattern-based detection |
| Testing | testing (stdlib) + testify | Standard Go test combo |
| Build | Gradle — N/A, Go uses go.mod | Native Go module system |

## Architecture

Single-binary Go application. No framework. Packages under `internal/` enforce encapsulation.

```
Target Path → FileWalker → [source files] → Detector[] → Finding[] → Report (JSON)
```

### Project Structure

```
klaws/
├── cmd/
│   └── klaws/
│       └── main.go            # Entry point: CLI or MCP mode
├── internal/
│   ├── scanner/
│   │   ├── scanner.go         # ScannerService: orchestrates scan
│   │   └── walker.go          # FileWalker: finds source files
│   ├── detector/
│   │   ├── detector.go        # Detector interface
│   │   ├── registry.go        # DetectorRegistry: collects all detectors
│   │   ├── logging.go         # PIPA-LOG-001: personal data in logs
│   │   ├── encryption.go      # PIPA-ENC-001: unencrypted personal data
│   │   └── consent.go         # PIPA-CST-001: missing consent check
│   ├── law/
│   │   ├── registry.go        # LawRegistry: loads from YAML + optional API
│   │   ├── client.go          # open.law.go.kr API client
│   │   └── laws.yaml          # Bundled law provisions
│   ├── report/
│   │   ├── model.go           # Finding, Report structs
│   │   └── formatter.go       # JSON/text output
│   └── mcp/
│       └── server.go          # MCP tool definitions and handlers
├── testdata/                  # Sample Java files for testing
├── docs/
│   ├── setup.md
│   └── roadmap.md
├── go.mod
├── go.sum
└── README.md
```

## Detector Design

### Interface

```go
type Detector interface {
    ID() string
    Name() string
    Description() string
    RelatedLawIDs() []string
    Scan(sourceCode string, filePath string) []Finding
}
```

Detectors are stateless. They receive raw source code as a string and return zero or more findings. Pattern matching is regex-based — no AST parsing.

### MVP Detectors

#### PIPA-LOG-001: Personal Data Logging Risk

- **What:** Detects `log.*` calls containing personal data field names
- **Pattern:** `log\.(info|debug|warn|error)\(.*?(email|phone|ssn|password|주민|이름|전화|이메일)`
- **Risk level:** MEDIUM
- **Related law:** PIPA Article 29 (Duty of Safety Measures)
- **Message:** "Possible personal data ({field}) in log output — may require review under PIPA Article 29"

#### PIPA-ENC-001: Unencrypted Personal Data

- **What:** Detects String fields storing sensitive identifiers without evidence of encryption
- **Pattern:** Field declarations matching `(residentNumber|ssn|주민번호|resident.*[Nn]o)` as plain `String` without `@Encrypted` or `encrypt(` in surrounding context
- **Algorithm:** Split source by `\n`. For each line matching the field pattern, check lines `[max(0, i-5) : min(len, i+6)]` for `@Encrypted` or `encrypt(`. If no encryption evidence found, emit a finding.
- **Risk level:** HIGH
- **Related law:** PIPA Article 24-2, Article 29
- **Message:** "Possible unencrypted personal identifier ({field}) — may require review under PIPA Article 24-2"

#### PIPA-CST-001: Missing Consent Check

- **What:** Detects controller endpoints accepting personal data but no consent check
- **Pattern:** `@(Post|Put)Mapping` + personal data params, no `consent|동의|agree` nearby
- **Algorithm:** Split source by `\n`. When a line matches `@(Post|Put)Mapping`, scan the next 30 lines for personal data parameter names (email, phone, name, ssn, etc.). If personal data params found but no `consent|동의|agree` keyword in that same 30-line window, emit a finding.
- **Risk level:** HIGH
- **Related law:** PIPA Article 15
- **Message:** "Endpoint accepts possible personal data without apparent consent mechanism — may require review under PIPA Article 15"

## Core Type Definitions

### Law

```go
type Law struct {
    ID        string `json:"id" yaml:"id"`
    NameKo    string `json:"name_ko" yaml:"name_ko"`
    NameEn    string `json:"name_en" yaml:"name_en"`
    Summary   string `json:"summary" yaml:"summary"`
    URL       string `json:"url" yaml:"url"`
    RiskLevel string `json:"risk_level" yaml:"risk_level"`
    FullText  string `json:"full_text,omitempty" yaml:"-"` // populated only on live fetch
}
```

### LawRegistry

```go
type LawRegistry interface {
    Lookup(id string) (Law, error)          // from bundled YAML
    LookupLive(id string) (Law, error)      // from open.law.go.kr, fallback to YAML
    All() []Law                              // all bundled provisions
}
```

### ScannerService

```go
type ScannerService struct {
    Detectors []Detector
    Walker    FileWalker
}

func (s *ScannerService) ScanDirectory(path string, pattern string) (Report, error)
func (s *ScannerService) ScanFile(path string) (Report, error)
```

`pattern` defaults to `"*.java"` when empty.

### Finding

```go
type Finding struct {
    DetectorID  string   `json:"detector_id"`
    RiskLevel   string   `json:"risk_level"`
    FilePath    string   `json:"file_path"`
    LineNumber  int      `json:"line_number"`
    Snippet     string   `json:"snippet"`
    Message     string   `json:"message"`
    RelatedLaws []string `json:"related_laws"`
}
```

### Report

```go
type Report struct {
    ScannedAt     string    `json:"scanned_at"`
    TargetPath    string    `json:"target_path"`
    FilesScanned  int       `json:"files_scanned"`
    TotalFindings int       `json:"total_findings"`
    Findings      []Finding `json:"findings"`
    Disclaimer    string    `json:"disclaimer"`
}
```

**Disclaimer (always present):**
> "This report identifies possible compliance risks for review. It does not constitute legal advice. Consult qualified legal counsel for definitive guidance."

### Example Output

```json
{
  "scanned_at": "2026-03-23T14:30:00Z",
  "target_path": "/home/dev/my-project",
  "files_scanned": 42,
  "total_findings": 1,
  "findings": [
    {
      "detector_id": "PIPA-LOG-001",
      "risk_level": "MEDIUM",
      "file_path": "src/main/java/com/example/UserService.java",
      "line_number": 45,
      "snippet": "log.info(\"User registered: \" + user.getEmail());",
      "message": "Possible personal data (email) in log output — may require review under PIPA Article 29",
      "related_laws": ["PIPA-29"]
    }
  ],
  "disclaimer": "This report identifies possible compliance risks for review. It does not constitute legal advice."
}
```

## Law Registry (Hybrid)

### Bundled Data (`laws.yaml`)

```yaml
laws:
  - id: "PIPA-15"
    name_ko: "개인정보 보호법 제15조"
    name_en: "PIPA Article 15 (Collection and Use of Personal Information)"
    summary: "Requires consent or legal basis before collecting personal information"
    url: "https://www.law.go.kr/법령/개인정보보호법/제15조"
    risk_level: "HIGH"

  - id: "PIPA-24-2"
    name_ko: "개인정보 보호법 제24조의2"
    name_en: "PIPA Article 24-2 (Restrictions on Resident Registration Numbers)"
    summary: "Prohibits processing resident registration numbers except where specifically permitted"
    url: "https://www.law.go.kr/법령/개인정보보호법/제24조의2"
    risk_level: "HIGH"

  - id: "PIPA-29"
    name_ko: "개인정보 보호법 제29조"
    name_en: "PIPA Article 29 (Duty of Safety Measures)"
    summary: "Requires technical, managerial, and physical measures to prevent data loss, theft, or leakage"
    url: "https://www.law.go.kr/법령/개인정보보호법/제29조"
    risk_level: "HIGH"
```

MVP ships ~10-15 curated PIPA provisions.

### Live Fetch (Optional)

- API: `https://www.law.go.kr/DRF/lawSearch.do?target=law&query=개인정보보호법`
- Fetches full article text from open.law.go.kr
- Merges with bundled metadata (risk_level, summary)
- Timeout + fallback to bundled YAML if API is unreachable
- Requires registration for higher rate limits; basic search works without key

### Behavior

| Call | Source |
|------|--------|
| `get_law_reference("PIPA-15", live=false)` | Bundled YAML |
| `get_law_reference("PIPA-15", live=true)` | open.law.go.kr API, fallback to YAML |

## MCP Server

Exposed via stdio transport using mcp-go SDK. Started with `klaws serve`.

### Tools

| Tool | Input | Output |
|------|-------|--------|
| `scan_directory` | `{ "path": string, "file_pattern"?: string }` | Full Report JSON |
| `scan_file` | `{ "path": string }` | Report for single file |
| `list_detectors` | none | Array of DetectorInfo JSON |
| `get_law_reference` | `{ "law_id": string, "live"?: bool }` | Law JSON |

- `file_pattern` is optional, defaults to `"*.java"`
- `live` is optional, defaults to `false`

#### DetectorInfo (list_detectors output)

```go
type DetectorInfo struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Description string   `json:"description"`
    RelatedLaws []string `json:"related_laws"`
}
```

#### get_law_reference output

Returns a `Law` JSON object (see Core Type Definitions above).

### MCP Client Configuration

```json
{
  "mcpServers": {
    "klaws": {
      "command": "klaws",
      "args": ["serve"]
    }
  }
}
```

## CLI

```bash
# Scan a directory (default: *.java files)
klaws scan ./my-java-project

# Scan a single file
klaws scan ./MyService.java

# Filter file pattern
klaws scan ./project --pattern "*.java"

# Output as text instead of JSON
klaws scan ./project --format text

# List available detectors
klaws detectors

# Look up a law provision
klaws law PIPA-15
klaws law PIPA-15 --live

# Start as MCP server (stdio)
klaws serve
```

## Language & Tone Rules

All detector messages and report outputs MUST:
- Use "possible", "may", "potential" — never "definite", "violation", "illegal"
- Reference the related law provision, not interpret it
- Include the disclaimer in every report
- Frame findings as "areas that may require review", not conclusions

## Scope

### MVP (this spec)
- 3 regex-based detectors targeting Java/Spring privacy patterns
- CLI with scan, detectors, law commands
- MCP server with 4 tools
- Bundled laws.yaml with ~10-15 PIPA provisions
- Optional live law fetch from open.law.go.kr
- JSON and text report output
- Unit tests for all detectors with sample Java testdata

### Later
- Additional detectors (data retention, cross-border transfer)
- Support for other languages (Python, JavaScript)
- Additional Korean laws (정보통신망법, 신용정보법)
- Auto-sync laws.yaml from open.law.go.kr
- CI/CD integration (GitHub Action)
- Severity thresholds and filtering
- Configuration file for custom patterns
