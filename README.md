# klaws

[한국어](README.ko.md)

Korean law compliance risk scanner for codebases. Scans source code for patterns that may indicate compliance risks under Korean law and maps findings to specific legal provisions.

Currently covers [PIPA](https://www.law.go.kr/법령/개인정보보호법) (Personal Information Protection Act), with additional Korean laws planned.

> **Disclaimer:** klaws identifies possible compliance risks for review. It does not constitute legal advice. Consult qualified legal counsel for definitive guidance.

## Quick Start

```bash
# Build
go build -o klaws ./cmd/klaws/

# Scan a directory
klaws scan ./my-project

# Scan a single file
klaws scan ./MyService.java
```

## Installation

**Requirements:** Go 1.23+

```bash
git clone https://github.com/rostradamus/klaws.git
cd klaws
go build -o klaws ./cmd/klaws/
```

## Usage

### Scan

```bash
# Scan a directory (default: *.java files)
klaws scan ./src

# Scan specific file types
klaws scan ./src --pattern "*.kt"

# Text output (default is JSON)
klaws scan ./src --format text

# Use a custom laws file
klaws scan ./src --laws ./my-laws.yaml
```

### Example Output

```
klaws scan report
Target:  ./testdata
Files:   4
Findings: 7

--- Finding 1 ---
  Detector:  PIPA-CST-001
  Risk:      HIGH
  Location:  testdata/MemberController.java:10
  Snippet:   @PostMapping("/register")
  Message:   Endpoint accepts possible personal data without apparent consent
             mechanism — may require review under PIPA Article 15
  Laws:      PIPA-15

--- Finding 2 ---
  Detector:  PIPA-ENC-001
  Risk:      HIGH
  Location:  testdata/MemberEntity.java:11
  Snippet:   private String residentNumber;
  Message:   Possible unencrypted personal identifier (residentNumber) — may
             require review under PIPA Article 24-2
  Laws:      PIPA-24-2, PIPA-29

--- Finding 3 ---
  Detector:  PIPA-LOG-001
  Risk:      MEDIUM
  Location:  testdata/UserService.java:11
  Snippet:   log.info("User registered: " + email);
  Message:   Possible personal data (email) in log output — may require review
             under PIPA Article 29
  Laws:      PIPA-29
```

### Look Up Law Provisions

```bash
# Look up from bundled database
klaws law PIPA-15

# Fetch live text from law.go.kr
klaws law PIPA-15 --live
```

### List Detectors

```bash
klaws detectors
```

```json
[
  {
    "id": "PIPA-LOG-001",
    "name": "Personal Data Logging Risk",
    "description": "Detects log statements that may contain personal data fields",
    "related_laws": ["PIPA-29"]
  },
  {
    "id": "PIPA-ENC-001",
    "name": "Unencrypted Personal Data Risk",
    "description": "Detects personal identifier fields stored without apparent encryption",
    "related_laws": ["PIPA-24-2", "PIPA-29"]
  },
  {
    "id": "PIPA-CST-001",
    "name": "Missing Consent Check Risk",
    "description": "Detects endpoints accepting personal data without apparent consent verification",
    "related_laws": ["PIPA-15"]
  }
]
```

## Detectors

| ID | Name | What it looks for | Risk | Related Law |
|----|------|-------------------|------|-------------|
| `PIPA-LOG-001` | Personal Data Logging | `log.*()` calls containing personal data field names (email, phone, SSN, password) | MEDIUM | Art. 29 |
| `PIPA-ENC-001` | Unencrypted Personal Data | Sensitive identifier fields (resident number, SSN) without encryption annotations or calls | HIGH | Art. 24-2, 29 |
| `PIPA-CST-001` | Missing Consent Check | `@PostMapping`/`@PutMapping` endpoints accepting personal data without consent verification | HIGH | Art. 15 |

Detectors use regex-based pattern matching. They support both English and Korean field names (e.g., `email`/`이메일`, `residentNumber`/`주민번호`, `consent`/`동의`).

## MCP Server

klaws can run as an [MCP](https://modelcontextprotocol.io/) server, making its scanning capabilities available to AI coding assistants.

```bash
klaws serve
```

### Available Tools

| Tool | Description |
|------|-------------|
| `scan_directory` | Scan a directory for compliance risks |
| `scan_file` | Scan a single file |
| `list_detectors` | List all available detectors |
| `get_law_reference` | Look up a Korean law provision by ID |

### Configuration

Add to your MCP client settings (e.g., Claude Code `~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "klaws": {
      "command": "/path/to/klaws",
      "args": ["serve"]
    }
  }
}
```

## Bundled Law Provisions

klaws ships with 10 PIPA articles embedded in the binary (no external files needed):

| ID | Article | Topic |
|----|---------|-------|
| `PIPA-15` | Art. 15 | Collection and use of personal information |
| `PIPA-17` | Art. 17 | Provision to third parties |
| `PIPA-18` | Art. 18 | Restriction on use beyond purpose |
| `PIPA-21` | Art. 21 | Destruction of personal information |
| `PIPA-23` | Art. 23 | Restriction on sensitive information |
| `PIPA-24` | Art. 24 | Restriction on unique identification info |
| `PIPA-24-2` | Art. 24-2 | Restrictions on resident registration numbers |
| `PIPA-29` | Art. 29 | Duty of safety measures |
| `PIPA-30` | Art. 30 | Privacy policy |
| `PIPA-34` | Art. 34 | Notification of data breach |

Full Korean article text is included. Use `--live` to fetch the latest version from [law.go.kr](https://www.law.go.kr).

## Architecture

```
klaws scan ./src
       │
       ▼
   FileWalker ──► walks directory, matches glob pattern
       │
       ▼
  ScannerService ──► reads each file
       │
       ▼
  DetectorRegistry ──► runs all detectors on source code
       │
       ▼
    Findings ──► mapped to law provisions
       │
       ▼
   Report ──► JSON or text output
```

## Roadmap

- **More detectors:** data retention (PIPA-RET-001), cross-border transfer (PIPA-XBR-001)
- **Multi-language:** Python, JavaScript/TypeScript detection patterns
- **More Korean laws:** Network Act (정보통신망법), Credit Information Act (신용정보법)
- **CI/CD:** GitHub Action, SARIF output, severity thresholds
- **Configuration:** custom pattern rules via config file

## License

MIT
