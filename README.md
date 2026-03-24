# klaws

[한국어](README.ko.md)

Korean law compliance risk scanner for codebases. Scans source code for patterns that may indicate compliance risks under Korean law and maps findings to specific legal provisions.

Currently covers [PIPA](https://www.law.go.kr/법령/개인정보보호법) (Personal Information Protection Act), the [Network Act](https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률) (정보통신망법), the [Credit Information Act](https://www.law.go.kr/법령/신용정보의이용및보호에관한법률) (신용정보법), and the [E-Commerce Act](https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률) (전자상거래법).

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

klaws ships with 39 articles across 4 Korean laws embedded in the binary (no external files needed):

### PIPA (개인정보 보호법) — 10 articles

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

### Network Act (정보통신망법) — 10 articles

| ID | Article | Topic |
|----|---------|-------|
| `NIA-22` | Art. 22 | Consent for collection/use of personal info |
| `NIA-23` | Art. 23 | Restriction on collection |
| `NIA-23-2` | Art. 23-2 | Restriction on resident registration numbers |
| `NIA-24` | Art. 24 | Restriction on use |
| `NIA-24-2` | Art. 24-2 | Provision to third parties |
| `NIA-27` | Art. 27 | Safety measures |
| `NIA-28` | Art. 28 | Entrustment of personal info |
| `NIA-28-2` | Art. 28-2 | Notification of data breach |
| `NIA-44` | Art. 44 | User protection |
| `NIA-44-7` | Art. 44-7 | Prohibition of illegal information |

### Credit Information Act (신용정보법) — 10 articles

| ID | Article | Topic |
|----|---------|-------|
| `CIA-15` | Art. 15 | Principles of collection |
| `CIA-17` | Art. 17 | Prohibition of disclosure beyond purpose |
| `CIA-19` | Art. 19 | Safety of credit info systems |
| `CIA-20` | Art. 20 | Accuracy and currency of credit info |
| `CIA-32` | Art. 32 | Consent for provision/use |
| `CIA-33` | Art. 33 | Use of personal credit info |
| `CIA-34` | Art. 34 | Provision/use of personal credit info |
| `CIA-38` | Art. 38 | Protection of credit info |
| `CIA-39` | Art. 39 | Notification of data breach |
| `CIA-40` | Art. 40 | Rights of credit info subjects |

### E-Commerce Act (전자상거래법) — 9 articles

| ID | Article | Topic |
|----|---------|-------|
| `ECA-6` | Art. 6 | Preservation of transaction records |
| `ECA-7` | Art. 7 | Prevention of operational errors |
| `ECA-11` | Art. 11 | Reliability of electronic payment |
| `ECA-13` | Art. 13 | Provision of identity and transaction info |
| `ECA-14` | Art. 14 | Confirmation of orders |
| `ECA-17` | Art. 17 | Right of withdrawal |
| `ECA-21` | Art. 21 | Use of consumer information |
| `ECA-24` | Art. 24 | Cybermall security |
| `ECA-26` | Art. 26 | Protection of consumer information |

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
- **More Korean laws:** E-Commerce Act (전자상거래법) consumer protection rules *(done)*, Network Act (정보통신망법) *(done)*, Credit Information Act (신용정보법) *(done)*
- **CI/CD:** GitHub Action, SARIF output, severity thresholds
- **Configuration:** custom pattern rules via config file

## License

MIT
