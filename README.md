# klaws

[![CI](https://github.com/rostradamus/klaws/actions/workflows/ci.yml/badge.svg)](https://github.com/rostradamus/klaws/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/rostradamus/klaws)](https://github.com/rostradamus/klaws/releases/latest)
[![Container](https://img.shields.io/badge/ghcr.io-rostradamus%2Fklaws-blue?logo=docker)](https://github.com/rostradamus/klaws/pkgs/container/klaws)
[![Glama](https://glama.ai/mcp/servers/rostradamus/klaws/badges/score.svg)](https://glama.ai/mcp/servers/rostradamus/klaws)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[한국어](README.ko.md)

Korean law compliance risk scanner for codebases. Scans source code for patterns that may indicate compliance risks under Korean law and maps findings to specific legal provisions. Runs as an [MCP](https://modelcontextprotocol.io/) server (so AI coding assistants can scan on request) and as a standalone CLI.

Currently covers [PIPA](https://www.law.go.kr/법령/개인정보보호법) (Personal Information Protection Act), the [Network Act](https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률) (정보통신망법), the [Credit Information Act](https://www.law.go.kr/법령/신용정보의이용및보호에관한법률) (신용정보법), and the [E-Commerce Act](https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률) (전자상거래법).

> **Disclaimer:** klaws identifies possible compliance risks for review. It does not constitute legal advice. Consult qualified legal counsel for definitive guidance.

> **Privacy:** klaws analyzes code **locally** and transmits nothing. The only outbound network call is the optional `--live` law lookup to [law.go.kr](https://www.law.go.kr); without that flag it is fully offline. See [Privacy & Security](#privacy--security).

## Quick Start

```bash
# Scan the current directory with Docker — no install needed
docker run --rm -v "$PWD":/src:ro ghcr.io/rostradamus/klaws scan /src

# ...or, if you installed the binary:
klaws scan ./my-project        # scan a directory
klaws scan ./MyService.java    # scan a single file
```

## Installation

### Docker (recommended)

No toolchain required — the image is published to GitHub Container Registry and works identically on macOS, Linux, and Windows:

```bash
# Scan the current directory (mount it read-only at /src)
docker run --rm -v "$PWD":/src:ro ghcr.io/rostradamus/klaws scan /src

# Pin a version instead of the floating latest tag
docker run --rm -v "$PWD":/src:ro ghcr.io/rostradamus/klaws:0.1.5 scan /src
```

### Prebuilt binary

Download the archive for your platform from the [latest release](https://github.com/rostradamus/klaws/releases/latest), extract it, and move `klaws` onto your `PATH`.

### go install

```bash
go install github.com/rostradamus/klaws/cmd/klaws@latest
```

### From source

**Requirements:** Go 1.23+

```bash
git clone https://github.com/rostradamus/klaws.git
cd klaws
go build -o klaws ./cmd/klaws/
```

Verify the install:

```bash
klaws --version
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

# SARIF output (for GitHub code scanning / other tools)
klaws scan ./src --format sarif > klaws.sarif

# Fail the command (exit 1) if any finding is at or above a severity
klaws scan ./src --fail-on HIGH

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
| `PIPA-LOG-001` | Personal Data Logging | `log.*()` calls containing personal data field names (email, phone, SSN, password) | MEDIUM | PIPA Art. 29 |
| `PIPA-ENC-001` | Unencrypted Personal Data | Sensitive identifier fields (resident number, SSN) without encryption annotations or calls | HIGH | PIPA Art. 24-2, 29 |
| `PIPA-CST-001` | Missing Consent Check | `@PostMapping`/`@PutMapping` endpoints accepting personal data without consent verification | HIGH | PIPA Art. 15 |
| `NIA-MKT-001` | Marketing Message Consent | Advertising/marketing message dispatch (`send`/`push`) without an apparent opt-in consent check | MEDIUM | Network Act Art. 50 |
| `CIA-ENC-001` | Unprotected Credit Information | Credit/financial identifier fields (card number, account number, credit score) without encryption or masking | HIGH | Credit Information Act Art. 19 |
| `ECA-RET-001` | Transaction Record Retention | Transaction record fields (order/payment IDs) stored without apparent retention or preservation handling | MEDIUM | E-Commerce Act Art. 6 |
| `PIPA-RET-001` | Personal Data Retention | Personal data fields (email, phone, resident number) stored without apparent destruction or retention-limit handling | MEDIUM | PIPA Art. 21 |
| `PIPA-XBR-001` | Third-Party Data Transfer | Personal data sent to a third-party or external endpoint (outbound call to an external URL/partner) without an apparent consent check | HIGH | PIPA Art. 17 |

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

All clients use the same launch command: `klaws serve` over stdio. Use the absolute path to the binary (run `which klaws`, or `where klaws` on Windows, to find it), or just `klaws` if it is on your `PATH`. Prefer not to install anything? Use the [Docker variant](#run-the-mcp-server-via-docker) below — it works in any client that supports stdio MCP servers.

**Claude Code** — `~/.claude/settings.json`:

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

Or add it in one command:

```bash
claude mcp add klaws -- klaws serve
```

**Claude Desktop** — `claude_desktop_config.json` (Settings → Developer → Edit Config):

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

**Cursor** — `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

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

**VS Code** — `.vscode/mcp.json`:

```json
{
  "servers": {
    "klaws": {
      "command": "klaws",
      "args": ["serve"]
    }
  }
}
```

Once connected, ask your assistant something like *"scan this directory for Korean compliance risks with klaws."*

#### Run the MCP server via Docker

No binary install needed — swap the `command`/`args` for a `docker run` that mounts the code you want scannable. The `-i` flag keeps stdin open for the stdio transport; `--scan-root /src` confines scans to the mounted directory:

```json
{
  "mcpServers": {
    "klaws": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/absolute/path/to/your/project:/src:ro",
        "ghcr.io/rostradamus/klaws:0.1.5",
        "serve", "--scan-root", "/src"
      ]
    }
  }
}
```

Point the assistant at paths under `/src` (the container-side mount), e.g. *"scan /src for Korean compliance risks."*

### Remote (Streamable HTTP)

By default `klaws serve` uses stdio (local). To run it as a remote MCP server over HTTP, pass `--http`:

```bash
klaws serve --http :8080
# or via the published container image:
docker run --rm -p 8080:8080 ghcr.io/rostradamus/klaws serve --http :8080
```

The MCP endpoint is then available at `http://<host>:8080/mcp` (Streamable HTTP transport). Point an HTTP-capable MCP client at that URL.

#### Securing a remote server

```bash
klaws serve --http :8080 \
  --auth-token "$(openssl rand -hex 32)" \
  --scan-root /workspace
```

- `--auth-token <token>` — requires `Authorization: Bearer <token>` on every HTTP request; unauthenticated requests get `401`. Can also be supplied via the `KLAWS_AUTH_TOKEN` environment variable. Applies to `--http` only.
- `--scan-root <dir>` — restricts `scan_directory` / `scan_file` to paths within `<dir>`; requests for paths outside it are rejected. (Also honored in stdio mode.)

> **Notes:**
> - `--auth-token` provides bearer auth but **not TLS**. For untrusted networks, still terminate TLS at a reverse proxy / gateway in front of klaws.
> - The `scan_directory` and `scan_file` tools read the **server's** filesystem (the paths you pass resolve on the host running klaws). For remote scanning, run klaws where the code lives (e.g. a CI runner with the repo checked out) and set `--scan-root` to that checkout. The `get_law_reference` and `list_detectors` tools have no filesystem dependency.

## Bundled Law Provisions

klaws ships with 40 articles across 4 Korean laws embedded in the binary (no external files needed):

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

### Network Act (정보통신망법) — 11 articles

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
| `NIA-50` | Art. 50 | Restriction on transmission of advertising info |

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

## Privacy & Security

klaws is designed to be safe to point at private code:

- **Local-only analysis.** Scanning is pure static pattern-matching on files you pass in. Source code never leaves your machine — nothing is uploaded, logged remotely, or sent to any service.
- **One optional outbound call.** The only network request klaws ever makes is the `--live` law lookup (CLI) / `get_law_reference` with live fetch (MCP), which fetches public statute text from [law.go.kr](https://www.law.go.kr). It sends only the statute's name (e.g. `개인정보보호법`, resolved from the provision you looked up) as the search query — never your code. Omit `--live` to stay fully offline.
- **Read-only by design.** klaws only reads the files it scans; it never modifies your code. Its MCP tools are annotated read-only.
- **Confine the reachable filesystem.** When exposing the MCP server, pass `--scan-root <dir>` to restrict `scan_directory`/`scan_file` to a single tree, and `--auth-token` when serving over `--http`. See [Securing a remote server](#securing-a-remote-server).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

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

- **More detectors:** marketing-message consent (NIA-MKT-001) *(done)*, unprotected credit information (CIA-ENC-001) *(done)*, transaction-record retention (ECA-RET-001) *(done)*, personal-data retention (PIPA-RET-001) *(done)*, third-party/cross-border transfer (PIPA-XBR-001) *(done)*
- **Multi-language:** Python, JavaScript/TypeScript detection patterns
- **More Korean laws:** E-Commerce Act (전자상거래법) consumer protection rules *(done)*, Network Act (정보통신망법) *(done)*, Credit Information Act (신용정보법) *(done)*
- **CI/CD:** GitHub Action, SARIF output, severity thresholds *(done)*
- **Configuration:** custom pattern rules via config file

## GitHub Action (CI)

klaws ships a composite action that scans your code and produces a SARIF report, which you can upload to GitHub code scanning so findings appear inline on pull requests and in the **Security** tab.

```yaml
# .github/workflows/klaws.yml
name: klaws compliance scan
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: klaws
        uses: rostradamus/klaws@v0.1.5
        with:
          path: ./src
          pattern: "*.java"
          fail-on: none      # or MEDIUM / HIGH to gate the PR
          version: v0.1.5

      - name: Upload SARIF
        if: always()          # upload even if fail-on tripped the step
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.klaws.outputs.sarif }}
```

Set `fail-on: HIGH` (or `MEDIUM`) to make the check fail the PR when findings at that severity or above are present. The `if: always()` on the upload step ensures the SARIF is still published when the gate fails.

## Releasing

Maintainers: see [RELEASE.md](RELEASE.md) for how to cut a release and publish to the MCP registry.

## License

MIT
