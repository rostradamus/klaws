# klaws Setup

## Prerequisites

- Go 1.23 or later

## Install

Build from source:

```bash
git clone https://github.com/rostradamus/klaws.git
cd klaws
go build -o klaws ./cmd/klaws/
```

## Usage

### Scan a directory

```bash
klaws scan ./my-java-project
```

### Scan a single file

```bash
klaws scan ./MyService.java
```

### Output as text

```bash
klaws scan ./project --format text
```

### Custom file pattern

```bash
klaws scan ./project --pattern "*.java"
```

### List detectors

```bash
klaws detectors
```

### Look up a law

```bash
klaws law PIPA-29
klaws law PIPA-29 --live
```

### Run as MCP server

```bash
klaws serve
```

Configure in Claude Code:

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

## Run tests

```bash
go test ./... -v
```

## Disclaimer

This tool identifies possible compliance risks for review. It does not constitute legal advice. Consult qualified legal counsel for definitive guidance.
