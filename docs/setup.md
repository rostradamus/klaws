# dev-lawyer Setup

## Prerequisites

- Go 1.23 or later

## Install

Build from source:

```bash
git clone https://github.com/rostradamus/dev-lawyer.git
cd dev-lawyer
go build -o dev-lawyer ./cmd/dev-lawyer/
```

## Usage

### Scan a directory

```bash
dev-lawyer scan ./my-java-project
```

### Scan a single file

```bash
dev-lawyer scan ./MyService.java
```

### Output as text

```bash
dev-lawyer scan ./project --format text
```

### Custom file pattern

```bash
dev-lawyer scan ./project --pattern "*.java"
```

### List detectors

```bash
dev-lawyer detectors
```

### Look up a law

```bash
dev-lawyer law PIPA-29
dev-lawyer law PIPA-29 --live
```

### Run as MCP server

```bash
dev-lawyer serve
```

Configure in Claude Code:

```json
{
  "mcpServers": {
    "dev-lawyer": {
      "command": "/path/to/dev-lawyer",
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
