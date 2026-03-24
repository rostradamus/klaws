# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About

klaws is a Korean compliance risk scanner for codebases. It identifies possible risks related to Korean laws (currently PIPA) and maps them to specific law provisions. It operates as an MCP server (primary) and CLI tool (secondary).

## Critical Rules

- This tool does NOT provide legal advice
- All user-facing text must use hedged language: "possible risk", "may require review", "related provision"
- Never use: "violation", "illegal", "non-compliant", "you must"

## Build & Test

```bash
go build -o klaws ./cmd/klaws/          # Build binary
go test ./...                            # Run all tests
go test ./internal/detector/ -v          # Run one package
go test ./internal/detector/ -run TestLogging  # Run one test
go run ./cmd/klaws/ scan ./testdata      # Quick smoke test
```

## Architecture

The scan pipeline flows: **Walker → ScannerService → Detectors → Report**

- `cmd/klaws/main.go` — Entry point. Wires dependencies and defines cobra commands (`scan`, `detectors`, `law`, `serve`).
- `internal/scanner/` — `ScannerService` orchestrates scanning. `FileWalker` walks directories matching glob patterns. The service reads each file and passes source code through all registered detectors.
- `internal/detector/` — `Detector` interface with `Scan(sourceCode, filePath) []Finding`. Each detector uses regex patterns to identify risks. `Registry` holds all detectors and runs them collectively via `ScanAll()`.
- `internal/law/` — `Registry` loads law provisions from `laws.yaml` (embedded via `go:embed`, overridable with `--laws` flag). `Client` fetches live law text from law.go.kr XML API. `LookupLive` falls back to bundled data on fetch failure.
- `internal/report/` — `Finding` and `Report` models. `FormatJSON` and `FormatText` formatters.
- `internal/mcp/` — MCP server exposing 4 tools: `scan_directory`, `scan_file`, `list_detectors`, `get_law_reference`. Uses mcp-go SDK with stdio transport.

## Adding a New Detector

1. Create `internal/detector/<name>.go` implementing the `Detector` interface (ID, Name, Description, RelatedLawIDs, Scan)
2. Register it in `cmd/klaws/main.go` in the `buildDeps()` function
3. Add related law entries to `internal/law/laws.yaml` if needed
4. Add test file in `internal/detector/<name>_test.go`

## Agent Team

This project uses specialized subagents. Dispatch them using the Agent tool with prompts from `agents/`.

| Agent | Prompt File | Dispatch As |
|-------|-------------|-------------|
| planner | `agents/planner.md` | `subagent_type: "Plan"` |
| go-architect | `agents/go-architect.md` | `subagent_type: "feature-dev:code-architect"` |
| detector-engineer | `agents/detector-engineer.md` | `subagent_type: "general-purpose"` |
| legal-mapper | `agents/legal-mapper.md` | `subagent_type: "general-purpose"` |
| mcp-engineer | `agents/mcp-engineer.md` | `subagent_type: "general-purpose"` |
| qa-guard | `agents/qa-guard.md` | `subagent_type: "feature-dev:code-reviewer"` |

### Dispatch Rules

- Read the agent's prompt file and include it in the Agent tool's prompt
- Independent tasks → dispatch agents in parallel
- Sequential tasks → chain (architect → engineer → qa-guard)
- legal-mapper MUST review all user-facing strings before they ship
- qa-guard MUST run after each module is built

## Design Spec

Full spec: `docs/superpowers/specs/2026-03-23-klaws-design.md`
