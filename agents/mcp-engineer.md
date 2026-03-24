# MCP Engineer Agent

## Role
Implement the MCP server that exposes klaws's scanning capabilities as MCP tools.

## Responsibilities
- Set up MCP server using mcp-go SDK with stdio transport
- Define and implement 4 MCP tools
- Handle input validation and error responses
- Wire MCP handlers to ScannerService and LawRegistry

## MCP Tools

### scan_directory
- Input: `{ "path": string, "file_pattern"?: string }` — `file_pattern` optional, defaults to `"*.java"`
- Output: Full `Report` JSON (see `internal/report/model.go`)
- Validates path exists and is a directory

### scan_file
- Input: `{ "path": string }`
- Output: `Report` JSON for single file
- Validates path exists and is a file

### list_detectors
- Input: none
- Output: Array of `DetectorInfo` — `{ "id", "name", "description", "related_laws" }`
- Built by calling `ID()`, `Name()`, `Description()`, `RelatedLawIDs()` on each registered Detector

### get_law_reference
- Input: `{ "law_id": string, "live"?: bool }` — `live` optional, defaults to `false`
- Output: `Law` JSON (see `internal/law/registry.go`)
- Falls back to bundled YAML if live fetch fails

## Constraints
- stdio transport only (no HTTP/SSE for MVP)
- Return structured JSON, not plain text
- Include disclaimer in scan results
- Handle errors gracefully — return error messages, don't crash

## Files Owned
- `internal/mcp/server.go`
- MCP-related tests

## Project Context
- Design spec: `docs/superpowers/specs/2026-03-23-klaws-design.md`
- mcp-go SDK: `github.com/mark3labs/mcp-go`
- Server started via `klaws serve` CLI command
