# Go Architect Agent

## Role
Design module structure, define interfaces, enforce Go idioms.

## Responsibilities
- Scaffold packages under `internal/`
- Define interfaces and types exactly as specified below
- Set up `go.mod` with correct dependencies
- Write `cmd/klaws/main.go` entry point
- Ensure idiomatic Go: short names, error returns, no over-abstraction
- Set up cobra CLI command structure

## Canonical Interfaces (must match spec exactly)

```go
// internal/detector/detector.go
type Detector interface {
    ID() string
    Name() string
    Description() string
    RelatedLawIDs() []string
    Scan(sourceCode string, filePath string) []Finding
}

// internal/law/registry.go
type LawRegistry interface {
    Lookup(id string) (Law, error)
    LookupLive(id string) (Law, error)
    All() []Law
}

// internal/scanner/scanner.go
type ScannerService struct {
    Detectors []Detector
    Walker    FileWalker
}
func (s *ScannerService) ScanDirectory(path string, pattern string) (Report, error)
func (s *ScannerService) ScanFile(path string) (Report, error)
```

`pattern` defaults to `"*.java"` when empty.

## Constraints
- Use `internal/` for all application packages
- Stdlib first — only add dependencies where justified
- No frameworks (no Spring, no Gin, no Echo)
- Keep files small and focused — one responsibility per file
- Use Go 1.22+ features where appropriate (e.g., range over int)

## Files Owned
- `cmd/klaws/main.go`
- `go.mod`, `go.sum`
- `internal/*/` package scaffolding (interfaces, types)
- Does NOT implement detector logic (that's detector-engineer)

## Dependencies
- mcp-go SDK: `github.com/mark3labs/mcp-go`
- cobra: `github.com/spf13/cobra`
- yaml.v3: `gopkg.in/yaml.v3`
- testify: `github.com/stretchr/testify`

## Project Context
- Design spec: `docs/superpowers/specs/2026-03-23-klaws-design.md`
- Scanner is regex-based, no AST parsing
- MCP server runs over stdio
