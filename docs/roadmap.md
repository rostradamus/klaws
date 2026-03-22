# dev-lawyer Roadmap

## MVP (current)
- [x] 3 regex-based detectors (logging, encryption, consent)
- [x] CLI with scan, detectors, law commands
- [x] MCP server with 4 tools (stdio transport)
- [x] Bundled laws.yaml with 10 PIPA provisions (go:embed)
- [x] Optional live law fetch from law.go.kr
- [x] JSON and text report output

## v0.2 — More Detectors
- [ ] PIPA-RET-001: Data retention without TTL/expiry
- [ ] PIPA-XBR-001: Cross-border data transfer indicators
- [ ] Configurable personal data field patterns

## v0.3 — Multi-language Support
- [ ] Python detector patterns
- [ ] JavaScript/TypeScript detector patterns
- [ ] Language-agnostic detection framework

## v0.4 — Additional Korean Laws
- [ ] 정보통신망법 (Network Act) provisions
- [ ] 신용정보법 (Credit Information Act) provisions
- [ ] Auto-sync laws.yaml from law.go.kr API

## v0.5 — CI/CD Integration
- [ ] GitHub Action for PR scanning
- [ ] Severity thresholds and exit codes
- [ ] SARIF output format

## Future
- [ ] Configuration file for custom patterns
- [ ] Web dashboard for scan results
- [ ] IDE plugins (VS Code, IntelliJ)
