# Law Expansion: Multi-Law Reference Database — Design Spec

## Goal

Expand klaws from PIPA-only to cover four Korean laws by adding law reference entries. No new detectors — this is a data expansion. Future detector work will reference these law IDs.

## Laws

| Law | Korean Name | Prefix | Articles |
|-----|-------------|--------|----------|
| Personal Information Protection Act | 개인정보 보호법 | `PIPA-` | 10 (existing) |
| Network Act | 정보통신망법 | `NIA-` | 10 (new) |
| Credit Information Act | 신용정보법 | `CIA-` | 10 (new) |
| E-Commerce Act | 전자상거래법 | `ECA-` | 9 (new) |

Total: 39 articles across 4 laws.

## File Structure Change

### Before

```
internal/law/
├── laws.yaml          # Single file, 10 PIPA articles, go:embed
├── law.go
├── registry.go
├── client.go
```

### After

```
internal/law/
├── laws/
│   ├── pipa.yaml              # 개인정보 보호법 (moved from laws.yaml)
│   ├── network-act.yaml       # 정보통신망법
│   ├── credit-info-act.yaml   # 신용정보법
│   └── ecommerce-act.yaml     # 전자상거래법
├── law.go
├── registry.go                # Updated embed directive
├── client.go
```

## Code Changes

### registry.go

Change embed directive from single file to directory:

```go
// Before
//go:embed laws.yaml
var embeddedLaws embed.FS

// After
//go:embed laws/*.yaml
var embeddedLaws embed.FS
```

Update `NewRegistry` to:
1. When `yamlPath == ""`: use `fs.Glob(embeddedLaws, "laws/*.yaml")` (or `embeddedLaws.ReadDir("laws")` + filter) to enumerate embedded YAML files, parse each, and merge into one registry. Do not use `filepath.Glob` — it does not work on `embed.FS`.
2. When `yamlPath != ""`: load single external file as before (override behavior preserved)

### law.go

No changes. The `Law` struct and `lawsFile` wrapper remain the same — each YAML file uses the same `laws:` top-level key.

### client.go

No changes.

## New Article Coverage

### 정보통신망법 (Network Act) — `NIA-`

| ID | Article | Topic |
|----|---------|-------|
| `NIA-22` | 제22조 | 개인정보의 수집ㆍ이용 동의 |
| `NIA-23` | 제23조 | 개인정보의 수집 제한 |
| `NIA-23-2` | 제23조의2 | 주민등록번호의 사용 제한 |
| `NIA-24` | 제24조 | 개인정보의 이용 제한 |
| `NIA-24-2` | 제24조의2 | 개인정보의 제3자 제공 |
| `NIA-27` | 제27조 | 개인정보의 보호조치 |
| `NIA-28` | 제28조 | 개인정보의 위탁 |
| `NIA-28-2` | 제28조의2 | 개인정보 유출등의 통지ㆍ신고 |
| `NIA-44` | 제44조 | 정보통신망에서의 이용자 보호 |
| `NIA-44-7` | 제44조의7 | 불법정보의 유통금지 |

### 신용정보법 (Credit Information Act) — `CIA-`

| ID | Article | Topic |
|----|---------|-------|
| `CIA-15` | 제15조 | 수집ㆍ조사의 원칙 |
| `CIA-17` | 제17조 | 업무 목적 외 누설금지 등 |
| `CIA-19` | 제19조 | 신용정보전산시스템의 안전보호 |
| `CIA-20` | 제20조 | 신용정보의 정확성 및 최신성의 유지 |
| `CIA-32` | 제32조 | 개인신용정보의 제공ㆍ활용에 대한 동의 |
| `CIA-33` | 제33조 | 개인신용정보의 이용 |
| `CIA-34` | 제34조 | 개인신용정보의 제공ㆍ이용 |
| `CIA-38` | 제38조 | 신용정보의 보호 |
| `CIA-39` | 제39조 | 신용정보 유출등의 통지ㆍ신고 |
| `CIA-40` | 제40조 | 신용정보주체의 권리 |

### 전자상거래법 (E-Commerce Act) — `ECA-`

| ID | Article | Topic |
|----|---------|-------|
| `ECA-6` | 제6조 | 거래기록의 보존 |
| `ECA-7` | 제7조 | 조작실수 등의 방지 |
| `ECA-11` | 제11조 | 전자적 대금지급의 신뢰확보 |
| `ECA-13` | 제13조 | 신원 및 거래조건에 대한 정보의 제공 |
| `ECA-14` | 제14조 | 청약의 확인 |
| `ECA-17` | 제17조 | 청약철회 등 |
| `ECA-21` | 제21조 | 소비자에 관한 정보의 이용 |
| `ECA-24` | 제24조 | 사이버몰의 안전성 확보 |
| `ECA-26` | 제26조 | 소비자정보의 보호 |

## YAML Entry Format

Each entry follows the existing format:

```yaml
laws:
  - id: "NIA-22"
    name_ko: "정보통신망 이용촉진 및 정보보호 등에 관한 법률 제22조"
    name_en: "Network Act Article 22 (Consent for Collection and Use of Personal Information)"
    summary: "Requires informed consent before collecting personal information via information and communications networks"
    url: "https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률/제22조"
    risk_level: "HIGH"
    full_text_ko: |
      제22조(개인정보의 수집ㆍ이용 동의 등)
      ① ...
```

## Data Sourcing

- `full_text_ko`: sourced from law.go.kr for each article
- `summary`: concise English description using hedged language
- `risk_level`: HIGH for consent/encryption/breach provisions, MEDIUM for procedural/administrative provisions
- `url`: direct link to the article on law.go.kr

## ID Convention

IDs follow the pattern `{PREFIX}-{article}` where `{article}` is the article number. Sub-articles (조의N in Korean, e.g., 제23조의2) use a trailing `-N` suffix: `NIA-23-2`, `PIPA-24-2`. This matches the existing PIPA convention.

## Merge Behavior

When loading multiple YAML files, `NewRegistry` merges all entries into one registry. Files are loaded in lexicographic order by filename. The order of entries in `All()` reflects file load order, then entry order within each file. If duplicate IDs are found across files, `NewRegistry` must return an error. Silent overwrites are not acceptable — a duplicate ID indicates a data authoring mistake.

## Testing

- Update `TestNewRegistry_FromFile` in `registry_test.go` to point to `laws/pipa.yaml` (the old `laws.yaml` path no longer exists after migration)
- Existing `TestNewRegistry_Embedded` and lookup tests must pass against the merged multi-file registry
- Add a test that verifies all 4 YAML files load and the total article count equals 39
- Add a test that verifies duplicate IDs across files produce an error

## External Override

The `--laws` flag (and `yamlPath` parameter) continues to accept a single external YAML file. Directory-based external override is explicitly out of scope — only single-file external loading is supported.

## What This Does NOT Include

- No new detectors — detectors will be added in a future iteration
- No changes to the MCP server, CLI, or report format
- No changes to the Law struct
