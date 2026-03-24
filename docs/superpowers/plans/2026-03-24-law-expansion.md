# Law Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the law reference database from 10 PIPA articles to 39 articles across 4 Korean laws, splitting the single `laws.yaml` into per-law YAML files.

**Architecture:** Move `laws.yaml` into `internal/law/laws/` directory as `pipa.yaml`. Add 3 new YAML files for Network Act, Credit Information Act, and E-Commerce Act. Update `registry.go` to load all `*.yaml` files from the embedded directory and merge them with duplicate ID detection.

**Tech Stack:** Go 1.23, go:embed, fs.Glob, gopkg.in/yaml.v3

**Spec:** `docs/superpowers/specs/2026-03-24-law-expansion-design.md`

---

### Task 1: Move laws.yaml to laws/pipa.yaml

**Files:**
- Move: `internal/law/laws.yaml` → `internal/law/laws/pipa.yaml`
- Delete: `internal/law/laws.yaml`

- [ ] **Step 1: Create the laws/ directory and move the file**

```bash
mkdir -p internal/law/laws
mv internal/law/laws.yaml internal/law/laws/pipa.yaml
```

- [ ] **Step 2: Verify the file is in place**

Run: `head -3 internal/law/laws/pipa.yaml`
Expected: `laws:` header followed by first PIPA entry

- [ ] **Step 3: Commit**

```bash
git add internal/law/laws/pipa.yaml
git rm internal/law/laws.yaml
git commit -m "refactor: move laws.yaml to laws/pipa.yaml"
```

---

### Task 2: Update registry.go to load multiple YAML files

**Files:**
- Modify: `internal/law/registry.go`

- [ ] **Step 1: Write failing test — embedded registry loads from new directory**

The existing `TestNewRegistry_LoadsEmbedded` test will fail because the embed directive still points to `laws.yaml`. This is the expected failure that drives the code change.

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_LoadsEmbedded -v`
Expected: FAIL (embed file not found)

- [ ] **Step 2: Update embed directive and NewRegistry to load multiple files**

Replace the contents of `registry.go` with:

```go
package law

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed laws/*.yaml
var embeddedLaws embed.FS

// Registry implements LawRegistry
type Registry struct {
	laws []Law
	byID map[string]Law
}

// NewRegistry loads from a YAML file path. Pass "" to use embedded laws/ directory.
func NewRegistry(yamlPath string) (*Registry, error) {
	if yamlPath != "" {
		return loadFromFile(yamlPath)
	}
	return loadFromEmbedded()
}

func loadFromFile(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading laws file: %w", err)
	}

	var file lawsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing laws YAML: %w", err)
	}

	return buildRegistry(file.Laws)
}

func loadFromEmbedded() (*Registry, error) {
	matches, err := fs.Glob(embeddedLaws, "laws/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("globbing embedded laws: %w", err)
	}
	sort.Strings(matches)

	var allLaws []Law
	for _, match := range matches {
		data, err := embeddedLaws.ReadFile(match)
		if err != nil {
			return nil, fmt.Errorf("reading embedded %s: %w", match, err)
		}

		var file lawsFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", match, err)
		}
		allLaws = append(allLaws, file.Laws...)
	}

	return buildRegistry(allLaws)
}

func buildRegistry(laws []Law) (*Registry, error) {
	byID := make(map[string]Law, len(laws))
	for _, l := range laws {
		if _, exists := byID[l.ID]; exists {
			return nil, fmt.Errorf("duplicate law ID: %s", l.ID)
		}
		byID[l.ID] = l
	}
	return &Registry{laws: laws, byID: byID}, nil
}

func (r *Registry) Lookup(id string) (Law, error) {
	l, ok := r.byID[id]
	if !ok {
		return Law{}, fmt.Errorf("law not found: %s", id)
	}
	return l, nil
}

func (r *Registry) All() []Law {
	return r.laws
}

func (r *Registry) LookupLive(id string) (Law, error) {
	l, err := r.Lookup(id)
	if err != nil {
		return Law{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := NewDefaultClient()
	text, fetchErr := client.FetchArticle(ctx, l.NameKo)
	if fetchErr != nil {
		// Fallback to bundled data without full text
		return l, nil
	}

	l.FullText = text
	return l, nil
}
```

- [ ] **Step 3: Run existing tests to verify they pass**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run "TestNewRegistry_LoadsEmbedded|TestRegistry_Lookup" -v`
Expected: PASS

- [ ] **Step 4: Update TestNewRegistry_FromFile to use new path**

Update the test in `internal/law/registry_test.go`:

```go
func TestNewRegistry_FromFile(t *testing.T) {
	reg, err := law.NewRegistry("laws/pipa.yaml")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(reg.All()), 10)
}
```

- [ ] **Step 5: Run all law tests**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/law/registry.go internal/law/registry_test.go
git commit -m "refactor: load laws from multiple embedded YAML files"
```

---

### Task 3: Add duplicate ID detection test

**Files:**
- Modify: `internal/law/registry_test.go`

- [ ] **Step 1: Write test for duplicate ID detection**

Add to `internal/law/registry_test.go`:

```go
func TestNewRegistry_DuplicateID(t *testing.T) {
	content := []byte(`laws:
  - id: "DUPE-1"
    name_ko: "first"
    name_en: "first"
    summary: "first"
    url: "http://example.com"
    risk_level: "HIGH"
  - id: "DUPE-1"
    name_ko: "second"
    name_en: "second"
    summary: "second"
    url: "http://example.com"
    risk_level: "HIGH"
`)
	tmpFile := t.TempDir() + "/dup.yaml"
	err := os.WriteFile(tmpFile, content, 0644)
	require.NoError(t, err)

	_, err = law.NewRegistry(tmpFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate law ID: DUPE-1")
}
```

Add `"os"` to the imports.

- [ ] **Step 2: Run the test**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_DuplicateID -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/law/registry_test.go
git commit -m "test: add duplicate ID detection test"
```

---

### Task 4: Add network-act.yaml (정보통신망법)

**Files:**
- Create: `internal/law/laws/network-act.yaml`

- [ ] **Step 1: Write the test first**

Add to `internal/law/registry_test.go`:

```go
func TestNewRegistry_NetworkActLoaded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("NIA-22")
	require.NoError(t, err)
	assert.Equal(t, "NIA-22", l.ID)
	assert.Contains(t, l.NameKo, "정보통신망")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_NetworkActLoaded -v`
Expected: FAIL — "law not found: NIA-22"

- [ ] **Step 3: Create network-act.yaml**

Create `internal/law/laws/network-act.yaml` with 10 entries (NIA-22, NIA-23, NIA-23-2, NIA-24, NIA-24-2, NIA-27, NIA-28, NIA-28-2, NIA-44, NIA-44-7).

Each entry must include: `id`, `name_ko`, `name_en`, `summary`, `url`, `risk_level`, `full_text_ko`.

- Use the full law name: "정보통신망 이용촉진 및 정보보호 등에 관한 법률"
- URL pattern: `https://www.law.go.kr/법령/정보통신망이용촉진및정보보호등에관한법률/제{N}조`
- Source `full_text_ko` from law.go.kr
- Use hedged language in summaries

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_NetworkActLoaded -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/law/laws/network-act.yaml internal/law/registry_test.go
git commit -m "feat: add Network Act (정보통신망법) law entries"
```

---

### Task 5: Add credit-info-act.yaml (신용정보법)

**Files:**
- Create: `internal/law/laws/credit-info-act.yaml`

- [ ] **Step 1: Write the test first**

Add to `internal/law/registry_test.go`:

```go
func TestNewRegistry_CreditInfoActLoaded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("CIA-32")
	require.NoError(t, err)
	assert.Equal(t, "CIA-32", l.ID)
	assert.Contains(t, l.NameKo, "신용정보")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_CreditInfoActLoaded -v`
Expected: FAIL — "law not found: CIA-32"

- [ ] **Step 3: Create credit-info-act.yaml**

Create `internal/law/laws/credit-info-act.yaml` with 10 entries (CIA-15, CIA-17, CIA-19, CIA-20, CIA-32, CIA-33, CIA-34, CIA-38, CIA-39, CIA-40).

- Full law name: "신용정보의 이용 및 보호에 관한 법률"
- URL pattern: `https://www.law.go.kr/법령/신용정보의이용및보호에관한법률/제{N}조`
- Source `full_text_ko` from law.go.kr
- Use hedged language in summaries

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_CreditInfoActLoaded -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/law/laws/credit-info-act.yaml internal/law/registry_test.go
git commit -m "feat: add Credit Information Act (신용정보법) law entries"
```

---

### Task 6: Add ecommerce-act.yaml (전자상거래법)

**Files:**
- Create: `internal/law/laws/ecommerce-act.yaml`

- [ ] **Step 1: Write the test first**

Add to `internal/law/registry_test.go`:

```go
func TestNewRegistry_EcommerceActLoaded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("ECA-21")
	require.NoError(t, err)
	assert.Equal(t, "ECA-21", l.ID)
	assert.Contains(t, l.NameKo, "전자상거래")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_EcommerceActLoaded -v`
Expected: FAIL — "law not found: ECA-21"

- [ ] **Step 3: Create ecommerce-act.yaml**

Create `internal/law/laws/ecommerce-act.yaml` with 9 entries (ECA-6, ECA-7, ECA-11, ECA-13, ECA-14, ECA-17, ECA-21, ECA-24, ECA-26).

- Full law name: "전자상거래 등에서의 소비자보호에 관한 법률"
- URL pattern: `https://www.law.go.kr/법령/전자상거래등에서의소비자보호에관한법률/제{N}조`
- Source `full_text_ko` from law.go.kr
- Use hedged language in summaries

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run TestNewRegistry_EcommerceActLoaded -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/law/laws/ecommerce-act.yaml internal/law/registry_test.go
git commit -m "feat: add E-Commerce Act (전자상거래법) law entries"
```

---

### Task 7: Add total count and full integration test

**Files:**
- Modify: `internal/law/registry_test.go`

- [ ] **Step 1: Write the total count test**

Add to `internal/law/registry_test.go`:

```go
func TestNewRegistry_TotalArticleCount(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	all := reg.All()
	assert.Equal(t, 39, len(all), "should have exactly 39 law entries across 4 laws")
}

func TestNewRegistry_NoDuplicateIDs(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	seen := make(map[string]bool)
	for _, l := range reg.All() {
		assert.False(t, seen[l.ID], "duplicate ID found: %s", l.ID)
		seen[l.ID] = true
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /Users/rostradamus/repos/klaws && go test ./internal/law/ -run "TestNewRegistry_TotalArticleCount|TestNewRegistry_NoDuplicateIDs" -v`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/rostradamus/repos/klaws && go test ./... -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add internal/law/registry_test.go
git commit -m "test: add total count and no-duplicate integration tests"
```

---

### Task 8: Update README and docs

**Files:**
- Modify: `README.md`
- Modify: `README.ko.md`
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update the Bundled Law Provisions section in README.md**

Add the new laws to the table in the "Bundled Law Provisions" section. Update the count from 10 PIPA articles to 39 articles across 4 laws.

- [ ] **Step 2: Update the same section in README.ko.md**

Mirror the changes in Korean.

- [ ] **Step 3: Update docs/roadmap.md**

Mark "정보통신망법 (Network Act) provisions", "신용정보법 (Credit Information Act) provisions" as done. Add 전자상거래법 completion.

- [ ] **Step 4: Commit**

```bash
git add README.md README.ko.md docs/roadmap.md
git commit -m "docs: update README and roadmap for multi-law support"
```
