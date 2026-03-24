package law_test

import (
	"os"
	"testing"

	"github.com/rostradamus/klaws/internal/law"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry_LoadsEmbedded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	all := reg.All()
	assert.GreaterOrEqual(t, len(all), 10, "should load at least 10 law provisions")
}

func TestRegistry_Lookup(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("PIPA-29")
	require.NoError(t, err)
	assert.Equal(t, "PIPA-29", l.ID)
	assert.Contains(t, l.NameEn, "Safety Measures")
	assert.Equal(t, "HIGH", l.RiskLevel)
}

func TestRegistry_Lookup_NotFound(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	_, err = reg.Lookup("NONEXISTENT")
	assert.Error(t, err)
}

func TestNewRegistry_FromFile(t *testing.T) {
	reg, err := law.NewRegistry("laws/pipa.yaml")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(reg.All()), 10)
}

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

func TestNewRegistry_NetworkActLoaded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("NIA-22")
	require.NoError(t, err)
	assert.Equal(t, "NIA-22", l.ID)
	assert.Contains(t, l.NameKo, "정보통신망")
}

func TestNewRegistry_CreditInfoActLoaded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("CIA-32")
	require.NoError(t, err)
	assert.Equal(t, "CIA-32", l.ID)
	assert.Contains(t, l.NameKo, "신용정보")
}

func TestNewRegistry_EcommerceActLoaded(t *testing.T) {
	reg, err := law.NewRegistry("")
	require.NoError(t, err)

	l, err := reg.Lookup("ECA-21")
	require.NoError(t, err)
	assert.Equal(t, "ECA-21", l.ID)
	assert.Contains(t, l.NameKo, "전자상거래")
}

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
