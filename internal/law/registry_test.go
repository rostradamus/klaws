package law_test

import (
	"testing"

	"github.com/rostradamus/dev-lawyer/internal/law"
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
	reg, err := law.NewRegistry("laws.yaml")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(reg.All()), 10)
}
