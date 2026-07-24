package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func one(id string) []taint {
	return []taint{{Source: SourceRule{ID: id}}}
}

func TestScopeSetAndGet(t *testing.T) {
	s := newScopeStack()
	s.set("ssn", one("ssn"))

	got, ok := s.get("ssn")
	assert.True(t, ok)
	require.Len(t, got, 1)
	assert.Equal(t, "ssn", got[0].Source.ID)
}

func TestScopeBindsMultipleTaints(t *testing.T) {
	s := newScopeStack()
	s.set("msg", []taint{
		{Source: SourceRule{ID: "email"}},
		{Source: SourceRule{ID: "ssn"}},
	})

	got, ok := s.get("msg")
	assert.True(t, ok)
	require.Len(t, got, 2, "a symbol may carry several sources at once")
	assert.Equal(t, "email", got[0].Source.ID)
	assert.Equal(t, "ssn", got[1].Source.ID)
}

func TestScopeInnerSeesOuter(t *testing.T) {
	s := newScopeStack()
	s.set("ssn", one("ssn"))
	s.push()

	_, ok := s.get("ssn")
	assert.True(t, ok, "inner scope must see outer taint")
}

func TestScopeTaintDoesNotEscapeClosedScope(t *testing.T) {
	s := newScopeStack()
	s.push()
	s.set("ssn", one("ssn"))
	s.pop()

	_, ok := s.get("ssn")
	assert.False(t, ok, "taint must not survive its scope — this is the anti-false-positive guarantee")
}

func TestScopeShadowing(t *testing.T) {
	s := newScopeStack()
	s.set("x", one("ssn"))
	s.push()
	s.set("x", one("email"))

	got, _ := s.get("x")
	require.Len(t, got, 1)
	assert.Equal(t, "email", got[0].Source.ID, "inner declaration shadows outer")

	s.pop()
	got, _ = s.get("x")
	require.Len(t, got, 1)
	assert.Equal(t, "ssn", got[0].Source.ID, "outer taint reappears after inner scope closes")
}

func TestScopeClearRemovesNearestBinding(t *testing.T) {
	s := newScopeStack()
	s.set("x", one("ssn"))
	s.clear("x")

	_, ok := s.get("x")
	assert.False(t, ok)
}

func TestScopeUnbalancedPopDegradesGracefully(t *testing.T) {
	s := newScopeStack()

	assert.NotPanics(t, func() {
		for i := 0; i < 10; i++ {
			s.pop()
		}
	}, "unbalanced braces must degrade, not panic")

	s.set("x", one("ssn"))
	_, ok := s.get("x")
	assert.True(t, ok, "stack must remain usable after over-popping")
}
