package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeSetAndGet(t *testing.T) {
	s := newScopeStack()
	s.set("ssn", taint{Source: SourceRule{ID: "ssn"}})

	got, ok := s.get("ssn")
	assert.True(t, ok)
	assert.Equal(t, "ssn", got.Source.ID)
}

func TestScopeInnerSeesOuter(t *testing.T) {
	s := newScopeStack()
	s.set("ssn", taint{Source: SourceRule{ID: "ssn"}})
	s.push()

	_, ok := s.get("ssn")
	assert.True(t, ok, "inner scope must see outer taint")
}

func TestScopeTaintDoesNotEscapeClosedScope(t *testing.T) {
	s := newScopeStack()
	s.push()
	s.set("ssn", taint{Source: SourceRule{ID: "ssn"}})
	s.pop()

	_, ok := s.get("ssn")
	assert.False(t, ok, "taint must not survive its scope — this is the anti-false-positive guarantee")
}

func TestScopeShadowing(t *testing.T) {
	s := newScopeStack()
	s.set("x", taint{Source: SourceRule{ID: "ssn"}})
	s.push()
	s.set("x", taint{Source: SourceRule{ID: "email"}})

	got, _ := s.get("x")
	assert.Equal(t, "email", got.Source.ID, "inner declaration shadows outer")

	s.pop()
	got, _ = s.get("x")
	assert.Equal(t, "ssn", got.Source.ID, "outer taint reappears after inner scope closes")
}

func TestScopeClearRemovesNearestBinding(t *testing.T) {
	s := newScopeStack()
	s.set("x", taint{Source: SourceRule{ID: "ssn"}})
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

	s.set("x", taint{Source: SourceRule{ID: "ssn"}})
	_, ok := s.get("x")
	assert.True(t, ok, "stack must remain usable after over-popping")
}
