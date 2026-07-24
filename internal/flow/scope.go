package flow

// taint is what a scope binds a symbol to: which source seeded it and how it
// travelled to get here. A symbol can carry several taints at once, because an
// expression may combine more than one distinct source — `msg = email + ssn`
// binds both to msg, so a later `log.info(msg)` reports each of them.
type taint struct {
	Source SourceRule
	Hops   []Hop
}

// scopeStack tracks tainted symbols per brace-depth frame. Correct shadowing is
// the property regex detectors fundamentally cannot provide.
type scopeStack struct {
	frames []map[string][]taint
}

func newScopeStack() *scopeStack {
	return &scopeStack{frames: []map[string][]taint{{}}}
}

func (s *scopeStack) push() {
	s.frames = append(s.frames, map[string][]taint{})
}

// pop never removes the final frame, so unbalanced braces degrade to a flatter
// scope rather than crashing the scan.
func (s *scopeStack) pop() {
	if len(s.frames) > 1 {
		s.frames = s.frames[:len(s.frames)-1]
	}
}

// set binds name to the given taints, replacing any prior binding — an
// assignment overwrites whatever the symbol previously carried.
func (s *scopeStack) set(name string, ts []taint) {
	s.frames[len(s.frames)-1][name] = ts
}

// get returns every taint bound to the nearest binding for name.
func (s *scopeStack) get(name string) ([]taint, bool) {
	for i := len(s.frames) - 1; i >= 0; i-- {
		if t, ok := s.frames[i][name]; ok {
			return t, true
		}
	}
	return nil, false
}

// clear removes the nearest binding for name, used when a symbol is reassigned
// from a clean value or passed through a sanitizer.
func (s *scopeStack) clear(name string) {
	for i := len(s.frames) - 1; i >= 0; i-- {
		if _, ok := s.frames[i][name]; ok {
			delete(s.frames[i], name)
			return
		}
	}
}

// cloneHops copies a hop slice so appending to one trace never mutates another
// that shares a prefix.
func cloneHops(hops []Hop) []Hop {
	out := make([]Hop, len(hops))
	copy(out, hops)
	return out
}
