// Package flow performs intra-file taint analysis on Java source: it traces
// personal data from where it enters a file to where it leaks.
//
// The package is deliberately free of any dependency on detectors, laws, or
// reports. Analyze is its entire public surface, so the lexer can be replaced
// without affecting consumers.
package flow

import "strings"

// Kind classifies a hop in a trace.
type Kind int

const (
	KindSource Kind = iota
	KindPropagate
	KindSink
)

// Hop is one step along a trace, anchored to a source line.
type Hop struct {
	Line       int
	Expression string
	Kind       Kind
	Note       string
}

// Trace is a complete path from a personal-data source to a sink.
type Trace struct {
	Source SourceRule
	Sink   SinkRule
	Hops   []Hop // ordered: source first, sink last
}

// Options tunes an analysis. The zero value is valid and uses the defaults.
type Options struct {
	MaxHops    int  // longest propagation chain to follow
	MaxTokens  int  // files larger than this are skipped
	IsTestFile bool // suppresses storage findings on test fixtures
}

const (
	DefaultMaxHops   = 10
	DefaultMaxTokens = 200000
)

// Analyze returns every taint trace in src. It never returns an error and never
// panics: malformed Java is normal input and simply yields no traces.
func Analyze(src string, opts Options) []Trace {
	if opts.MaxHops <= 0 {
		opts.MaxHops = DefaultMaxHops
	}
	if opts.MaxTokens <= 0 {
		opts.MaxTokens = DefaultMaxTokens
	}

	toks := Lex(src)
	if len(toks) == 0 || len(toks) > opts.MaxTokens {
		return nil
	}

	a := &analyzer{
		toks:   toks,
		lines:  strings.Split(src, "\n"),
		scopes: newScopeStack(),
		opts:   opts,
	}
	a.walk()
	return dedupeTraces(a.traces)
}
