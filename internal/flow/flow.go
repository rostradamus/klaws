// Package flow performs intra-file taint analysis on Java source: it traces
// personal data from where it enters a file to where it leaks.
//
// The package is deliberately free of any dependency on detectors, laws, or
// reports. Analyze is its entire public surface, so the lexer can be replaced
// without affecting consumers.
package flow

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
