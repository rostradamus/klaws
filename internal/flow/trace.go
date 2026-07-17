package flow

import "strings"

type analyzer struct {
	toks   []Token
	lines  []string
	scopes *scopeStack
	opts   Options
	traces []Trace
}

// lineText returns the trimmed source text of a 1-indexed line.
func (a *analyzer) lineText(line int) string {
	if line < 1 || line > len(a.lines) {
		return ""
	}
	return strings.TrimSpace(a.lines[line-1])
}

// walk splits the token stream into statements on ';', '{' and '}', maintaining
// the scope stack as braces open and close.
func (a *analyzer) walk() {
	start := 0
	for i, tok := range a.toks {
		if tok.Kind != TokenPunct {
			continue
		}
		switch tok.Text {
		case ";":
			a.statement(a.toks[start:i])
			start = i + 1
		case "{":
			seg := a.toks[start:i]
			a.scopes.push()
			a.params(seg) // parameters belong to the scope the brace opens
			start = i + 1
		case "}":
			a.statement(a.toks[start:i])
			a.scopes.pop()
			start = i + 1
		}
	}
}

// params taints parameter names that match a source rule. A parameter taints
// only by NAME: `void f(String ssn)` taints ssn, `void f(UserDto user)` taints
// nothing — tainting by declared type would require type resolution, which is
// an explicit non-goal.
func (a *analyzer) params(seg []Token) {
	open := indexPunct(seg, "(")
	if open < 0 {
		return
	}
	close := lastIndexPunct(seg, ")")
	if close <= open {
		return
	}

	inner := seg[open+1 : close]
	for i := 1; i < len(inner); i++ {
		prev, cur := inner[i-1], inner[i]
		// A parameter is `Type name`: two adjacent identifiers.
		if prev.Kind != TokenIdent || cur.Kind != TokenIdent {
			continue
		}
		rule, ok := MatchSource(cur.Text)
		if !ok {
			continue
		}
		a.scopes.set(cur.Text, taint{
			Source: rule,
			Hops: []Hop{{
				Line:       cur.Line,
				Expression: a.lineText(cur.Line),
				Kind:       KindSource,
				Note:       "source: " + rule.Label + " (parameter)",
			}},
		})
	}
}

// statement processes one statement: first any assignment, then any sink.
// A statement can be both, as in `String r = restTemplate.post(ssn);`.
func (a *analyzer) statement(seg []Token) {
	if len(seg) == 0 {
		return
	}
	if eq := topLevelAssign(seg); eq > 0 {
		a.assign(lhsName(seg[:eq]), seg[eq+1:])
	}
	a.checkSink(seg)
}

// assign updates the taint bound to lhs based on the right-hand side. A
// sanitizer only clears the operand it covers (per sanitizedIndices) — it
// does not blanket-clear the whole RHS, so an unsanitized tainted operand
// elsewhere on the RHS still taints lhs.
func (a *analyzer) assign(lhs string, rhs []Token) {
	if lhs == "" || len(rhs) == 0 {
		return
	}

	sanitized := sanitizedIndices(rhs)

	// Propagate from an already-tainted symbol, ignoring any occurrence that
	// falls inside a sanitizer's span.
	for i, tok := range rhs {
		if tok.Kind != TokenIdent || sanitized[i] {
			continue
		}
		existing, ok := a.scopes.get(tok.Text)
		if !ok {
			continue
		}
		hops := append(cloneHops(existing.Hops), Hop{
			Line:       tok.Line,
			Expression: a.lineText(tok.Line),
			Kind:       KindPropagate,
			Note:       propagateNote(rhs),
		})
		if len(hops) > a.opts.MaxHops {
			a.scopes.clear(lhs)
			return
		}
		a.scopes.set(lhs, taint{Source: existing.Source, Hops: hops})
		return
	}

	// Seed a new source from the RHS: `user.getSsn()` or `dto.ssn`, ignoring
	// any occurrence that falls inside a sanitizer's span.
	for i, tok := range rhs {
		if tok.Kind != TokenIdent || sanitized[i] {
			continue
		}
		if rule, ok := MatchSource(tok.Text); ok {
			a.scopes.set(lhs, taint{Source: rule, Hops: []Hop{{
				Line:       tok.Line,
				Expression: a.lineText(tok.Line),
				Kind:       KindSource,
				Note:       "source: " + rule.Label,
			}}})
			return
		}
	}

	// No unsanitized tainted symbol and no unsanitized source identifier on
	// the RHS, so any prior taint on lhs is gone.
	a.scopes.clear(lhs)
}

// checkSink emits a trace for every distinct tainted source that reaches a
// dangerous destination. It processes every sink call found in the
// statement — not just the first — so a statement with multiple sink calls
// (or a single call with multiple tainted arguments) reports every one of
// them, rather than stopping at the first match and silently dropping the
// rest (which may be the higher-risk source).
func (a *analyzer) checkSink(seg []Token) {
	for _, call := range findCalls(seg) {
		rule, ok := MatchSink(call.text)
		if !ok {
			continue
		}
		if rule.Kind == SinkPersist && a.opts.IsTestFile {
			continue
		}

		args := seg[call.argStart:call.argEnd]
		sanitized := sanitizedIndices(args)

		// seen dedupes by identifier token text within this one sink call:
		// `log.info(ssn, ssn)` must yield one trace, not two, and an
		// identifier already claimed by the tainted-symbol path must not
		// also be reported by the direct-source path.
		seen := make(map[string]bool)
		a.emitFromTaintedArg(args, sanitized, rule, seen)
		a.emitFromDirectSource(args, sanitized, rule, seen)
	}
}

// sanitizedIndices marks which token indices within args are covered by a
// sanitizer call. A sanitizer clears only the value it covers: in
// `log.info(s + encrypt(other))`, only `other` is marked, so the unwrapped
// sibling `s` is still reported. Blanket-suppressing the whole call whenever
// any sanitizer appears anywhere in the argument list — regardless of what it
// covers — would silently drop that finding.
//
// A sanitizer covers two things: the tokens inside its own parentheses (the
// WRAP form, `encrypt(s)`) and the receiver chain it is invoked on (the
// RECEIVER form, `s.mask()` or `user.getSsn().mask()`), since fluent-style
// sanitizing is invoked ON the tainted value rather than wrapped around it.
func sanitizedIndices(args []Token) []bool {
	marks := make([]bool, len(args))
	for _, call := range findCalls(args) {
		if !IsSanitizer(call.text) {
			continue
		}
		end := call.argEnd
		if end > len(args) {
			end = len(args)
		}

		// The receiver chain (if any) starts at or before call.argStart-1,
		// the index of the sanitizer's own '('. Marking from there through
		// end covers both the WRAP span and the RECEIVER span in one pass.
		start := call.argStart
		if parenIdx := call.argStart - 1; parenIdx >= 0 && parenIdx < len(args) {
			if s := receiverChainStart(args, parenIdx); s >= 0 && s < start {
				start = s
			}
		}
		if start < 0 {
			start = 0
		}
		for i := start; i < end; i++ {
			marks[i] = true
		}
	}
	return marks
}

// receiverChainStart walks backward from just before a sanitizer call's own
// '(' (at args[parenIdx]) over the dotted receiver chain that precedes it —
// e.g. the `user.getSsn()` in `user.getSsn().mask()`. It stops at a '+', a
// ',', an unmatched '(', or the start of args, and returns the index at
// which the receiver chain begins. It returns parenIdx (an empty span) if
// there is no receiver chain to include.
func receiverChainStart(args []Token, parenIdx int) int {
	i := parenIdx - 1
	for i >= 0 {
		tok := args[i]
		if tok.Kind == TokenIdent || (tok.Kind == TokenPunct && tok.Text == ".") {
			i--
			continue
		}
		if tok.Kind == TokenPunct && tok.Text == ")" {
			open := matchingParenBackward(args, i)
			if open < 0 {
				break // malformed/unbalanced: stop without jumping
			}
			i = open - 1
			continue
		}
		break // '+', ',', an unmatched '(', or anything else ends the chain
	}
	return i + 1
}

// emitFromTaintedArg reports every tainted symbol passed to a sink.
// Identifiers wrapped by a sanitizer call (per sanitized) are skipped. An
// identifier bound in scope is claimed for seen (added to it) as soon as
// it's found tainted, even if its hop chain exceeds MaxHops and is thereby
// skipped from emission — it is a scoped variable, not a bare source
// expression, so emitFromDirectSource must not also consider it.
func (a *analyzer) emitFromTaintedArg(args []Token, sanitized []bool, rule SinkRule, seen map[string]bool) {
	for i, tok := range args {
		if tok.Kind != TokenIdent || sanitized[i] || seen[tok.Text] {
			continue
		}
		existing, ok := a.scopes.get(tok.Text)
		if !ok {
			continue
		}
		seen[tok.Text] = true
		hops := append(cloneHops(existing.Hops), Hop{
			Line:       tok.Line,
			Expression: a.lineText(tok.Line),
			Kind:       KindSink,
			Note:       "sink: " + rule.Label,
		})
		if len(hops) > a.opts.MaxHops {
			continue
		}
		a.traces = append(a.traces, Trace{Source: existing.Source, Sink: rule, Hops: hops})
	}
}

// emitFromDirectSource reports every `log.info(user.getSsn())` — a source that
// reaches a sink without ever being bound to a variable. Identifiers wrapped
// by a sanitizer call (per sanitized), or already claimed by
// emitFromTaintedArg (per seen), are skipped.
func (a *analyzer) emitFromDirectSource(args []Token, sanitized []bool, rule SinkRule, seen map[string]bool) {
	for i, tok := range args {
		if tok.Kind != TokenIdent || sanitized[i] || seen[tok.Text] {
			continue
		}
		src, ok := MatchSource(tok.Text)
		if !ok {
			continue
		}
		seen[tok.Text] = true
		a.traces = append(a.traces, Trace{Source: src, Sink: rule, Hops: []Hop{
			{Line: tok.Line, Expression: a.lineText(tok.Line), Kind: KindSource, Note: "source: " + src.Label},
			{Line: tok.Line, Expression: a.lineText(tok.Line), Kind: KindSink, Note: "sink: " + rule.Label},
		}})
	}
}

// propagateNote describes how data moved, for the trace display.
func propagateNote(rhs []Token) string {
	for _, tok := range rhs {
		if tok.Kind == TokenPunct && tok.Text == "+" {
			return "propagates via concat"
		}
	}
	for _, tok := range rhs {
		if tok.Kind != TokenIdent {
			continue
		}
		switch tok.Text {
		case "format":
			return "propagates via String.format"
		case "append":
			return "propagates via StringBuilder"
		}
	}
	return "propagates via assignment"
}

type call struct {
	text     string // dotted chain, e.g. "log.info"
	argStart int    // index just past '('
	argEnd   int    // index of the matching ')'
}

// findCalls extracts every `a.b.c(` chain in a statement. Each call's argument
// span is bounded to its own matching parenthesis, so a sink call's arguments
// never spill into a sibling call's arguments or code that follows the call —
// e.g. in `compute(repository.save(clean), s)`, `s` must not be attributed to
// repository.save, and in `log.info(s + encrypt(other))`, a sanitizer applied
// to `other` must not suppress the unsanitized use of `s`.
func findCalls(seg []Token) []call {
	var calls []call
	for i := 0; i < len(seg); i++ {
		if seg[i].Kind != TokenPunct || seg[i].Text != "(" {
			continue
		}
		// Walk backwards over the dotted chain preceding '('.
		end := i
		j := i - 1
		for j >= 0 && (seg[j].Kind == TokenIdent || (seg[j].Kind == TokenPunct && seg[j].Text == ".")) {
			j--
		}
		if j+1 >= end {
			continue
		}
		close := matchingParen(seg, i)
		if close < 0 {
			close = len(seg) // unbalanced parens: fall back to end of segment
		}
		var sb strings.Builder
		for _, tok := range seg[j+1 : end] {
			sb.WriteString(tok.Text)
		}
		if sb.Len() > 0 {
			calls = append(calls, call{text: sb.String(), argStart: i + 1, argEnd: close})
		}
	}
	return calls
}

// matchingParen returns the index of the ')' that closes the '(' at seg[open],
// or -1 if the parens never balance (malformed/truncated input).
func matchingParen(seg []Token, open int) int {
	depth := 0
	for i := open; i < len(seg); i++ {
		if seg[i].Kind != TokenPunct {
			continue
		}
		switch seg[i].Text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// matchingParenBackward returns the index of the '(' that opens the ')' at
// seg[close], scanning leftward, or -1 if the parens never balance
// (malformed/truncated input). It mirrors matchingParen but walks backward,
// for chasing a receiver chain like `foo(bar).mask()` right-to-left.
func matchingParenBackward(seg []Token, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		if seg[i].Kind != TokenPunct {
			continue
		}
		switch seg[i].Text {
		case ")":
			depth++
		case "(":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// topLevelAssign returns the index of the statement's '=' when it is a plain
// assignment, or -1. It ignores '==', '!=', '<=', '>=' and anything inside
// parentheses, so `if (a == b)` and `f(x = 1)` are not treated as assignments.
func topLevelAssign(seg []Token) int {
	depth := 0
	for i, tok := range seg {
		if tok.Kind != TokenPunct {
			continue
		}
		switch tok.Text {
		case "(", "[":
			depth++
		case ")", "]":
			depth--
		case "=":
			if depth != 0 {
				continue
			}
			if i > 0 && seg[i-1].Kind == TokenPunct &&
				(seg[i-1].Text == "=" || seg[i-1].Text == "!" || seg[i-1].Text == "<" ||
					seg[i-1].Text == ">" || seg[i-1].Text == "+" || seg[i-1].Text == "-") {
				continue
			}
			if i+1 < len(seg) && seg[i+1].Kind == TokenPunct && seg[i+1].Text == "=" {
				continue // this is the first '=' of '=='
			}
			return i
		}
	}
	return -1
}

// lhsName returns the assigned symbol: the last identifier before '='. This
// handles both `String s` (declaration) and `s` (reassignment).
func lhsName(lhs []Token) string {
	for i := len(lhs) - 1; i >= 0; i-- {
		if lhs[i].Kind == TokenIdent {
			return lhs[i].Text
		}
	}
	return ""
}

func indexPunct(seg []Token, text string) int {
	for i, tok := range seg {
		if tok.Kind == TokenPunct && tok.Text == text {
			return i
		}
	}
	return -1
}

func lastIndexPunct(seg []Token, text string) int {
	for i := len(seg) - 1; i >= 0; i-- {
		if seg[i].Kind == TokenPunct && seg[i].Text == text {
			return i
		}
	}
	return -1
}
