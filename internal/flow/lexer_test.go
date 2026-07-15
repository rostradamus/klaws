package flow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLexIdentifiersAndPunctuation(t *testing.T) {
	toks := Lex(`String s = user.getSsn();`)

	require.Len(t, toks, 9)
	assert.Equal(t, Token{Kind: TokenIdent, Text: "String", Line: 1}, toks[0])
	assert.Equal(t, Token{Kind: TokenIdent, Text: "s", Line: 1}, toks[1])
	assert.Equal(t, Token{Kind: TokenPunct, Text: "=", Line: 1}, toks[2])
	assert.Equal(t, Token{Kind: TokenIdent, Text: "user", Line: 1}, toks[3])
	assert.Equal(t, Token{Kind: TokenPunct, Text: ".", Line: 1}, toks[4])
	assert.Equal(t, Token{Kind: TokenIdent, Text: "getSsn", Line: 1}, toks[5])
}

func TestLexStringLiteralIsNotAnIdentifier(t *testing.T) {
	toks := Lex(`log.info("user ssn field");`)

	for _, tok := range toks {
		if tok.Text == "user ssn field" {
			assert.Equal(t, TokenString, tok.Kind, "string literal must never lex as an identifier")
			return
		}
	}
	t.Fatal("string literal token not found")
}

func TestLexDiscardsComments(t *testing.T) {
	src := "// ssn comment\nString a = 1; /* block ssn\n spanning lines */ String b = 2;"
	toks := Lex(src)

	for _, tok := range toks {
		assert.NotContains(t, tok.Text, "comment")
		assert.NotContains(t, tok.Text, "spanning")
	}
}

func TestLexTracksLineNumbersAcrossComments(t *testing.T) {
	src := "String a = 1;\n/* two\nline */\nString b = 2;"
	toks := Lex(src)

	last := toks[len(toks)-1]
	assert.Equal(t, 4, last.Line, "line count must survive multi-line block comments")
}

func TestLexKoreanIdentifiers(t *testing.T) {
	toks := Lex(`String 주민등록번호 = x;`)

	require.GreaterOrEqual(t, len(toks), 2)
	assert.Equal(t, TokenIdent, toks[1].Kind)
	assert.Equal(t, "주민등록번호", toks[1].Text)
}

func TestLexMalformedInputDoesNotPanic(t *testing.T) {
	cases := []string{
		``,
		`"unterminated`,
		`/* unterminated`,
		`}}}{{{`,
		"\x00\xff binary",
		`'a`,
	}
	for _, src := range cases {
		assert.NotPanics(t, func() { Lex(src) }, "input: %q", src)
	}
}

func TestLexCharLiteralTracksNewlines(t *testing.T) {
	// The stray, unterminated char literal opened on line 1 doesn't find its
	// closing quote until the opening quote of 'x' on line 4 — swallowing
	// lines 2-3 in between. Every '\n' it passes over must still increment
	// the line counter, so by the time the lexer reaches the bare "x" that
	// follows, it must be tagged Line: 4, not Line: 1.
	src := "String s = 'oops no closing quote here\nfoo();\nbar();\nchar c = 'x';\nqux();"
	toks := Lex(src)

	var x *Token
	for i := range toks {
		if toks[i].Kind == TokenIdent && toks[i].Text == "x" {
			x = &toks[i]
			break
		}
	}
	require.NotNil(t, x, "x identifier token not found")
	assert.Equal(t, 4, x.Line, "char-literal branch must track newlines it consumes")
}

func TestLexBackslashNewlineInStringTracksLine(t *testing.T) {
	// The '\n' immediately following the backslash is consumed as the second
	// rune of the escape pair, before the loop's own '\n' check ever sees it.
	// That must still count as a line break.
	src := "String a = \"a\\\nb\";\nqux();"
	toks := Lex(src)

	var qux *Token
	for i := range toks {
		if toks[i].Kind == TokenIdent && toks[i].Text == "qux" {
			qux = &toks[i]
			break
		}
	}
	require.NotNil(t, qux, "qux identifier token not found")
	assert.Equal(t, 3, qux.Line, "backslash-newline escape pair must still increment the line counter")
}

func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		"cardNumber": {"card", "number"},
		"SSN":        {"ssn"},
		"getSsn":     {"get", "ssn"},
		"userRRN":    {"user", "rrn"},
		"user_ssn":   {"user", "ssn"},
		"주민등록번호":     {"주민등록번호"},
		"":           nil,
	}
	for in, want := range cases {
		assert.Equal(t, want, splitWords(in), "input: %q", in)
	}
}
