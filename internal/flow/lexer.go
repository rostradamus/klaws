package flow

import (
	"strings"
	"unicode"
)

// TokenKind classifies a lexed Java token.
type TokenKind int

const (
	TokenIdent TokenKind = iota
	TokenString
	TokenNumber
	TokenPunct
)

// Token is a single lexed token. Line is 1-indexed.
type Token struct {
	Kind TokenKind
	Text string
	Line int
}

// Lex tokenizes Java source. Comments are discarded. String and character
// literals become TokenString so their contents can never be mistaken for an
// identifier — this is what keeps log.info("user ssn field") from tainting.
//
// Lex never panics: malformed input yields whatever tokens could be read.
func Lex(src string) []Token {
	var toks []Token
	runes := []rune(src)
	n := len(runes)
	line := 1

	for i := 0; i < n; {
		c := runes[i]

		switch {
		case c == '\n':
			line++
			i++

		case unicode.IsSpace(c):
			i++

		case c == '/' && i+1 < n && runes[i+1] == '/':
			for i < n && runes[i] != '\n' {
				i++
			}

		case c == '/' && i+1 < n && runes[i+1] == '*':
			i += 2
			for i+1 < n && !(runes[i] == '*' && runes[i+1] == '/') {
				if runes[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
			if i > n {
				i = n // unterminated block comment
			}

		case c == '"':
			startLine := line
			i++
			var sb strings.Builder
			for i < n && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < n {
					if runes[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if runes[i] == '\n' {
					line++
				}
				sb.WriteRune(runes[i])
				i++
			}
			i++ // consume closing quote (or run past end if unterminated)
			if i > n {
				i = n
			}
			toks = append(toks, Token{Kind: TokenString, Text: sb.String(), Line: startLine})

		case c == '\'':
			startLine := line
			i++
			for i < n && runes[i] != '\'' {
				if runes[i] == '\\' && i+1 < n {
					if runes[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if runes[i] == '\n' {
					line++
				}
				i++
			}
			i++
			if i > n {
				i = n
			}
			toks = append(toks, Token{Kind: TokenString, Text: "", Line: startLine})

		case isIdentStart(c):
			start := i
			for i < n && isIdentPart(runes[i]) {
				i++
			}
			toks = append(toks, Token{Kind: TokenIdent, Text: string(runes[start:i]), Line: line})

		case unicode.IsDigit(c):
			start := i
			for i < n && (unicode.IsDigit(runes[i]) || runes[i] == '.' || isIdentPart(runes[i])) {
				i++
			}
			toks = append(toks, Token{Kind: TokenNumber, Text: string(runes[start:i]), Line: line})

		default:
			toks = append(toks, Token{Kind: TokenPunct, Text: string(c), Line: line})
			i++
		}
	}

	return toks
}

func isIdentStart(c rune) bool { return unicode.IsLetter(c) || c == '_' || c == '$' }
func isIdentPart(c rune) bool  { return isIdentStart(c) || unicode.IsDigit(c) }

// splitWords breaks an identifier into lowercase words on camelCase boundaries
// and underscores. Acronyms stay whole ("SSN" → ["ssn"], not ["s","s","n"]).
// Korean identifiers have no case, so they survive as a single word.
func splitWords(name string) []string {
	var words []string
	var cur []rune
	prevLower := false

	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}

	for _, r := range name {
		if r == '_' || r == '$' {
			flush()
			prevLower = false
			continue
		}
		if unicode.IsUpper(r) && prevLower {
			flush()
		}
		cur = append(cur, r)
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
	}
	flush()

	return words
}
