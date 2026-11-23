package querylang

import (
	"fmt"
	"strings"
)

// tokenKind identifies a lexical token.
type tokenKind int

const (
	tkEOF    tokenKind = iota
	tkIdent            // field name or keyword (unquoted run of allowed chars)
	tkString           // quoted string literal
	tkNumber           // unsigned integer or decimal
	tkOp               // = != : !: ~ > >= < <=
	tkLParen           // (
	tkRParen           // )
	tkComma            // ,
	tkDash             // - (range separator)
)

type token struct {
	kind tokenKind
	// text is the unescaped value for strings, the literal text otherwise.
	text string
	// raw is the original source text (including quotes for strings).
	raw string
	// pos is the byte offset of the token's first byte in the input.
	pos int
}

// ParseError points at the exact byte offset where parsing failed and says
// why, instead of a generic "invalid query". Line/column are computed from the
// offset against the original input.
type ParseError struct {
	Version string
	Pos     int
	Line    int
	Column  int
	Input   string
	Reason  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: syntax error at line %d column %d (offset %d): %s",
		e.Version, e.Line, e.Column, e.Pos, e.Reason)
}

// Caret renders the offending input line with a ^ marker under the error
// position, suitable for CLI output.
func (e *ParseError) Caret() string {
	lineStart := strings.LastIndexByte(e.Input[:clamp(e.Pos, 0, len(e.Input))], '\n') + 1
	lineEnd := strings.IndexByte(e.Input[lineStart:], '\n')
	if lineEnd < 0 {
		lineEnd = len(e.Input)
	} else {
		lineEnd += lineStart
	}
	line := e.Input[lineStart:lineEnd]
	pad := e.Pos - lineStart
	if pad < 0 {
		pad = 0
	}
	if pad > len(line) {
		pad = len(line)
	}
	return line + "\n" + strings.Repeat(" ", pad) + "^"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func newParseError(input string, pos int, format string, args ...any) *ParseError {
	line := 1
	col := 1
	for i := 0; i < pos && i < len(input); i++ {
		if input[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return &ParseError{
		Version: SyntaxVersion,
		Pos:     pos,
		Line:    line,
		Column:  col,
		Input:   input,
		Reason:  fmt.Sprintf(format, args...),
	}
}

// lex tokenizes the full input. Whitespace separates tokens but is otherwise
// insignificant; keywords (AND, OR, NOT, BETWEEN, IN) are case-insensitive
// idents resolved by the parser.
func lex(input string) ([]token, error) {
	var toks []token
	i := 0
	n := len(input)
	for i < n {
		c := input[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tkLParen, text: "(", raw: "(", pos: i})
			i++
		case c == ')':
			toks = append(toks, token{kind: tkRParen, text: ")", raw: ")", pos: i})
			i++
		case c == ',':
			toks = append(toks, token{kind: tkComma, text: ",", raw: ",", pos: i})
			i++
		case c == '"' || c == '\'':
			tok, next, err := lexString(input, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tok)
			i = next
		case isDigit(c):
			tok, next := lexNumber(input, i)
			toks = append(toks, tok)
			i = next
		case c == '=':
			toks = append(toks, token{kind: tkOp, text: "=", raw: "=", pos: i})
			i++
		case c == '!':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, token{kind: tkOp, text: "!=", raw: "!=", pos: i})
				i += 2
			} else if i+1 < n && input[i+1] == ':' {
				toks = append(toks, token{kind: tkOp, text: "!:", raw: "!:", pos: i})
				i += 2
			} else {
				return nil, newParseError(input, i, "unexpected '!', expected '!=' or '!:' operator")
			}
		case c == ':':
			toks = append(toks, token{kind: tkOp, text: ":", raw: ":", pos: i})
			i++
		case c == '~':
			toks = append(toks, token{kind: tkOp, text: "~", raw: "~", pos: i})
			i++
		case c == '>':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, token{kind: tkOp, text: ">=", raw: ">=", pos: i})
				i += 2
			} else {
				toks = append(toks, token{kind: tkOp, text: ">", raw: ">", pos: i})
				i++
			}
		case c == '<':
			if i+1 < n && input[i+1] == '=' {
				toks = append(toks, token{kind: tkOp, text: "<=", raw: "<=", pos: i})
				i += 2
			} else {
				toks = append(toks, token{kind: tkOp, text: "<", raw: "<", pos: i})
				i++
			}
		case c == '-':
			toks = append(toks, token{kind: tkDash, text: "-", raw: "-", pos: i})
			i++
		case isIdentStart(c):
			start := i
			for i < n && isIdentPart(input[i]) {
				i++
			}
			text := input[start:i]
			toks = append(toks, token{kind: tkIdent, text: text, raw: text, pos: start})
		default:
			return nil, newParseError(input, i, "unexpected character %q", string(c))
		}
	}
	toks = append(toks, token{kind: tkEOF, pos: n})
	return toks, nil
}

func lexString(input string, start int) (token, int, error) {
	quote := input[start]
	var b strings.Builder
	i := start + 1
	for i < len(input) {
		c := input[i]
		if c == '\\' && i+1 < len(input) {
			// Only the quote char and backslash need escaping; everything
			// else passes through literally so engine-specific regexes are
			// not mangled.
			next := input[i+1]
			if next == quote || next == '\\' {
				b.WriteByte(next)
			} else {
				b.WriteByte('\\')
				b.WriteByte(next)
			}
			i += 2
			continue
		}
		if c == quote {
			return token{kind: tkString, text: b.String(), raw: input[start : i+1], pos: start}, i + 1, nil
		}
		b.WriteByte(c)
		i++
	}
	return token{}, i, newParseError(input, start, "unterminated string literal, missing closing %q", string(quote))
}

func lexNumber(input string, start int) (token, int) {
	i := start
	for i < len(input) && (isDigit(input[i]) || input[i] == '.') {
		i++
	}
	// IPv4/CIDR/range forms stay attached to the number token: values such as
	// 10.0.0.0/24 or 80-443 are consumed whole here and classified by the
	// parser/value layer, which keeps the grammar simple and unambiguous.
	for i < len(input) && (isIdentPart(input[i]) || input[i] == '-') {
		i++
	}
	text := input[start:i]
	return token{kind: tkNumber, text: text, raw: text, pos: start}, i
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Identifiers carry field paths (domain, cert.issuer_org) and keywords.
func isIdentStart(c byte) bool {
	return c == '_' || c == '*' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || isDigit(c) || c == '.'
}
