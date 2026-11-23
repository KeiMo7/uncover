package querylang

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Parse compiles unified-syntax text into a condition tree.
//
// Grammar (AND binds tighter than OR; NOT binds tightest; parentheses
// override):
//
//	expr    = orExpr
//	orExpr  = andExpr ( OR andExpr )*
//	andExpr = unary  ( (AND | <implicit>) unary )*
//	unary   = NOT unary | primary
//	primary = '(' expr ')' | leaf
//	leaf    = field operator value
//
// Every error is a *ParseError carrying the byte/line/column position and a
// specific reason.
func Parse(input string) (Node, error) {
	toks, err := lex(input)
	if err != nil {
		return nil, err
	}
	p := &parser{input: input, toks: toks}
	tree, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkEOF {
		return nil, p.failf(p.peek().pos, "unexpected token %q after complete condition", p.peek().raw)
	}
	return tree, nil
}

type parser struct {
	input string
	toks  []token
	pos   int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) atEOF() bool { return p.peek().kind == tkEOF }

func (p *parser) failf(pos int, format string, args ...any) error {
	return newParseError(p.input, pos, format, args...)
}

func isKeyword(t token, kw string) bool {
	return t.kind == tkIdent && strings.EqualFold(t.text, kw)
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	var children []Node
	for isKeyword(p.peek(), "OR") {
		p.next()
		if p.atEOF() || isKeyword(p.peek(), "OR") || isKeyword(p.peek(), "AND") {
			return nil, p.failf(p.peek().pos, "OR needs a condition on both sides")
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 0 {
		return left, nil
	}
	return &LogicalNode{Op: Or, Children: append([]Node{left}, children...), Position: left.Pos()}, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	var children []Node
	for {
		// Explicit AND is optional; two adjacent conditions imply AND.
		if isKeyword(p.peek(), "AND") {
			p.next()
			if p.atEOF() || isKeyword(p.peek(), "OR") || isKeyword(p.peek(), "AND") {
				return nil, p.failf(p.peek().pos, "AND needs a condition on both sides")
			}
		} else if p.startsUnary() {
			// implicit AND: no keyword consumed
		} else {
			break
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		children = append(children, right)
	}
	if len(children) == 0 {
		return left, nil
	}
	return &LogicalNode{Op: And, Children: append([]Node{left}, children...), Position: left.Pos()}, nil
}

// startsUnary reports whether the current token can begin a unary/primary
// expression, which drives implicit-AND detection. Boolean join keywords
// never start a condition.
func (p *parser) startsUnary() bool {
	t := p.peek()
	if t.kind != tkLParen && t.kind != tkIdent {
		return false
	}
	upper := strings.ToUpper(t.text)
	if upper == "AND" || upper == "OR" {
		return false
	}
	return t.kind == tkLParen || isKeyword(t, "NOT") || t.kind == tkIdent
}

func (p *parser) parseUnary() (Node, error) {
	if isKeyword(p.peek(), "NOT") {
		notTok := p.next()
		if !p.startsUnary() {
			return nil, p.failf(notTok.pos, "NOT must be followed by a condition")
		}
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &NotNode{Child: child, Position: notTok.pos}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	t := p.peek()
	if t.kind == tkLParen {
		return p.parseParen()
	}
	return p.parseLeaf()
}

func (p *parser) parseParen() (Node, error) {
	open := p.next() // '('
	inner, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkRParen {
		return nil, p.failf(p.peek().pos, "missing closing ')' for group opened at offset %d", open.pos)
	}
	p.next() // ')'
	return inner, nil
}

func (p *parser) parseLeaf() (Node, error) {
	fieldTok := p.peek()
	if fieldTok.kind != tkIdent {
		if fieldTok.kind == tkEOF {
			return nil, p.failf(fieldTok.pos, "unexpected end of input, expected a field name (e.g. domain, ip, port)")
		}
		return nil, p.failf(fieldTok.pos, "expected a field name but found %q", fieldTok.raw)
	}
	if upper := strings.ToUpper(fieldTok.text); upper == "AND" || upper == "OR" || upper == "NOT" {
		return nil, p.failf(fieldTok.pos, "keyword %q used where a field name was expected", fieldTok.text)
	}
	p.next()

	field, ok := resolveField(fieldTok.text)
	if !ok {
		return nil, p.failf(fieldTok.pos, "unknown field %q: no engine mapping exists, so it cannot be compiled safely; use one of the documented canonical fields or aliases", fieldTok.text)
	}

	// Keyword-form predicates need no comparison operator:
	// field BETWEEN low AND high / field IN (v1, v2, ...).
	if isKeyword(p.peek(), "BETWEEN") || isKeyword(p.peek(), "IN") {
		leaf := &LeafNode{Field: field, Position: fieldTok.pos}
		if isKeyword(p.peek(), "BETWEEN") {
			if err := p.parseBetween(leaf); err != nil {
				return nil, err
			}
		} else {
			if err := p.parseIn(leaf); err != nil {
				return nil, err
			}
		}
		if !allowsKind(field, leaf.Kind) {
			return nil, p.failf(leaf.Position, "field %q does not accept %s values; expected %s",
				field, leaf.Kind, allowedKindsText(field))
		}
		if !allowsOperator(field, leaf.Op) {
			return nil, p.failf(leaf.Position, "operator %s is not valid for field %q (allowed: %s)",
				leaf.Op, field, allowedOpsText(field))
		}
		return leaf, nil
	}

	opTok := p.peek()
	if opTok.kind != tkOp {
		return nil, p.failf(opTok.pos, "field %q must be followed by an operator (=, !=, :, !:, ~, >, >=, <, <=) or the BETWEEN/IN keyword", fieldTok.text)
	}
	p.next()
	op := opFromToken(opTok.text)
	if op < 0 {
		return nil, p.failf(opTok.pos, "unsupported operator %q", opTok.text)
	}

	if !allowsOperator(field, op) {
		return nil, p.failf(opTok.pos, "operator %s is not valid for field %q (allowed: %s)", opTok.text, field, allowedOpsText(field))
	}

	leaf := &LeafNode{Field: field, Op: op, Position: fieldTok.pos}

	if err := p.parseSimpleValue(leaf); err != nil {
		return nil, err
	}

	if !allowsKind(field, leaf.Kind) {
		// Quoted literals arrive as strings; when the field expects a typed
		// value (ip, cidr, number), re-parse the quoted text so
		// ip = "10.0.0.1" works the same as the bare form.
		if coerced, ok := coerceToFieldKind(field, leaf); ok {
			leaf.Value = coerced.value
			leaf.Kind = coerced.kind
		} else {
			return nil, p.failf(leaf.Position, "field %q does not accept %s values; expected %s",
				field, leaf.Kind, allowedKindsText(field))
		}
	}
	return leaf, nil
}

type coercedValue struct {
	value any
	kind  ValueKind
}

func coerceToFieldKind(field string, leaf *LeafNode) (coercedValue, bool) {
	if leaf.Kind != KindString {
		return coercedValue{}, false
	}
	raw := leaf.RawValue
	for _, want := range fieldValueKinds[field] {
		switch want {
		case KindIP:
			if _, err := netip.ParseAddr(raw); err == nil {
				return coercedValue{value: parseIP(raw), kind: KindIP}, true
			}
		case KindCIDR:
			if ip, ipNet, err := parseCIDR(raw); err == nil {
				_ = ip
				return coercedValue{value: ipNet, kind: KindCIDR}, true
			}
		case KindNumber:
			if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
				return coercedValue{value: i, kind: KindNumber}, true
			}
		}
	}
	return coercedValue{}, false
}

func opFromToken(text string) Operator {
	switch text {
	case TokenEq:
		return OpEqual
	case TokenNeq:
		return OpNotEqual
	case TokenHas:
		return OpContains
	case TokenNhas:
		return OpNotContains
	case TokenRegex:
		return OpRegex
	case TokenGt:
		return OpGreater
	case TokenGte:
		return OpGreaterOrEqual
	case TokenLt:
		return OpLess
	case TokenLte:
		return OpLessOrEqual
	default:
		return -1
	}
}

func (p *parser) parseSimpleValue(leaf *LeafNode) error {
	vTok := p.peek()
	if vTok.kind == tkEOF {
		return p.failf(vTok.pos, "operator %s requires a value", leaf.Op)
	}
	if vTok.kind == tkRParen || vTok.kind == tkComma || vTok.kind == tkOp {
		return p.failf(vTok.pos, "unexpected %q where a value was expected", vTok.raw)
	}
	p.next()

	// Time fields get their strings validated/normalized up front.
	if (leaf.Field == FieldFirstSeen || leaf.Field == FieldLastSeen) &&
		(leaf.Op == OpGreater || leaf.Op == OpGreaterOrEqual || leaf.Op == OpLess || leaf.Op == OpLessOrEqual || leaf.Op == OpEqual) {
		if vTok.kind == tkString || vTok.kind == tkNumber || vTok.kind == tkIdent {
			normalized, err := parseTimeValue(vTok.text)
			if err != nil {
				return p.failf(vTok.pos, "%v", err)
			}
			leaf.Value = normalized
			leaf.Kind = KindString
			leaf.RawValue = vTok.text
			return nil
		}
	}

	val, kind, err := parseValueToken(vTok)
	if err != nil {
		if pe, ok := err.(*ParseError); ok {
			pe.Input = p.input
			if pe.Pos == 0 {
				pe.Pos = vTok.pos
			}
			return pe
		}
		return p.failf(vTok.pos, "%v", err)
	}
	leaf.Value = val
	leaf.Kind = kind
	leaf.RawValue = vTok.text
	return nil
}

func (p *parser) parseBetween(leaf *LeafNode) error {
	betweenTok := p.next() // BETWEEN
	from := p.next()
	if from.kind != tkString && from.kind != tkNumber && from.kind != tkIdent {
		return p.failf(from.pos, "BETWEEN requires a lower bound value")
	}
	if !isKeyword(p.peek(), "AND") {
		return p.failf(p.peek().pos, "BETWEEN syntax is: field BETWEEN <low> AND <high>")
	}
	p.next() // AND
	to := p.next()
	if to.kind != tkString && to.kind != tkNumber && to.kind != tkIdent {
		return p.failf(to.pos, "BETWEEN requires an upper bound value")
	}
	leaf.Op = OpBetween

	switch leaf.Field {
	case FieldPortRange, FieldPort:
		lo, err1 := atoiToken(from)
		hi, err2 := atoiToken(to)
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return p.failf(betweenTok.pos, "invalid port interval BETWEEN %s AND %s: need 1 <= low <= high <= 65535", from.text, to.text)
		}
		leaf.Value = &PortRangeValue{Low: lo, High: hi}
		leaf.Kind = KindPortRange
	case FieldIPRange, FieldIP, FieldCIDR:
		start, err1 := parseIPText(from.text)
		end, err2 := parseIPText(to.text)
		if err1 != nil || err2 != nil || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
			return p.failf(betweenTok.pos, "invalid IP interval BETWEEN %s AND %s", from.text, to.text)
		}
		leaf.Value = &IPRangeValue{Start: start.String(), End: end.String()}
		leaf.Kind = KindIPRange
	case FieldFirstSeen, FieldLastSeen:
		tr, err := parseTimeRange(from.text, to.text, betweenTok.pos)
		if err != nil {
			return err
		}
		leaf.Value = tr
		leaf.Kind = KindTimeRange
	default:
		return p.failf(betweenTok.pos, "BETWEEN is only valid for port, ip and time fields, not %q", leaf.Field)
	}
	leaf.RawValue = from.text + " AND " + to.text
	return nil
}

func (p *parser) parseIn(leaf *LeafNode) error {
	inTok := p.next() // IN
	if p.peek().kind != tkLParen {
		return p.failf(p.peek().pos, "IN syntax is: field IN (value1, value2, ...)")
	}
	p.next() // '('
	var values []string
	for {
		vTok := p.next()
		if vTok.kind != tkString && vTok.kind != tkNumber && vTok.kind != tkIdent {
			return p.failf(vTok.pos, "IN list only accepts literal values")
		}
		// For IP fields validate each element now.
		if leaf.Field == FieldIP {
			if _, err := parseIPText(vTok.text); err != nil {
				return p.failf(vTok.pos, "IN list entry %q is not a valid IP address", vTok.text)
			}
		}
		if leaf.Field == FieldPort {
			if _, err := atoiToken(vTok); err != nil {
				return p.failf(vTok.pos, "IN list entry %q is not a valid port number", vTok.text)
			}
		}
		values = append(values, vTok.text)
		if p.peek().kind == tkComma {
			p.next()
			continue
		}
		break
	}
	if p.peek().kind != tkRParen {
		return p.failf(p.peek().pos, "IN list must end with ')' (opened at offset %d)", inTok.pos)
	}
	p.next() // ')'
	leaf.Op = OpIn
	leaf.Value = values
	leaf.Kind = KindStringList
	leaf.RawValue = ""
	return nil
}

func atoiToken(t token) (int, error) {
	if t.kind != tkNumber {
		return 0, errors.New("not a numeric token")
	}
	return strconv.Atoi(t.text)
}

func parseIPText(text string) (netip.Addr, error) {
	return netip.ParseAddr(text)
}

func parseIP(text string) net.IP {
	return net.ParseIP(text)
}

func parseCIDR(text string) (net.IP, *net.IPNet, error) {
	return net.ParseCIDR(text)
}

func allowedOpsText(field string) string {
	ops := fieldOperators[field]
	parts := make([]string, 0, len(ops))
	for _, op := range ops {
		parts = append(parts, op.String())
	}
	return strings.Join(parts, ", ")
}

func allowedKindsText(field string) string {
	kinds := fieldValueKinds[field]
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, k.String())
	}
	return strings.Join(parts, " or ")
}
