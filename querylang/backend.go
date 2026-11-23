package querylang

import (
	"fmt"
	"strings"
)

// Backend renders a condition tree into one engine's native query string.
// Implementations live under backends/; each one pairs a Capabilities
// declaration with a Render function, so the capability table and the actual
// emitted syntax can never drift apart silently.
type Backend interface {
	Name() string
	Capabilities() Capabilities
	// Render emits the native query. drops lists conjuncts already authorized
	// for omission by the compiler; the renderer must skip exactly those
	// nodes and must not drop anything else.
	Render(tree Node, drops []Degradation) (string, []AlternativeRendering, error)
}

// Dialect captures the syntactic shape of an engine's query language so a
// single renderer can drive most backends. Engines with genuinely bespoke
// syntax (e.g. Censys's dotted field: value grammar) implement Backend
// directly.
type Dialect struct {
	Engine string
	// FieldNames maps canonical field -> native field name.
	FieldNames map[string]string
	// AndToken / OrToken / NotToken are the engine's boolean spellings.
	AndToken, OrToken, NotToken string
	// Quote is the string-literal delimiter, usually `"`.
	Quote byte
	// FieldSeparator joins field and value in a leaf, e.g. ":" or "=".
	FieldSeparator string
	// WrapNotInGroup places parentheses around a NOT expression.
	WrapNotInGroup bool
	// LowerKeywords renders boolean keywords in lowercase (Lucene-style).
	LowerKeywords bool
	// Escape is applied to quoted string values.
	Escape func(s string, quote byte) string
	// RenderLeaf allows per-engine leaf overrides; returning ok=false falls
	// back to the generic rendering.
	RenderLeaf func(leaf *LeafNode) (text string, alt *AlternativeRendering, ok bool, err error)
	// RenderRange formats port/ip/time ranges natively.
	RenderRange func(leaf *LeafNode) (string, error)
}

// GenericBackend is a Backend built entirely from a Dialect plus its
// capabilities.
type GenericBackend struct {
	engineName string
	caps       Capabilities
	dialect    Dialect
}

func NewGenericBackend(name string, caps Capabilities, d Dialect) *GenericBackend {
	d.Engine = name
	return &GenericBackend{engineName: name, caps: caps, dialect: d}
}

func (g *GenericBackend) Name() string               { return g.engineName }
func (g *GenericBackend) Capabilities() Capabilities { return g.caps }

func (g *GenericBackend) Render(tree Node, drops []Degradation) (string, []AlternativeRendering, error) {
	r := &dialectRenderer{dialect: g.dialect, drops: dropSet(drops)}
	text, err := r.node(tree)
	if err != nil {
		return "", nil, err
	}
	return text, r.alts, nil
}

func dropSet(drops []Degradation) map[string]bool {
	m := map[string]bool{}
	for _, d := range drops {
		m[d.Condition] = true
	}
	return m
}

// DropSet exports the dropped-condition lookup for custom Backend
// implementations in subpackages.
func DropSet(drops []Degradation) map[string]bool {
	return dropSet(drops)
}

type dialectRenderer struct {
	dialect Dialect
	drops   map[string]bool
	alts    []AlternativeRendering
}

func (r *dialectRenderer) node(n Node) (string, error) {
	return r.nodeWithParent(n, -1)
}

// nodeWithParent renders n, parenthesizing a logical group when its operator
// differs from the parent group's (parentOp is -1 for the root). This keeps
// the emitted native query faithful to the parsed tree's precedence.
func (r *dialectRenderer) nodeWithParent(n Node, parentOp LogicalOp) (string, error) {
	switch t := n.(type) {
	case *LogicalNode:
		parts := make([]string, 0, len(t.Children))
		for _, ch := range t.Children {
			text, err := r.nodeWithParent(ch, t.Op)
			if err != nil {
				return "", err
			}
			if text == "" {
				continue // conjunct explicitly dropped
			}
			parts = append(parts, text)
		}
		if len(parts) == 0 {
			return "", nil
		}
		joined := strings.Join(parts, r.booleanJoin(t.Op))
		if parentOp >= 0 && parentOp != t.Op {
			return "(" + joined + ")", nil
		}
		return joined, nil
	case *NotNode:
		text, err := r.nodeWithParent(t.Child, -1)
		if err != nil {
			return "", err
		}
		not := r.dialect.NotToken
		if r.dialect.WrapNotInGroup {
			return not + " (" + text + ")", nil
		}
		return not + " " + text, nil
	case *LeafNode:
		if r.drops[t.String()] {
			return "", nil
		}
		return r.leaf(t)
	default:
		return "", fmt.Errorf("unknown node type %T", n)
	}
}

func (r *dialectRenderer) booleanToken(op LogicalOp) string {
	tok := r.dialect.AndToken
	if op == Or {
		tok = r.dialect.OrToken
	}
	if r.dialect.LowerKeywords {
		return strings.ToLower(tok)
	}
	return tok
}

// booleanJoin renders the separator between same-group predicates. An empty
// AND token means the dialect joins conjunctions with whitespace alone
// (Shodan), so the separator collapses to a single space.
func (r *dialectRenderer) booleanJoin(op LogicalOp) string {
	tok := r.booleanToken(op)
	if tok == "" {
		return " "
	}
	return " " + tok + " "
}

func (r *dialectRenderer) leaf(leaf *LeafNode) (string, error) {
	if r.dialect.RenderLeaf != nil {
		if text, alt, ok, err := r.dialect.RenderLeaf(leaf); ok {
			if alt != nil {
				r.alts = append(r.alts, *alt)
			}
			return text, err
		} else if err != nil {
			return "", err
		}
	}

	nativeField, ok := r.dialect.FieldNames[leaf.Field]
	if !ok {
		return "", fmt.Errorf("internal: no native field mapping for %q on %q", leaf.Field, r.dialect.Engine)
	}

	if (leaf.Kind == KindPortRange || leaf.Kind == KindIPRange || leaf.Kind == KindTimeRange) && r.dialect.RenderRange != nil {
		rangeText, err := r.dialect.RenderRange(leaf)
		if err != nil {
			return "", err
		}
		return nativeField + r.dialect.FieldSeparator + rangeText, nil
	}

	return nativeField + r.dialect.FieldSeparator + r.formatValue(leaf), nil
}

func (r *dialectRenderer) formatValue(leaf *LeafNode) string {
	switch leaf.Kind {
	case KindNumber:
		return fmt.Sprint(leaf.Value)
	case KindStringList:
		list, _ := leaf.Value.([]string)
		parts := make([]string, 0, len(list))
		for _, s := range list {
			parts = append(parts, r.quote(s))
		}
		return "(" + strings.Join(parts, ", ") + ")"
	case KindCIDR:
		return r.quote(leaf.RawValue)
	case KindIP:
		return r.quote(leaf.RawValue)
	default:
		return r.quote(leaf.RawValue)
	}
}

func (r *dialectRenderer) quote(s string) string {
	q := r.dialect.Quote
	if q == 0 {
		q = '"'
	}
	if r.dialect.Escape != nil {
		return string(q) + r.dialect.Escape(s, q) + string(q)
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, c := range s {
		if c == rune(q) || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	b.WriteByte(q)
	return b.String()
}

// Explain produces the human-readable cross-engine equivalence description
// required by hard constraint 5: for each engine it shows the native query,
// the effective canonical conditions, any alternative spellings and any
// dropped conditions.
func Explain(queries map[string]*CompiledQuery, errors map[string]error) string {
	var b strings.Builder
	engines := make([]string, 0, len(queries)+len(errors))
	for e := range queries {
		engines = append(engines, e)
	}
	for e := range errors {
		engines = append(engines, e)
	}
	sortStrings(engines)
	for _, engine := range engines {
		b.WriteString("• ")
		b.WriteString(engine)
		b.WriteString(":\n")
		if err, ok := errors[engine]; ok {
			b.WriteString("    rejected: ")
			b.WriteString(err.Error())
			b.WriteString("\n")
			continue
		}
		cq := queries[engine]
		b.WriteString("    native query : ")
		b.WriteString(cq.Query)
		b.WriteString("\n    effective    : ")
		b.WriteString(strings.Join(cq.EffectiveConditions, " AND "))
		b.WriteString("\n")
		for _, a := range cq.Alternatives {
			b.WriteString("    alternative  : ")
			b.WriteString(a.Condition)
			b.WriteString(" -> ")
			b.WriteString(a.Emitted)
			b.WriteString(" (")
			b.WriteString(a.Explanation)
			b.WriteString(")\n")
		}
		for _, d := range cq.Dropped {
			b.WriteString("    DROPPED      : ")
			b.WriteString(d.Condition)
			b.WriteString(" (")
			b.WriteString(d.Reason)
			b.WriteString(")\n")
		}
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
