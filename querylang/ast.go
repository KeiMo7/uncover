package querylang

import (
	"fmt"
	"strings"
)

// Node is any element of a parsed condition tree.
type Node interface {
	// nodeMarker keeps external packages from implementing Node; the tree is
	// produced only by the parser so its invariants can be trusted by
	// compilers.
	nodeMarker()
	// String renders the node back into canonical unified syntax. Rendering is
	// deterministic: parsing a query and rendering its tree always produces
	// the same string for the same tree, which is what makes repeated
	// compilation stable.
	String() string
	// Pos returns the byte offset of the node's first token in the original
	// input, used for error messages.
	Pos() int
}

// LogicalOp is a boolean combinator.
type LogicalOp int

const (
	And LogicalOp = iota
	Or
)

func (op LogicalOp) String() string {
	switch op {
	case And:
		return "AND"
	case Or:
		return "OR"
	default:
		return "UNKNOWN"
	}
}

// LogicalNode combines child conditions with a single boolean operator.
// AND binds tighter than OR at parse time; parentheses override that. The
// tree structure itself preserves the intended precedence.
type LogicalNode struct {
	Op       LogicalOp
	Children []Node
	Position int
}

func (n *LogicalNode) nodeMarker() {}
func (n *LogicalNode) Pos() int    { return n.Position }
func (n *LogicalNode) String() string {
	parts := make([]string, 0, len(n.Children))
	for _, c := range n.Children {
		parts = append(parts, renderChild(n, c))
	}
	return strings.Join(parts, " "+n.Op.String()+" ")
}

// NotNode negates its child.
type NotNode struct {
	Child    Node
	Position int
}

func (n *NotNode) nodeMarker() {}
func (n *NotNode) Pos() int    { return n.Position }
func (n *NotNode) String() string {
	return "NOT " + renderChild(n, n.Child)
}

// Operator is a comparison or matching operator between a field and a value.
type Operator int

const (
	OpEqual Operator = iota
	OpNotEqual
	OpContains
	OpNotContains
	OpRegex
	OpGreater
	OpGreaterOrEqual
	OpLess
	OpLessOrEqual
	OpBetween
	OpIn
)

// Canonical operator tokens in unified syntax.
const (
	TokenEq    = "="
	TokenNeq   = "!="
	TokenHas   = ":"
	TokenNhas  = "!:"
	TokenRegex = "~"
	TokenGt    = ">"
	TokenGte   = ">="
	TokenLt    = "<"
	TokenLte   = "<="
)

func (op Operator) String() string {
	switch op {
	case OpEqual:
		return TokenEq
	case OpNotEqual:
		return TokenNeq
	case OpContains:
		return TokenHas
	case OpNotContains:
		return TokenNhas
	case OpRegex:
		return TokenRegex
	case OpGreater:
		return TokenGt
	case OpGreaterOrEqual:
		return TokenGte
	case OpLess:
		return TokenLt
	case OpLessOrEqual:
		return TokenLte
	case OpBetween:
		return "BETWEEN"
	case OpIn:
		return "IN"
	default:
		return "UNKNOWN"
	}
}

// ValueKind classifies a leaf's value so compilers can validate it against
// the engine's expected input shape.
type ValueKind int

const (
	KindString ValueKind = iota
	KindNumber
	KindIP
	KindCIDR
	KindIPRange
	KindPortRange
	KindTimeRange
	KindStringList
)

func (k ValueKind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindNumber:
		return "number"
	case KindIP:
		return "ip"
	case KindCIDR:
		return "cidr"
	case KindIPRange:
		return "ip-range"
	case KindPortRange:
		return "port-range"
	case KindTimeRange:
		return "time-range"
	case KindStringList:
		return "string-list"
	default:
		return "unknown"
	}
}

// LeafNode is a single field/operator/value condition, e.g.
//
//	port = 443
//	domain : "example.com"
//	cert.fingerprint = "AA:BB:..."
type LeafNode struct {
	// Field is the canonical unified field path, lowercase, e.g. "domain",
	// "ip", "port", "service", "cert.issuer_org".
	Field string
	Op    Operator
	// Value holds the parsed value: string, int64, net.IP, *net.IPNet,
	// *IPRangeValue, *PortRangeValue, *TimeRangeValue or []string.
	Value    any
	Kind     ValueKind
	Position int
	// RawValue is the value text exactly as written by the user (quotes
	// stripped), retained for error messages and stable round-tripping.
	RawValue string
}

func (n *LeafNode) nodeMarker() {}
func (n *LeafNode) Pos() int    { return n.Position }

func (n *LeafNode) String() string {
	if n.Op == OpBetween {
		return fmt.Sprintf("%s BETWEEN %s", n.Field, renderBetween(n.Value, n.Kind))
	}
	return fmt.Sprintf("%s %s %s", n.Field, n.Op.String(), renderValue(n.Value, n.Kind, n.RawValue))
}

func renderBetween(v any, kind ValueKind) string {
	switch kind {
	case KindPortRange:
		pr, _ := v.(*PortRangeValue)
		return fmt.Sprintf("%d AND %d", pr.Low, pr.High)
	case KindIPRange:
		ipr, _ := v.(*IPRangeValue)
		return quoteString(ipr.Start) + " AND " + quoteString(ipr.End)
	case KindTimeRange:
		tr, _ := v.(*TimeRangeValue)
		return quoteString(tr.From) + " AND " + quoteString(tr.To)
	default:
		return fmt.Sprint(v)
	}
}

// IPRangeValue is an inclusive IP address range, start <= end.
type IPRangeValue struct {
	Start string
	End   string
}

// PortRangeValue is an inclusive port range, 1 <= Low <= High <= 65535.
// For a single port expressed as a range Low == High; the parser keeps plain
// port equality as OpEqual with KindNumber instead.
type PortRangeValue struct {
	Low  int
	High int
}

// TimeRangeValue is an inclusive time window. Bounds are RFC3339 timestamps;
// either side may be empty when the query only pins one end via
// > / < operators (Between always has both).
type TimeRangeValue struct {
	From string
	To   string
}

// renderChild adds parentheses around a child when its precedence is lower
// than the parent's, so rendered output always re-parses to the same tree.
func renderChild(parent Node, child Node) string {
	switch p := parent.(type) {
	case *NotNode:
		if _, ok := child.(*LogicalNode); ok {
			return "(" + child.String() + ")"
		}
	case *LogicalNode:
		if c, ok := child.(*LogicalNode); ok && c.Op != p.Op {
			return "(" + child.String() + ")"
		}
	}
	return child.String()
}

func renderValue(v any, kind ValueKind, raw string) string {
	if raw != "" {
		// Quoted when the raw form contains spaces or syntax characters.
		if needsQuoting(raw) {
			return quoteString(raw)
		}
		return raw
	}
	switch kind {
	case KindStringList:
		list, _ := v.([]string)
		quoted := make([]string, 0, len(list))
		for _, s := range list {
			quoted = append(quoted, quoteString(s))
		}
		return "(" + strings.Join(quoted, ", ") + ")"
	default:
		return fmt.Sprint(v)
	}
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		switch r {
		case ' ', '\t', '(', ')', '"', ':', '=', '!', '~', '>', '<':
			return true
		}
	}
	return false
}

func quoteString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// Walk visits every node in the tree depth-first, calling fn for each node
// (parents before children). A non-nil error aborts the walk.
func Walk(n Node, fn func(Node) error) error {
	if err := fn(n); err != nil {
		return err
	}
	switch t := n.(type) {
	case *LogicalNode:
		for _, c := range t.Children {
			if err := Walk(c, fn); err != nil {
				return err
			}
		}
	case *NotNode:
		return Walk(t.Child, fn)
	}
	return nil
}

// Leaves returns every leaf condition in the tree, in left-to-right order.
// The compiler uses this to account for every condition exactly once: the
// number of leaves compiled plus the number reported as degraded must equal
// len(Leaves(tree)).
func Leaves(n Node) []*LeafNode {
	var out []*LeafNode
	_ = Walk(n, func(node Node) error {
		if leaf, ok := node.(*LeafNode); ok {
			out = append(out, leaf)
		}
		return nil
	})
	return out
}
