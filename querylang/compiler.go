package querylang

import (
	"fmt"
	"sort"
	"strings"
)

// DegradationMode controls what the compiler may do when a backend cannot
// fully express a condition.
type DegradationMode int

const (
	// DegradeReject (default): any unsupported condition fails compilation
	// for that backend. Nothing is ever silently dropped.
	DegradeReject DegradationMode = iota
	// DegradeTopLevelAND: a top-level AND conjunct that the backend cannot
	// express may be omitted, but only when it is itself a complete conjunct
	// (never a branch of OR or a child of NOT). Every omission is recorded.
	DegradeTopLevelAND
)

// Degradation records one condition that could not be compiled for a backend.
type Degradation struct {
	// Engine the condition was dropped for.
	Engine string
	// Condition is the canonical rendering of the dropped node.
	Condition string
	// Reason explains why the backend cannot express it.
	Reason string
	// Alternatives lists equivalent spellings the user can use instead,
	// when any exist.
	Alternatives []string
}

// AlternativeRendering records a condition emitted through a non-obvious
// native spelling, so the equivalence report can explain the mapping.
type AlternativeRendering struct {
	Condition   string // canonical condition
	Emitted     string // what the backend received
	Explanation string
}

// CompiledQuery is the result of compiling one condition tree for one engine.
type CompiledQuery struct {
	Engine string
	// Query is the exact native query string handed to the engine. Existing
	// transports (base64, query-escape, JSON body) apply on top of it and are
	// unchanged.
	Query string
	// Version is the grammar version the tree was parsed under.
	Version string
	// EffectiveConditions is the canonical rendering of every condition that
	// actually constrains the emitted query (all leaves minus dropped ones),
	// in stable left-to-right order.
	EffectiveConditions []string
	// Dropped lists every condition omitted under DegradeTopLevelAND. It is
	// empty in DegradeReject mode because compilation fails instead.
	Dropped []Degradation
	// Alternatives documents non-obvious native spellings used.
	Alternatives []AlternativeRendering
	// Degraded is true when Dropped is non-empty.
	Degraded bool
}

// CompileError means a backend cannot express the query under the chosen
// degradation policy. It is distinct from a runtime engine error and from an
// empty result set.
type CompileError struct {
	Engine       string
	Condition    string
	Reason       string
	Alternatives []string
}

func (e *CompileError) Error() string {
	msg := fmt.Sprintf("engine %q cannot compile condition %s: %s", e.Engine, e.Condition, e.Reason)
	if len(e.Alternatives) > 0 {
		msg += " — supported alternatives: " + strings.Join(e.Alternatives, "; ")
	}
	return msg
}

// Compiler compiles parsed condition trees against registered backends.
type Compiler struct {
	backends map[string]Backend
	mode     DegradationMode
}

func NewCompiler(mode DegradationMode) *Compiler {
	return &Compiler{backends: map[string]Backend{}, mode: mode}
}

// Register adds or replaces a backend.
func (c *Compiler) Register(b Backend) {
	c.backends[b.Name()] = b
}

// Engines returns registered backend names in stable order.
func (c *Compiler) Engines() []string {
	names := make([]string, 0, len(c.backends))
	for name := range c.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Compile produces a native query for the named engine.
func (c *Compiler) Compile(engine string, tree Node) (*CompiledQuery, error) {
	b, ok := c.backends[engine]
	if !ok {
		return nil, fmt.Errorf("no query backend registered for engine %q", engine)
	}
	caps := b.Capabilities()

	// Structural capability checks first.
	if err := checkStructure(caps, tree); err != nil {
		return nil, err
	}

	// Per-leaf capability accounting. The invariant enforced below:
	// every leaf is either fully compiled, reported as an alternative, or
	// (only with explicit degradation) recorded as dropped. Nothing vanishes.
	var drops []Degradation
	allLeaves := Leaves(tree)
	for _, leaf := range allLeaves {
		level, fc, _ := caps.LeafSupport(leaf)
		if level == SupportFull || level == SupportAlternative {
			continue
		}
		cond := leaf.String()
		reason := unsupportedReason(caps, leaf, fc)
		alts := suggestAlternatives(caps, leaf)
		if level == SupportDegradable && c.mode == DegradeTopLevelAND && isTopLevelAndConjunct(tree, leaf) {
			drops = append(drops, Degradation{
				Engine: engine, Condition: cond, Reason: reason, Alternatives: alts,
			})
			continue
		}
		return nil, &CompileError{
			Engine: engine, Condition: cond, Reason: reason, Alternatives: alts,
		}
	}

	native, alts, err := b.Render(tree, drops)
	if err != nil {
		return nil, &CompileError{Engine: engine, Reason: err.Error()}
	}

	effective := effectiveConditions(tree, drops)
	return &CompiledQuery{
		Engine:              engine,
		Query:               native,
		Version:             SyntaxVersion,
		EffectiveConditions: effective,
		Dropped:             drops,
		Alternatives:        alts,
		Degraded:            len(drops) > 0,
	}, nil
}

// CompileAll compiles for every registered backend. Per-engine failures are
// returned as entries keyed by engine rather than aborting the whole fan-out,
// so partial engine coverage can be reported to the caller.
func (c *Compiler) CompileAll(tree Node) (map[string]*CompiledQuery, map[string]error) {
	out := map[string]*CompiledQuery{}
	errs := map[string]error{}
	for _, name := range c.Engines() {
		cq, err := c.Compile(name, tree)
		if err != nil {
			errs[name] = err
			continue
		}
		out[name] = cq
	}
	return out, errs
}

func checkStructure(caps Capabilities, tree Node) error {
	return Walk(tree, func(n Node) error {
		switch t := n.(type) {
		case *NotNode:
			if !caps.SupportsNot && !canPushDownNot(t) {
				return &CompileError{
					Engine:    caps.Engine,
					Condition: t.String(),
					Reason:    "engine cannot negate a sub-expression and the NOT cannot be rewritten into leaf operators",
				}
			}
		case *LogicalNode:
			if t.Op == Or && !caps.SupportsNestedOr && hasAndAncestorContext(tree, t) {
				return &CompileError{
					Engine:    caps.Engine,
					Condition: t.String(),
					Reason:    "engine only supports flat conjunctions and cannot nest an OR group inside AND",
				}
			}
		}
		return nil
	})
}

// canPushDownNot reports whether the NOT only wraps leaves whose operators
// have an in-engine inverse (e.g. = -> !=, : -> !:).
func canPushDownNot(n *NotNode) bool {
	canInvert := true
	_ = Walk(n.Child, func(node Node) error {
		if leaf, ok := node.(*LeafNode); ok {
			if inverseOp(leaf.Op) < 0 {
				canInvert = false
			}
		}
		return nil
	})
	return canInvert
}

func inverseOp(op Operator) Operator {
	switch op {
	case OpEqual:
		return OpNotEqual
	case OpNotEqual:
		return OpEqual
	case OpContains:
		return OpNotContains
	case OpNotContains:
		return OpContains
	default:
		return -1
	}
}

// hasAndAncestorContext is true when the OR node sits below an AND anywhere
// in the tree (i.e. nesting is actually required).
func hasAndAncestorContext(root Node, orNode *LogicalNode) bool {
	found := false
	var walk func(n Node, underAnd bool)
	walk = func(n Node, underAnd bool) {
		if found {
			return
		}
		if n == orNode {
			found = underAnd
			return
		}
		switch t := n.(type) {
		case *LogicalNode:
			for _, ch := range t.Children {
				walk(ch, underAnd || t.Op == And)
			}
		case *NotNode:
			walk(t.Child, underAnd)
		}
	}
	walk(root, false)
	return found
}

// isTopLevelAndConjunct reports whether leaf belongs to the root AND node's
// direct child list (possibly nested inside a NOT-free direct child group).
// Degradation is only legal at this boundary because dropping a conjunct of
// the top-level AND widens the result in an explainable way; dropping an OR
// branch or a negated condition would silently change semantics.
func isTopLevelAndConjunct(root Node, leaf *LeafNode) bool {
	rootAnd, ok := root.(*LogicalNode)
	if !ok || rootAnd.Op != And {
		return false
	}
	for _, child := range rootAnd.Children {
		direct := true
		inThisConjunct := false
		_ = Walk(child, func(n Node) error {
			if n == leaf {
				inThisConjunct = true
			}
			if _, isNot := n.(*NotNode); isNot {
				direct = false
			}
			return nil
		})
		if inThisConjunct && direct {
			return true
		}
	}
	return false
}

func effectiveConditions(tree Node, drops []Degradation) []string {
	dropped := map[string]bool{}
	for _, d := range drops {
		dropped[d.Condition] = true
	}
	var out []string
	for _, leaf := range Leaves(tree) {
		rendered := leaf.String()
		if !dropped[rendered] {
			out = append(out, rendered)
		}
	}
	return out
}

func unsupportedReason(caps Capabilities, leaf *LeafNode, fc FieldCapability) string {
	if _, ok := caps.Fields[leaf.Field]; !ok {
		return fmt.Sprintf("engine has no field equivalent to canonical %q", leaf.Field)
	}
	if fc.Note != "" {
		return fc.Note
	}
	return fmt.Sprintf("engine field for %q does not support operator %s", leaf.Field, leaf.Op)
}

func suggestAlternatives(caps Capabilities, leaf *LeafNode) []string {
	fc, ok := caps.Fields[leaf.Field]
	if !ok {
		return nil
	}
	var alts []string
	for _, op := range fc.SupportedOps {
		alts = append(alts, fmt.Sprintf("%s %s <value>", leaf.Field, op))
	}
	if len(fc.AlternativeNames) > 0 {
		alts = append(alts, "native field name(s): "+strings.Join(fc.AlternativeNames, ", "))
	}
	return alts
}
