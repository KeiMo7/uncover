package querylang

// SupportLevel states how a backend handles one specific field/operator
// combination.
type SupportLevel int

const (
	// SupportFull: the backend expresses the condition natively.
	SupportFull SupportLevel = iota
	// SupportAlternative: the backend cannot express it directly but has a
	// documented equivalent spelling the compiler can emit. The emitted
	// query remains semantically equivalent; the alternative is recorded in
	// the compile report.
	SupportAlternative
	// SupportDegradable: only expressible by dropping part of the semantics.
	// Allowed only when the caller explicitly enables degradation, and the
	// dropped condition is enumerated in the report.
	SupportDegradable
	// SupportUnsupported: the backend cannot express this condition at all;
	// compilation of this query fails for this backend.
	SupportUnsupported
)

// FieldCapability describes a backend's support for one canonical field.
type FieldCapability struct {
	Field string
	// SupportedOps lists operators the engine expresses natively (or via a
	// documented equivalent). An operator absent from this list triggers
	// rejection or degradation at compile time.
	SupportedOps []Operator
	// Level overrides the default SupportFull for the field as a whole.
	Level SupportLevel
	// Note is a human-readable explanation shown in the equivalence report,
	// e.g. "FOFA has no certificate fingerprint filter; body matching is not
	// equivalent and is not substituted."
	Note string
	// AlternativeNames lists the engine's own field spellings accepted as
	// aliases, purely for documentation and the explain output.
	AlternativeNames []string
}

// Capabilities is a backend engine's declared ability boundary. The compiler
// consults this before emitting anything, so an unsupported combination is
// caught before a request is sent — an engine never receives a query missing
// a constraint it silently ignores.
type Capabilities struct {
	// Engine is the uncover agent name, e.g. "shodan", "fofa".
	Engine string
	// Fields maps canonical field name to its capability.
	Fields map[string]FieldCapability
	// SupportsNot says whether the engine can negate a whole sub-expression
	// (NOT / minus groups). When false, a tree containing NOT is rejected
	// unless the NOT can be pushed down into leaf operators the engine does
	// support.
	SupportsNot bool
	// SupportsNestedOr says whether OR can be nested inside AND groups.
	// Some engines only accept flat conjunctions.
	SupportsNestedOr bool
	// FreeTextOnly engines accept a single raw text term and no structured
	// filters; any structured leaf is rejected with a clear message.
	FreeTextOnly bool
	// Notes are engine-wide caveats surfaced in the equivalence report.
	Notes []string
}

// LeafSupport resolves the support level for a concrete leaf.
func (c *Capabilities) LeafSupport(leaf *LeafNode) (SupportLevel, FieldCapability, bool) {
	fc, ok := c.Fields[leaf.Field]
	if !ok {
		return SupportUnsupported, FieldCapability{Field: leaf.Field}, false
	}
	if fc.Level == SupportUnsupported {
		return SupportUnsupported, fc, false
	}
	// A field-wide degradable/alternative declaration applies even when the
	// specific operator is absent from SupportedOps: it states the engine
	// cannot express this field precisely at all.
	if fc.Level == SupportDegradable {
		return SupportDegradable, fc, true
	}
	if fc.Level == SupportAlternative {
		return SupportAlternative, fc, true
	}
	for _, op := range fc.SupportedOps {
		if op == leaf.Op {
			return SupportFull, fc, true
		}
	}
	return SupportUnsupported, fc, false
}

// SupportsField reports any level of support for the field.
func (c *Capabilities) SupportsField(field string) bool {
	fc, ok := c.Fields[field]
	return ok && fc.Level != SupportUnsupported
}
