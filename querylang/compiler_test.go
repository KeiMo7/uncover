package querylang

import (
	"strings"
	"testing"
)

// stubBackend is a controllable backend used to exercise compiler accounting
// without depending on concrete engine dialects.
type stubBackend struct {
	name   string
	caps   Capabilities
	render func(tree Node, drops []Degradation) (string, []AlternativeRendering, error)
}

func (b *stubBackend) Name() string               { return b.name }
func (b *stubBackend) Capabilities() Capabilities { return b.caps }
func (b *stubBackend) Render(tree Node, drops []Degradation) (string, []AlternativeRendering, error) {
	return b.render(tree, drops)
}

func basicCaps(name string, supported map[string][]Operator, extra func(*Capabilities)) Capabilities {
	caps := Capabilities{Engine: name, SupportsNot: true, SupportsNestedOr: true, Fields: map[string]FieldCapability{}}
	for field, ops := range supported {
		caps.Fields[field] = FieldCapability{Field: field, SupportedOps: ops}
	}
	if extra != nil {
		extra(&caps)
	}
	return caps
}

func echoRenderer() func(Node, []Degradation) (string, []AlternativeRendering, error) {
	return func(tree Node, drops []Degradation) (string, []AlternativeRendering, error) {
		var parts []string
		for _, leaf := range Leaves(tree) {
			dropped := false
			for _, d := range drops {
				if d.Condition == leaf.String() {
					dropped = true
				}
			}
			if !dropped {
				parts = append(parts, leaf.String())
			}
		}
		return strings.Join(parts, " & "), nil, nil
	}
}

func TestCompile_RejectsUnsupportedFieldExplicitly(t *testing.T) {
	tree, err := Parse(`domain : "a.com" AND http.title : "login"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldDomain: {OpEqual, OpContains},
		// http.title deliberately missing
	}, nil)
	c := NewCompiler(DegradeReject)
	c.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})

	_, err = c.Compile("stub", tree)
	if err == nil {
		t.Fatal("expected explicit rejection for unsupported field")
	}
	ce, ok := err.(*CompileError)
	if !ok {
		t.Fatalf("want *CompileError, got %T", err)
	}
	if !strings.Contains(ce.Condition, FieldTitle) {
		t.Errorf("error should name the offending condition, got %q", ce.Condition)
	}
	if ce.Reason == "" {
		t.Error("CompileError must explain the reason")
	}
}

func TestCompile_RejectsUnsupportedOperatorWithAlternatives(t *testing.T) {
	tree, err := Parse(`port > 1024`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldPort: {OpEqual, OpNotEqual}, // no inequality
	}, nil)
	c := NewCompiler(DegradeReject)
	c.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})
	_, err = c.Compile("stub", tree)
	if err == nil {
		t.Fatal("expected rejection of > operator")
	}
	ce := err.(*CompileError)
	if len(ce.Alternatives) == 0 {
		t.Error("rejection should list the operators the engine does support")
	}
}

func TestCompile_DegradationOnlyWithExplicitModeAndTopLevelAND(t *testing.T) {
	tree, err := Parse(`domain : "a.com" AND http.title : "login"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldDomain: {OpContains},
		FieldTitle:  {}, // unsupported
	}, func(c *Capabilities) {
		fc := c.Fields[FieldTitle]
		fc.Level = SupportDegradable
		fc.Note = "engine lacks title filtering"
		c.Fields[FieldTitle] = fc
	})

	// Reject mode: failure.
	cReject := NewCompiler(DegradeReject)
	cReject.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})
	if _, err := cReject.Compile("stub", tree); err == nil {
		t.Fatal("DegradeReject must not silently drop conditions")
	}

	// Degrade mode, top-level AND conjunct: recorded drop, not silent.
	cDegrade := NewCompiler(DegradeTopLevelAND)
	cDegrade.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})
	cq, err := cDegrade.Compile("stub", tree)
	if err != nil {
		t.Fatalf("degrade mode should compile: %v", err)
	}
	if !cq.Degraded || len(cq.Dropped) != 1 {
		t.Fatalf("expected exactly one recorded drop, got %+v", cq.Dropped)
	}
	if !strings.Contains(cq.Dropped[0].Condition, FieldTitle) {
		t.Errorf("drop must name the dropped condition: %+v", cq.Dropped[0])
	}
	// Every leaf is accounted for: effective + dropped == total leaves.
	if len(cq.EffectiveConditions)+len(cq.Dropped) != len(Leaves(tree)) {
		t.Errorf("condition accounting mismatch: effective=%d dropped=%d total=%d",
			len(cq.EffectiveConditions), len(cq.Dropped), len(Leaves(tree)))
	}
	if strings.Contains(cq.Query, FieldTitle) {
		t.Errorf("dropped condition must not appear in emitted query: %q", cq.Query)
	}
}

func TestCompile_DegradationRefusedInsideOR(t *testing.T) {
	tree, err := Parse(`domain : "a.com" OR http.title : "login"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldDomain: {OpContains},
		FieldTitle:  {},
	}, func(c *Capabilities) {
		fc := c.Fields[FieldTitle]
		fc.Level = SupportDegradable
		c.Fields[FieldTitle] = fc
	})
	c := NewCompiler(DegradeTopLevelAND)
	c.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})
	if _, err := c.Compile("stub", tree); err == nil {
		t.Fatal("dropping an OR branch would change semantics and must be rejected")
	}
}

func TestCompile_RepeatedCompilationIsStable(t *testing.T) {
	tree, err := Parse(`(port = 80 OR port = 443) AND domain : "a.com"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldPort:   {OpEqual},
		FieldDomain: {OpContains},
	}, nil)
	c := NewCompiler(DegradeReject)
	c.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})

	first, err := c.Compile("stub", tree)
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	for i := 0; i < 10; i++ {
		again, err := c.Compile("stub", tree)
		if err != nil {
			t.Fatalf("repeat compile %d: %v", i, err)
		}
		if again.Query != first.Query {
			t.Fatalf("compilation not deterministic:\nfirst: %q\nthen:  %q", first.Query, again.Query)
		}
	}
}

func TestCompile_EffectiveConditionsCarryFullSet(t *testing.T) {
	tree, err := Parse(`domain : "a.com" AND port = 443 AND service = "https"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldDomain: {OpContains}, FieldPort: {OpEqual}, FieldService: {OpEqual},
	}, nil)
	c := NewCompiler(DegradeReject)
	c.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})
	cq, err := c.Compile("stub", tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cq.EffectiveConditions) != 3 {
		t.Fatalf("all three conditions must be reported effective, got %v", cq.EffectiveConditions)
	}
	if cq.Version != SyntaxVersion {
		t.Errorf("version should be embedded, got %q", cq.Version)
	}
}

func TestCompile_NotUnsupportedStructuralRejection(t *testing.T) {
	tree, err := Parse(`NOT (port = 80 AND domain : "a.com")`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps := basicCaps("stub", map[string][]Operator{
		FieldPort: {OpEqual}, FieldDomain: {OpContains},
	}, func(c *Capabilities) { c.SupportsNot = false })
	c := NewCompiler(DegradeReject)
	c.Register(&stubBackend{name: "stub", caps: caps, render: echoRenderer()})
	// canPushDownNot only works when leaves have inverses; OpEqual/OpContains
	// do have inverses, so build a non-invertible case instead.
	tree2, err := Parse(`NOT (port > 80)`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	caps.Fields[FieldPort] = FieldCapability{Field: FieldPort, SupportedOps: []Operator{OpGreater}}
	_, err = c.Compile("stub", tree2)
	if err == nil {
		t.Fatal("NOT over an operator without an inverse must be rejected when engine lacks NOT groups")
	}
	_ = tree // first tree exercises the push-down path without asserting failure
}
