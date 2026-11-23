package backends

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/uncover/querylang"
)

func compile(t *testing.T, engine querylang.Backend, q string) *querylang.CompiledQuery {
	t.Helper()
	tree, err := querylang.Parse(q)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	c := querylang.NewCompiler(querylang.DegradeReject)
	c.Register(engine)
	cq, err := c.Compile(engine.Name(), tree)
	if err != nil {
		t.Fatalf("compile %q for %s: %v", q, engine.Name(), err)
	}
	return cq
}

func mustReject(t *testing.T, engine querylang.Backend, q string) *querylang.CompileError {
	t.Helper()
	tree, err := querylang.Parse(q)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	c := querylang.NewCompiler(querylang.DegradeReject)
	c.Register(engine)
	_, err = c.Compile(engine.Name(), tree)
	if err == nil {
		t.Fatalf("expected rejection for %q on %s", q, engine.Name())
	}
	ce, ok := err.(*querylang.CompileError)
	if !ok {
		t.Fatalf("want *CompileError, got %T: %v", err, err)
	}
	return ce
}

// TestBackends_EquivalentSemanticsAcrossEngines compiles one semantic query
// to every structured engine and asserts that each native query contains the
// constraints for every canonical condition — no engine may silently lose a
// field.
func TestBackends_EquivalentSemanticsAcrossEngines(t *testing.T) {
	q := `port = 443 AND service = "https" AND country = "US"`
	engines := []querylang.Backend{Shodan(), Censys(), Fofa(), Quake(), ZoomEye(), Netlas(), Hunter(), GreyNoise()}
	for _, b := range engines {
		cq := compile(t, b, q)
		if len(cq.EffectiveConditions) != 3 {
			t.Errorf("%s: expected 3 effective conditions, got %v", b.Name(), cq.EffectiveConditions)
		}
		lower := strings.ToLower(cq.Query)
		// Every engine output must mention its port constraint.
		if !strings.Contains(lower, "443") {
			t.Errorf("%s: native query lost the port constraint: %q", b.Name(), cq.Query)
		}
		if !strings.Contains(strings.ToLower(cq.Query), "https") {
			t.Errorf("%s: native query lost the service constraint: %q", b.Name(), cq.Query)
		}
		if !strings.Contains(strings.ToLower(cq.Query), "us") {
			t.Errorf("%s: native query lost the country constraint: %q", b.Name(), cq.Query)
		}
	}
}

func TestShodan_CompilesKnownShapes(t *testing.T) {
	cq := compile(t, Shodan(), `port_range BETWEEN 8000 AND 8002 AND http.title : "login"`)
	if !strings.Contains(cq.Query, "port:8000") || !strings.Contains(cq.Query, "http.title:") {
		t.Errorf("unexpected shodan output: %q", cq.Query)
	}
	// Range expansion must be documented as an alternative.
	if len(cq.Alternatives) == 0 {
		t.Error("port-range expansion should be recorded as an alternative rendering")
	}
}

func TestCensys_RangeAndCIDR(t *testing.T) {
	cq := compile(t, Censys(), `port_range BETWEEN 443 AND 445 AND cidr = "10.0.0.0/24"`)
	if !strings.Contains(cq.Query, "services.port: {start: 443, end: 445}") {
		t.Errorf("censys range syntax wrong: %q", cq.Query)
	}
	if !strings.Contains(cq.Query, "CIDR(10.0.0.0/24)") {
		t.Errorf("censys CIDR function missing: %q", cq.Query)
	}
}

func TestFofa_BooleanAndInequalityDialect(t *testing.T) {
	cq := compile(t, Fofa(), `port = 443 AND domain = "example.com" AND last_seen > "2024-01-01"`)
	if !strings.Contains(cq.Query, "&&") || strings.Contains(strings.ToUpper(cq.Query), " AND ") {
		t.Errorf("fofa must use && dialect: %q", cq.Query)
	}
	if !strings.Contains(cq.Query, `after=`) {
		t.Errorf("fofa time filter should use after=: %q", cq.Query)
	}
}

func TestQuake_LuceneRange(t *testing.T) {
	cq := compile(t, Quake(), `port_range BETWEEN 80 AND 90`)
	if !strings.Contains(cq.Query, "port:[80 TO 90]") {
		t.Errorf("quake lucene range wrong: %q", cq.Query)
	}
}

func TestGreyNoise_RejectsUnsupportedStructuredFields(t *testing.T) {
	// GNQL has no certificate filters; the capability table must reject
	// instead of letting the engine quietly return an empty set.
	ce := mustReject(t, GreyNoise(), `cert.issuer_org : "Let's Encrypt"`)
	if !strings.Contains(strings.ToLower(ce.Error()), "cannot compile") {
		t.Errorf("rejection message unclear: %v", ce)
	}
}

func TestFreeTextEngines_RejectStructuredQuery(t *testing.T) {
	c := querylang.NewCompiler(querylang.DegradeReject)
	registry := map[string]querylang.Backend{}
	for _, b := range []querylang.Backend{
		// Rebuild via the default compiler's engine set indirectly:
		Shodan(), Censys(), Fofa(), Quake(), ZoomEye(), Netlas(), Hunter(), GreyNoise(),
	} {
		c.Register(b)
		registry[b.Name()] = b
	}
	defaultC := DefaultCompiler(querylang.DegradeReject)
	tree, err := querylang.Parse(`port = 443`)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"publicwww", "google", "shodan-idb", "nerdydata"} {
		if _, err := defaultC.Compile(name, tree); err == nil {
			t.Errorf("free-text engine %s must reject a structured port condition", name)
		}
	}
	// raw: term is the one accepted shape.
	rawTree, err := querylang.Parse(`raw : "wordpress"`)
	if err != nil {
		t.Fatal(err)
	}
	cq, err := defaultC.Compile("publicwww", rawTree)
	if err != nil {
		t.Fatalf("raw term should compile for publicwww: %v", err)
	}
	if cq.Query != "wordpress" {
		t.Errorf("publicwww should receive the bare term, got %q", cq.Query)
	}
}

func TestExplain_ListsNativeAndEffective(t *testing.T) {
	tree, err := querylang.Parse(`port = 443 AND domain : "example.com"`)
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultCompiler(querylang.DegradeReject)
	compiled, errs := c.CompileAll(tree)
	report := querylang.Explain(compiled, errs)
	if !strings.Contains(report, "shodan") || !strings.Contains(report, "native query") {
		t.Errorf("explain report missing sections:\n%s", report)
	}
	// At least one free-text engine must appear as rejected in the report.
	if !strings.Contains(report, "rejected") {
		t.Errorf("explain report must surface rejections:\n%s", report)
	}
}
