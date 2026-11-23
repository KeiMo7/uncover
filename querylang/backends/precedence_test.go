package backends

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/uncover/querylang"
)

// Mixed AND/OR nesting must survive compilation with parentheses so the
// emitted native query has the same precedence as the parsed tree.
func TestBackends_PreserveBooleanPrecedence(t *testing.T) {
	q := `(port = 80 OR port = 443) AND domain : "example.com"`
	for _, b := range []querylang.Backend{Shodan(), Censys(), Fofa(), Quake(), ZoomEye(), Netlas()} {
		cq := compile(t, b, q)
		if !strings.Contains(cq.Query, "(") || !strings.Contains(cq.Query, ")") {
			t.Errorf("%s: OR group lost its parentheses: %q", b.Name(), cq.Query)
		}
	}
}

// The OR-looser-than-AND default precedence must also be parenthesized when
// the OR group is nested below an explicit AND.
func TestBackends_DefaultPrecedenceParens(t *testing.T) {
	q := `domain : "example.com" AND (port = 80 OR port = 443)`
	for _, b := range []querylang.Backend{Shodan(), Fofa(), Quake()} {
		cq := compile(t, b, q)
		open := strings.Index(cq.Query, "(")
		closeIdx := strings.Index(cq.Query, ")")
		if open < 0 || closeIdx < 0 || open > closeIdx {
			t.Errorf("%s: expected a parenthesized OR group, got %q", b.Name(), cq.Query)
		}
	}
}

// Cert fingerprint and issuer org shapes must compile on the engines that
// claim full support and be rejected or explicitly degraded elsewhere.
func TestBackends_CertificateShapes(t *testing.T) {
	q := `cert.fingerprint = "AA:BB:CC" AND cert.issuer_org : "Let's Encrypt"`
	fullySupported := []querylang.Backend{Shodan(), Censys(), Quake(), ZoomEye(), Netlas()}
	for _, b := range fullySupported {
		cq := compile(t, b, q)
		if !strings.Contains(strings.ToLower(cq.Query), "aa:bb:cc") {
			t.Errorf("%s: fingerprint constraint missing: %q", b.Name(), cq.Query)
		}
	}
	// GreyNoise has no certificate fields at all: hard rejection.
	mustReject(t, GreyNoise(), q)

	// FOFA/Hunter only offer generic cert content: rejection under the
	// default policy, recorded degradation when explicitly allowed.
	tree, err := querylang.Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	rejectC := querylang.NewCompiler(querylang.DegradeReject)
	rejectC.Register(Fofa())
	if _, err := rejectC.Compile("fofa", tree); err == nil {
		t.Fatal("fofa fingerprint must be rejected under DegradeReject")
	}
	degradeC := querylang.NewCompiler(querylang.DegradeTopLevelAND)
	degradeC.Register(Fofa())
	cq, err := degradeC.Compile("fofa", tree)
	if err != nil {
		t.Fatalf("fofa should compile under degrade policy: %v", err)
	}
	if !cq.Degraded || len(cq.Dropped) != 1 {
		t.Fatalf("expected exactly one recorded drop, got %+v", cq.Dropped)
	}
	if strings.Contains(cq.Query, "AA:BB:CC") {
		t.Errorf("dropped fingerprint must not be emitted: %q", cq.Query)
	}
}

// Time range compiles to each engine's native interval spelling.
func TestBackends_TimeRange(t *testing.T) {
	q := `last_seen BETWEEN "2024-01-01" AND "2024-06-30"`
	cq := compile(t, Quake(), q)
	if !strings.Contains(cq.Query, `time:["2024-01-01T00:00:00Z" TO "2024-06-30T00:00:00Z"]`) {
		t.Errorf("quake time range wrong: %q", cq.Query)
	}
	cq = compile(t, Censys(), q)
	if !strings.Contains(cq.Query, "last_observed_at: {start:") {
		t.Errorf("censys time range wrong: %q", cq.Query)
	}
}

// The same canonical domain condition must render through each engine's own
// field table — a shared renderer must never leak one engine's native field
// name into another engine's query string.
func TestBackends_FieldTablesDoNotLeak(t *testing.T) {
	q := `domain = "example.com"`
	expected := map[string]string{
		"shodan":  `hostname:"example.com"`,
		"quake":   `domain:"example.com"`,
		"zoomeye": `hostname:"example.com"`,
		"netlas":  `domain:"example.com"`,
		"fofa":    `domain="example.com"`,
		"censys":  `dns.names: "example.com"`,
		"hunter":  `domain="example.com"`,
	}
	engines := map[string]querylang.Backend{
		"shodan": Shodan(), "quake": Quake(), "zoomeye": ZoomEye(),
		"netlas": Netlas(), "fofa": Fofa(), "censys": Censys(), "hunter": Hunter(),
	}
	for name, b := range engines {
		cq := compile(t, b, q)
		if !strings.Contains(cq.Query, expected[name]) {
			t.Errorf("%s: expected %q in native query, got %q", name, expected[name], cq.Query)
		}
	}
}
