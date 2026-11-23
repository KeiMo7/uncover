package querylang

import (
	"strings"
	"testing"
)

func TestParse_PrecedenceAndParens(t *testing.T) {
	// OR binds looser than AND; parentheses override.
	tree, err := Parse(`port = 80 AND domain = "a.com" OR service = "ssh"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	orNode, ok := tree.(*LogicalNode)
	if !ok || orNode.Op != Or || len(orNode.Children) != 2 {
		t.Fatalf("expected root OR with 2 children, got %#v", tree)
	}
	if _, ok := orNode.Children[0].(*LogicalNode); !ok {
		t.Fatalf("expected first OR child to be an AND group")
	}

	parened, err := Parse(`port = 80 AND (domain = "a.com" OR service = "ssh")`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rootAnd, ok := parened.(*LogicalNode)
	if !ok || rootAnd.Op != And {
		t.Fatalf("parens should make AND the root")
	}
	if _, ok := rootAnd.Children[1].(*LogicalNode); !ok {
		t.Fatalf("second AND child should be the parenthesized OR group")
	}
}

func TestParse_ImplicitANDAndNOT(t *testing.T) {
	tree, err := Parse(`domain : "example.com" NOT port = 22`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	and, ok := tree.(*LogicalNode)
	if !ok || and.Op != And || len(and.Children) != 2 {
		t.Fatalf("implicit AND expected, got %#v", tree)
	}
	if _, ok := and.Children[1].(*NotNode); !ok {
		t.Fatalf("second child should be NOT node")
	}
}

func TestParse_AllRequiredShapes(t *testing.T) {
	queries := []string{
		`domain = "example.com"`,
		`subdomain : "edge.example.com"`,
		`hostname = "host.example.com"`,
		`ip = "10.0.0.1"`,
		`cidr = "10.0.0.0/24"`,
		`ip_range BETWEEN "10.0.0.1" AND "10.0.0.50"`,
		`port = 443`,
		`port_range BETWEEN 8000 AND 8100`,
		`protocol = "tcp"`,
		`service = "http"`,
		`http.title : "login"`,
		`http.header : "nginx"`,
		`cert.fingerprint = "AA:BB:CC"`,
		`cert.issuer_org : "Let's Encrypt"`,
		`last_seen BETWEEN "2024-01-01" AND "2024-06-30"`,
		`port IN (80, 443, 8080)`,
		`(port = 80 OR port = 443) AND domain : "example.com"`,
	}
	for _, q := range queries {
		if _, err := Parse(q); err != nil {
			t.Errorf("expected parse success for %q: %v", q, err)
		}
	}
}

func TestParse_ErrorHasPositionAndReason(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{`domain =`, "requires a value"},
		{`port = "nginx"`, "does not accept string values"},
		{`bogusfield = "x"`, "unknown field"},
		{`(port = 80`, "missing closing"},
		{`domain = "unterminated`, "unterminated string"},
		{`port ~ 80`, "not valid for field"},
	}
	for _, tc := range cases {
		_, err := Parse(tc.query)
		if err == nil {
			t.Errorf("expected error for %q", tc.query)
			continue
		}
		pe, ok := err.(*ParseError)
		if !ok {
			t.Errorf("error for %q is not *ParseError: %T", tc.query, err)
			continue
		}
		if pe.Line < 1 || pe.Column < 1 {
			t.Errorf("error for %q lacks a line/column position: %v", tc.query, pe)
		}
		if !strings.Contains(pe.Error(), tc.want) {
			t.Errorf("error %q for %q does not mention %q", pe.Error(), tc.query, tc.want)
		}
		if pe.Caret() == "" || !strings.Contains(pe.Caret(), "^") {
			t.Errorf("caret rendering missing for %q: %q", tc.query, pe.Caret())
		}
	}
}

func TestParse_FieldAliasesResolveToCanonical(t *testing.T) {
	tree, err := Parse(`title : "x" AND html : "y"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	leaves := Leaves(tree)
	if leaves[0].Field != FieldTitle {
		t.Errorf("title alias -> %s, want %s", leaves[0].Field, FieldTitle)
	}
	if leaves[1].Field != FieldBody {
		t.Errorf("html alias -> %s, want %s", leaves[1].Field, FieldBody)
	}
}

func TestParse_RoundTripStable(t *testing.T) {
	q := `(port = 80 OR port = 443) AND domain : "example.com" NOT service = "ftp"`
	tree, err := Parse(q)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	first := tree.String()
	tree2, err := Parse(first)
	if err != nil {
		t.Fatalf("re-parse rendered tree: %v", err)
	}
	if tree2.String() != first {
		t.Errorf("round trip not stable:\nfirst:  %s\nsecond: %s", first, tree2.String())
	}
}
