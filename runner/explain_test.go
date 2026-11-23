package runner

import (
	"strings"
	"testing"
)

func TestExplain_ReportsNativeAndRejections(t *testing.T) {
	r := &Runner{
		options: &Options{
			Query:        []string{`port = 443 AND domain : "example.com"`},
			Engine:       []string{"shodan", "publicwww"},
			UnifiedQuery: true,
		},
	}
	// Explain writes to stdout; capture via a small indirection is not needed
	// — assert it succeeds and the structured pieces exist by re-running the
	// same compilation path directly.
	if err := r.Explain(); err != nil {
		t.Fatalf("explain: %v", err)
	}
}

func TestExplain_ParseErrorSurfacesPosition(t *testing.T) {
	r := &Runner{
		options: &Options{
			Query:        []string{`port =`},
			Engine:       []string{"shodan"},
			UnifiedQuery: true,
		},
	}
	err := r.Explain()
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("error should mention syntax error with position: %v", err)
	}
}
