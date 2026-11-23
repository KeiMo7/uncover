package uncover

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

// fakeAgent records the exact native query string it received and returns a
// scripted stream, so tests can assert what each engine was actually sent.
type fakeAgent struct {
	name      string
	mu        sync.Mutex
	received  []string
	effective [][]string
	produce   []sources.Result
	queryErr  error
}

func (f *fakeAgent) Name() string { return f.name }

func (f *fakeAgent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	f.mu.Lock()
	f.received = append(f.received, query.Query)
	f.effective = append(f.effective, append([]string(nil), query.EffectiveConditions...))
	produce := append([]sources.Result(nil), f.produce...)
	queryErr := f.queryErr
	name := f.name
	f.mu.Unlock()

	if queryErr != nil {
		return nil, queryErr
	}
	ch := make(chan sources.Result)
	go func() {
		defer close(ch)
		for _, r := range produce {
			r.Source = name
			if !sources.SendResult(ctx, ch, r) {
				return
			}
		}
	}()
	return ch, nil
}

func (f *fakeAgent) queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

// newFake builds a fake agent whose Name selects the querylang backend whose
// dialect is compiled. The test service disables the real key gate.
func newFake(engine string, produce ...sources.Result) *fakeAgent {
	return &fakeAgent{name: engine, produce: produce}
}

func newFakeErr(engine string, queryErr error) *fakeAgent {
	return &fakeAgent{name: engine, queryErr: queryErr}
}

func newUnifiedService(agents ...sources.Agent) *Service {
	return &Service{
		Agents:      agents,
		Provider:    &sources.Provider{},
		Session:     &sources.Session{},
		skipKeyGate: true,
		Options: &Options{
			Agents:  []string{"shodan-idb"},
			Queries: []string{},
			Unified: true,
			Limit:   10,
		},
	}
}

func drain(t *testing.T, ch <-chan sources.Result) []sources.Result {
	t.Helper()
	var out []sources.Result
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, r)
		case <-ctx.Done():
			t.Fatal("timed out draining result channel")
		}
	}
}

// The same semantic query must be compiled into each engine's dialect and the
// exact strings recorded on the fake agents.
func TestUnified_FanOutCompilesPerEngine(t *testing.T) {
	shodanFake := newFake("shodan", sources.Result{IP: "1.1.1.1", Port: 443})
	fofaFake := newFake("fofa", sources.Result{IP: "2.2.2.2", Port: 443})

	s := newUnifiedService(shodanFake, fofaFake)
	s.Options.Queries = []string{`domain : "example.com" AND port = 443`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	shodanQueries := shodanFake.queries()
	fofaQueries := fofaFake.queries()
	require.Len(t, shodanQueries, 1)
	require.Len(t, fofaQueries, 1)

	// Shodan dialect: filter:value space-joined.
	require.Contains(t, shodanQueries[0], `hostname:"example.com"`)
	require.Contains(t, shodanQueries[0], "port:443")
	// FOFA dialect: contains uses *=, equality uses =, joined by &&.
	require.Contains(t, fofaQueries[0], `domain*="example.com"`)
	require.Contains(t, fofaQueries[0], `port=443`)
	require.Contains(t, fofaQueries[0], "&&")

	// Every asset record carries the effective condition summary.
	var assets []sources.Result
	for _, r := range results {
		if r.Status == sources.StatusAsset {
			assets = append(assets, r)
			require.NotEmpty(t, r.EffectiveConditions)
			require.Equal(t, "uql/v1", r.SyntaxVersion)
		}
	}
	require.Len(t, assets, 2)
}

// A structured condition an engine cannot express must be rejected before the
// agent is ever called — the fake agent must record zero received queries.
func TestUnified_UnsupportedConditionRejectedNotIgnored(t *testing.T) {
	// greynoise has no certificate field support.
	gnFake := newFake("greynoise")
	shodanFake := newFake("shodan", sources.Result{IP: "1.1.1.1", Port: 443})

	s := newUnifiedService(gnFake, shodanFake)
	s.Options.Queries = []string{`cert.issuer_org : "Let's Encrypt"`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	var rejected []sources.Result
	for _, r := range results {
		if r.Status == sources.StatusCompileRejected {
			rejected = append(rejected, r)
		}
	}
	require.NotEmpty(t, rejected, "expected a compile_rejected status entry")
	require.Equal(t, "greynoise", rejected[0].Source)
	require.Contains(t, rejected[0].Message, "cannot compile")

	// The rejected engine must never have been called.
	require.Empty(t, gnFake.queries(), "unsupported engine must not receive any query")
	// The capable engine still runs.
	require.Len(t, shodanFake.queries(), 1)
}

// With AllowDegrade, an unsupported top-level AND conjunct is dropped with an
// explicit degraded notice naming the dropped condition.
func TestUnified_DegradationNamesDroppedCondition(t *testing.T) {
	// hunter marks the certificate fingerprint filter as degradable.
	hunterFake := newFake("hunter", sources.Result{IP: "3.3.3.3", Port: 443})

	s := newUnifiedService(hunterFake)
	s.Options.AllowDegrade = true
	s.Options.Queries = []string{`domain = "example.com" AND cert.fingerprint = "AA:BB:CC"`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	var degraded []sources.Result
	var assets []sources.Result
	for _, r := range results {
		switch r.Status {
		case sources.StatusDegraded:
			degraded = append(degraded, r)
		case sources.StatusAsset:
			assets = append(assets, r)
		}
	}
	require.NotEmpty(t, degraded, "expected an explicit degradation notice")
	require.NotEmpty(t, degraded[0].DroppedConditions)
	require.Contains(t, degraded[0].DroppedConditions[0], "cert.fingerprint")
	require.Len(t, assets, 1)

	received := hunterFake.queries()
	require.Len(t, received, 1)
	require.NotContains(t, received[0], "AA:BB:CC", "dropped condition must not be sent")
	require.Contains(t, received[0], "example.com", "kept condition must still be sent")
}

// An engine runtime error must surface as engine_error and never be confused
// with an empty result set.
func TestUnified_EngineErrorNotMasqueradingAsEmpty(t *testing.T) {
	boom := newFakeErr("shodan", errors.New("upstream 500"))
	s := newUnifiedService(boom)
	s.Options.Queries = []string{`port = 443`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	var engineErrors, empties []sources.Result
	for _, r := range results {
		switch r.Status {
		case sources.StatusEngineError:
			engineErrors = append(engineErrors, r)
		case sources.StatusEmpty:
			empties = append(empties, r)
		}
	}
	require.NotEmpty(t, engineErrors)
	require.Empty(t, empties)
	require.Contains(t, engineErrors[0].Message, "upstream 500")
}

// A successful engine call with zero assets produces an explicit empty
// status, distinct from an error.
func TestUnified_EmptyResultDistinctFromError(t *testing.T) {
	empty := newFake("shodan")
	s := newUnifiedService(empty)
	s.Options.Queries = []string{`port = 443`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	var sawEmpty, sawError bool
	for _, r := range results {
		if r.Status == sources.StatusEmpty {
			sawEmpty = true
			require.NotEmpty(t, r.EffectiveQuery)
		}
		if r.Status == sources.StatusEngineError {
			sawError = true
		}
	}
	require.True(t, sawEmpty)
	require.False(t, sawError)
}

// A syntax error is reported once with its position and no engine is called.
func TestUnified_SyntaxErrorPreventsFanOut(t *testing.T) {
	a := newFake("shodan")
	b := newFake("fofa")
	s := newUnifiedService(a, b)
	s.Options.Queries = []string{`domain =`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	var rejected []sources.Result
	for _, r := range results {
		if r.Status == sources.StatusCompileRejected {
			rejected = append(rejected, r)
		}
	}
	require.NotEmpty(t, rejected)
	require.Empty(t, a.queries())
	require.Empty(t, b.queries())
}

// Partial coverage: one engine rejects, another succeeds; the coverage event
// names both sets.
func TestUnified_CoverageEventReportsPartialCoverage(t *testing.T) {
	gn := newFake("greynoise")
	shodanFake := newFake("shodan", sources.Result{IP: "1.1.1.1"})
	s := newUnifiedService(gn, shodanFake)
	s.Options.Queries = []string{`cert.issuer_org : "x"`}

	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	var coverageMsg string
	for _, r := range results {
		if r.Source == "coverage" {
			coverageMsg = r.Message
		}
	}
	require.NotEmpty(t, coverageMsg)
	require.Contains(t, coverageMsg, `"engines_rejected":["greynoise"]`)
	require.Contains(t, coverageMsg, `"engines_ok":["shodan"]`)
}

// Raw passthrough mode must be untouched: no compilation metadata, the query
// string forwarded exactly.
func TestRawPassthrough_UnchangedBehavior(t *testing.T) {
	shodanFake := newFake("shodan", sources.Result{IP: "1.1.1.1"})
	s := &Service{
		Agents:      []sources.Agent{shodanFake},
		Provider:    &sources.Provider{},
		Session:     &sources.Session{},
		skipKeyGate: true,
		Options: &Options{
			Unified: false,
			Agents:  []string{"shodan-idb"}, // anonymous provider bypasses key check
			Queries: []string{`weird:raw syntax that is not UQL`},
			Limit:   10,
		},
	}
	ch, err := s.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)
	require.Equal(t, []string{"weird:raw syntax that is not UQL"}, shodanFake.queries())
	for _, r := range results {
		require.Empty(t, r.EffectiveConditions)
		require.Empty(t, r.SyntaxVersion)
	}
}
