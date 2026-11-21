package uncover

import (
	"context"
	"errors"
	"testing"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

// scriptedAgent is a mock engine that replays a fixed script: it either
// fails at query time, or streams its results (which may themselves carry
// errors) and closes the channel.
type scriptedAgent struct {
	name      string
	queryErr  error
	results   []sources.Result
	resultErr error // attached to every streamed result when set
}

func (a *scriptedAgent) Name() string { return a.name }

func (a *scriptedAgent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if a.queryErr != nil {
		return nil, a.queryErr
	}
	ch := make(chan sources.Result)
	go func() {
		defer close(ch)
		for _, r := range a.results {
			r.Source = a.name
			if a.resultErr != nil {
				r.Error = a.resultErr
			}
			if !sources.SendResult(ctx, ch, r) {
				return
			}
		}
	}()
	return ch, nil
}

// anonymous engine names, so the service does not demand provider keys
const (
	engineA = "shodan-idb"
	engineB = "scanmalware"
	engineC = "subdomaincenter"
)

func newMergeService(t *testing.T, agents ...sources.Agent) *Service {
	t.Helper()
	names := make([]string, 0, len(agents))
	for _, a := range agents {
		names = append(names, a.Name())
	}
	return &Service{
		Agents:   agents,
		Options:  &Options{Agents: names, Queries: []string{"test"}},
		Provider: &sources.Provider{},
		Session:  &sources.Session{},
	}
}

func engineStates(merged *sources.MergeResult) map[string]sources.EngineReport {
	states := map[string]sources.EngineReport{}
	for _, e := range merged.Engines {
		states[e.Name] = e
	}
	return states
}

// Scenario 1: a single engine. Assets carry that engine as their only
// source with confidence 1.
func TestExecuteMerged_SingleEngine(t *testing.T) {
	svc := newMergeService(t, &scriptedAgent{
		name: engineA,
		results: []sources.Result{
			{IP: "1.1.1.1", Port: 80},
			{IP: "2.2.2.2", Port: 443},
		},
	})

	merged, err := svc.ExecuteMerged(context.Background())
	require.NoError(t, err)
	require.Len(t, merged.Assets, 2)
	for _, asset := range merged.Assets {
		require.Equal(t, []string{engineA}, asset.Sources)
		require.Equal(t, 1, asset.Confidence())
	}
	require.Equal(t, sources.EngineStateOK, engineStates(merged)[engineA].State)
}

// Scenario 2: multiple engines. The same asset reported by three engines
// merges into one entry keeping all three sources, and assets are ordered
// by confidence (engine count), not by return order.
func TestExecuteMerged_MultiEngineConfidenceOrdering(t *testing.T) {
	svc := newMergeService(t,
		&scriptedAgent{name: engineA, results: []sources.Result{
			{IP: "1.1.1.1", Port: 80},
			{IP: "3.3.3.3", Port: 22},
		}},
		&scriptedAgent{name: engineB, results: []sources.Result{
			{IP: "1.1.1.1", Port: 80},
			{IP: "2.2.2.2", Port: 443},
		}},
		&scriptedAgent{name: engineC, results: []sources.Result{
			// different surface form of the same asset: scheme + default port
			{Url: "http://1.1.1.1", Host: "1.1.1.1"},
			{IP: "2.2.2.2", Port: 443},
		}},
	)

	merged, err := svc.ExecuteMerged(context.Background())
	require.NoError(t, err)
	require.Len(t, merged.Assets, 3)

	// confidence ordering: 3 engines > 2 engines > 1 engine
	require.Equal(t, 3, merged.Assets[0].Confidence())
	require.Equal(t, []string{engineB, engineA, engineC}, merged.Assets[0].Sources) // sorted
	require.Equal(t, "1.1.1.1:80", merged.Assets[0].Key)

	require.Equal(t, 2, merged.Assets[1].Confidence())
	require.ElementsMatch(t, []string{engineB, engineC}, merged.Assets[1].Sources)

	require.Equal(t, 1, merged.Assets[2].Confidence())
	require.Equal(t, []string{engineA}, merged.Assets[2].Sources)

	for _, e := range merged.Engines {
		require.Equal(t, sources.EngineStateOK, e.State)
	}
}

// Scenario 3: one engine fails, the others are unaffected and still merge.
func TestExecuteMerged_OneEngineFails(t *testing.T) {
	svc := newMergeService(t,
		&scriptedAgent{name: engineA, results: []sources.Result{{IP: "1.1.1.1", Port: 80}}},
		&scriptedAgent{name: engineB, queryErr: errors.New("upstream timeout")},
		&scriptedAgent{name: engineC, results: []sources.Result{{IP: "1.1.1.1", Port: 80}}},
	)

	merged, err := svc.ExecuteMerged(context.Background())
	require.NoError(t, err)
	require.Len(t, merged.Assets, 1)
	require.ElementsMatch(t, []string{engineA, engineC}, merged.Assets[0].Sources)

	states := engineStates(merged)
	require.Equal(t, sources.EngineStateOK, states[engineA].State)
	require.Equal(t, sources.EngineStateError, states[engineB].State)
	require.Contains(t, states[engineB].Err, "upstream timeout")
	require.Equal(t, sources.EngineStateOK, states[engineC].State)
}

// Scenario 3b: an engine that answers but returns nothing is reported as
// empty, distinct from an engine that errored.
func TestExecuteMerged_EmptyEngineDistinctFromError(t *testing.T) {
	svc := newMergeService(t,
		&scriptedAgent{name: engineA, results: []sources.Result{{IP: "1.1.1.1", Port: 80}}},
		&scriptedAgent{name: engineB, results: nil},
		&scriptedAgent{name: engineC, queryErr: errors.New("boom")},
	)

	merged, err := svc.ExecuteMerged(context.Background())
	require.NoError(t, err)
	states := engineStates(merged)
	require.Equal(t, sources.EngineStateEmpty, states[engineB].State)
	require.Empty(t, states[engineB].Err)
	require.Equal(t, sources.EngineStateError, states[engineC].State)
}

// Scenario 4: every engine fails. The run reports an explicit error instead
// of silently producing an empty list.
func TestExecuteMerged_AllEnginesFail(t *testing.T) {
	svc := newMergeService(t,
		&scriptedAgent{name: engineA, queryErr: errors.New("timeout")},
		&scriptedAgent{name: engineB, resultErr: errors.New("bad gateway"), results: []sources.Result{{IP: "1.1.1.1", Port: 80}}},
		&scriptedAgent{name: engineC, queryErr: errors.New("keys rejected")},
	)

	merged, err := svc.ExecuteMerged(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "all engines failed")
	require.NotNil(t, merged)
	require.Empty(t, merged.Assets)
	for _, e := range merged.Engines {
		require.Equal(t, sources.EngineStateError, e.State)
	}
}

// Malformed results are skipped and counted, not merged.
func TestExecuteMerged_MalformedSkippedAndCounted(t *testing.T) {
	svc := newMergeService(t, &scriptedAgent{
		name: engineA,
		results: []sources.Result{
			{IP: "1.1.1.1", Port: 80},
			{}, // no identity at all
			{},
		},
	})

	merged, err := svc.ExecuteMerged(context.Background())
	require.NoError(t, err)
	require.Len(t, merged.Assets, 1)
	require.Equal(t, 2, engineStates(merged)[engineA].Malformed)
}

// Same inputs twice must produce byte-identical output lines.
func TestExecuteMerged_DeterministicOutput(t *testing.T) {
	newSvc := func() *Service {
		return newMergeService(t,
			&scriptedAgent{name: engineA, results: []sources.Result{
				{IP: "1.1.1.1", Port: 80}, {IP: "2.2.2.2", Port: 443}, {IP: "3.3.3.3", Port: 22},
			}},
			&scriptedAgent{name: engineB, results: []sources.Result{
				{IP: "2.2.2.2", Port: 443}, {IP: "1.1.1.1", Port: 80},
			}},
			&scriptedAgent{name: engineC, results: []sources.Result{
				{IP: "1.1.1.1", Port: 80},
			}},
		)
	}

	render := func(merged *sources.MergeResult) []string {
		lines := make([]string, 0, len(merged.Assets))
		for i := range merged.Assets {
			lines = append(lines, merged.Assets[i].JSON())
		}
		return lines
	}

	first, err := newSvc().ExecuteMerged(context.Background())
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		next, err := newSvc().ExecuteMerged(context.Background())
		require.NoError(t, err)
		require.Equal(t, render(first), render(next))
	}
}

// Benchmarks: same-scale input through the default streaming path and the
// merged path, to quantify the cost of provenance-keeping.
func benchmarkService() *Service {
	results := make([]sources.Result, 0, 1000)
	for i := 0; i < 1000; i++ {
		results = append(results, sources.Result{IP: "10.0.0.1", Port: i%50 + 1, Host: "example.com"})
	}
	return &Service{
		Agents: []sources.Agent{
			&scriptedAgent{name: engineA, results: results},
			&scriptedAgent{name: engineB, results: results},
			&scriptedAgent{name: engineC, results: results},
		},
		Options:  &Options{Agents: []string{engineA, engineB, engineC}, Queries: []string{"test"}},
		Provider: &sources.Provider{},
		Session:  &sources.Session{},
	}
}

func BenchmarkExecuteDefault(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ch, err := benchmarkService().Execute(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		for range ch { //nolint
		}
	}
}

func BenchmarkExecuteMerged(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := benchmarkService().ExecuteMerged(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
