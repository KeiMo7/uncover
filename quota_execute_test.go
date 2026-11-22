package uncover

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
	"github.com/stretchr/testify/require"
)

// quotaMockAgent is a test engine whose Query charges the shared quota the
// same way a real engine's Session.Do does. This lets Execute-level tests
// model quota behaviour without network access.
type quotaMockAgent struct {
	name     string
	results  int
	queryErr error
	// calls counts how many times Query was invoked.
	calls atomic.Int64
	// charged records how many results were actually emitted.
	charged atomic.Int64
}

func (m *quotaMockAgent) Name() string { return m.name }

func (m *quotaMockAgent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	m.calls.Add(1)
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	ch := make(chan sources.Result)
	go func() {
		defer close(ch)
		for i := 0; i < m.results; i++ {
			// Model the quota layer: reserve, then commit or release.
			if session.Quota != nil {
				token, err := session.Quota.Acquire(m.name)
				if err != nil {
					sources.SendResult(ctx, ch, sources.Result{Source: m.name, Error: err})
					return
				}
				session.Quota.Commit(token)
			}
			select {
			case <-ctx.Done():
				return
			case ch <- sources.Result{Source: m.name, IP: "127.0.0.1", Port: 80}:
				m.charged.Add(1)
			}
		}
	}()
	return ch, nil
}

func newQuotaService(t *testing.T, cfg *sources.QuotaConfig, queries []string, agents ...*quotaMockAgent) *Service {
	t.Helper()
	names := make([]string, 0, len(agents))
	serviceAgents := make([]sources.Agent, 0, len(agents))
	for _, agent := range agents {
		names = append(names, agent.name)
		serviceAgents = append(serviceAgents, agent)
	}
	manager, err := sources.NewQuotaManager(cfg, names)
	require.NoError(t, err)
	return &Service{
		Agents:   serviceAgents,
		Options:  &Options{Agents: names, Queries: queries},
		Provider: &sources.Provider{Shodan: []string{"test-key"}},
		Session:  &sources.Session{Quota: manager},
		Quota:    manager,
	}
}

func drain(t *testing.T, ch <-chan sources.Result) []sources.Result {
	t.Helper()
	var out []sources.Result
	timeout := time.After(5 * time.Second)
	for {
		select {
		case res, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, res)
		case <-timeout:
			t.Fatal("timed out draining results")
			return out
		}
	}
}

func usageFor(t *testing.T, manager *sources.QuotaManager, engine string) sources.EngineUsage {
	t.Helper()
	return manager.Usage(engine)
}

func TestExecuteQuotaNormalMultiEngine(t *testing.T) {
	shodan := &quotaMockAgent{name: "shodan", results: 2}
	fofa := &quotaMockAgent{name: "fofa", results: 2}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{
			"shodan": {Limit: intPtr(10)},
			"fofa":   {Limit: intPtr(10)},
		},
	}, []string{"test"}, shodan, fofa)

	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)
	require.Len(t, results, 4)

	report := service.Report()
	require.NotNil(t, report)
	require.True(t, report.Enabled)
	require.ElementsMatch(t, []string{"shodan", "fofa"}, report.Participated)
	require.Empty(t, report.Skipped)
	for _, engine := range report.Engines {
		require.Equal(t, sources.StatusParticipated, engine.Status)
		require.Equal(t, 2, engine.CallsUsed)
		require.Equal(t, 8, *engine.Remaining)
	}
	require.Equal(t, 2, usageFor(t, service.Quota, "shodan").Used)
	require.Equal(t, 2, usageFor(t, service.Quota, "fofa").Used)
}

func TestExecuteQuotaSingleEngineExhaustedOthersContinue(t *testing.T) {
	shodan := &quotaMockAgent{name: "shodan", results: 5}
	fofa := &quotaMockAgent{name: "fofa", results: 3}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{
			// Enough for two calls only.
			"shodan": {Limit: intPtr(2)},
			"fofa":   {Limit: intPtr(10)},
		},
	}, []string{"test"}, shodan, fofa)

	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)

	// shodan emitted two results then hit its quota; fofa is unaffected.
	bySource := map[string]int{}
	for _, res := range results {
		if res.Error == nil {
			bySource[res.Source]++
		}
	}
	require.Equal(t, 2, bySource["shodan"])
	require.Equal(t, 3, bySource["fofa"], "single-engine exhaustion must not affect the others")

	report := service.Report()
	require.Contains(t, report.Participated, "fofa")
	require.Contains(t, report.Participated, "shodan")
	shodanUsage := usageFor(t, service.Quota, "shodan")
	require.True(t, shodanUsage.QuotaBlocked)
	require.Equal(t, 2, shodanUsage.Used)
	require.Equal(t, 0, *shodanUsage.Remaining)
	require.Equal(t, 3, usageFor(t, service.Quota, "fofa").Used)
}

func TestExecuteQuotaAllEnginesSkipped(t *testing.T) {
	shodan := &quotaMockAgent{name: "shodan", results: 1}
	fofa := &quotaMockAgent{name: "fofa", results: 1}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{
			"shodan": {Limit: intPtr(0)},
			"fofa":   {Limit: intPtr(0)},
		},
	}, []string{"test"}, shodan, fofa)

	_, err := service.Execute(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "all engines were skipped")
	require.Contains(t, err.Error(), "shodan")
	require.Contains(t, err.Error(), "fofa")
	require.Contains(t, err.Error(), sources.ReasonQuotaExhausted)
	require.Zero(t, shodan.calls.Load(), "skipped engines must not be queried")

	report := service.Report()
	require.NotNil(t, report)
	require.Empty(t, report.Participated)
	require.Len(t, report.Skipped, 2)
	for _, skip := range report.Skipped {
		require.Equal(t, sources.ReasonQuotaExhausted, skip.Reason)
	}
}

func TestExecuteQuotaAllSkippedWithMixedReasons(t *testing.T) {
	// shodan has no budget, fofa fails at Query setup: both must be named with
	// their own reason instead of a silent empty result.
	shodan := &quotaMockAgent{name: "shodan", results: 1}
	fofa := &quotaMockAgent{name: "fofa", queryErr: errors.New("boom")}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{
			"shodan": {Limit: intPtr(0)},
		},
	}, []string{"test"}, shodan, fofa)

	_, err := service.Execute(context.Background())
	require.Error(t, err)

	skips := service.Report().Skipped
	reasons := map[string]string{}
	for _, skip := range skips {
		reasons[skip.Engine] = skip.Reason
	}
	require.Equal(t, sources.ReasonQuotaExhausted, reasons["shodan"])
	require.Equal(t, sources.ReasonQueryError, reasons["fofa"])
}

func TestExecuteQuotaAbnormalExitReturnsBudget(t *testing.T) {
	// The agent reserves a call, then fails before committing (models a
	// network error / malformed upstream response).
	flaky := &quotaMockAgent{name: "shodan"}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, []string{"test"}, flaky)

	token, err := service.Quota.Acquire("shodan")
	require.NoError(t, err)
	service.Quota.Release(token) // abnormal exit path

	usage := service.Quota.Usage("shodan")
	require.Equal(t, 0, usage.Used)
	require.Equal(t, 1, *usage.Remaining, "the budget must be returned")

	// The service can still use the engine.
	flaky.results = 1
	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)
	require.Len(t, results, 1)
	require.Equal(t, 1, service.Quota.Usage("shodan").Used)
}

func TestExecuteQuotaMidStreamExhaustionIsPartial(t *testing.T) {
	// The engine starts, produces some results, then its budget runs out. The
	// report must say partial/quota_exhausted, not error/query_error.
	shodan := &quotaMockAgent{name: "shodan", results: 5}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{"shodan": {Limit: intPtr(2)}},
	}, []string{"test"}, shodan)

	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	results := drain(t, ch)
	require.Len(t, results, 3, "two results plus the quota error")
	for _, res := range results {
		if res.Error != nil {
			require.ErrorIs(t, res.Error, sources.ErrQuotaExhausted)
		}
	}

	report := service.Report()
	require.Len(t, report.Engines, 1)
	entry := report.Engines[0]
	require.Equal(t, sources.StatusPartial, entry.Status)
	require.Equal(t, sources.ReasonQuotaExhausted, entry.Reason)
	require.True(t, entry.QuotaExhausted)
	require.Contains(t, report.Participated, "shodan")
}

func TestExecuteQuotaDisabledMissingKeysKeepsLegacySuccess(t *testing.T) {
	// Legacy behaviour: an engine whose key is missing is logged and skipped,
	// and Execute still succeeds with an empty stream. Quota mode is what turns
	// "all skipped" into an error.
	agent := &quotaMockAgent{name: "shodan", results: 1, queryErr: errors.New("empty shodan keys")}
	service := &Service{
		Agents:   []sources.Agent{agent},
		Options:  &Options{Agents: []string{"shodan"}, Queries: []string{"test"}},
		Provider: &sources.Provider{Fofa: []string{"other-key"}},
		Session:  &sources.Session{},
	}
	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	require.Empty(t, drain(t, ch))
}

func TestExecuteQuotaDisabledMissingKeysWithQuotaErrors(t *testing.T) {
	// With quota enabled, the same all-engines-failed situation becomes an
	// explicit error naming each engine.
	agent := &quotaMockAgent{name: "shodan", results: 1, queryErr: errors.New("empty shodan keys")}
	manager, err := sources.NewQuotaManager(&sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{"shodan": {Limit: intPtr(10)}},
	}, []string{"shodan"})
	require.NoError(t, err)
	service := &Service{
		Agents:   []sources.Agent{agent},
		Options:  &Options{Agents: []string{"shodan"}, Queries: []string{"test"}},
		Provider: &sources.Provider{Fofa: []string{"other-key"}},
		Session:  &sources.Session{Quota: manager},
		Quota:    manager,
	}
	_, err = service.Execute(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "shodan")
}

func TestExecuteQuotaMultiQueryPartialNotSkipped(t *testing.T) {
	// shodan produces results for the first query, then its budget is gone for
	// the second. It participated, so it must not be reported as fully skipped.
	shodan := &quotaMockAgent{name: "shodan", results: 1}
	fofa := &quotaMockAgent{name: "fofa", results: 1}
	service := newQuotaService(t, &sources.QuotaConfig{
		Engines: map[string]*sources.EngineQuota{
			"shodan": {Limit: intPtr(1)},
			"fofa":   {Limit: intPtr(10)},
		},
	}, []string{"q1", "q2"}, shodan, fofa)

	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	// q1: shodan + fofa; q2: fofa + shodan's quota error.
	require.Len(t, drain(t, ch), 4)

	report := service.Report()
	for _, engine := range report.Engines {
		if engine.Engine == "shodan" {
			require.Equal(t, sources.StatusPartial, engine.Status)
			require.Equal(t, sources.ReasonQuotaExhausted, engine.Reason)
			require.Contains(t, report.Participated, "shodan")
		}
	}
	require.Empty(t, report.Skipped)
}

func TestExecuteQuotaDisabledIsUnchanged(t *testing.T) {
	agent := &quotaMockAgent{name: "shodan", results: 2}
	service := &Service{
		Agents:   []sources.Agent{agent},
		Options:  &Options{Agents: []string{"shodan"}, Queries: []string{"test"}},
		Provider: &sources.Provider{Shodan: []string{"test-key"}},
		Session:  &sources.Session{},
	}
	ch, err := service.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, drain(t, ch), 2)
	require.Nil(t, service.Report(), "no quota report when quota is disabled")
}

func intPtr(v int) *int { return &v }
