package sources

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func intPtr(v int) *int { return &v }

func newTestManager(t *testing.T, cfg *QuotaConfig, agents ...string) *QuotaManager {
	t.Helper()
	manager, err := NewQuotaManager(cfg, agents)
	require.NoError(t, err)
	require.NotNil(t, manager)
	return manager
}

func TestQuotaAcquireExhausts(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(2)}},
	}, "shodan")

	for i := 0; i < 2; i++ {
		token, err := manager.Acquire("shodan")
		require.NoError(t, err)
		manager.Commit(token)
	}
	_, err := manager.Acquire("shodan")
	require.ErrorIs(t, err, ErrQuotaExhausted)

	usage := manager.Usage("shodan")
	require.Equal(t, 2, usage.Used)
	require.Equal(t, 0, *usage.Remaining)
}

func TestQuotaConcurrentNeverExceedsLimit(t *testing.T) {
	const limit = 10
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(limit)}},
	}, "shodan")

	var acquired atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := manager.Acquire("shodan")
			if err != nil {
				require.ErrorIs(t, err, ErrQuotaExhausted)
				return
			}
			acquired.Add(1)
			manager.Commit(token)
		}()
	}
	wg.Wait()
	require.EqualValues(t, limit, acquired.Load())
	require.Equal(t, limit, manager.Usage("shodan").Used)
}

func TestQuotaReleaseOnFailure(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, "shodan")

	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Release(token) // simulate a call that exited with an error

	usage := manager.Usage("shodan")
	require.Equal(t, 0, usage.Used)
	require.Equal(t, 1, *usage.Remaining)

	// The released unit must be acquirable again.
	token, err = manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)

	// Double release after commit must not push the budget above the limit.
	manager.Release(token)
	require.Equal(t, 1, manager.Usage("shodan").Used)
}

func TestQuotaEnginesAreIndependent(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{
			"shodan": {Limit: intPtr(1)},
			"fofa":   {Limit: intPtr(1)},
		},
	}, "shodan", "fofa")

	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)

	_, err = manager.Acquire("shodan")
	require.ErrorIs(t, err, ErrQuotaExhausted)

	// fofa is unaffected.
	token, err = manager.Acquire("fofa")
	require.NoError(t, err)
	manager.Commit(token)
	require.Equal(t, 1, manager.Usage("fofa").Used)
}

func TestQuotaZeroLimitSkipsEngine(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(0)}},
	}, "shodan")
	require.False(t, manager.Available("shodan"))
	_, err := manager.Acquire("shodan")
	require.ErrorIs(t, err, ErrQuotaExhausted)
}

func TestQuotaUnconfiguredEngineIsUnlimited(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, "shodan", "fofa")
	for i := 0; i < 5; i++ {
		token, err := manager.Acquire("fofa")
		require.NoError(t, err)
		manager.Commit(token)
	}
	require.Nil(t, manager.Usage("fofa").Limit)
	require.Nil(t, manager.Usage("fofa").Remaining)
}

func TestQuotaFixedWindowResetsAndReleasesStaleEpoch(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Window: &WindowConfig{Type: "fixed", Size: Duration(time.Minute)},
		Engines: map[string]*EngineQuota{
			"shodan": {Limit: intPtr(1)},
		},
	}, "shodan")

	now := time.Unix(1_700_000_000, 0)
	manager.now = func() time.Time { return now }

	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)
	require.False(t, manager.Available("shodan"))

	// Roll to the next window: budget is restored.
	now = now.Add(time.Minute)
	require.True(t, manager.Available("shodan"))

	// A late release from the previous epoch must not inflate the new window.
	manager.Release(token)
	require.Equal(t, 1, manager.Usage("shodan").Used, "a committed call stays counted")
	require.Equal(t, 1, *manager.Usage("shodan").Remaining, "but it belongs to the old window")
}

func TestQuotaRollingWindowRestoresPerCall(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Window: &WindowConfig{Type: "rolling", Size: Duration(time.Minute)},
		Engines: map[string]*EngineQuota{
			"shodan": {Limit: intPtr(2)},
		},
	}, "shodan")

	base := time.Unix(1_700_000_000, 0)
	current := base
	manager.now = func() time.Time { return current }

	tokenA, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(tokenA)

	current = base.Add(30 * time.Second)
	tokenB, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(tokenB)

	// Both calls are still inside the rolling window.
	current = base.Add(45 * time.Second)
	_, err = manager.Acquire("shodan")
	require.ErrorIs(t, err, ErrQuotaExhausted)

	// Only the first call has aged out; exactly one slot is free again.
	current = base.Add(time.Minute + time.Second)
	require.True(t, manager.Available("shodan"))
	tokenC, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(tokenC)

	// The second call is still inside the window, so the engine is full again.
	_, err = manager.Acquire("shodan")
	require.ErrorIs(t, err, ErrQuotaExhausted)

	usage := manager.Usage("shodan")
	require.Equal(t, 2, *usage.Limit)
	require.Equal(t, 0, *usage.Remaining)
}

func TestQuotaRollingWindowCountsOnlyCommittedOrReserved(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Window: &WindowConfig{Type: "rolling", Size: Duration(time.Minute)},
		Engines: map[string]*EngineQuota{
			"shodan": {Limit: intPtr(1)},
		},
	}, "shodan")

	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Release(token)
	// A released rolling call frees its slot immediately.
	token, err = manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)
}

func TestQuotaFailOpenOnAccountingError(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, "shodan")
	manager.warn = func(string, ...any) {}
	var fired atomic.Bool
	manager.onAcquire = func(string) {
		if !fired.Swap(true) {
			panic("simulated accounting failure")
		}
	}

	token, err := manager.Acquire("shodan")
	require.NoError(t, err, "accounting errors must degrade to unlimited")
	manager.Commit(token)

	// Subsequent calls also succeed, regardless of limit.
	token, err = manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)

	usage := manager.Usage("shodan")
	require.True(t, usage.FailOpen)
	require.Contains(t, usage.FailOpenReason, "simulated")
	require.Nil(t, usage.Remaining)
}

func TestQuotaRateExhaustedStopsEngine(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(5)}},
	}, "shodan")

	manager.MarkRateExhausted("shodan")
	require.False(t, manager.Available("shodan"))
	_, err := manager.Acquire("shodan")
	require.ErrorIs(t, err, ErrRateLimitedExhausted)
	reason, _ := manager.SkipReason("shodan")
	require.Equal(t, ReasonRateLimited, reason)
}

func TestQuotaConfigValidation(t *testing.T) {
	cases := []struct {
		name   string
		yaml   string
		errHas string
		parse  bool
	}{
		{
			name:   "negative limit",
			yaml:   "engines:\n  shodan:\n    limit: -1\n",
			errHas: "engines.shodan.limit",
		},
		{
			name:   "unknown engine",
			yaml:   "engines:\n  nosuchengine:\n    limit: 1\n",
			errHas: "unknown engine",
		},
		{
			name:   "bad window type",
			yaml:   "engines:\n  shodan:\n    limit: 1\n    window:\n      type: sliding\n",
			errHas: "engines.shodan.window.type",
		},
		{
			name:   "rate max zero",
			yaml:   "engines:\n  shodan:\n    rate:\n      max: 0\n      per: 1s\n",
			errHas: "engines.shodan.rate.max",
		},
		{
			name:   "limit and unlimited",
			yaml:   "engines:\n  shodan:\n    limit: 1\n    unlimited: true\n",
			errHas: "mutually exclusive",
		},
		{
			name:   "unknown field",
			yaml:   "engines:\n  shodan:\n    limitt: 1\n",
			errHas: "field limitt not found",
			parse:  true,
		},
		{
			name:   "duplicate alias",
			yaml:   "engines:\n  subdomaincenter:\n    limit: 1\n  subdomain-center:\n    limit: 2\n",
			errHas: "duplicate engine",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseQuotaConfig([]byte(tc.yaml))
			if tc.parse {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errHas)
				return
			}
			require.NoError(t, err)
			err = cfg.ValidateForAgents([]string{"shodan"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errHas)
		})
	}
}

func TestQuotaConfigParsesDurationsAndDefaults(t *testing.T) {
	cfg, err := ParseQuotaConfig([]byte(`
window:
  type: rolling
  size: 1h
max_retries: 3
backoff:
  initial: 250ms
  max: 4s
defaults:
  limit: 50
engines:
  shodan:
    limit: 10
    rate:
      max: 2
      per: 1s
  fofa:
    unlimited: true
`))
	require.NoError(t, err)
	require.NoError(t, cfg.ValidateForAgents([]string{"shodan", "fofa"}))

	manager := newTestManager(t, cfg, "shodan", "fofa")

	shodan := manager.Usage("shodan")
	require.Equal(t, 10, *shodan.Limit)
	require.Equal(t, string(WindowRolling), shodan.WindowType)
	require.Equal(t, 3, manager.RateLimitRetries("shodan"))
	require.Equal(t, 250*time.Millisecond, manager.Backoff("shodan", 0))
	require.Equal(t, 500*time.Millisecond, manager.Backoff("shodan", 1))

	fofa := manager.Usage("fofa")
	require.Nil(t, fofa.Limit, "unlimited: true must override defaults")

	overrides := manager.RateLimitOverrides([]string{"shodan", "fofa"})
	require.Len(t, overrides, 1)
	require.EqualValues(t, 2, overrides["shodan"].Max)
	require.Equal(t, time.Second, overrides["shodan"].Per)
}

func TestRetryAfterDuration(t *testing.T) {
	require.Equal(t, 5*time.Second, RetryAfterDuration("5"))
	require.Zero(t, RetryAfterDuration(""))
	require.Zero(t, RetryAfterDuration("not-a-date"))
	when := time.Now().Add(2 * time.Second).UTC().Format(time.RFC1123)
	require.InDelta(t, float64(2*time.Second), float64(RetryAfterDuration(when)), float64(1500*time.Millisecond))
}

func TestQuotaManagerNilConfig(t *testing.T) {
	manager, err := NewQuotaManager(nil, []string{"shodan"})
	require.NoError(t, err)
	require.Nil(t, manager)
	// Every manager method must be nil-safe.
	require.True(t, manager.Available("shodan"))
	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	require.NoError(t, nil)
	manager.Commit(token)
	manager.Release(token)
	require.False(t, manager.Has("shodan"))
}

func TestSkipReasonNamesEngineReason(t *testing.T) {
	manager := newTestManager(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, "shodan")
	token, _ := manager.Acquire("shodan")
	manager.Commit(token)
	reason, message := manager.SkipReason("shodan")
	require.Equal(t, ReasonQuotaExhausted, reason)
	require.Contains(t, message, "1/1")
	require.True(t, errors.Is(ErrQuotaExhausted, ErrQuotaExhausted))
}
