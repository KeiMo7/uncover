package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func newQuotaSession(t *testing.T, cfg *QuotaConfig, engines []string) (*Session, *QuotaManager) {
	t.Helper()
	manager, err := NewQuotaManager(cfg, engines)
	require.NoError(t, err)
	if cfg == nil {
		require.Nil(t, manager)
	} else {
		require.NotNil(t, manager)
	}
	session, err := NewSessionWithQuota(&Keys{}, 0, 5, 0, engines, time.Second, "", manager)
	require.NoError(t, err)
	return session, manager
}

func TestSessionQuotaRetries429WithoutInflatingBudget(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	session, manager := newQuotaSession(t, &QuotaConfig{
		MaxRetries: intPtr(2),
		Engines:    map[string]*EngineQuota{"shodan": {Limit: intPtr(5)}},
	}, []string{"shodan"})
	// Keep the test fast: milliseconds instead of the 500ms default.
	manager.engines["shodan"].backoffInit = time.Millisecond
	manager.engines["shodan"].backoffMax = time.Millisecond

	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	resp, err := session.Do(req, "shodan")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())

	require.EqualValues(t, 3, calls.Load(), "two 429s then success")
	usage := manager.Usage("shodan")
	require.Equal(t, 1, usage.Used, "only the successful call is charged")
	require.Equal(t, 4, *usage.Remaining)
	require.True(t, usage.RateLimited)
	require.False(t, usage.RateExhausted)
}

func TestSessionQuotaStopsEngineAfter429Retries(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	session, manager := newQuotaSession(t, &QuotaConfig{
		MaxRetries: intPtr(1),
		Engines:    map[string]*EngineQuota{"shodan": {Limit: intPtr(10)}},
	}, []string{"shodan"})
	manager.engines["shodan"].backoffInit = time.Millisecond
	manager.engines["shodan"].backoffMax = time.Millisecond

	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	_, err = session.Do(req, "shodan")
	require.ErrorIs(t, err, ErrRateLimitedExhausted)

	usage := manager.Usage("shodan")
	require.Equal(t, 0, usage.Used, "rejected calls are not charged")
	require.True(t, usage.RateExhausted)

	// The engine is now skipped for the rest of the run.
	req, err = retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	_, err = session.Do(req, "shodan")
	require.ErrorIs(t, err, ErrRateLimitedExhausted)
	require.EqualValues(t, 2, calls.Load(), "no extra HTTP call once stopped")
}

func TestSessionQuotaReleasesOnNetworkError(t *testing.T) {
	session, manager := newQuotaSession(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, []string{"shodan"})

	// Port 1 on localhost is refused; the request fails before a response.
	req, err := retryablehttp.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	require.NoError(t, err)
	_, err = session.Do(req, "shodan")
	require.Error(t, err)

	usage := manager.Usage("shodan")
	require.Equal(t, 0, usage.Used, "failed call must return its reservation")
	require.Equal(t, 1, *usage.Remaining)

	// The unit is usable again.
	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)
}

func TestSessionQuotaReleasesOnServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()

	session, manager := newQuotaSession(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, []string{"shodan"})

	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	_, err = session.Do(req, "shodan")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected status code 502")
	require.Equal(t, 0, manager.Usage("shodan").Used, "a 5xx must not consume budget")
}

func TestSessionQuotaExhaustedBeforeRequest(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	session, manager := newQuotaSession(t, &QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: intPtr(1)}},
	}, []string{"shodan"})
	token, err := manager.Acquire("shodan")
	require.NoError(t, err)
	manager.Commit(token)

	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	_, err = session.Do(req, "shodan")
	require.ErrorIs(t, err, ErrQuotaExhausted)
	require.EqualValues(t, 0, calls.Load(), "no HTTP request when the budget is gone")
}

func TestSessionQuotaDisabledKeepsLegacyBehaviour(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	session, manager := newQuotaSession(t, nil, []string{"shodan"})
	require.Nil(t, manager)
	req, err := retryablehttp.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	_, err = session.Do(req, "shodan")
	// Legacy path: a non-200 is an error but not a quota/rate-limit error.
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrRateLimitedExhausted)
	require.NotErrorIs(t, err, ErrQuotaExhausted)
	require.Contains(t, err.Error(), "unexpected status code 429")
}

func TestSessionQuotaHonoursContextCancellationDuringBackoff(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	session, manager := newQuotaSession(t, &QuotaConfig{
		MaxRetries: intPtr(5),
		Engines:    map[string]*EngineQuota{"shodan": {Limit: intPtr(5)}},
	}, []string{"shodan"})
	manager.engines["shodan"].backoffInit = time.Hour
	manager.engines["shodan"].backoffMax = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
		if err != nil {
			done <- err
			return
		}
		_, err = session.Do(req, "shodan")
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Do did not return after context cancellation")
	}
	require.Equal(t, 0, manager.Usage("shodan").Used)
}
