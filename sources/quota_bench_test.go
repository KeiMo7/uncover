package sources

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// These benchmarks compare the legacy (quota disabled) call path with the
// quota-enabled path on the same local upstream. The per-engine rate limiter
// is neutralised on both sides so only quota bookkeeping is measured.
//
//	go test ./sources/ -run '^$' -bench 'BenchmarkQuotaSession' -benchmem -benchtime=2000x

func benchSession(b *testing.B, session *Session, engine string) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b.Cleanup(ts.Close)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := NewHTTPRequest(b.Context(), http.MethodGet, ts.URL, nil)
		if err != nil {
			b.Fatal(err)
		}
		resp, err := session.Do(req, engine)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

func BenchmarkQuotaSessionDisabled(b *testing.B) {
	// "bench-engine" is absent from DefaultRateLimits, so the session uses the
	// unlimited fallback limiter: the legacy path without artificial waiting.
	session, err := NewSessionWithQuota(&Keys{}, 0, 5, 0, []string{"bench-engine"}, 0, "", nil)
	if err != nil {
		b.Fatal(err)
	}
	benchSession(b, session, "bench-engine")
}

func BenchmarkQuotaSessionEnabled(b *testing.B) {
	limit := 1 << 30
	manager, err := NewQuotaManager(&QuotaConfig{
		Engines: map[string]*EngineQuota{
			"shodan": {
				Limit: &limit,
				Rate:  &RateConfig{Unlimited: true},
			},
		},
	}, []string{"shodan"})
	if err != nil {
		b.Fatal(err)
	}
	session, err := NewSessionWithQuota(&Keys{}, 0, 5, 0, []string{"shodan"}, 0, "", manager)
	if err != nil {
		b.Fatal(err)
	}
	benchSession(b, session, "shodan")
}

func BenchmarkQuotaManagerAcquireCommit(b *testing.B) {
	limit := 1 << 30
	manager, err := NewQuotaManager(&QuotaConfig{
		Engines: map[string]*EngineQuota{"shodan": {Limit: &limit}},
	}, []string{"shodan"})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		token, err := manager.Acquire("shodan")
		if err != nil {
			b.Fatal(err)
		}
		manager.Commit(token)
	}
}
