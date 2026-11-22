package sources

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// DefaultRateLimits of all/most of sources are hardcoded by default to improve performance
// engine is not present in default ratelimits then user given ratelimit from cli options is used
var DefaultRateLimits = map[string]*ratelimit.Options{
	"shodan":          {Key: "shodan", MaxCount: 1, Duration: time.Second},
	"shodan-idb":      {Key: "shodan-idb", MaxCount: 1, Duration: time.Second},
	"fofa":            {Key: "fofa", MaxCount: 1, Duration: time.Second},
	"censys":          {Key: "censys", MaxCount: 1, Duration: 3 * time.Second},
	"quake":           {Key: "quake", MaxCount: 1, Duration: time.Second},
	"hunter":          {Key: "hunter", MaxCount: 15, Duration: time.Second},
	"zoomeye":         {Key: "zoomeye", MaxCount: 1, Duration: time.Second},
	"netlas":          {Key: "netlas", MaxCount: 1, Duration: time.Second},
	"criminalip":      {Key: "criminalip", MaxCount: 1, Duration: time.Second},
	"publicwww":       {Key: "publicwww", MaxCount: 1, Duration: time.Minute},
	"hunterhow":       {Key: "hunterhow", MaxCount: 1, Duration: 3 * time.Second},
	"google":          {Key: "google", MaxCount: 1, Duration: 3 * time.Second},
	"odin":            {Key: "odin", MaxCount: 1, Duration: time.Second},
	"binaryedge":      {Key: "binaryedge", MaxCount: 1, Duration: time.Second},
	"onyphe":          {Key: "onyphe", MaxCount: 1, Duration: time.Second},
	"driftnet":        {Key: "driftnet", MaxCount: 5, Duration: time.Second},
	"greynoise":       {Key: "greynoise", MaxCount: 1, Duration: time.Second},
	"nerdydata":       {Key: "nerdydata", MaxCount: 1, Duration: time.Second},
	"scanmalware":     {Key: "scanmalware", MaxCount: 1, Duration: time.Second},
	"subdomaincenter": {Key: "subdomaincenter", MaxCount: 1, Duration: time.Second},
}

// Session handles session agent sessions
type Session struct {
	Keys       *Keys
	Client     *retryablehttp.Client
	RetryMax   int
	RateLimits *ratelimit.MultiLimiter
	// Quota is optional. When set, every engine call is charged to the
	// engine budget and 429 responses are retried with backoff.
	Quota *QuotaManager
}

// NewSession builds a session. It is kept for backwards compatibility; quota
// support is wired by NewSessionWithQuota.
func NewSession(keys *Keys, retryMax, timeout, rateLimit int, engines []string, duration time.Duration, proxy string) (*Session, error) {
	return NewSessionWithQuota(keys, retryMax, timeout, rateLimit, engines, duration, proxy, nil)
}

// NewSessionWithQuota builds a session and applies per-engine quota and rate
// overrides. quota may be nil, in which case behaviour is identical to
// NewSession.
func NewSessionWithQuota(keys *Keys, retryMax, timeout, rateLimit int, engines []string, duration time.Duration, proxy string, quota *QuotaManager) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ResponseHeaderTimeout: time.Duration(timeout) * time.Second,
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxy != "" {
				if proxyURL, err := url.Parse(proxy); err == nil {
					return http.ProxyURL(proxyURL)(req)
				}
			}
			return http.ProxyFromEnvironment(req)
		},
	}

	httpclient := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	options := retryablehttp.Options{RetryMax: retryMax}
	options.RetryWaitMax = time.Duration(timeout) * time.Second
	client := retryablehttp.NewWithHTTPClient(httpclient, options)

	session := &Session{
		Client:   client,
		Keys:     keys,
		RetryMax: retryMax,
		Quota:    quota,
	}

	var defaultRatelimit *ratelimit.Options
	switch {
	case rateLimit > 0:
		defaultRatelimit = &ratelimit.Options{Key: "default", MaxCount: uint(rateLimit), Duration: duration}
	default:
		defaultRatelimit = &ratelimit.Options{IsUnlimited: true, Key: "default"}
	}

	var err error
	session.RateLimits, err = ratelimit.NewMultiLimiter(context.Background(), defaultRatelimit)
	if err != nil {
		return nil, err
	}

	// setup ratelimit of all engines
	rateOverrides := quota.RateLimitOverrides(engines)
	for _, engine := range engines {
		rateLimitOpts := DefaultRateLimits[engine]
		if rateLimitOpts == nil {
			// fallback to using default ratelimit
			rateLimitOpts = defaultRatelimit
			rateLimitOpts.Key = engine
		}
		if override, ok := rateOverrides[engine]; ok {
			// Copy before mutating: DefaultRateLimits entries are shared.
			optCopy := *rateLimitOpts
			optCopy.Key = engine
			switch {
			case override.Unlimited:
				optCopy.IsUnlimited = true
			default:
				optCopy.IsUnlimited = false
				optCopy.MaxCount = override.Max
				optCopy.Duration = override.Per
			}
			rateLimitOpts = &optCopy
		}
		if err = session.RateLimits.Add(rateLimitOpts); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("failed to setup ratelimit of %v got %v", engine, err)
		}
	}

	return session, nil
}

func (s *Session) Do(request *retryablehttp.Request, source string) (*http.Response, error) {
	if s.Quota != nil {
		return s.doWithQuota(request, source)
	}
	if err := s.RateLimits.Take(source); err != nil {
		return nil, err
	}
	// close request connection (does not reuse connections)
	request.Close = true
	resp, err := s.Client.Do(request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.String())
		return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	return resp, nil
}

// doWithQuota is the quota-enabled path. One unit of budget is charged per
// successful engine call; 429 retries and failed calls release their
// reservation, so retries never inflate the total. After `max_retries` 429s
// the engine is marked rate-limited for the rest of the run and the error is
// surfaced to the caller, which skips that engine only.
func (s *Session) doWithQuota(request *retryablehttp.Request, source string) (*http.Response, error) {
	// Take the rate limiter first so an exhausted engine does not burn budget
	// waiting on a token.
	if err := s.RateLimits.Take(source); err != nil {
		return nil, err
	}
	request.Close = true

	maxRetries := s.Quota.RateLimitRetries(source)
	for attempt := 0; ; attempt++ {
		token, err := s.Quota.Acquire(source)
		if err != nil {
			return nil, err
		}
		resp, err := s.Client.Do(request)
		if err != nil {
			s.Quota.Release(token)
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			s.Quota.MarkRateLimited(source)
			if attempt < maxRetries {
				wait := retryAfter(resp)
				if wait <= 0 {
					wait = s.Quota.Backoff(source, attempt)
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				s.Quota.Release(token)
				if !sleepWithContext(request.Context(), wait) {
					return nil, request.Context().Err()
				}
				if err := s.RateLimits.Take(source); err != nil {
					return nil, err
				}
				continue
			}
			// Retries exhausted: do not charge budget for a rejected call, and
			// stop this engine for the remainder of the run.
			_ = resp.Body.Close()
			s.Quota.Release(token)
			s.Quota.MarkRateExhausted(source)
			return nil, fmt.Errorf("%w: %s answered 429 after %d retries", ErrRateLimitedExhausted, source, maxRetries)
		}
		if resp.StatusCode != http.StatusOK {
			// The upstream answered but the call did not succeed. Return the
			// reservation so an abnormal reply cannot consume budget.
			s.Quota.Release(token)
			requestURL, _ := url.QueryUnescape(request.String())
			return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
		}
		s.Quota.Commit(token)
		return resp, nil
	}
}

func retryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	return RetryAfterDuration(resp.Header.Get("Retry-After"))
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
