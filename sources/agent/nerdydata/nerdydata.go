package nerdydata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "nerdydata"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.NerdyDataToken == "" {
		return nil, errors.New("empty NerdyData keys")
	}

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		const maxRetries = 5
		const baseBackoff = 30 * time.Second
		const maxBackoff = 960 * time.Second
		numberOfResults := 0
		nextPage := ""

		for {
			if ctx.Err() != nil {
				return
			}
			nerdydataRequest := &Request{
				Query: query.Query,
				Page:  nextPage,
			}

			var resp *http.Response
			var err error
			for attempt := 0; attempt < maxRetries; attempt++ {
				resp, err = agent.queryURL(ctx, session, nerdydataRequest.buildURL(), session.Keys.NerdyDataToken)
				if err != nil {
					sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
					return
				}
				if resp.StatusCode != http.StatusAccepted {
					break
				}
				// 202 = server-side timeout; back off and retry with same cursor
				_ = resp.Body.Close()
				backoff := baseBackoff * (1 << attempt)
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
			}
			if resp.StatusCode == http.StatusAccepted {
				_ = resp.Body.Close()
				sources.SendResult(ctx, results, sources.Result{
					Source: agent.Name(),
					Error:  fmt.Errorf("server returned 202 after %d retries", maxRetries),
				})
				return
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				sources.SendResult(ctx, results, sources.Result{
					Source: agent.Name(),
					Error:  fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body),
				})
				return
			}

			var apiResponse Response
			if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
				_ = resp.Body.Close()
				sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
				return
			}
			_ = resp.Body.Close()

			if len(apiResponse.Sites) == 0 {
				break
			}

			for _, s := range apiResponse.Sites {
				if numberOfResults >= query.Limit {
					return
				}
				result := sources.Result{Source: agent.Name()}
				result.Host = s.Domain
				if result.Host == "" {
					result.Host = s.URL
				}
				result.Url = s.URL
				raw, _ := json.Marshal(s)
				result.Raw = raw
				if !sources.SendResult(ctx, results, result) {
					return
				}
				numberOfResults++
			}

			if apiResponse.NextPage == "" {
				break
			}
			nextPage = apiResponse.NextPage
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(ctx context.Context, session *sources.Session, URL string, token string) (*http.Response, error) {
	request, err := sources.NewHTTPRequest(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("api_key", token)
	request.Header.Set("x-uncover", "1")
	// Bypass session.Do (which errors on non-200) to handle 202 retry ourselves.
	if err := session.RateLimits.Take(agent.Name()); err != nil {
		return nil, err
	}
	request.Close = true
	if session.Quota == nil {
		return session.Client.Do(request)
	}
	// Quota mode: charge the call and treat 429 like every other engine. 202
	// handling stays here because it is nerdydata-specific.
	maxRetries := session.Quota.RateLimitRetries(agent.Name())
	for attempt := 0; ; attempt++ {
		reserved, err := session.Quota.Acquire(agent.Name())
		if err != nil {
			return nil, err
		}
		resp, err := session.Client.Do(request)
		if err != nil {
			session.Quota.Release(reserved)
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			session.Quota.MarkRateLimited(agent.Name())
			if attempt < maxRetries {
				wait := sources.RetryAfterDuration(resp.Header.Get("Retry-After"))
				if wait <= 0 {
					wait = session.Quota.Backoff(agent.Name(), attempt)
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				session.Quota.Release(reserved)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
				if err := session.RateLimits.Take(agent.Name()); err != nil {
					return nil, err
				}
				continue
			}
			_ = resp.Body.Close()
			session.Quota.Release(reserved)
			session.Quota.MarkRateExhausted(agent.Name())
			return nil, fmt.Errorf("%w: %s answered 429 after %d retries", sources.ErrRateLimitedExhausted, agent.Name(), maxRetries)
		}
		if resp.StatusCode == http.StatusOK {
			session.Quota.Commit(reserved)
			return resp, nil
		}
		// 202 (server-side timeout, caller retries) and other non-200 replies
		// produced no result; return the reservation so retries do not inflate
		// the total.
		session.Quota.Release(reserved)
		return resp, nil
	}
}
