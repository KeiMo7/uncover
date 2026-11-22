package censys

import (
	"context"
	"encoding/json"

	"errors"
	"fmt"
	"net/http"
	"time"

	censyssdkgo "github.com/censys/censys-sdk-go"
	"github.com/censys/censys-sdk-go/models/components"
	"github.com/censys/censys-sdk-go/models/operations"
	"github.com/censys/censys-sdk-go/models/sdkerrors"
	"github.com/censys/censys-sdk-go/retry"
	"github.com/projectdiscovery/uncover/sources"
)

const (
	MaxPerPage = 100
)

type Agent struct{}

func (agent *Agent) Name() string {
	return "censys"
}

func (agent *Agent) Query(ctx context.Context, session *sources.Session, query *sources.Query) (chan sources.Result, error) {
	if session.Keys.CensysToken == "" || session.Keys.CensysOrgId == "" {
		return nil, errors.New("empty censys keys")
	}

	sdkOptions := []censyssdkgo.SDKOption{
		censyssdkgo.WithOrganizationID(session.Keys.CensysOrgId),
		censyssdkgo.WithSecurity(session.Keys.CensysToken),
		censyssdkgo.WithClient(
			session.Client.HTTPClient,
		),
	}
	if session.Quota != nil {
		// Quota mode owns retries, so disable the SDK's built-in retry loop.
		// Otherwise the SDK would retry 429 internally without charging the
		// budget or honouring the configured backoff.
		sdkOptions = append(sdkOptions, censyssdkgo.WithRetryConfig(retry.Config{Strategy: "none"}))
	}
	s := censyssdkgo.New(sdkOptions...)

	results := make(chan sources.Result)

	go func() {
		defer close(results)

		var numberOfResults int
		nextCursor := ""
		for {
			if ctx.Err() != nil {
				return
			}
			censysRequest := &CensysRequest{
				Query:   query.Query,
				PerPage: MaxPerPage,
				Cursor:  nextCursor,
			}
			censysResponse := agent.query(ctx, s, session, censysRequest, results)
			if censysResponse == nil {
				break
			}
			hasNextCursor := false
			if censysResponse.ResponseEnvelopeSearchQueryResponse.Result != nil && censysResponse.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken != "" {
				hasNextCursor = true
			}

			if !hasNextCursor || numberOfResults > query.Limit || len(censysResponse.ResponseEnvelopeSearchQueryResponse.Result.Hits) == 0 {
				break
			}
			nextCursor = censysResponse.ResponseEnvelopeSearchQueryResponse.Result.NextPageToken
			numberOfResults += len(censysResponse.ResponseEnvelopeSearchQueryResponse.Result.Hits)
		}
	}()

	return results, nil
}

func (agent *Agent) queryURL(ctx context.Context, s *censyssdkgo.SDK, censysRequest *CensysRequest) (*operations.V3GlobaldataSearchQueryResponse, error) {
	return s.GlobalData.Search(ctx, operations.V3GlobaldataSearchQueryRequest{
		SearchQueryInputBody: components.SearchQueryInputBody{
			PageSize:  censyssdkgo.Int64(int64(censysRequest.PerPage)),
			Query:     censysRequest.Query,
			PageToken: &censysRequest.Cursor,
		},
	})
}

func (agent *Agent) query(ctx context.Context, s *censyssdkgo.SDK, session *sources.Session, censysRequest *CensysRequest, results chan sources.Result) *operations.V3GlobaldataSearchQueryResponse {
	// In quota mode the SDK has no retry hook of its own, so charge the call
	// and implement the same 429 backoff used by Session.Do.
	if session != nil && session.Quota != nil {
		resp, err := agent.queryWithQuota(ctx, s, session, censysRequest)
		if err != nil {
			sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
			return nil
		}
		return agent.emitResults(ctx, resp, results)
	}
	resp, err := agent.queryURL(ctx, s, censysRequest)
	if err != nil {
		sources.SendResult(ctx, results, sources.Result{Source: agent.Name(), Error: err})
		return nil
	}
	return agent.emitResults(ctx, resp, results)
}

func (agent *Agent) queryWithQuota(ctx context.Context, s *censyssdkgo.SDK, session *sources.Session, censysRequest *CensysRequest) (*operations.V3GlobaldataSearchQueryResponse, error) {
	maxRetries := session.Quota.RateLimitRetries(agent.Name())
	for attempt := 0; ; attempt++ {
		token, err := session.Quota.Acquire(agent.Name())
		if err != nil {
			return nil, err
		}
		resp, err := agent.queryURL(ctx, s, censysRequest)
		if err != nil {
			// The SDK returns the 429 as an SDKError, without a response
			// object. Inspect the error so quota mode still backs off.
			status, headers := sdkResponseMeta(err)
			if status == http.StatusTooManyRequests {
				session.Quota.Release(token)
				session.Quota.MarkRateLimited(agent.Name())
				if attempt < maxRetries {
					wait := sources.RetryAfterDuration(headers.Get("Retry-After"))
					if wait <= 0 {
						wait = session.Quota.Backoff(agent.Name(), attempt)
					}
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(wait):
					}
					continue
				}
				session.Quota.MarkRateExhausted(agent.Name())
				return nil, fmt.Errorf("%w: %s answered 429 after %d retries", sources.ErrRateLimitedExhausted, agent.Name(), maxRetries)
			}
			session.Quota.Release(token)
			return nil, err
		}
		if resp != nil && resp.HTTPMeta.Response != nil && resp.HTTPMeta.Response.StatusCode == http.StatusTooManyRequests {
			session.Quota.Release(token)
			session.Quota.MarkRateLimited(agent.Name())
			if attempt < maxRetries {
				wait := sources.RetryAfterDuration(resp.HTTPMeta.Response.Header.Get("Retry-After"))
				if wait <= 0 {
					wait = session.Quota.Backoff(agent.Name(), attempt)
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
				continue
			}
			session.Quota.MarkRateExhausted(agent.Name())
			return nil, fmt.Errorf("%w: %s answered 429 after %d retries", sources.ErrRateLimitedExhausted, agent.Name(), maxRetries)
		}
		session.Quota.Commit(token)
		return resp, nil
	}
}

// sdkResponseMeta extracts the HTTP status and headers from an SDK error.
func sdkResponseMeta(err error) (int, http.Header) {
	var sdkErr *sdkerrors.SDKError
	if errors.As(err, &sdkErr) {
		if sdkErr.RawResponse != nil {
			return sdkErr.StatusCode, sdkErr.RawResponse.Header
		}
		return sdkErr.StatusCode, http.Header{}
	}
	return 0, http.Header{}
}

func (agent *Agent) emitResults(ctx context.Context, resp *operations.V3GlobaldataSearchQueryResponse, results chan sources.Result) *operations.V3GlobaldataSearchQueryResponse {
	if result := resp.ResponseEnvelopeSearchQueryResponse.Result; result != nil {
		for _, censysResult := range result.Hits {
			for _, host := range censysResult.WebpropertyV1.Resource.Endpoints {
				out := sources.Result{Source: agent.Name()}
				if host.IP != nil {
					out.IP = *host.IP
				}
				if host.Hostname != nil {
					out.Host = *host.Hostname
				}
				if host.Port != nil {
					out.Port = *host.Port
				}
				if host.HTTP != nil && host.HTTP.URI != nil {
					out.Url = *host.HTTP.URI
				}
				raw, _ := json.Marshal(host)
				out.Raw = raw
				if !sources.SendResult(ctx, results, out) {
					return resp
				}
			}
		}
	}

	return resp
}

type CensysRequest struct {
	Query   string
	PerPage int
	Cursor  string
}
