package uncover

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/sources"
	"github.com/projectdiscovery/uncover/sources/agent/binaryedge"
	"github.com/projectdiscovery/uncover/sources/agent/censys"
	"github.com/projectdiscovery/uncover/sources/agent/criminalip"
	"github.com/projectdiscovery/uncover/sources/agent/daydaymap"
	"github.com/projectdiscovery/uncover/sources/agent/driftnet"
	"github.com/projectdiscovery/uncover/sources/agent/fofa"
	"github.com/projectdiscovery/uncover/sources/agent/google"
	"github.com/projectdiscovery/uncover/sources/agent/greynoise"
	"github.com/projectdiscovery/uncover/sources/agent/hunter"
	"github.com/projectdiscovery/uncover/sources/agent/hunterhow"
	"github.com/projectdiscovery/uncover/sources/agent/nerdydata"
	"github.com/projectdiscovery/uncover/sources/agent/netlas"
	"github.com/projectdiscovery/uncover/sources/agent/odin"
	"github.com/projectdiscovery/uncover/sources/agent/onyphe"
	"github.com/projectdiscovery/uncover/sources/agent/publicwww"
	"github.com/projectdiscovery/uncover/sources/agent/quake"
	"github.com/projectdiscovery/uncover/sources/agent/scanmalware"
	"github.com/projectdiscovery/uncover/sources/agent/shodan"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	"github.com/projectdiscovery/uncover/sources/agent/subdomaincenter"
	"github.com/projectdiscovery/uncover/sources/agent/zoomeye"

	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var DefaultChannelBuffSize = 32

type Options struct {
	Agents   []string // Uncover Agents to use
	Queries  []string // Queries to pass to Agents
	Limit    int
	MaxRetry int
	Timeout  int
	// Note these ratelimits are used as fallback in case agent
	// ratelimit is not available in DefaultRateLimits
	RateLimit     uint          // default 30 req
	RateLimitUnit time.Duration // default unit
	Proxy         string        // http proxy to use with uncover
	// Quota enables per-engine quota management. Nil keeps the legacy
	// behaviour: no budgets, no 429 backoff, no run report.
	Quota *sources.QuotaConfig
}

// Service handler of all uncover Agents
type Service struct {
	Options  *Options
	Agents   []sources.Agent
	Session  *sources.Session
	Provider *sources.Provider
	Keys     sources.Keys
	Quota    *sources.QuotaManager

	reportMu sync.Mutex
	report   *sources.RunReport
}

// New creates new uncover service instance
func New(opts *Options) (*Service, error) {
	s := &Service{Agents: []sources.Agent{}, Options: opts}
	for _, v := range opts.Agents {
		switch v {
		case "shodan":
			s.Agents = append(s.Agents, &shodan.Agent{})
		case "censys":
			s.Agents = append(s.Agents, &censys.Agent{})
		case "fofa":
			s.Agents = append(s.Agents, &fofa.Agent{})
		case "shodan-idb":
			s.Agents = append(s.Agents, &shodanidb.Agent{})
		case "quake":
			s.Agents = append(s.Agents, &quake.Agent{})
		case "hunter":
			s.Agents = append(s.Agents, &hunter.Agent{})
		case "zoomeye":
			s.Agents = append(s.Agents, &zoomeye.Agent{})
		case "netlas":
			s.Agents = append(s.Agents, &netlas.Agent{})
		case "criminalip":
			s.Agents = append(s.Agents, &criminalip.Agent{})
		case "publicwww":
			s.Agents = append(s.Agents, &publicwww.Agent{})
		case "hunterhow":
			s.Agents = append(s.Agents, &hunterhow.Agent{})
		case "google":
			s.Agents = append(s.Agents, &google.Agent{})
		case "odin":
			s.Agents = append(s.Agents, &odin.Agent{})
		case "binaryedge":
			s.Agents = append(s.Agents, &binaryedge.Agent{})
		case "onyphe":
			s.Agents = append(s.Agents, &onyphe.Agent{})
		case "driftnet":
			s.Agents = append(s.Agents, &driftnet.Agent{})
		case "greynoise":
			s.Agents = append(s.Agents, &greynoise.Agent{})
		case "daydaymap":
			s.Agents = append(s.Agents, &daydaymap.Agent{})
		case "nerdydata":
			s.Agents = append(s.Agents, &nerdydata.Agent{})
		case "scanmalware":
			s.Agents = append(s.Agents, &scanmalware.Agent{})
		case "subdomaincenter", "subdomain-center":
			s.Agents = append(s.Agents, &subdomaincenter.Agent{})
		}
	}
	s.Provider = sources.NewProvider()
	s.Keys = s.Provider.GetKeys()

	if opts.RateLimit == 0 {
		opts.RateLimit = 30
	}
	if opts.RateLimitUnit == 0 {
		opts.RateLimitUnit = time.Minute
	}

	var err error
	s.Quota, err = sources.NewQuotaManager(opts.Quota, opts.Agents)
	if err != nil {
		return nil, errorutil.NewWithTag("uncover", "invalid quota configuration: %s", err)
	}
	s.Session, err = sources.NewSessionWithQuota(&s.Keys, opts.MaxRetry, opts.Timeout, 10, opts.Agents, opts.RateLimitUnit, opts.Proxy, s.Quota)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Execute(ctx context.Context) (<-chan sources.Result, error) {
	// unlikely but as a precaution to handle random panics check all types
	if err := s.nilCheck(); err != nil {
		return nil, err
	}
	switch {
	case len(s.Agents) == 0:
		return nil, errorutil.NewWithTag("uncover", "no agent/source specified")
	case !s.hasAnyAnonymousProvider() && !s.Provider.HasKeys():
		return nil, errorutil.NewWithTag("uncover", "agents %v requires keys but no keys were found", s.Options.Agents)
	}

	run := newRunState(s.Quota, s.Options.Agents)
	if s.Quota != nil {
		// Counters are per-run; the remaining budget itself is preserved.
		s.Quota.ResetRun()
	}

	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	// iterate and run all sources
	wg := &sync.WaitGroup{}
	started := 0
	for _, q := range s.Options.Queries {
	agentLabel:
		for _, agent := range s.Agents {
			name := agent.Name()
			keys := s.Provider.GetKeys()
			if keys.Empty() && name != "shodan-idb" && name != "scanmalware" && name != "subdomaincenter" {
				gologger.Error().Msgf(name, "agent given but keys not found")
				run.markSkipped(name, sources.ReasonMissingKeys, "agent given but keys not found")
				continue agentLabel
			}
			// Advisory check only: Acquire inside Session.Do is authoritative.
			// This avoids starting an engine that is known to be out of budget
			// and gives a clear skip reason even if the engine never calls Do.
			if s.Quota != nil && !s.Quota.Available(name) {
				reason, message := s.Quota.SkipReason(name)
				gologger.Warning().Msgf("skipping engine %s: %s", name, message)
				run.markSkipped(name, reason, message)
				continue agentLabel
			}
			ch, err := agent.Query(ctx, s.Session, &sources.Query{
				Query: q,
				Limit: s.Options.Limit,
			})
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				run.markSkipped(name, classifyQueryError(err), err.Error())
				continue agentLabel
			}
			run.markStarted(name)
			started++
			wg.Add(1)
			go func(engine string, source, relay chan sources.Result, ctx context.Context) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case res, ok := <-source:
						res.Timestamp = time.Now().Unix()
						if !ok {
							return
						}
						if res.Error != nil {
							run.markError(engine, res.Error)
						} else {
							run.markProduced(engine)
						}
						select {
						case <-ctx.Done():
							return
						case relay <- res:
						}
					}
				}
			}(name, ch, megaChan, ctx)
		}
	}

	// All requested engines were skipped before any request was made. This is
	// an explicit failure, not an empty success. Gate on quota being enabled so
	// the legacy path (for example a missing key) keeps its old exit behaviour.
	if s.Quota != nil && started == 0 && len(run.skippedSnapshot()) > 0 {
		s.setReport(run.report())
		return nil, errorutil.NewWithTag("uncover", "all engines were skipped: %s", run.skipSummary())
	}

	// close channel when all sources return
	go func(wg *sync.WaitGroup, megaChan chan sources.Result) {
		wg.Wait()
		s.setReport(run.report())
		close(megaChan)
	}(wg, megaChan)

	return megaChan, nil
}

// ExecuteWithWriters writes output to writer along with stdout
func (s *Service) ExecuteWithCallback(ctx context.Context, callback func(result sources.Result)) error {
	ch, err := s.Execute(ctx)
	if err != nil {
		return err
	}
	if callback == nil {
		return errorutil.NewWithTag("uncover", "result callback cannot be nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, ok := <-ch:
			if !ok {
				return nil
			}
			callback(result)
		}
	}
}

// AllAgents returns all supported uncover Agents
func (s *Service) AllAgents() []string {
	return []string{
		"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye", "netlas", "criminalip", "publicwww", "hunterhow", "google", "odin", "binaryedge", "onyphe", "driftnet", "greynoise", "daydaymap", "nerdydata", "scanmalware", "subdomaincenter",
	}
}

func (s *Service) nilCheck() error {
	if s.Provider == nil {
		return errorutil.NewWithTag("uncover", "provider cannot be nil")
	}
	if s.Options == nil {
		return errorutil.NewWithTag("uncover", "options cannot be nil")
	}
	if s.Session == nil {
		return errorutil.NewWithTag("uncover", "session cannot be nil")
	}
	return nil
}

func (s *Service) hasAnyAnonymousProvider() bool {
	return stringsutil.EqualFoldAny("shodan-idb", s.Options.Agents...) ||
		stringsutil.EqualFoldAny("scanmalware", s.Options.Agents...) ||
		stringsutil.EqualFoldAny("subdomaincenter", s.Options.Agents...) ||
		stringsutil.EqualFoldAny("subdomain-center", s.Options.Agents...)
}
