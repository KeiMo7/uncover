package uncover

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/uncover/querylang"
	"github.com/projectdiscovery/uncover/querylang/backends"
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
	// Unified enables the unified query language pipeline: queries are
	// parsed into a condition tree and compiled per engine instead of being
	// forwarded verbatim. Default false preserves the historical raw
	// passthrough behavior exactly.
	Unified bool
	// AllowDegrade permits an engine to omit a top-level AND conjunct it
	// cannot express; every omission is reported on the result stream. It
	// has no effect when Unified is false.
	AllowDegrade bool
}

// CoverageEvent summarizes one unified fan-out so partial engine coverage is
// explicit rather than inferred from missing data. It is emitted on the
// result channel (Status == "coverage") once per Execute call.
type CoverageEvent struct {
	Status          string   `json:"status"`
	Query           string   `json:"query"`
	SyntaxVersion   string   `json:"syntax_version,omitempty"`
	EnginesTotal    int      `json:"engines_total"`
	EnginesOK       []string `json:"engines_ok"`
	EnginesFailed   []string `json:"engines_failed"`
	EnginesRejected []string `json:"engines_rejected"`
	EnginesDegraded []string `json:"engines_degraded"`
}

// Service handler of all uncover Agents
type Service struct {
	Options  *Options
	Agents   []sources.Agent
	Session  *sources.Session
	Provider *sources.Provider
	Keys     sources.Keys
	// skipKeyGate disables the per-agent empty-key check. It is intended for
	// in-process tests driving Agent fakes without a provider config;
	// production construction via New never sets it.
	skipKeyGate bool
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
	s.Session, err = sources.NewSession(&s.Keys, opts.MaxRetry, opts.Timeout, 10, opts.Agents, opts.RateLimitUnit, opts.Proxy)
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

	if s.Options.Unified {
		return s.executeUnified(ctx), nil
	}
	return s.executeRaw(ctx), nil
}

// executeRaw is the unchanged historical path: every query string is passed
// to every agent verbatim.
func (s *Service) executeRaw(ctx context.Context) <-chan sources.Result {
	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	// iterate and run all sources
	wg := &sync.WaitGroup{}
	for _, q := range s.Options.Queries {
	agentLabel:
		for _, agent := range s.Agents {
			keys := s.Provider.GetKeys()
			if !s.skipKeyGate && keys.Empty() && agent.Name() != "shodan-idb" && agent.Name() != "scanmalware" && agent.Name() != "subdomaincenter" {
				gologger.Error().Label(agent.Name()).Msg("agent given but keys not found")
				continue agentLabel
			}
			ch, err := agent.Query(ctx, s.Session, &sources.Query{
				Query: q,
				Limit: s.Options.Limit,
			})
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				continue agentLabel
			}
			wg.Add(1)
			go func(source, relay chan sources.Result, ctx context.Context) {
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
						select {
						case <-ctx.Done():
							return
						case relay <- res:
						}
					}
				}
			}(ch, megaChan, ctx)
		}
	}

	// close channel when all sources return
	go func(wg *sync.WaitGroup, megaChan chan sources.Result) {
		wg.Wait()
		defer close(megaChan)
	}(wg, megaChan)

	return megaChan
}

// executeUnified parses each query once into a condition tree, compiles it
// per engine against that engine's declared capabilities, and only then
// calls the agent. Unsupported conditions are rejected (or explicitly
// degraded and reported) before any network request is made.
func (s *Service) executeUnified(ctx context.Context) <-chan sources.Result {
	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	mode := querylang.DegradeReject
	if s.Options.AllowDegrade {
		mode = querylang.DegradeTopLevelAND
	}
	compiler := backends.DefaultCompiler(mode)

	outerWg := &sync.WaitGroup{}
	for _, rawQuery := range s.Options.Queries {
		tree, err := querylang.Parse(rawQuery)
		if err != nil {
			// Parse failure applies to every engine; say so once with the
			// precise position rather than fanning out a broken query.
			outerWg.Add(1)
			go func(q string, perr error) {
				defer outerWg.Done()
				emit(ctx, megaChan, sources.Result{
					Source:  "querylang",
					Status:  sources.StatusCompileRejected,
					Message: perr.Error(),
					Raw:     []byte(q),
				})
			}(rawQuery, err)
			continue
		}

		coverage := &CoverageEvent{
			Status:        "coverage",
			Query:         rawQuery,
			SyntaxVersion: querylang.SyntaxVersion,
			EnginesTotal:  len(s.Agents),
		}
		var covMu sync.Mutex
		queryWg := &sync.WaitGroup{}

		for _, agent := range s.Agents {
			// Same key gate as the raw path: anonymous providers need no
			// keys; everything else is skipped with a warning when the
			// provider config is empty.
			keys := s.Provider.GetKeys()
			if !s.skipKeyGate && keys.Empty() && agent.Name() != "shodan-idb" && agent.Name() != "scanmalware" && agent.Name() != "subdomaincenter" {
				gologger.Error().Label(agent.Name()).Msg("agent given but keys not found")
				continue
			}

			cq, compileErr := compiler.Compile(agent.Name(), tree)
			if compileErr != nil {
				queryWg.Add(1)
				go func(name string, perr error) {
					defer queryWg.Done()
					covMu.Lock()
					coverage.EnginesRejected = append(coverage.EnginesRejected, name)
					covMu.Unlock()
					emit(ctx, megaChan, sources.Result{
						Source:        name,
						Status:        sources.StatusCompileRejected,
						Message:       perr.Error(),
						SyntaxVersion: querylang.SyntaxVersion,
					})
				}(agent.Name(), compileErr)
				continue
			}

			compiledSourcesQuery := &sources.Query{
				Query:               cq.Query,
				Limit:               s.Options.Limit,
				Unified:             rawQuery,
				EffectiveConditions: cq.EffectiveConditions,
				Degraded:            cq.Degraded,
				DroppedConditions:   dropSummary(cq),
				SyntaxVersion:       cq.Version,
			}

			queryWg.Add(1)
			go func(agent sources.Agent, q *sources.Query, cq *querylang.CompiledQuery) {
				defer queryWg.Done()
				if cq.Degraded {
					covMu.Lock()
					coverage.EnginesDegraded = append(coverage.EnginesDegraded, agent.Name())
					covMu.Unlock()
					emit(ctx, megaChan, sources.Result{
						Source:              agent.Name(),
						Status:              sources.StatusDegraded,
						Message:             "query compiled with degraded conditions; see dropped_conditions",
						EffectiveQuery:      cq.Query,
						EffectiveConditions: cq.EffectiveConditions,
						DroppedConditions:   dropSummary(cq),
						SyntaxVersion:       cq.Version,
					})
				}

				ch, err := agent.Query(ctx, s.Session, q)
				if err != nil {
					covMu.Lock()
					coverage.EnginesFailed = append(coverage.EnginesFailed, agent.Name())
					covMu.Unlock()
					// An engine-side failure is reported as an error, never
					// as an empty result set.
					emit(ctx, megaChan, sources.Result{
						Source:              agent.Name(),
						Status:              sources.StatusEngineError,
						Error:               err,
						Message:             err.Error(),
						EffectiveQuery:      cq.Query,
						EffectiveConditions: cq.EffectiveConditions,
						SyntaxVersion:       cq.Version,
					})
					return
				}

				producedAny := false
				hadError := false
				for {
					select {
					case <-ctx.Done():
						return
					case res, ok := <-ch:
						if !ok {
							covMu.Lock()
							if hadError {
								coverage.EnginesFailed = append(coverage.EnginesFailed, agent.Name())
							} else {
								coverage.EnginesOK = append(coverage.EnginesOK, agent.Name())
							}
							covMu.Unlock()
							if !producedAny && !hadError {
								// Successful call, zero assets: make the
								// empty-vs-error distinction explicit.
								emit(ctx, megaChan, sources.Result{
									Source:              agent.Name(),
									Status:              sources.StatusEmpty,
									Message:             "engine returned zero assets for the compiled query",
									EffectiveQuery:      cq.Query,
									EffectiveConditions: cq.EffectiveConditions,
									DroppedConditions:   dropSummary(cq),
									SyntaxVersion:       cq.Version,
								})
							}
							return
						}
						res.Timestamp = time.Now().Unix()
						if res.Error != nil {
							hadError = true
							res.Status = sources.StatusEngineError
							res.Message = res.Error.Error()
						} else {
							producedAny = true
						}
						res.EffectiveQuery = cq.Query
						res.EffectiveConditions = cq.EffectiveConditions
						res.DroppedConditions = dropSummary(cq)
						res.SyntaxVersion = cq.Version
						if !sources.SendResult(ctx, megaChan, res) {
							return
						}
					}
				}
			}(agent, compiledSourcesQuery, cq)
		}

		// One coverage event per query, emitted after its engines settle.
		outerWg.Add(1)
		go func(coverage *CoverageEvent) {
			defer outerWg.Done()
			queryWg.Wait()
			emit(ctx, megaChan, sources.Result{
				Source:  "coverage",
				Status:  sources.ResultStatus(coverage.Status),
				Message: CoverageJSON(coverage),
			})
		}(coverage)
	}

	go func() {
		outerWg.Wait()
		close(megaChan)
	}()

	return megaChan
}

// emit sends a non-asset status result, honoring cancellation.
func emit(ctx context.Context, ch chan<- sources.Result, r sources.Result) {
	if r.Timestamp == 0 {
		r.Timestamp = time.Now().Unix()
	}
	_ = sources.SendResult(ctx, ch, r)
}

func dropSummary(cq *querylang.CompiledQuery) []string {
	if !cq.Degraded {
		return nil
	}
	out := make([]string, 0, len(cq.Dropped))
	for _, d := range cq.Dropped {
		out = append(out, d.Condition+" dropped: "+d.Reason)
	}
	return out
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

// CoverageJSON renders a coverage event for tests and CLI diagnostics.
func CoverageJSON(e *CoverageEvent) string {
	data, _ := json.Marshal(e)
	return string(data)
}
