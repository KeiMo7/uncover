package uncover

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

// runState accumulates per-engine participation and skip information for one
// Execute call. It is safe for concurrent use.
type runState struct {
	quota     *sources.QuotaManager
	requested map[string]struct{}

	mu           sync.Mutex
	started      map[string]struct{}
	produced     map[string]bool
	quotaBlocked map[string]bool
	rateLimited  map[string]bool
	lastError    map[string]string
	skipped      map[string]sources.SkippedEngine
	errors       map[string]string
}

func newRunState(quota *sources.QuotaManager, agents []string) *runState {
	requested := make(map[string]struct{}, len(agents))
	for _, agent := range agents {
		requested[sources.CanonicalEngineName(agent)] = struct{}{}
	}
	return &runState{
		quota:        quota,
		requested:    requested,
		started:      make(map[string]struct{}),
		produced:     make(map[string]bool),
		quotaBlocked: make(map[string]bool),
		rateLimited:  make(map[string]bool),
		lastError:    make(map[string]string),
		skipped:      make(map[string]sources.SkippedEngine),
		errors:       make(map[string]string),
	}
}

func (r *runState) markStarted(engine string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started[engine] = struct{}{}
}

func (r *runState) markSkipped(engine, reason, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Do not let a less-specific reason overwrite a quota or rate-limit verdict
	// already recorded for this run.
	if existing, ok := r.skipped[engine]; ok {
		if existing.Reason == sources.ReasonQuotaExhausted || existing.Reason == sources.ReasonRateLimited {
			return
		}
	}
	r.skipped[engine] = sources.SkippedEngine{Engine: engine, Reason: reason, Error: message}
}

// markError records the last error produced by an engine. Quota and rate
// limit errors are reclassified as skips so a mid-stream exhaustion shows as
// `quota_exhausted`, not `query_error`.
func (r *runState) markError(engine string, err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case errors.Is(err, sources.ErrQuotaExhausted):
		r.quotaBlocked[engine] = true
		r.lastError[engine] = err.Error()
	case errors.Is(err, sources.ErrRateLimitedExhausted):
		r.rateLimited[engine] = true
		r.lastError[engine] = err.Error()
	default:
		r.errors[engine] = err.Error()
	}
}

// markStarted records that an engine produced at least one result (or was
// started). It is called by Execute for each engine it launches.
func (r *runState) markProduced(engine string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.produced[engine] = true
}

func (r *runState) skippedSnapshot() []sources.SkippedEngine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sources.SkippedEngine, 0, len(r.skipped))
	for _, skip := range r.skipped {
		out = append(out, skip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Engine < out[j].Engine })
	return out
}

func (r *runState) skipSummary() string {
	skips := r.skippedSnapshot()
	parts := make([]string, 0, len(skips))
	for _, skip := range skips {
		parts = append(parts, fmt.Sprintf("%s (%s)", skip.Engine, skip.Reason))
	}
	return strings.Join(parts, ", ")
}

// report builds a snapshot of the run. Engines known to the quota manager but
// not requested are omitted; requested engines always appear.
func (r *runState) report() *sources.RunReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	report := &sources.RunReport{
		Schema:       "uncover.quota-report/v1",
		Enabled:      r.quota != nil,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Participated: []string{},
		Skipped:      []sources.SkippedEngine{},
	}

	requested := make(map[string]struct{})
	for engine := range r.requested {
		requested[engine] = struct{}{}
	}
	for engine := range r.started {
		requested[engine] = struct{}{}
	}
	for engine := range r.skipped {
		requested[engine] = struct{}{}
	}
	for engine := range r.errors {
		requested[engine] = struct{}{}
	}
	for engine := range r.quotaBlocked {
		requested[engine] = struct{}{}
	}
	for engine := range r.rateLimited {
		requested[engine] = struct{}{}
	}

	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry := sources.EngineReport{Engine: name}
		if usage, ok := r.usageFor(name); ok {
			entry.CallsUsed = usage.Used
			entry.CallsAttempted = usage.Attempted
			entry.Limit = usage.Limit
			entry.Remaining = usage.Remaining
			entry.Window = string(usage.WindowType)
			entry.QuotaExhausted = usage.QuotaBlocked
			entry.RateLimited = usage.RateLimited || usage.RateExhausted
			entry.FailOpen = usage.FailOpen
			entry.FailOpenReason = usage.FailOpenReason
			entry.Unconfigured = usage.Limit == nil
		}
		produced := r.produced[name]
		switch {
		// An engine that produced results in any query is never reported as
		// fully skipped, even if a later query had to skip it.
		case r.quotaBlocked[name] && produced:
			entry.QuotaExhausted = true
			entry.Status = sources.StatusPartial
			entry.Reason = sources.ReasonQuotaExhausted
			entry.Error = r.lastError[name]
			report.Participated = append(report.Participated, name)
		case r.rateLimited[name] && produced:
			entry.RateLimited = true
			entry.Status = sources.StatusPartial
			entry.Reason = sources.ReasonRateLimited
			entry.Error = r.lastError[name]
			report.Participated = append(report.Participated, name)
		case r.quotaBlocked[name]:
			entry.QuotaExhausted = true
			entry.Status = sources.StatusSkipped
			entry.Reason = sources.ReasonQuotaExhausted
			entry.Error = r.lastError[name]
			report.Skipped = append(report.Skipped, sources.SkippedEngine{Engine: name, Reason: sources.ReasonQuotaExhausted, Error: entry.Error})
		case r.rateLimited[name]:
			entry.RateLimited = true
			entry.Status = sources.StatusSkipped
			entry.Reason = sources.ReasonRateLimited
			entry.Error = r.lastError[name]
			report.Skipped = append(report.Skipped, sources.SkippedEngine{Engine: name, Reason: sources.ReasonRateLimited, Error: entry.Error})
		case r.skipped[name].Engine != "" && produced:
			skip := r.skipped[name]
			entry.Status = sources.StatusPartial
			entry.Reason = skip.Reason
			entry.Error = skip.Error
			report.Participated = append(report.Participated, name)
		case r.skipped[name].Engine != "":
			skip := r.skipped[name]
			entry.Status = sources.StatusSkipped
			entry.Reason = skip.Reason
			entry.Error = skip.Error
			report.Skipped = append(report.Skipped, skip)
		case r.errors[name] != "":
			entry.Status = sources.StatusError
			entry.Reason = sources.ReasonQueryError
			entry.Error = r.errors[name]
			report.Participated = append(report.Participated, name)
		default:
			entry.Status = sources.StatusParticipated
			report.Participated = append(report.Participated, name)
		}
		report.Engines = append(report.Engines, entry)
	}
	return report
}

func (r *runState) usageFor(engine string) (sources.EngineUsage, bool) {
	if r.quota == nil {
		return sources.EngineUsage{}, false
	}
	if !r.quota.Has(engine) {
		return sources.EngineUsage{}, false
	}
	return r.quota.Usage(engine), true
}

// classifyQueryError maps an error returned from Agent.Query to a skip reason.
func classifyQueryError(err error) string {
	switch {
	case errors.Is(err, sources.ErrQuotaExhausted):
		return sources.ReasonQuotaExhausted
	case errors.Is(err, sources.ErrRateLimitedExhausted):
		return sources.ReasonRateLimited
	default:
		return sources.ReasonQueryError
	}
}

func (s *Service) setReport(report *sources.RunReport) {
	// Legacy mode has no report; keep Report() nil so callers can tell quota
	// management is off.
	if s.Quota == nil {
		return
	}
	s.reportMu.Lock()
	s.report = report
	s.reportMu.Unlock()
}

// Report returns the report of the most recent completed run, or nil when
// quota management is disabled or no run has completed.
func (s *Service) Report() *sources.RunReport {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	return s.report
}
