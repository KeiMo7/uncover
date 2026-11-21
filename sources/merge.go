package sources

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// EngineState describes how one engine behaved during a merged run.
type EngineState string

const (
	// EngineStateOK means the engine returned at least one usable result.
	EngineStateOK EngineState = "ok"
	// EngineStateEmpty means the engine answered but returned no results.
	// It is deliberately distinct from EngineStateError.
	EngineStateEmpty EngineState = "empty"
	// EngineStateError means the engine failed (query error, missing keys,
	// or only error results) and produced nothing usable.
	EngineStateError EngineState = "error"
)

// EngineReport is the per-engine outcome of a merged run.
type EngineReport struct {
	Name      string      `json:"name"`
	State     EngineState `json:"state"`
	Results   int         `json:"results"`
	Errors    int         `json:"errors,omitempty"`
	Malformed int         `json:"malformed,omitempty"`
	Err       string      `json:"error,omitempty"`
}

// MergedAsset is one asset merged across engines. Sources stays a structured
// slice all the way to the output layer; it is never pre-rendered into a
// string inside the pipeline.
type MergedAsset struct {
	Key string `json:"asset"`
	// Result is the representative original form (first result seen for
	// this identity). It is never normalized in place.
	Result Result `json:"-"`
	// Sources are the engines that returned this asset, sorted.
	Sources []string `json:"sources"`
	// Results keeps every original engine result for this asset, so the
	// raw per-engine forms survive merging.
	Results []Result `json:"-"`
}

// Confidence is the number of distinct engines that returned this asset.
func (m *MergedAsset) Confidence() int {
	return len(m.Sources)
}

// jsonView is the JSONL rendering of a merged asset: representative fields
// in their original form plus structured provenance.
type mergedAssetJSON struct {
	Asset      string   `json:"asset"`
	IP         string   `json:"ip,omitempty"`
	Port       int      `json:"port,omitempty"`
	Host       string   `json:"host,omitempty"`
	Url        string   `json:"url,omitempty"`
	Sources    []string `json:"sources"`
	Confidence int      `json:"confidence"`
	Timestamp  int64    `json:"timestamp"`
}

// JSON renders the merged asset as one JSONL line.
func (m *MergedAsset) JSON() string {
	view := mergedAssetJSON{
		Asset:      m.Key,
		IP:         m.Result.IP,
		Port:       m.Result.Port,
		Host:       m.Result.Host,
		Url:        m.Result.Url,
		Sources:    m.Sources,
		Confidence: m.Confidence(),
		Timestamp:  m.Result.Timestamp,
	}
	data, _ := json.Marshal(view)
	return string(data)
}

// ResultObserver receives per-engine lifecycle events and per-result data
// from the service fan-out. Implementations must be safe for concurrent
// use: every agent relay goroutine calls Add independently.
type ResultObserver interface {
	// NoteEngineStart records that an engine was launched for this run, so
	// an engine that streams nothing is still reported (as empty).
	NoteEngineStart(name string)
	// NoteEngineError records that an engine could not run at all
	// (query construction failed, keys missing, ...).
	NoteEngineError(name string, err error)
	// Add consumes one streamed result from an engine.
	Add(res Result)
}

type engineStats struct {
	results   int
	errors    int
	malformed int
	fatal     string // query-level failure, engine never streamed
	lastErr   string // last streamed error message
}

// Merger merges results from all engines by canonical asset identity while
// keeping per-engine provenance. It is the ResultObserver used by merged
// runs and is safe for concurrent use.
type Merger struct {
	mu      sync.Mutex
	assets  map[string]*MergedAsset
	sources map[string]map[string]struct{} // asset key -> engine set
	engines map[string]*engineStats
}

// NewMerger creates an empty Merger.
func NewMerger() *Merger {
	return &Merger{
		assets:  map[string]*MergedAsset{},
		sources: map[string]map[string]struct{}{},
		engines: map[string]*engineStats{},
	}
}

func (m *Merger) statsFor(name string) *engineStats {
	st, ok := m.engines[name]
	if !ok {
		st = &engineStats{}
		m.engines[name] = st
	}
	return st
}

// NoteEngineStart implements ResultObserver.
func (m *Merger) NoteEngineStart(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statsFor(name)
}

// NoteEngineError implements ResultObserver.
func (m *Merger) NoteEngineError(name string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.statsFor(name)
	st.errors++
	st.fatal = err.Error()
}

// Add implements ResultObserver. Results carrying an Error are counted
// against their engine; results without any usable identity are malformed
// and skipped (counted); everything else is merged by AssetKey.
func (m *Merger) Add(res Result) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.statsFor(res.Source)
	if res.Error != nil {
		st.errors++
		st.lastErr = res.Error.Error()
		return
	}
	key := AssetKey(res)
	if key == "" {
		st.malformed++
		return
	}
	st.results++
	asset, ok := m.assets[key]
	if !ok {
		asset = &MergedAsset{Key: key, Result: res}
		m.assets[key] = asset
		m.sources[key] = map[string]struct{}{}
	}
	asset.Results = append(asset.Results, res)
	if _, seen := m.sources[key][res.Source]; !seen {
		m.sources[key][res.Source] = struct{}{}
		asset.Sources = append(asset.Sources, res.Source)
	}
}

// MergeResult is the finalized outcome of a merged run.
type MergeResult struct {
	Assets  []MergedAsset
	Engines []EngineReport
}

// AllEnginesFailed reports whether at least one engine ran and every engine
// ended in the error state.
func (r *MergeResult) AllEnginesFailed() bool {
	if len(r.Engines) == 0 {
		return false
	}
	for _, e := range r.Engines {
		if e.State != EngineStateError {
			return false
		}
	}
	return true
}

// FailureSummary renders the per-engine errors for the all-failed message.
func (r *MergeResult) FailureSummary() string {
	parts := make([]string, 0, len(r.Engines))
	for _, e := range r.Engines {
		if e.Err != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", e.Name, e.Err))
		}
	}
	return strings.Join(parts, "; ")
}

// Finalize sorts assets and engine reports deterministically. Assets are
// ordered by confidence (number of engines) descending, then by canonical
// key ascending, so identical inputs always produce byte-identical output
// regardless of engine completion order.
func (m *Merger) Finalize() *MergeResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := &MergeResult{
		Assets:  make([]MergedAsset, 0, len(m.assets)),
		Engines: make([]EngineReport, 0, len(m.engines)),
	}
	for _, asset := range m.assets {
		sort.Strings(asset.Sources)
		result.Assets = append(result.Assets, *asset)
	}
	sort.Slice(result.Assets, func(i, j int) bool {
		a, b := &result.Assets[i], &result.Assets[j]
		if a.Confidence() != b.Confidence() {
			return a.Confidence() > b.Confidence()
		}
		return a.Key < b.Key
	})
	for name, st := range m.engines {
		report := EngineReport{
			Name:      name,
			Results:   st.results,
			Errors:    st.errors,
			Malformed: st.malformed,
		}
		switch {
		case st.fatal != "":
			report.State = EngineStateError
			report.Err = st.fatal
		case st.results == 0 && st.errors > 0:
			report.State = EngineStateError
			report.Err = st.lastErr
		case st.results == 0:
			report.State = EngineStateEmpty
		default:
			report.State = EngineStateOK
		}
		result.Engines = append(result.Engines, report)
	}
	sort.Slice(result.Engines, func(i, j int) bool {
		return result.Engines[i].Name < result.Engines[j].Name
	})
	return result
}
