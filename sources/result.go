package sources

import (
	"encoding/json"
	"fmt"
	"net"
)

// ResultStatus classifies a result stream entry so callers can tell the
// three fundamentally different "no asset" situations apart:
// a genuinely empty result set, an engine error, and a query that was
// compiled with degraded conditions. Status zero keeps historical
// behavior: an ordinary asset record.
type ResultStatus string

const (
	// StatusAsset is a normal asset record (zero value, unchanged behavior).
	StatusAsset ResultStatus = ""
	// StatusEngineError means the upstream engine returned an error. This
	// must never be converted into an empty result set.
	StatusEngineError ResultStatus = "engine_error"
	// StatusCompileRejected means the query could not be compiled for this
	// engine at all (unsupported field/operator under the active policy).
	StatusCompileRejected ResultStatus = "compile_rejected"
	// StatusDegraded marks the first stream notice that conditions were
	// dropped with an explicit degradation policy. Asset records that follow
	// carry the same metadata on each record as well.
	StatusDegraded ResultStatus = "degraded"
	// StatusEmpty means the engine call succeeded with zero matching assets.
	StatusEmpty ResultStatus = "empty"
)

type Result struct {
	Timestamp int64  `json:"timestamp"`
	Source    string `json:"source"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Host      string `json:"host"`
	Url       string `json:"url"`
	Raw       []byte `json:"-"`
	Error     error  `json:"-"`

	// Status classifies non-asset stream entries; empty means an asset.
	Status ResultStatus `json:"status,omitempty"`
	// Message carries a human-readable explanation for non-asset statuses.
	Message string `json:"message,omitempty"`
	// EffectiveQuery is the exact native query string sent to the engine
	// when unified query mode was used.
	EffectiveQuery string `json:"effective_query,omitempty"`
	// EffectiveConditions lists the canonical conditions constraining the
	// query (the conditions actually in effect, after any degradation).
	EffectiveConditions []string `json:"effective_conditions,omitempty"`
	// DroppedConditions lists conditions omitted under degradation, each
	// with the reason. Always empty unless the query was actually degraded.
	DroppedConditions []string `json:"dropped_conditions,omitempty"`
	// SyntaxVersion is the unified grammar version applied to this query.
	SyntaxVersion string `json:"syntax_version,omitempty"`
}

func (result *Result) IpPort() string {
	return net.JoinHostPort(result.IP, fmt.Sprint(result.Port))
}

func (result *Result) HostPort() string {
	return net.JoinHostPort(result.Host, fmt.Sprint(result.Port))
}

func (result *Result) RawData() string {
	return string(result.Raw)
}

func (result *Result) JSON() string {
	data, _ := json.Marshal(result)
	return string(data)
}
