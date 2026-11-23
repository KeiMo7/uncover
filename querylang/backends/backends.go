// Package backends contains the per-engine Capabilities declarations and
// native query renderers used by the querylang compiler.
//
// Each file covers one engine family. The capability table is the source of
// truth for what may be compiled: if a field/operator pair is absent, the
// compiler rejects the query for that engine (or records an explicit
// degradation when the caller opted in), so no condition is ever sent to an
// engine that would silently ignore it.
package backends

import (
	"github.com/projectdiscovery/uncover/querylang"
)

// allOps / commonOps are shorthand sets reused across capability tables.
var (
	eqNeq       = []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual}
	textOps     = []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpContains, querylang.OpNotContains, querylang.OpRegex}
	containsOps = []querylang.Operator{querylang.OpContains, querylang.OpNotContains, querylang.OpEqual, querylang.OpNotEqual}
	orderedOps  = []querylang.Operator{querylang.OpEqual, querylang.OpNotEqual, querylang.OpGreater, querylang.OpGreaterOrEqual, querylang.OpLess, querylang.OpLessOrEqual}
)
