package sources

import "context"

// Query is the unit of work handed to an Agent.
type Query struct {
	// Query is the native query string the agent sends to its upstream API.
	// In raw passthrough mode it is the user's text unchanged. In unified
	// query mode it is the per-engine output of the querylang compiler.
	Query string
	Limit int
	// Unified is the original unified-syntax text when compilation was used,
	// empty in raw passthrough mode.
	Unified string
	// EffectiveConditions are the canonical conditions that actually
	// constrain Query (all parsed conditions minus explicitly degraded ones).
	// Empty in raw passthrough mode.
	EffectiveConditions []string
	// Degraded reports whether one or more conditions were dropped for this
	// engine; DroppedConditions describes each omission.
	Degraded bool
	// DroppedConditions lists human-readable descriptions of conditions
	// omitted under an explicit degradation policy.
	DroppedConditions []string
	// SyntaxVersion records the grammar version the query was compiled under.
	SyntaxVersion string
}

// Agent fans out a query to one upstream search engine and streams results
// on the returned channel. Implementations must honor ctx during channel
// sends so cancellation does not leak the producer goroutine.
type Agent interface {
	Query(ctx context.Context, session *Session, query *Query) (chan Result, error)
	Name() string
}

// SendResult delivers r on ch unless ctx is cancelled first. It returns
// false when the caller should stop producing, freeing producer goroutines
// blocked on send when no reader remains downstream.
func SendResult(ctx context.Context, ch chan<- Result, r Result) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- r:
		return true
	}
}
