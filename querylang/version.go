// Package querylang implements the uncover unified query language.
//
// A unified query is parsed once into a condition tree (see ast.go) and then
// compiled independently for every search engine backend (see compiler.go and
// backends/). Backends declare their capability boundaries up front
// (capabilities.go); the compiler rejects or explicitly degrades unsupported
// conditions instead of silently dropping them, so an engine that would ignore
// an unknown field can never produce an under-constrained result set that
// looks normal.
//
// The language is versioned (SyntaxVersion). Parsing an older version always
// yields the same semantics; versions only add syntax, they never change the
// meaning of an already valid query.
package querylang

// SyntaxVersion is the version of the unified query grammar understood by
// this build. It is embedded in every ParseError and every compiled query so
// callers can record which grammar semantics were applied.
//
// Compatibility rules:
//   - v1 is and remains the baseline: every v1 query parses to the same
//     condition tree on every future build.
//   - A new version may add fields/operators/keywords, but must never change
//     the meaning of a query that was valid under an older version.
//   - Queries without an explicit version header parse as LATEST syntax while
//     retaining v1-compatible semantics for the subset that v1 defined.
const SyntaxVersion = "uql/v1"
