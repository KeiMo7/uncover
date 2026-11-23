# Unified Query Language (uql/v1)

The unified query language solves one problem: the same search intent must
constrain every engine to the same scope. A query is parsed once into a
condition tree, then compiled independently for each engine against that
engine's declared capability boundary. A raw query string is never forwarded
verbatim in unified mode, so an engine that silently ignores unknown fields
can no longer return an under-constrained result set that looks normal.

- Grammar version: `uql/v1` (reported on every compiled query and parse
  error).
- Enable per run with `-uq` / `--unified-query`. Without it, uncover keeps
  the historical raw passthrough behavior byte-for-byte.
- Inspect what each engine would receive without sending any request:
  `-eq` / `--explain-query`.

## Syntax

```
expr    = orExpr
orExpr  = andExpr ( OR andExpr )*
andExpr = unary  ( (AND | <implicit>) unary )*
unary   = NOT unary | primary
primary = '(' expr ')' | leaf
leaf    = field operator value
        | field BETWEEN low AND high
        | field IN (v1, v2, ...)
```

`AND` binds tighter than `OR`; `NOT` binds tightest; parentheses override.
`AND` is optional — two adjacent conditions imply conjunction. Keywords are
case-insensitive.

### Operators

| Token | Meaning |
|---|---|
| `=` | equality |
| `!=` | inequality |
| `:` | contains/sub-tree match |
| `!:` | negated contains |
| `~` | regex |
| `> >= < <=` | ordered comparison (numeric/time fields) |
| `BETWEEN a AND b` | inclusive interval |
| `IN (a, b, ...)` | value set |

### Canonical fields

Domain/host: `domain`, `subdomain`, `hostname`
Network: `ip`, `cidr`, `ip_range`, `port`, `port_range`, `protocol`
Application: `service`, `product`, `os`
HTTP: `http.title`, `http.header`, `http.status`, `http.body`
Certificate: `cert`, `cert.common_name`, `cert.issuer`, `cert.issuer_org`,
`cert.subject`, `cert.organization`, `cert.fingerprint`
Time: `first_seen`, `last_seen`
Other: `asn`, `organization`, `country`, `raw`

Common per-engine spellings are accepted as aliases and normalized at parse
time (e.g. `title` → `http.title`, `html` → `http.body`, `ssl` → `cert`,
`sha1`/`sha256` → `cert.fingerprint`). Unknown fields are a parse error, not
a silent ignore.

### Examples

```
domain : "example.com" AND port = 443
port IN (80, 443, 8080)
port_range BETWEEN 8000 AND 8100
ip_range BETWEEN "10.0.0.1" AND "10.0.0.50"
cidr = "10.0.0.0/24"
cert.fingerprint = "AA:BB:CC:..."
cert.issuer_org : "Let's Encrypt"
last_seen BETWEEN "2024-01-01" AND "2024-06-30"
(port = 80 OR port = 443) AND NOT service = "ftp"
```

## Capability boundaries and the no-silent-drop rule

Every engine backend declares, in code, which canonical fields and operators
it can express (`querylang/backends/*`). At compile time each leaf is
accounted for exactly once:

1. **Full / alternative support** — compiled natively; non-obvious native
   spellings (range expansion, keyword substitution, field aliases) are
   recorded as `alternative` entries in the equivalence report.
2. **Unsupported** — compilation for that engine fails with a
   `compile_rejected` result naming the condition, the reason, and any
   supported alternative spellings. No request is sent to that engine.
3. **Degradable** — only emitted when the run explicitly opts in with
   `-ad` / `--allow-degrade`, and only for a top-level `AND` conjunct. The
   dropped condition is enumerated on every result (`dropped_conditions`)
   and in a `degraded` stream notice. Dropping an `OR` branch or a negated
   condition is always rejected, because it would change semantics rather
   than merely widen scope.

Invariant: `effective conditions + dropped conditions == parsed conditions`.

## Distinguishing empty results, errors, and degradation

Unified-mode stream entries carry an explicit status:

| Status | Meaning |
|---|---|
| *(empty)* | ordinary asset record |
| `empty` | engine call succeeded, zero matching assets |
| `engine_error` | upstream error — never converted into an empty set |
| `compile_rejected` | query could not be compiled for this engine |
| `degraded` | conditions were explicitly dropped under `-ad` |
| `coverage` | per-query summary of which engines succeeded/failed/rejected/degraded |

Every asset record also carries `effective_query` (the exact native string
sent), `effective_conditions`, `dropped_conditions`, and `syntax_version`.

## Versioning and backward compatibility

- `uql/v1` is the baseline. Every v1-valid query parses to the same
  condition tree on every future build.
- New versions may add fields/operators/keywords but must never change the
  meaning of a query valid under an older version.
- Adding a field alias is safe; removing or retargeting one requires a
  syntax version bump.
- Repeated compilation of the same tree is deterministic (covered by
  `TestCompile_RepeatedCompilationIsStable`).

## Existing behavior that is intentionally untouched

- Raw passthrough remains the default; engine-specific flags (`-shodan`,
  `-fofa`, ...) work exactly as before.
- Provider config and key loading are unchanged.
- Asset result fields and JSON/raw/text output formats are unchanged; the
  new metadata is additive (`omitempty`).
- No external query service or online syntax validation is used — parsing,
  capability checks and compilation are all local.
