# Quota report sample

Real output of a four-engine run with this configuration:

```yaml
window: {type: fixed, size: 1h}
engines:
  shodan: {limit: 100}
  censys: {limit: 2}
```

and one engine (`odin`) whose upstream returned malformed JSON.

| Engine | Status | Why |
| --- | --- | --- |
| `shodan` | participated | used 3 / 100 |
| `fofa` | participated | no quota entry (`unconfigured: true`), unlimited |
| `censys` | **partial** | **quota exhausted** after 2 of 2 calls (`reason: quota_exhausted`) |
| `odin` | **skipped** | **upstream error**, not quota (`reason: query_error`) |

The distinction the request asked for is the `reason` field:

- `quota_exhausted` — the engine was skipped because its budget ran out.
- `query_error` — the engine was skipped or truncated because the call failed.

`censys` is `partial` rather than `skipped` because it returned its two allowed
results before the budget ran out; `odin` produced nothing, so it is `skipped`.
