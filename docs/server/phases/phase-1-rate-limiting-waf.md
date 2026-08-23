# Phase 1 — Rate Limiting & WAF / Firewall

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: **implemented** — `internal/security`, wired in
> `internal/server` behind the `security:` config block; user docs in
> [rate-limiting-firewall.md](../rate-limiting-firewall.md).
> Deviations from this plan: the `identity` key strategy is rejected at
> validation until Phase 2 exists (instead of silently falling back to
> `ip`); path matching uses the same wildcard style as the agent's route
> matchers (exact / `…*` prefix / `…/*` subtree) rather than a general
> glob, applied after percent-decoding and dot-segment collapse; the
> access-policy slot in the middleware chain is still TODO (Phase 2).
> Note the agent-side complement that shipped first: per-service
> `routes:` policies (`ip_whitelist`, `rate_limit`) in
> `internal/agent/middleware.go` — the edge layer is coarse and
> pre-dispatch, the agent layer is per-service and path-aware.

## 1. Goal

Give the public edge cheap, **pre-authentication** abuse protection:

- **Rate limiting** — token-bucket throttling keyed by client IP,
  `Host`, or identity.
- **Firewall (basic WAF)** — an ordered allow/deny rule list matching
  on IP CIDR, `Host`, path, method; plus a hard request-size cap.

Both run before the Phase 2 access-policy layer so floods and obvious
junk are rejected without ever touching identity, OIDC, or agent
dispatch code.

This is **not** a managed WAF rule engine (ModSecurity-class). It is a
deterministic, operator-authored rule list.

## 2. Where it sits

New package `internal/security`. Two `http.Handler` middlewares in the
chain built in `internal/server/server.go`. Recall the chain wraps
inner-to-outer; target order outermost-first:

```
accessLog → metrics → WAF → rateLimit → accessPolicy → altSvc → router
                      ▲         ▲
                      │         └─ 429 Too Many Requests + Retry-After
                      └─ 403 Forbidden (deny) / 413 Payload Too Large
```

WAF is outside rate-limit: a request denied by a static firewall rule
should not even consume a rate-limit token. Both are outside
`accessPolicy`: cheapest rejects first.

## 3. Rate limiter architecture

### 3.1 Algorithm

Token bucket per key. Each bucket:

```go
type bucket struct {
    tokens   float64   // current tokens
    last     time.Time // last refill timestamp
}
```

On `Allow(key)`:

```
now    := time.Now()
elapsed := now.Sub(b.last).Seconds()
b.tokens = min(burst, b.tokens + elapsed*rate)   // lazy refill
b.last   = now
if b.tokens >= 1 { b.tokens--; return true }
return false
```

Lazy refill — no background ticker per bucket. A bucket is only
touched when its key is seen.

### 3.2 Sharding & memory

A single `map` + `sync.Mutex` would serialize the whole edge. Instead:

```go
type Limiter struct {
    shards   [N]shard          // N = 256, power of two
    rate     float64
    burst    float64
}
type shard struct {
    mu      sync.Mutex
    buckets map[string]*bucket
}
```

Shard index = `fnv32(key) & (N-1)`. Lock contention is 1/N of a global
lock.

**Eviction.** Idle buckets must not leak memory under IP churn. One
background goroutine sweeps every `evictInterval` (default 60s) and
drops any bucket whose `last` is older than `idleTTL` (default 10m).
Per-shard locking keeps the sweep from stalling the hot path. Shard
count is fixed, so the map-of-maps itself is bounded.

### 3.3 Key strategies

| `key` | Derived from | Use |
|-------|--------------|-----|
| `ip` | `r.RemoteAddr` host | default; per-source throttle |
| `host` | `r.Host` | protect one slow backend globally |
| `ip+host` | concat | per-source-per-service |
| `identity` | Phase 2 identity (falls back to `ip` if access disabled) | per-user quota |

**Source IP is `r.RemoteAddr`, never `X-Forwarded-For`.** The proxy is
the TLS termination point; a client-supplied `X-Forwarded-For` is
attacker-controlled. This matches `setForwardedHeaders` in
`modules/ztrouter/handler.go`, which *overwrites* forwarded headers.

### 3.4 Overrides

`overrides` is a list of `{hosts:[glob], key, rate, burst}`. First
hostname-glob match wins; its own `Limiter` instance is used. No match
→ the `default` limiter. Compiled once at config load into:

```go
type rateLimitSet struct {
    def       *Limiter
    overrides []struct{ hosts []glob; lim *Limiter }
}
```

## 4. Firewall architecture

### 4.1 Rule model

```go
type firewallRule struct {
    name    string
    action  action            // allow | deny
    hosts   []glob            // empty = any
    paths   []glob            // empty = any
    methods map[string]bool   // empty = any
    cidrs   []*net.IPNet      // empty = any
}
```

A rule **matches** when every non-empty clause matches. Clauses are
AND-ed; the lists within a clause are OR-ed.

### 4.2 Evaluation

```
for each rule in order:
    if rule matches request:
        return rule.action          // first match wins
return allow                        // default: allow
```

Default-allow keeps the firewall opt-in per rule — an empty
`firewall.rules` is a no-op. To make a host default-deny, end its
rules with a catch-all `deny` (see the config example).

Size cap is separate from the rule list: if `Content-Length >
max_request_bytes` → `413` immediately. For chunked bodies with no
`Content-Length`, the middleware wraps `r.Body` in a counting reader
that aborts past the cap.

### 4.3 Compilation & hot reload

Raw YAML rules compile once into `[]firewallRule` (globs and CIDRs
parsed). The compiled set lives behind an `atomic.Pointer[firewallSet]`;
SIGHUP builds a new set and `Store`s it. In-flight requests keep the
old pointer — no lock on the hot path, no torn reads.

## 5. Configuration

```yaml
security:
  rate_limit:
    enabled: true
    default:
      key: ip
      rate: 100/s          # parsed: "<n>/<s|m|h>"
      burst: 200
    overrides:
      - hosts: ["api.example.com"]
        key: ip
        rate: 20/s
        burst: 40

  firewall:
    enabled: true
    rules:
      - name: block-secrets-probes
        action: deny
        when:
          paths: ["/.env", "/.git/*", "/wp-admin/*"]
      - name: office-only-admin
        action: allow
        when:
          hosts: ["admin.example.com"]
          source_cidrs: ["203.0.113.0/24"]
      - name: deny-other-admin
        action: deny
        when:
          hosts: ["admin.example.com"]
    max_request_bytes: 33554432   # 32 MiB; 0 = unlimited
```

Validation: `rate` matches `^\d+/[smh]$`; `burst ≥ 1`; `key` ∈
{ip,host,ip+host,identity}; `action` ∈ {allow,deny}; every glob
compiles; every CIDR parses; rule `name`s are unique (they label
metrics).

## 6. Request flow

```
            ┌───────────── WAF middleware ─────────────┐
request ───▶│ Content-Length > cap?  ──yes──▶ 413      │
            │ firewall.Decision(r)   ──deny─▶ 403       │
            │           │ allow                        │
            └───────────┼──────────────────────────────┘
                        ▼
            ┌────────── rateLimit middleware ──────────┐
            │ key := keyFor(r, cfg.key)                │
            │ lim := setForHost(r.Host)                │
            │ lim.Allow(key)?  ──no──▶ 429 + Retry-After│
            │           │ yes                          │
            └───────────┼──────────────────────────────┘
                        ▼
                  access policy → router
```

`429` carries `Retry-After: 1` (seconds) and a short text body. `413`
and `403` carry a plain-text reason; no rule internals are leaked to
the client.

## 7. Concurrency & failure modes

- Limiter: per-shard `sync.Mutex`; the eviction goroutine takes the
  same per-shard lock — no separate lock order. `-race` covers
  concurrent `Allow` + sweep.
- Firewall: lock-free read via `atomic.Pointer`; SIGHUP swaps the
  pointer.
- A panic in either middleware must not take down the listener — the
  stdlib `http.Server` already recovers per-request, but the
  middlewares themselves contain no panicking paths (pure map/slice
  ops).
- If `security` is absent or `enabled: false`, the middleware is not
  inserted at all — zero overhead, not a no-op wrapper.

## 8. Observability

| Metric | Type | Labels |
|--------|------|--------|
| `ztp_ratelimit_rejected_total` | counter | `key_strategy` |
| `ztp_ratelimit_buckets` | gauge | — (live bucket count) |
| `ztp_firewall_denied_total` | counter | `rule` |
| `ztp_firewall_oversize_total` | counter | — |

Added to `internal/server/metrics.go`. Denials also log at `warn` with
the rule name and source IP (truncated) for incident triage.

## 9. Implementation steps

1. `serverconfig`: `SecurityConfig`, `RateLimitConfig`,
   `FirewallConfig`, the `rate` parser, validator.
2. `internal/security/ratelimit.go`: `bucket`, `shard`, `Limiter`,
   `rateLimitSet`, eviction goroutine. Tests: refill math, burst
   ceiling, eviction, `-race`.
3. `internal/security/firewall.go`: `firewallRule`, compile, `Decision`,
   counting body reader. Tests: precedence, AND/OR semantics, CIDR,
   size cap.
4. `internal/security/middleware.go`: the two `http.Handler` wrappers.
5. `internal/server/server.go`: insert into the chain when
   `security.*.enabled`; `metrics.go`: new counters; `reload.go`:
   classify `security` hot-reloadable.
6. Docs: `docs/server/rate-limiting-firewall.md`.

## 10. Testing strategy

- Token-bucket: a burst of `burst` requests passes, the next is
  rejected; after `1/rate` seconds exactly one more passes. Use an
  injectable clock so tests are deterministic.
- Eviction: insert keys, advance the clock past `idleTTL`, run the
  sweep, assert the shard map shrank.
- `-race`: N goroutines hammering `Allow` while the sweeper runs.
- Firewall: table-driven precedence — the office-only-admin example
  must allow `203.0.113.5` and deny `198.51.100.5` on
  `admin.example.com`.
- Middleware: assert exact status codes and `Retry-After` header.
- Hot reload: swap rules mid-test, confirm new rules apply and no
  request errors during the swap.

## 11. Limitations & out of scope

- **Single instance.** In-memory buckets do not coordinate across
  multiple proxy replicas — each replica enforces its own limit.
  `ratelimit.go` is written behind a `Limiter` interface so a shared
  backend (Redis, etc.) can be added later without touching the
  middleware. Documented, not built.
- No managed/CRS rule sets, no anomaly scoring, no bot fingerprinting.
- No per-rule rate limits (rate limiting and firewall are separate
  layers); compose them with overrides if needed.
