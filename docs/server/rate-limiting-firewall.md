# Edge Rate Limiting & Firewall

The server's `security:` block adds two pre-dispatch protections in
front of the router: an ordered allow/deny **firewall** (with a
request-size cap) and a per-key token-bucket **rate limiter**. Both
reject abusive traffic before it consumes an agent connection.

They complement the **agent-side route policies** (`routes:` with
`ip_whitelist` / `rate_limit` in `config/agent.yaml`): the edge layer
is coarse, cheap, and pre-dispatch; the agent layer is per-service,
path-aware, and travels with the service definition. Use the edge for
floods and scanner junk, the agent for service-specific policy.

## Middleware order

```
accessLog → metrics → WAF → rateLimit → router
```

A firewall-denied request never consumes a rate-limit token; both are
counted by the metrics middleware.

## Configuration

```yaml
security:
  rate_limit:
    enabled: true
    default:
      key: ip            # ip | host | ip+host
      rate: 100/s        # <n>/<s|m|h> (second/minute/hour also accepted)
      burst: 200         # 0 = default to the rate count
    overrides:           # first hostname match wins
      - hosts: ["api.example.com"]
        rate: 20/s
        burst: 40

  firewall:
    enabled: true
    max_request_bytes: 33554432   # 0 = unlimited
    rules:                        # ordered; first match wins; no match = allow
      - name: block-secret-probes
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
```

### Rate limiter

- Token bucket with lazy refill, sharded 256 ways; idle buckets are
  swept every minute after 10 minutes of inactivity, so IP churn is
  memory-bounded.
- The key is derived from **`r.RemoteAddr`**, never from
  `X-Forwarded-For` — forwarding headers are client-controlled and the
  proxy is the TLS termination point.
- `key: identity` is reserved for the access-policy layer and rejected
  until that ships.
- Rejections: `429` with a `Retry-After` header (whole seconds until a
  token refills).

### Firewall

- A rule matches when **every non-empty clause matches** (clauses
  AND-ed; the values inside one clause OR-ed).
- Host patterns: exact, `*` (any), `*.suffix` (any subdomain, one or
  more labels). Path patterns: exact, `…/*` (base + subtree), `…*`
  (prefix), `/*` (any). Paths are matched after percent-decoding and
  dot-segment collapse, so `/public/../.git/config` still hits a
  `/.git/*` rule.
- Default is allow — an empty rule list is a no-op. End a host's rules
  with a catch-all `deny` to make it default-deny.
- `max_request_bytes` rejects oversized bodies with `413`: immediately
  when `Content-Length` is known, or mid-read for chunked bodies (the
  router maps the cap error to `413`).

## Hot reload

Rules, limits, and overrides re-apply on `SIGHUP` (compiled sets are
swapped atomically; rate-limit buckets reset). Flipping
`security.rate_limit.enabled` or `security.firewall.enabled` requires
a restart — the middleware is only inserted at startup — and the
reload will say so rather than silently ignoring it.

## Metrics

| Metric | Type | Labels |
|--------|------|--------|
| `ztp_ratelimit_rejected_total` | counter | `key_strategy` |
| `ztp_ratelimit_buckets` | gauge | — |
| `ztp_firewall_denied_total` | counter | `rule` |
| `ztp_firewall_oversize_total` | counter | — |

Denials also log at `warn` with the rule name and source address.

## Limitations

- Buckets are in-memory and per-instance: multiple proxy replicas each
  enforce their own limit. The limiter sits behind a small interface so
  a shared backend could be added later.
- This is a deterministic operator-authored rule list, not a managed
  WAF (no CRS rule sets, no anomaly scoring).
