# Server

The server-side component is the `zero-trust-proxy` binary at
`cmd/zero-trust-proxy`. It owns TLS termination, HTTP routing, and the
agent mTLS control plane.

> Caddy was replaced by this binary — see
> [replace-caddy-plan.md](replace-caddy-plan.md) for the migration
> history.

## Packages

| Package | Role |
|---------|------|
| `cmd/zero-trust-proxy` | Entrypoint |
| `internal/server` | Lifecycle: TLS, listeners, redirector, HTTP/3, metrics, access log, known-hosts cache, signal handling |
| `internal/security` | Edge firewall (ordered allow/deny rules, request-size cap) + rate limiter, applied before agent dispatch |
| `internal/serverconfig` | YAML config schema, loader, validator |
| `modules/ztagents` | mTLS listener, agent registry, WebSocket session tracking |
| `modules/ztrouter` | `http.Handler`: per-request agent lookup and mTLS multiplexing; branded error pages |
| `modules/zttcp` | Public TCP listeners for `protocol: tcp` services (byte relay, optional TLS offload) |

## Build

```bash
go build -o bin/zero-trust-proxy ./cmd/zero-trust-proxy
```

## Run

```bash
./bin/zero-trust-proxy run --config config/server.yaml

# Validate config without starting:
./bin/zero-trust-proxy validate --config config/server.yaml

# Override listen addresses (useful for local dev — non-privileged ports):
./bin/zero-trust-proxy run --config config/server.yaml --http :8080 --https :8443
```

## Configuration

```yaml
listen:
  http: ":80"
  https: ":443"
  http3: ""                  # optional UDP address, e.g. ":443" — HTTP/3 / QUIC
  http_redirect: true        # 308 → https://{host}{uri}, ACME challenge bypass

tls:
  mode: acme                 # manual | sni | acme | none
  manual:
    cert_file: config/certs/server.crt
    key_file:  config/certs/server.key
  sni:
    "service.example.com":
      cert_file: ...
      key_file:  ...
  acme:
    storage_dir: /config/acme
    email: ops@example.com
    ca_url: ""               # optional override

agents:
  listen:    ":8443"
  cert_file: config/certs/server.crt
  key_file:  config/certs/server.key
  ca_file:   config/certs/ca.crt
  check_addr: ":2020"        # optional legacy ACME-ask endpoint; "" disables
  tcp_port_min: 20000        # optional: port range for TCP-service listeners
  tcp_port_max: 30000        #           (protocol: tcp services get a port from this range)
  identity:
    bind_to: none            # cn | san | none — bind register ID to the client cert
  acl:                       # per-agent hostname allow-list (label-aware globs)
    allow_unlisted: true
    agents:
      - id: "synology"
        allowed_hosts: ["*.local.example.com"]
  revocation:                # client-cert revocation at the TLS handshake
    crl_file: ""             # re-read on SIGHUP
    denied_serials: []       # hex serials

router:
  request_timeout: 2m

logging:
  level: info                # debug | info | warn | error
  format: console            # console | json
  access_log: false          # per-request JSON access logs (method, host, status, duration, agent_id, …)

metrics:
  addr: ""                   # e.g. "127.0.0.1:9100" — Prometheus exporter at /metrics, no auth

security:                    # optional edge protections, applied before agent dispatch
  rate_limit:
    enabled: false
    default:
      key: ip                # ip | host | ip+host — bucket key strategy
      rate: 100/s            # <n>/<s|m|h> (second/minute/hour also accepted)
      burst: 200             # 0 = default to the rate count
    overrides:               # first hostname match wins (exact, "*", or "*.suffix")
      - hosts: ["api.example.com"]
        rate: 20/s
        burst: 40
  firewall:
    enabled: false
    max_request_bytes: 33554432   # 413 above this; 0 = unlimited
    rules:                        # ordered; first match wins; no match = allow
      - name: block-secret-probes
        action: deny              # allow | deny
        when:                     # clauses AND-ed; values within a clause OR-ed
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

## Edge security

With `security.firewall` / `security.rate_limit` enabled, requests pass
through `WAF → rateLimit` before reaching the router, so floods and
scanner junk are rejected (403 / 413 / 429 with `Retry-After`) without
consuming an agent connection — and a firewall-denied request never
consumes a rate-limit token. Client IPs come from the TCP connection
(`RemoteAddr`), never from forwarding headers; firewall paths are
matched after percent-decoding and dot-segment collapse. This edge
layer is coarse and pre-dispatch — for per-service, path-aware policy
(IP whitelists, per-route rate limits) use the agent's `routes:`
section instead. Full reference:
[rate-limiting-firewall.md](rate-limiting-firewall.md).

## Metrics

Setting `metrics.addr` enables a Prometheus text-format exporter at
`/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `ztp_requests_total{method,status}` | counter | HTTP requests handled (status grouped by 2xx/3xx/4xx/5xx) |
| `ztp_request_duration_seconds` | histogram | request duration with 5ms–10s buckets |
| `ztp_agents_registered` | gauge | currently registered agents |
| `ztp_websocket_sessions` | gauge | active WebSocket sessions |
| `ztp_agent_services` | gauge | services registered across all agents |
| `ztp_ratelimit_rejected_total{key_strategy}` | counter | requests rejected by the edge rate limiter |
| `ztp_ratelimit_buckets` | gauge | live rate-limit buckets across all limiters |
| `ztp_firewall_denied_total{rule}` | counter | requests denied by a firewall rule |
| `ztp_firewall_oversize_total` | counter | requests rejected for exceeding `max_request_bytes` |
| `ztp_agent_identity_mismatch_total` | counter | agent register ID ≠ client-cert identity (also counted in `bind_to: none` observe mode) |
| `ztp_agent_register_rejected_total{reason}` | counter | agent registrations rejected (`version` / `identity` / `acl`) |
| `ztp_build_info{version}` | gauge | binary version info (always 1) |

Bind the exporter to a private interface — no authentication is
applied.

## Ports

| Port | Purpose |
|------|---------|
| `:80`  | Inbound HTTP (308 → HTTPS, with `/.well-known/acme-challenge/*` bypass) |
| `:443` | Inbound HTTPS (TLS termination + `ztrouter` handler) |
| `:8443`| mTLS agent control plane |
| `:2020`| Optional `check-domain` endpoint (used by ACME `ask` and external tooling) |
| dynamic | TCP-service listeners — one per `protocol: tcp` service, allocated from `agents.tcp_port_min`–`tcp_port_max` |

## Environment variables

```bash
LOG_LEVEL=DEBUG    # Override log level (DEBUG|INFO|WARN|ERROR)
```

## Lifecycle

**Startup**
1. Parse `--config` YAML, validate.
2. Build TLS config (manual / sni / acme).
3. Start agent mTLS listener on `:8443`.
4. Start HTTPS server on `:443` wrapping `ztrouter.Handler`.
5. Start HTTP redirector on `:80` (if `http_redirect: true`), ACME
   `HTTPHandler` mounted at `/.well-known/acme-challenge/*` when
   `tls.mode == acme`.

**Agent-down behavior**
- If no agent serves a `Host`, `ztrouter` returns a branded error page
  (HTML for browsers, plain text for API clients) instead of a bare 503.
- In ACME mode, hostnames that have ever registered are persisted in a
  known-hosts file (`internal/server/knownhosts.go`); their cached certs
  keep being served while the agent is down, so clients reach the error
  page instead of hitting a TLS handshake failure.

**Hot reload — SIGHUP**
- Re-reads config, swaps cert files / router timeout / log level /
  security rules and limits atomically without dropping live
  connections (rate-limit buckets reset on swap).
- Listen address, TLS mode, ACME storage path, and
  `security.*.enabled` changes require a restart (logged + rejected).

**Shutdown — SIGINT / SIGTERM**
- HTTP redirector drains, HTTPS server drains, agent listener closes.
- WebSocket sessions terminate at idle-timeout or context cancel.
