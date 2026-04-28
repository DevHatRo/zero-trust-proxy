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
| `internal/server` | Lifecycle: TLS, listeners, redirector, signal handling |
| `internal/serverconfig` | YAML config schema, loader, validator |
| `modules/ztagents` | mTLS listener, agent registry, WebSocket session tracking |
| `modules/ztrouter` | `http.Handler`: per-request agent lookup and mTLS multiplexing |

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

router:
  request_timeout: 2m

logging:
  level: info                # debug | info | warn | error
  format: console            # console | json

metrics:
  addr: ""                   # e.g. "127.0.0.1:9100" — Prometheus exporter at /metrics, no auth
```

## Metrics

Setting `metrics.addr` enables a Prometheus text-format exporter at
`/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `ztp_requests_total{method,status}` | counter | HTTP requests handled (status grouped by 2xx/3xx/4xx/5xx) |
| `ztp_request_duration_seconds` | histogram | request duration with 5ms–10s buckets |
| `ztp_agents_registered` | gauge | currently registered agents |
| `ztp_websocket_sessions` | gauge | active WebSocket sessions |

Bind the exporter to a private interface — no authentication is
applied.

## Ports

| Port | Purpose |
|------|---------|
| `:80`  | Inbound HTTP (308 → HTTPS, with `/.well-known/acme-challenge/*` bypass) |
| `:443` | Inbound HTTPS (TLS termination + `ztrouter` handler) |
| `:8443`| mTLS agent control plane |
| `:2020`| Optional `check-domain` endpoint (used by ACME `ask` and external tooling) |

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

**Hot reload — SIGHUP**
- Re-reads config, swaps cert files / router timeout / log level
  atomically without dropping live connections.
- Listen address, TLS mode, and ACME storage path changes require a
  restart (logged + rejected).

**Shutdown — SIGINT / SIGTERM**
- HTTP redirector drains, HTTPS server drains, agent listener closes.
- WebSocket sessions terminate at idle-timeout or context cancel.
