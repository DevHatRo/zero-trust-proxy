# Zero Trust Reverse Proxy

Enterprise reverse proxy with mTLS authentication. Agents connect from
private networks and expose backend services by hostname; all traffic
is multiplexed over the single mTLS tunnel with no additional hops.

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Architecture

```
Client → zero-trust-proxy (:80/:443/:443-quic) ⟷ mTLS (:8443) ⟷ Agent → Backends
```

The server is a purpose-built `zero-trust-proxy` binary
(`cmd/zero-trust-proxy`) that owns:

- **`internal/server`** — lifecycle: TLS termination (manual / SNI /
  ACME), HTTP→HTTPS redirector, optional HTTP/3 listener, optional
  Prometheus exporter, SIGHUP cert hot-swap.
- **`modules/ztagents`** — mTLS agent listener, agent registry,
  WebSocket session tracking.
- **`modules/ztrouter`** — `http.Handler` that catches every inbound
  request, looks up the agent by `Host`, and multiplexes it over the
  mTLS channel.

The **agent** (`cmd/agent`) runs on-premises: connects out to the
server over mTLS, validates service configs locally, and proxies to
upstream services.

> Caddy was replaced by this binary —
> [docs/server/replace-caddy-plan.md](docs/server/replace-caddy-plan.md)
> records the migration history.

## Quick Start

### Prerequisites

- Go 1.25+
- Valid TLS certificates for mTLS (use `certgen` to generate them)

### 1. Build

```bash
go build -o bin/zero-trust-proxy ./cmd/zero-trust-proxy
go build -o bin/agent             ./cmd/agent
go build -o bin/certgen           ./cmd/certgen
```

### 2. Generate certificates

```bash
./bin/certgen --out config/certs --name ca     --type ca
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name server --type server
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name agent  --type agent
```

### 3. Write the server config

`config/server.yaml` (see [`config/server.yaml.example`](config/server.yaml.example)):

```yaml
listen:
  http: ":80"
  https: ":443"
  http_redirect: true

tls:
  mode: manual          # manual | sni | acme | none
  manual:
    cert_file: config/certs/server.crt
    key_file:  config/certs/server.key

agents:
  listen:    ":8443"
  cert_file: config/certs/server.crt
  key_file:  config/certs/server.key
  ca_file:   config/certs/ca.crt

router:
  request_timeout: 2m

logging:
  level: info
  format: console
```

For Let's Encrypt, swap `tls`:

```yaml
tls:
  mode: acme
  acme:
    storage_dir: /config/acme
    email: ops@example.com
```

### 4. Start the server

```bash
./bin/zero-trust-proxy run --config config/server.yaml

# Validate without starting:
./bin/zero-trust-proxy validate --config config/server.yaml

# Local dev with non-privileged ports:
./bin/zero-trust-proxy run --config config/server.yaml --http :8080 --https :8443
```

### 5. Start an agent

```bash
./bin/agent --server server.example.com:8443 \
            --cert config/certs/agent.crt \
            --key  config/certs/agent.key \
            --ca   config/certs/ca.crt \
            --id   agent1 \
            --config config/agent.yaml
```

## Agent configuration

`config/agent.yaml`:

```yaml
agent:
  id: "production-agent-01"

server:
  address: "server.example.com:8443"
  cert:    "config/certs/agent.crt"
  key:     "config/certs/agent.key"
  ca_cert: "config/certs/ca.crt"

log_level: "INFO"
hot_reload:
  enabled: true

services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "localhost:3000"
        weight: 100
```

### Multi-service with load balancing

```yaml
services:
  - id: "webapp"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "10.0.1.100:3000"
        weight: 70
      - address: "10.0.1.101:3000"
        weight: 30
    load_balancing:
      policy: "weighted_round_robin"

  - id: "api"
    hostname: "api.example.com"
    protocol: "https"
    websocket: true
    upstreams:
      - address: "backend-1:8080"
      - address: "backend-2:8080"
```

## Request flow

1. Client → `zero-trust-proxy` `:443`
2. `ztrouter` looks up the agent for the request's `Host` in the `ztagents` registry (503 if no agent).
3. Normal requests: body is read and forwarded as an `http_request` JSON message over mTLS.
4. Large uploads (`Content-Length > 1 MiB`): streamed as `http_upload_start` + `http_upload_chunk` messages.
5. WebSocket: client connection is hijacked; frames are relayed bidirectionally.
6. Streaming downloads (`IsStream: true` response): chunks are piped straight to the client.
7. Agent proxies to the upstream and responds with `http_response` (or chunked equivalents).

## Build & test

```bash
go test ./...                    # all packages
go test -race ./...              # race detector
go test ./modules/ztrouter/...   # single package
go build ./...                   # verify compilation
make sec                         # security scan (HIGH severity, G402 excluded)
```

## Hot reload

- **Server**: `kill -HUP $(pgrep zero-trust-proxy)` reloads
  `--config`. Cert files, router timeout, and log level swap atomically;
  listen-address / TLS-mode / agents.listen changes are rejected and
  require a restart.
- **Agent**: edit `agent.yaml`; with `hot_reload.enabled: true` the
  agent picks up service changes without restarting.

## Optional features

- **HTTP/3 (QUIC)** — set `listen.http3: ":443"` in `server.yaml`. The
  HTTPS listener advertises `Alt-Svc: h3=":443"` so capable clients
  upgrade automatically.
- **Prometheus metrics** — set `metrics.addr: "127.0.0.1:9100"`.
  Exposes `ztp_requests_total`, `ztp_request_duration_seconds`,
  `ztp_agents_registered`, `ztp_websocket_sessions`. No auth — bind to
  a private interface.

## Documentation

- [Server reference](docs/server/README.md)
- [Agent reference](docs/agent/README.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Hot reload](docs/hot-reload.md)
- [WebSocket configuration](docs/websocket-configuration.md)
- [HTTP redirect features](docs/http-redirect-features.md)
- [Docker deployment](docs/deployment/docker.md)
- [Caddy → custom server migration history](docs/server/replace-caddy-plan.md)

## Security

- mTLS between agent and server (TLS 1.2+, agent client cert
  required).
- `G402` (`TLS InsecureSkipVerify`) is intentional on the
  agent→backend leg — backends are internal and the agent is the TLS
  termination point.
- Run `make sec-full` to see the full MEDIUM/LOW backlog.

## Load-balancing algorithms

| Policy | Description |
|--------|-------------|
| `round_robin` | Equal distribution |
| `weighted_round_robin` | Weight-proportional distribution |
| `least_conn` | Route to upstream with fewest active connections |
| `ip_hash` | Consistent hashing by client IP |

## License

Apache 2.0 — see [LICENSE](LICENSE).
