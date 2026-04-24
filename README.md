# Zero Trust Reverse Proxy

Enterprise reverse proxy with mTLS authentication. Agents connect from private networks and expose backend services by hostname; all traffic is multiplexed over the single mTLS tunnel with no additional hops.

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Architecture

```
Client → Caddy (:80/:443, ztrouter handler) ⟷ mTLS (:8443, ztagents app) ⟷ Agent → Backends
```

The server is a **custom Caddy binary** hosting two first-party modules:

- **`modules/ztagents`** — Caddy *app* (`zerotrust.agents`). Owns the mTLS listener, agent registry, and WebSocket session tracking.
- **`modules/ztrouter`** — Caddy *HTTP handler* (`zerotrust_router`). Catches every inbound request, looks up the agent by `Host`, and multiplexes it over the mTLS channel.

The **agent** (`cmd/agent`) runs on-premises: connects out to the server over mTLS, validates service configs locally, and proxies to upstream services.

## Quick Start

### Prerequisites

- Go 1.22+
- Valid TLS certificates for mTLS (use `certgen` to generate them)

### 1. Build

```bash
go build -o bin/caddy   ./cmd/caddy    # custom Caddy binary (server-side)
go build -o bin/agent   ./cmd/agent
go build -o bin/certgen ./cmd/certgen
```

### 2. Generate Certificates

```bash
# Generate CA
./bin/certgen --out config/certs --name ca     --type ca
# Generate server cert
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name server --type server
# Generate agent cert
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name agent  --type agent
```

### 3. Configure Caddy

Create a `Caddyfile` (see `config/Caddyfile.example`):

```caddyfile
{
    zerotrust_agents {
        listen    :8443
        cert_file config/certs/server.crt
        key_file  config/certs/server.key
        ca_file   config/certs/ca.crt
    }
}

:443 {
    route {
        zerotrust_router { request_timeout 2m }
    }
}
```

### 4. Start the Server

```bash
./bin/caddy run --config config/Caddyfile.example --adapter caddyfile
```

### 5. Start an Agent

```bash
./bin/agent --server server.example.com:8443 \
            --cert config/certs/agent.crt \
            --key  config/certs/agent.key \
            --ca   config/certs/ca.crt \
            --id   agent1 \
            --config config/agent.yaml
```

## Agent Configuration

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

### Multi-Service with Load Balancing

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

## Request Flow

1. Client → Caddy `:443`
2. `ztrouter` looks up the agent for the request's `Host` in the `ztagents` registry (503 if no agent).
3. Normal requests: body is read and forwarded as an `http_request` JSON message over mTLS.
4. Large uploads (`Content-Length > 1 MiB`): streamed as `http_upload_start` + `http_upload_chunk` messages.
5. WebSocket: client connection is hijacked; frames are relayed bidirectionally.
6. Streaming downloads (`IsStream: true` response): chunks are piped straight to the client.
7. Agent proxies to the upstream and responds with `http_response` (or chunked equivalents).

## Build & Test

```bash
go test ./...                    # all packages
go test ./modules/ztrouter/...   # single package
go build ./...                   # verify compilation
make sec                         # security scan (HIGH severity, G402 excluded)
```

## Hot Reload

- **Caddy config changes**: `./bin/caddy reload --config config/Caddyfile.example --adapter caddyfile`
- **Agent config changes**: Edit `agent.yaml`; with `hot_reload.enabled: true` the agent picks up service changes without restarting.

## Documentation

- [Troubleshooting](docs/troubleshooting.md)
- [Hot Reload](docs/hot-reload.md)
- [WebSocket Configuration](docs/websocket-configuration.md)
- [HTTP Redirect Features](docs/http-redirect-features.md)
- [Docker Deployment](docs/deployment/docker.md)
- [Agent Reference](docs/agent/README.md)

## Security

- mTLS between all components (TLS 1.3)
- `G402` (`TLS InsecureSkipVerify`) is intentional on the agent→backend leg — backends are internal; the agent is the TLS termination point.
- Run `make sec-full` to see the full MEDIUM/LOW backlog.

## Load Balancing Algorithms

| Policy | Description |
|--------|-------------|
| `round_robin` | Equal distribution |
| `weighted_round_robin` | Weight-proportional distribution |
| `least_conn` | Route to upstream with fewest active connections |
| `ip_hash` | Consistent hashing by client IP |

## License

Apache 2.0 — see [LICENSE](LICENSE).
