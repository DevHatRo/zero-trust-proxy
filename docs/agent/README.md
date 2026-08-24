# Agent Reference

The agent (`cmd/agent`) runs on-premises. It connects outbound to the `zero-trust-proxy` server over mTLS and proxies requests to local backend services.

## Command Line Options

```bash
./bin/agent [options]

Options:
  --server string      Server address (required, e.g. server.example.com:8443)
  --cert string        Agent certificate file (default "config/certs/agent.crt")
  --key string         Agent private key file  (default "config/certs/agent.key")
  --ca string          CA certificate file     (default "config/certs/ca.crt")
  --id string          Agent ID — must match the certificate CN (required)
  --config string      Config file path        (default "config/agent.yaml")
  --log-level string   DEBUG|INFO|WARN|ERROR   (default "INFO")
```

## Environment Variables

```bash
LOG_LEVEL=DEBUG          # Override log level
ZERO_TRUST_SERVER=...    # Server address (overridden by --server flag)
```

## Configuration File (agent.yaml)

```yaml
agent:
  id: "my-agent"           # must match certificate CN
  name: "My Agent"         # human-readable label
  region: "us-east"        # optional

server:
  address: "server.example.com:8443"
  cert:    "config/certs/agent.crt"
  key:     "config/certs/agent.key"
  ca_cert: "config/certs/ca.crt"

# Structured logging (preferred over top-level log_level, which is deprecated):
logging:
  level: "INFO"        # DEBUG | INFO | WARN | ERROR | FATAL
  format: "console"    # console | json
  output: "stdout"     # stdout | stderr | file path

hot_reload:
  enabled: true            # watch agent.yaml for changes
  debounce_delay: "100ms"

services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "localhost:3000"
        weight: 100

  - id: "api"
    hostname: "api.example.com"
    protocol: "https"
    websocket: true
    upstreams:
      - address: "10.0.1.10:8080"
      - address: "10.0.1.11:8080"
    load_balancing:
      policy: "least_conn"
```

## Service Definition Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique service identifier |
| `hostname` | yes | Hostname clients use to reach this service |
| `hosts` | no | Multiple hostnames for one service (alternative to single `hostname`) |
| `name` | no | Human-readable service label |
| `protocol` | yes | `http`, `https`, or `tcp` |
| `upstreams` | yes | One or more backend addresses |
| `websocket` | no | Enable WebSocket proxying (default: false) |
| `timeout` | no | Per-service request-timeout override (0 = server's `router.request_timeout`) |
| `load_balancing.policy` | no | `round_robin`, `weighted_round_robin`, `least_conn`, `ip_hash` |
| `routes` | no | Route policies (match + handler chain); default is a `/*` → `reverse_proxy` catch-all |
| `access_policy` | no | Names a server-defined access rule to apply to this service's host. Advisory: honoured only when the server sets `access.allow_agent_policy: true`, and even then only where no server rule already matched and the named rule carries an identity requirement — it can never grant unauthenticated access. See [docs/server/access-policy.md](../server/access-policy.md). |

## Routes and Middleware

Each service can define `routes`: an ordered list of match conditions with a
handler chain. The agent evaluates them on every HTTP request (including
WebSocket upgrades and streamed uploads) **before** proxying to an upstream.
First matching route wins; a request matching **no** route is rejected with
404 — defined routes are an explicit policy, not a suggestion.

```yaml
services:
  - id: "internal-app"
    hosts: [app.home.example.com]
    protocol: http
    upstreams:
      - address: "traefik:80"
    routes:
      # Tight limit on the login endpoint.
      - match:
          path: "/api/v1/auth/*"
        handle:
          - type: "rate_limit"
            config:
              rate: "10/minute"   # <count>/<second|minute|hour>
              burst: 5            # optional; defaults to <count>
          - type: "reverse_proxy"
      # Everything else: home network only.
      - match:
          path: "/*"
        handle:
          - type: "ip_whitelist"
            config:
              allowed_ips:
                - "203.0.113.7/32"   # CIDRs or bare IPs (v4 or v6)
          - type: "reverse_proxy"
```

Match conditions (`path` with `*` / trailing `/*` wildcards, `method`,
`headers`, `query`) are ANDed. Handlers run in order:

| Handler | Effect |
|---------|--------|
| `ip_whitelist` | 403 unless the client IP (taken from the proxy-stamped `X-Forwarded-For`) is in `allowed_ips`. Fails closed if the client IP is missing. |
| `rate_limit` | Per-client-IP token bucket; over-limit requests get 429 with a `Retry-After` header. Buckets are shared across all hosts of the service and reset on config reload. |
| `reverse_proxy` | Terminal handler — proxy to an upstream. |

`global_middleware` at the top level of `agent.yaml` takes the same handler
entries and runs before every route's chain on every service (a global
`rate_limit` shares its buckets across all services).

Unknown handler types and malformed handler configs (bad CIDRs, bad rate
specs) are **load errors** — the agent refuses to start, and a hot reload
keeps the previous config, rather than silently skipping the policy.

Blocked requests are reported to the server with a `blocked_by` marker, so
the proxy serves its branded error page (HTML for browsers, plain text for
API clients) showing the client as "Blocked" — the same style as the
agent-unreachable page.

### TCP services

With `protocol: tcp`, the server opens a public TCP listener for the
service and relays raw bytes to the agent. The port is allocated from
the server's `agents.tcp_port_min`–`tcp_port_max` range and returned to
the agent in the `service_add_response`.

## Load Balancing

| Policy | Description |
|--------|-------------|
| `round_robin` | Equal distribution (default) |
| `weighted_round_robin` | Weight-proportional distribution |
| `least_conn` | Route to upstream with fewest active connections |
| `ip_hash` | Consistent hashing by client IP |

## Health Checks

```yaml
upstreams:
  - address: "localhost:3000"
    health_check:
      path:     "/health"
      interval: "30s"
      timeout:  "5s"
```

## Hot Reload

With `hot_reload.enabled: true`, the agent watches `agent.yaml` for changes and applies service additions, updates, and removals at runtime without reconnecting to the server. Changes are pushed to the server via `service_add` / `service_update` / `service_remove` messages.

## Agent Lifecycle

1. Load and validate `agent.yaml`.
2. Establish mTLS connection to `server.address`.
3. Send `register` message with agent ID and metadata.
4. Push all configured services via `service_add`.
5. Enter message loop: handle `http_request`, `http_upload_*`, `websocket_frame`, `tcp_connect` / `tcp_data` / `tcp_disconnect`, `ping`.
6. On disconnect: reconnect with exponential backoff; re-register all services on reconnect.
