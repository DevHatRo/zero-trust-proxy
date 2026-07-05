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
