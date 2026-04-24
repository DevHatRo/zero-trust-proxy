# Server (Custom Caddy Binary)

The server-side component is a **custom Caddy binary** (`cmd/caddy`) that embeds two first-party modules. There is no separate server process — Caddy hosts both modules directly.

## Modules

| Module | Caddy ID | Role |
|--------|----------|------|
| `modules/ztagents` | `zerotrust.agents` | mTLS listener, agent registry, WebSocket session tracking |
| `modules/ztrouter` | `http.handlers.zerotrust_router` | Per-request agent lookup and mTLS multiplexing |

## Build

```bash
go build -o bin/caddy ./cmd/caddy
```

## Run

```bash
# Caddyfile (preferred)
./bin/caddy run --config config/Caddyfile.example --adapter caddyfile

# JSON config
./bin/caddy run --config config/caddy.smoke.json

# Hot reload config without dropping connections
./bin/caddy reload --config config/Caddyfile.example --adapter caddyfile
```

## Caddyfile Reference

```caddyfile
{
    # zerotrust_agents configures the mTLS listener and agent registry.
    zerotrust_agents {
        listen    :8443
        cert_file config/certs/server.crt
        key_file  config/certs/server.key
        ca_file   config/certs/ca.crt
    }
}

# All inbound HTTP/HTTPS traffic is handled by zerotrust_router.
:443 {
    route {
        zerotrust_router {
            request_timeout 2m   # optional; default 2m
        }
    }
}
```

## Ports

| Port | Purpose |
|------|---------|
| `:8443` | mTLS agent connections |
| `:80` / `:443` | Inbound client traffic (Caddy HTTP stack) |
| `:2019` | Caddy admin API (local only) |

## Environment Variables

```bash
LOG_LEVEL=DEBUG    # Override log level (DEBUG|INFO|WARN|ERROR)
```

## Lifecycle

**Startup**
1. Caddy loads the Caddyfile/JSON config.
2. `zerotrust.agents` app starts: loads TLS certs, opens mTLS listener on `:8443`.
3. Caddy HTTP stack starts: `zerotrust_router` handler provisions itself by resolving the `zerotrust.agents` app.
4. Agents can now connect and register services.

**Hot reload**
```bash
./bin/caddy reload --config config/Caddyfile.example --adapter caddyfile
```
Live connections are preserved; the mTLS listener and agent registry continue without interruption.

**Shutdown**
Caddy drains active connections gracefully before exiting.

## Architecture Diagram

```
Internet
    ↓
Caddy HTTP stack (:80/:443)
    ↓  zerotrust_router handler
Agent registry (in-process, zerotrust.agents app)
    ↓  mTLS (:8443)
Agent process (remote)
    ↓
Private backend services
```
