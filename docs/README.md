# Zero Trust Proxy — Documentation

## Contents

| Document | Description |
|----------|-------------|
| [Agent Reference](agent/README.md) | Agent CLI options, config format, service definitions |
| [Deployment: Docker](deployment/docker.md) | Building and running with Docker / Docker Compose |
| [Hot Reload](hot-reload.md) | Agent config hot reload and Caddy config reload |
| [WebSocket Configuration](websocket-configuration.md) | WebSocket proxying setup |
| [HTTP Redirect Features](http-redirect-features.md) | HTTP→HTTPS and redirect handling |
| [Troubleshooting](troubleshooting.md) | Common issues and diagnostics |

## Architecture Overview

```
Client → Caddy (:80/:443)
           ├─ zerotrust_router handler   (modules/ztrouter)
           │    looks up agent by Host
           │    multiplexes request over mTLS
           └─ zerotrust_agents app       (modules/ztagents)
                mTLS listener :8443
                agent registry
                WebSocket session tracking
                     ↕ mTLS
               Agent (cmd/agent)
                     ↕
               Backend services
```

The "server" is a **custom Caddy binary** (`cmd/caddy`). There is no separate server process — Caddy hosts both modules directly.

## Quick Navigation

| Goal | Document |
|------|----------|
| Build and run locally | [README.md (root)](../README.md#quick-start) |
| Configure an agent | [Agent Reference](agent/README.md) |
| Deploy with Docker | [Docker Deployment](deployment/docker.md) |
| Enable hot reload | [Hot Reload](hot-reload.md) |
| Proxy WebSocket traffic | [WebSocket Configuration](websocket-configuration.md) |
| Debug connection problems | [Troubleshooting](troubleshooting.md) |
