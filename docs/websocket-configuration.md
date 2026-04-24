# WebSocket Configuration

WebSocket proxying is supported end-to-end through the mTLS channel.

## Architecture

```
Client
  ↓  WebSocket upgrade (HTTP 101)
Caddy / ztrouter handler
  ↓  hijacks client TCP connection
  ↕  websocket_frame messages over mTLS
Agent
  ↕  WebSocket connection to backend
Backend service
```

How it works:
1. Client sends a WebSocket upgrade request (`Connection: Upgrade`).
2. `ztrouter` detects the upgrade, registers the client connection in `WebSocketManager`, and writes the HTTP 101 response.
3. Frames from the client are forwarded to the agent as `websocket_frame` messages over the mTLS channel.
4. The agent dials the backend with a real WebSocket connection and relays frames in both directions.
5. Either side closing the connection sends a `websocket_disconnect` message to clean up.

## Configuration

Enable WebSocket support in the agent service definition:

```yaml
services:
  - id: "pihole"
    hostname: "pihole.example.com"
    protocol: "http"
    websocket: true        # required for WebSocket proxying
    upstreams:
      - address: "192.168.1.100:80"
```

The server-side Caddyfile does **not** need any WebSocket-specific directives — `zerotrust_router` handles upgrades automatically.

## Examples

### Home Assistant

```yaml
- id: "homeassistant"
  hostname: "ha.example.com"
  protocol: "http"
  websocket: true
  upstreams:
    - address: "192.168.1.10:8123"
```

### Pi-hole Admin (real-time graphs)

```yaml
- id: "pihole"
  hostname: "pihole.example.com"
  protocol: "http"
  websocket: true
  upstreams:
    - address: "192.168.1.100:80"
      health_check:
        path: "/admin/"
        interval: "30s"
```

### Backend requiring TLS

```yaml
- id: "grafana"
  hostname: "grafana.example.com"
  protocol: "https"    # agent dials backend with TLS
  websocket: true
  upstreams:
    - address: "grafana-server:3000"
```

## Inactivity Timeout

WebSocket connections have a 5-minute inactivity timeout (no frames in either direction). This is managed by `common.WebSocketManager`. For applications with long-lived idle connections, ensure the backend or client sends periodic ping frames.

## Troubleshooting

### HTTP 400 on upgrade

The `websocket: true` flag may be missing from the service config. Add it and reload the agent config.

### HTTP 503 on upgrade

No agent is registered for the requested `Host`. Check that the agent is connected and the service `hostname` matches the request.

### Connection drops after a few minutes

The 5-minute inactivity timeout may be firing. Verify the application sends ping frames, or that there is regular frame activity.

### Testing

```bash
# Test upgrade round-trip
curl -v \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://pihole.example.com/

# Expected: HTTP 101 Switching Protocols

# Interactive WebSocket test
wscat -c wss://ha.example.com/api/websocket
```

## Security

WebSocket connections benefit from the same security model as HTTP requests:
- Client → Caddy traffic is standard HTTPS/WSS
- Caddy → Agent traffic is over the authenticated mTLS channel
- Agent → Backend: protocol determined by the service `protocol` field (`http`/`https`)
