# WebSocket Configuration and Support

This document describes how WebSocket support works in the 0Trust zero-trust networking solution.

## Architecture Overview

The WebSocket support in 0Trust follows a **proxy-first architecture**:

1. **Client** initiates WebSocket upgrade request to Caddy
2. **Caddy** forwards the request to the server's HTTP proxy API
3. **Server** forwards the request to the appropriate agent as a regular HTTP request
4. **Agent** forwards the request to the backend service as a regular HTTP request
5. **Backend** responds (may include WebSocket upgrade response)
6. **Response flows back**: Backend → Agent → Server → Caddy
7. **Caddy** handles the WebSocket upgrade protocol and establishes the WebSocket tunnel

### Key Design Principles

- **Agents never perform WebSocket upgrades** - They forward all requests as regular HTTP
- **Caddy handles the upgrade protocol** - Only the proxy layer manages WebSocket upgrades
- **Transparent forwarding** - WebSocket upgrade requests flow through the system like any HTTP request
- **Backend compatibility** - Backends work normally without special WebSocket handling

## Configuration

### 1. Enhanced Service Configuration with WebSocket Support

```yaml
version: "1.0"
agent_id: "agent-1"
services:
  - id: "pihole-service"
    name: "Pi-hole Admin Interface"
    hostname: "pihole.example.com"
    protocol: "http"
    websocket: true  # Enable WebSocket support for real-time features
    upstreams:
      - address: "192.168.1.100:80"
        weight: 100
        health_check:
          path: "/admin/"
          method: "GET"
          interval: "30s"
          timeout: "5s"
    load_balancing:
      policy: "round_robin"
      health_check_required: true
    routes:
      - match:
          path: "*"
        handle:
          - type: "reverse_proxy"
```

### 2. Simple Service Configuration

For backward compatibility, simple configurations work automatically:

```yaml
services:
  - hostname: "pihole.example.com"
    backend: "192.168.1.100:80"
    protocol: "http"
```

WebSocket requests are automatically forwarded and handled properly.

## How WebSocket Requests are Processed

### 1. Request Flow

```
Browser/Client
    ↓ (WebSocket Upgrade Request)
Caddy (proxy layer)
    ↓ (forwards as HTTP to server)
Server (zero-trust server)
    ↓ (forwards as HTTP to agent)
Agent (on-premises)
    ↓ (forwards as HTTP to backend)
Backend Service (e.g., Pi-hole)
```

### 2. Response Flow

```
Backend Service
    ↓ (HTTP response, may be upgrade)
Agent
    ↓ (forwards response as-is)
Server
    ↓ (forwards response as-is)
Caddy
    ↓ (handles WebSocket upgrade protocol)
Browser/Client (WebSocket connection established)
```

### 3. Agent Behavior

The agent detects WebSocket upgrade requests for logging purposes but treats them as regular HTTP:

```go
// Agent detects WebSocket upgrade request
isWebSocketUpgrade := a.isWebSocketUpgrade(msg.HTTP.Headers)
if isWebSocketUpgrade {
    logger.Debug("Detected WebSocket upgrade request for host: %s - forwarding as regular HTTP", host)
}

// Forward as regular HTTP request - NO special WebSocket handling
req, err := http.NewRequest(msg.HTTP.Method, url, bytes.NewReader(msg.HTTP.Body))
```

## Caddy Configuration

Caddy automatically handles WebSocket upgrades when the `websocket: true` flag is set:

### For Enhanced Services

```json
{
  "handler": "reverse_proxy",
  "upstreams": [{"dial": "127.0.0.1:9443"}],
  "headers": {
    "request": {
      "set": {
        "Upgrade": ["{http.request.header.Upgrade}"],
        "Connection": ["upgrade"]
      }
    }
  },
  "handle_response": [
    {
      "match": {"status_code": [101]},
      "routes": [
        {
          "handle": [
            {
              "handler": "headers",
              "response": {
                "set": {
                  "Connection": ["upgrade"],
                  "Upgrade": ["websocket"]
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### For All Services (Default Handling)

Even simple services automatically support WebSocket upgrades through the default `handle_response` configuration that processes HTTP 101 responses.

## Troubleshooting

### Common Issues and Solutions

#### 1. "WebSocket upgrade failed with status: 200" (FIXED)

**Problem**: Previously, agents tried to perform WebSocket upgrades themselves, causing backends to respond with HTTP 200 instead of 101.

**Solution**: Agents now forward WebSocket upgrade requests as regular HTTP requests, letting Caddy handle the upgrade protocol.

#### 2. WebSocket Connections Not Established

**Check**:
- Ensure the backend service supports WebSocket upgrades
- Verify the `websocket: true` flag is set in enhanced service configuration
- Check that Caddy configuration includes WebSocket handling directives

#### 3. Real-time Features Not Working

**Common Causes**:
- Backend service requires specific WebSocket subprotocols
- Backend expects certain headers to be preserved
- Network timeouts affecting long-lived connections

**Solutions**:
- Add necessary headers in the route configuration
- Increase timeout values in load balancer settings
- Check backend-specific WebSocket requirements

## Testing WebSocket Functionality

### 1. Test WebSocket Upgrade

```bash
# Test WebSocket upgrade request
curl -v \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://pihole.example.com/
```

Expected: HTTP 101 Switching Protocols response

### 2. Test Backend Directly

```bash
# Test backend WebSocket support directly
curl -v \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  http://192.168.1.100:80/
```

### 3. Browser Developer Tools

1. Open browser developer tools
2. Navigate to the Network tab
3. Access the application through the 0Trust proxy
4. Look for WebSocket connections (WS protocol)
5. Verify connection status and message flow

## Performance Considerations

### Connection Handling

- **WebSocket connections are persistent** - They remain open for the duration of the session
- **Resource usage** - Each WebSocket connection consumes memory and file descriptors
- **Connection limits** - Consider backend connection limits and proxy timeout settings

### Optimization Tips

1. **Set appropriate timeouts**:
   ```yaml
   load_balancing:
     health_check_required: true
   ```

2. **Use connection pooling** where possible
3. **Monitor connection counts** and resource usage
4. **Implement heartbeat/ping mechanisms** for long-lived connections

## Security Considerations

### WebSocket-Specific Security

1. **Origin validation** - Backends should validate WebSocket origins
2. **Authentication** - WebSocket connections should inherit HTTP authentication
3. **Rate limiting** - Apply rate limits to prevent WebSocket abuse
4. **Message validation** - Backends should validate WebSocket message content

### 0Trust Security Model

WebSocket connections benefit from the same zero-trust security:
- **Mutual TLS** between agents and server
- **Certificate-based authentication** for agent connections
- **Encrypted tunneling** for all traffic
- **Network isolation** - Backend services remain isolated from direct internet access

## Example: Pi-hole with WebSocket Support

Pi-hole's admin interface uses WebSocket connections for real-time updates:

```yaml
version: "1.0"
agent_id: "pihole-agent"
services:
  - id: "pihole-admin"
    name: "Pi-hole Admin Interface"
    hostname: "pihole.example.com"
    protocol: "http"
    websocket: true  # Enable for real-time graphs and statistics
    upstreams:
      - address: "192.168.1.100:80"
        weight: 100
        health_check:
          path: "/admin/"
          method: "GET"
          interval: "30s"
          timeout: "5s"
```

This configuration enables:
- Real-time query graphs
- Live DNS query logs  
- Dynamic statistics updates
- Interactive network monitoring

## Architecture Benefits

### Simplified Agent Logic
- Agents don't need to understand WebSocket protocols
- Reduces complexity and potential bugs
- Easier to maintain and debug

### Centralized WebSocket Handling
- Caddy handles all WebSocket upgrade logic
- Consistent behavior across all services
- Better debugging and monitoring capabilities

### Backend Compatibility
- No special WebSocket handling required in agents
- Backends work normally with their standard WebSocket implementations
- Easier migration of existing WebSocket applications

### Scalability
- WebSocket connections are handled efficiently by Caddy
- Agent resources are not consumed by WebSocket connection management
- Better resource utilization across the system 
