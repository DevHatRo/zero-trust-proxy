# HTTP Redirect and Protocol Binding Features

The 0Trust system now supports advanced HTTP to HTTPS redirect functionality and flexible protocol binding options for services.

## Features Overview

### 1. HTTP to HTTPS Redirect

Automatically redirect HTTP requests to HTTPS to ensure secure connections.

**Configuration:**
```yaml
services:
  - id: "my-app"
    hosts: ["app.example.com"]
    protocol: "https"
    http_redirect: true  # Enable HTTP to HTTPS redirect
    upstreams:
      - address: "localhost:3000"
```

**Behavior:**
- HTTP requests to `http://app.example.com/path` → `https://app.example.com/path` (301 redirect)
- HTTPS requests work normally
- WebSocket upgrades are also redirected to secure connections

### 2. Protocol Binding

Control which protocols (HTTP/HTTPS) your services listen on.

**Configuration Options:**
```yaml
listen_on: "both"   # Listen on both HTTP (80) and HTTPS (443) - DEFAULT
listen_on: "https"  # Only listen on HTTPS (443)
listen_on: "http"   # Only listen on HTTP (80)
```

## Configuration Examples

### Example 1: Web Application with Redirect
```yaml
services:
  - id: "web-app"
    name: "Web Application"
    hosts: ["app.example.com"]
    protocol: "https"
    http_redirect: true    # Redirect HTTP → HTTPS
    listen_on: "both"      # Accept both HTTP and HTTPS
    upstreams:
      - address: "localhost:3000"
        weight: 100
```

**Result:**
- HTTP requests redirected to HTTPS
- HTTPS requests proxied to backend
- Caddy listens on both ports 80 and 443

### Example 2: HTTPS-Only Secure API
```yaml
services:
  - id: "secure-api"
    name: "Secure API"
    hosts: ["api.example.com"]
    protocol: "https"
    listen_on: "https"     # HTTPS only - no HTTP listener
    upstreams:
      - address: "localhost:8080"
```

**Result:**
- Only HTTPS connections accepted
- HTTP requests get connection refused
- Enhanced security for sensitive APIs

### Example 3: HTTP-Only Internal Service
```yaml
services:
  - id: "internal-service"
    name: "Internal Debug Service"
    hosts: ["debug.internal.com"]
    protocol: "http"
    listen_on: "http"      # HTTP only
    upstreams:
      - address: "localhost:9090"
```

**Result:**
- Only HTTP connections accepted
- Useful for internal/debugging services
- No TLS overhead for internal communication

### Example 4: WebSocket with Redirect
```yaml
services:
  - id: "websocket-app"
    name: "WebSocket Application"
    hosts: ["ws.example.com"]
    protocol: "https"
    websocket: true
    http_redirect: true    # Redirect to secure WebSocket
    listen_on: "both"
    upstreams:
      - address: "localhost:4000"
```

**Result:**
- HTTP WebSocket connections redirected to HTTPS
- Secure WebSocket (WSS) connections work normally
- Maintains WebSocket compatibility

## Default Behavior

If not specified:
- `http_redirect`: `true` for services with `listen_on: "both"` (security-first default)
- `http_redirect`: `false` for services with `listen_on: "http"` or `listen_on: "https"`
- `listen_on`: `"both"` (listen on both HTTP and HTTPS)

## Use Cases

### Security Enhancement
- **Force HTTPS**: Use `http_redirect: true` to ensure all traffic is encrypted
- **API Security**: Use `listen_on: "https"` for sensitive APIs that should never accept HTTP

### Performance Optimization
- **Internal Services**: Use `listen_on: "http"` for internal services to reduce TLS overhead
- **Development**: Use HTTP-only for local development environments

### Compliance
- **Regulatory Requirements**: Some industries require HTTPS-only access
- **Security Policies**: Corporate policies may mandate encrypted connections

### Mixed Environments
- **Public Services**: Use redirect for public-facing applications
- **Admin Interfaces**: Use HTTPS-only for administrative interfaces
- **Health Checks**: Use HTTP-only for simple health check endpoints

## Technical Implementation

### Caddy Configuration
The system automatically configures Caddy with:

1. **Listen Ports**: Dynamic based on service `listen_on` settings
2. **Redirect Routes**: Automatic HTTP → HTTPS redirects (301 status)
3. **Protocol Routing**: Separate route handling for HTTP and HTTPS
4. **WebSocket Support**: Maintains compatibility with secure WebSocket upgrades

### Example Generated Caddy Config
```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":80", ":443"],
          "routes": [
            {
              "match": [{"host": ["app.example.com"], "scheme": ["http"]}],
              "handle": [{
                "handler": "static_response",
                "status": 301,
                "location": ["https://{http.request.host}{http.request.uri}"]
              }]
            },
            {
              "match": [{"host": ["app.example.com"]}],
              "handle": [{"handler": "reverse_proxy", "upstreams": [...]}]
            }
          ]
        }
      }
    }
  }
}
```

### Security Considerations

1. **Certificate Management**: Ensure valid TLS certificates for HTTPS-enabled services
2. **Mixed Content**: Avoid HTTP resources on HTTPS pages
3. **HSTS Headers**: Consider adding HTTP Strict Transport Security headers
4. **Redirect Loops**: Don't use `http_redirect: true` with `listen_on: "http"`

### Monitoring and Logging

The system provides detailed logging for:
- Service configuration: HTTP redirect and protocol binding settings
- Caddy configuration: Listen ports and route generation
- Redirect activity: HTTP → HTTPS redirections
- Connection attempts: Failed connections to disabled protocols

### Hot Reload Support

Both `http_redirect` and `listen_on` settings support hot reload:
- Configuration changes applied without service restart
- Caddy automatically reconfigured
- Active connections maintained during updates

## Troubleshooting

### Common Issues

1. **Certificate Errors**: Ensure valid TLS certificates when using HTTPS
2. **Port Conflicts**: Check that ports 80/443 are available
3. **Firewall Rules**: Ensure firewall allows configured ports
4. **DNS Configuration**: Verify DNS points to correct server

### Debug Commands

```bash
# Check Caddy configuration
curl -X GET http://localhost:2019/config/

# Test HTTP redirect
curl -I http://app.example.com/

# Test HTTPS access
curl -I https://app.example.com/

# Check listening ports
netstat -tlnp | grep -E ':(80|443)'
```

### Log Analysis

Look for these log entries:
```
✅ Enhanced service app.example.com added to Caddy successfully with 1 upstreams, HTTP redirect: enabled, Listen on: both
🔧 Caddy listen configuration: [:80 :443] (HTTP: true, HTTPS: true)
🔀 Added HTTP to HTTPS redirect for: app.example.com
```

## Migration Guide

### From Simple Configuration
```yaml
# Before
services:
  - id: "my-app"
    hosts: ["app.example.com"]
    protocol: "https"
    upstreams:
      - address: "localhost:3000"

# After (with new features - automatic defaults applied)
services:
  - id: "my-app"
    hosts: ["app.example.com"]
    protocol: "https"
    # http_redirect: true    # Automatically applied by default
    # listen_on: "both"      # Automatically applied by default
    upstreams:
      - address: "localhost:3000"
```

### Important Default Change
**⚠️ SECURITY ENHANCEMENT**: Starting with this version, `http_redirect` defaults to `true` for services that listen on both HTTP and HTTPS (`listen_on: "both"`).

This means existing configurations will now automatically redirect HTTP to HTTPS for enhanced security.

### Disable HTTP Redirect (if needed)
If you need to disable the redirect for a specific service:
```yaml
services:
  - id: "my-app"
    hosts: ["app.example.com"]
    protocol: "https"
    http_redirect: false   # Explicitly disable redirect
    listen_on: "both"
    upstreams:
      - address: "localhost:3000"
```

### HTTP-Only Services (no change)
Services that only listen on HTTP are unaffected:
```yaml
services:
  - id: "internal-service"
    hosts: ["debug.internal.com"]
    protocol: "http"
    listen_on: "http"      # http_redirect automatically stays false
    upstreams:
      - address: "localhost:9090"
```

The new fields are backward compatible, but the security-first defaults may change behavior for existing configurations that rely on HTTP access without redirect. 
