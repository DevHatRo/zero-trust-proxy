# 🖥️ Zero Trust Server Documentation

The Zero Trust Server is the central component that manages agent connections and provides the secure tunnel endpoint.

## 🔗 **Quick Reference**

### Command Line Options
```bash
./bin/server [options]

Options:
  --listen string       Server listening address (default ":8443")
  --api string         API server address (default ":9443")  
  --cert string        Server certificate file (default "certs/server.crt")
  --key string         Server private key file (default "certs/server.key")
  --ca string          CA certificate file (default "certs/ca.crt")
  --log-level string   Log level: DEBUG|INFO|WARN|ERROR|FATAL (default "INFO")
```

### Environment Variables
```bash
LOG_LEVEL=DEBUG         # Override log level
CADDY_ADMIN_API=...     # Caddy admin API URL (default "http://localhost:2019")
```

### Basic Configuration Template
```yaml
# Basic server configuration
server:
  listen_addr: ":8443"
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
  ca_file: "certs/ca.crt"

api:
  listen_addr: ":9443"

caddy:
  admin_api: "http://localhost:2019"
  
log_level: "INFO"
hot_reload:
  enabled: true
```

### Default Ports
- **8443**: Main server port (agent connections)
- **9443**: Internal API port (Caddy integration)
- **2019**: Caddy admin API port

## 🔄 **Server Lifecycle**

### Startup Process
1. **Configuration Loading** - Load and validate configuration
2. **Certificate Loading** - Load TLS certificates
3. **Server Initialization** - Initialize server components
4. **Agent Listener** - Start listening for agent connections
5. **API Server** - Start internal API server
6. **Caddy Integration** - Configure Caddy reverse proxy
7. **Health Checks** - Enable health monitoring

### Shutdown Process
1. **Graceful Shutdown** - Stop accepting new connections
2. **Agent Cleanup** - Disconnect agents gracefully
3. **Configuration Cleanup** - Remove Caddy configuration
4. **Resource Cleanup** - Clean up system resources

## 🌐 **Network Architecture**

```
Internet
    ↓
Caddy (Reverse Proxy)
    ↓ (Internal API :9443)
Zero Trust Server
    ↓ (mTLS :8443)
Zero Trust Agents
    ↓ (Backend Connections)
Private Services
```
