# 🤖 Zero Trust Agent Documentation

The Zero Trust Agent is the on-premises component that securely connects your private services to the zero trust network.

### Command Line Options
```bash
./bin/agent [options]

Options:
  --server string      Server address (required)
  --cert string        Agent certificate file (default "certs/client.crt")
  --key string         Agent private key file (default "certs/client.key") 
  --ca string          CA certificate file (default "certs/ca.crt")
  --id string          Agent ID (must match certificate CN) (required)
  --config string      Configuration file (default "config/agent.yaml")
  --log-level string   Log level: DEBUG|INFO|WARN|ERROR|FATAL (default "INFO")
```

### Environment Variables
```bash
LOG_LEVEL=DEBUG         # Override log level
ZERO_TRUST_SERVER=...   # Server address
JWT_SECRET=...          # JWT secret for authentication
```

### Basic Configuration Template
```yaml
# Basic agent configuration
agent:
  id: "my-agent"
  name: "My Agent"

server:
  address: "server.example.com:8443"
  cert: "certs/agent.crt"
  key: "certs/agent.key"
  ca_cert: "certs/ca.crt"

services:
  - id: "web-service"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "localhost:3000"

log_level: "INFO"
hot_reload:
  enabled: true
```
