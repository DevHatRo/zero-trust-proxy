# 📁 Zero Trust Proxy Examples

This directory contains ready-to-use configuration examples and deployment files for the Zero Trust Proxy system.

## 📋 File Overview

### 🐳 **Docker Deployment**
- **[`docker-compose.yml`](docker-compose.yml)** - Complete Docker Compose setup with health checks, networks, and persistent storage
- **[`docker-compose-homelab.yml`](docker-compose-homelab.yml)** - Real-world homelab example for Synology NAS deployment
- **[`generate-certificates.sh`](generate-certificates.sh)** - Automated certificate generation script using Docker

### ⚙️ **Configuration Files**
- **[`server-config.yaml`](server-config.yaml)** - Complete server configuration with detailed comments
- **[`agent-config.yaml`](agent-config.yaml)** - Basic agent configuration with multiple service examples
- **[`agent-homelab-config.yaml`](agent-homelab-config.yaml)** - Production homelab configuration with real services
- **[`agent-logging-config.yaml`](agent-logging-config.yaml)** - Comprehensive agent logging configuration for production
- **[`server-logging-config.yaml`](server-logging-config.yaml)** - Comprehensive Caddy logging configuration for production
- **[`server-logging-simple.yaml`](server-logging-simple.yaml)** - Simple Caddy logging setup for development
- **[`server-logging-production.yaml`](server-logging-production.yaml)** - Production JSON logging for log aggregation

### 🔧 **Legacy Examples** (from existing configs)
- **[`agent-hot-reload-config.yaml`](agent-hot-reload-config.yaml)** - Hot reload configuration example
- **[`flexible-port-config.yaml`](flexible-port-config.yaml)** - Flexible port configuration
- **[`flexible-protocol-config.yaml`](flexible-protocol-config.yaml)** - Protocol flexibility examples
- **[`http-redirect-config.yaml`](http-redirect-config.yaml)** - HTTP to HTTPS redirect setup
- **[`server-hot-reload-config.yaml`](server-hot-reload-config.yaml)** - Server hot reload configuration
- **[`websocket-config.yaml`](websocket-config.yaml)** - WebSocket configuration examples

## 🚀 Quick Start Guide

### 1. **Docker Deployment (Recommended)**

```bash
# Clone or download the examples
cd zero-trust-proxy

# Generate certificates
./examples/generate-certificates.sh

# Copy and customize configuration
cp examples/docker-compose.yml ./
cp examples/server-config.yaml ./config/
cp examples/agent-config.yaml ./config/

# Edit configurations for your environment
nano config/server-config.yaml
nano config/agent-config.yaml

# Deploy services
docker-compose up -d
```

### 2. **Homelab Deployment**

For a real-world homelab setup similar to the production example:

```bash
# Use the homelab-specific configurations
cp examples/docker-compose-homelab.yml ./docker-compose.yml
cp examples/agent-homelab-config.yaml ./config/agent.yaml
cp examples/server-config.yaml ./config/server.yaml

# Generate certificates
./examples/generate-certificates.sh

# Update server address in agent config
sed -i 's/195.201.146.166:8443/YOUR_SERVER_IP:8443/' config/agent.yaml

# Deploy
docker-compose up -d
```

## 📖 Configuration Guide

### **Server Configuration**

The [`server-config.yaml`](server-config.yaml) includes:
- **Hot Reload**: Dynamic configuration updates
- **TLS Settings**: Certificate paths and CA configuration
- **API Configuration**: Internal API for Caddy integration
- **Caddy Integration**: Reverse proxy settings

Key settings to customize:
```yaml
server:
  cert_file: "/config/certs/server.crt"  # Your server certificate
  key_file: "/config/certs/server.key"   # Your server private key
  ca_file: "/config/certs/ca.crt"        # Certificate Authority

api:
  listen_addr: "localhost:9443"          # Keep as localhost for security

# Optional: Configure Caddy logging
caddy:
  admin_api: "http://localhost:2019"
  logging:
    enabled: true
    level: "INFO"                        # DEBUG, INFO, WARN, ERROR
    format: "console"                    # json, console, single_field
    output: "stdout"                     # stdout, stderr, or file path
```

### **Agent Configuration**

The [`agent-config.yaml`](agent-config.yaml) and [`agent-logging-config.yaml`](agent-logging-config.yaml) demonstrate comprehensive agent setup including:
- **Agent Identity**: ID, name, region, and tags for organization
- **Server Connection**: TLS certificate configuration
- **Service Definitions**: Backend service configurations with load balancing
- **Application Logging**: Structured logging for agent operations

Key settings to customize:
```yaml
agent:
  id: "production-agent-01"         # Unique agent identifier
  name: "Production Agent 01"       # Human-readable name
  region: "us-west-1"               # Deployment region
  tags: ["production", "critical"]  # Organization tags

server:
  address: "server.example.com:8443"  # Your server address
  cert: "/config/certs/agent.crt"     # Agent certificate
  key: "/config/certs/agent.key"      # Agent private key
  ca_cert: "/config/certs/ca.crt"     # Certificate Authority

# Agent application logging
# Each module automatically sets its own hierarchical component name:
# - agent: Agent core functionality
# - caddy.manager: Caddy configuration management  
# - caddy.validation: Caddy configuration validation
# - common.websocket: WebSocket connection management
# - common.cert: Certificate handling
# - common.hotreload: Configuration hot reloading
logging:
  level: "INFO"                       # DEBUG, INFO, WARN, ERROR, FATAL
  format: "console"                   # console or json
  output: "stdout"                    # stdout, stderr, or file path
```

#### **Agent Service Configuration**

Each service defines how to proxy traffic to backend applications:

```yaml
services:
  - id: "webapp"                      # Service identifier
    name: "Web Application"           # Human-readable name
    hosts:                            # Domain names to handle
      - "app.example.com"
      - "www.example.com"
    protocol: "https"                 # Backend protocol
    websocket: true                   # Enable WebSocket support
    http_redirect: true               # Redirect HTTP to HTTPS
    listen_on: "both"                 # "http", "https", or "both"
    upstreams:                        # Backend servers
      - address: "192.168.1.10:8080"
        weight: 100                   # Load balancing weight
        health_check:                 # Health monitoring
          path: "/health"
          interval: 30s
          timeout: 5s
    load_balancing:                   # Load balancing options
      policy: "round_robin"           # round_robin, least_conn, ip_hash
      health_check_required: true
      session_affinity: true
```

### **Caddy Logging Configuration**

The Zero Trust Proxy now supports two separate logging systems:

#### **1. Application Logging (`logging` section)**

Controls the internal Go application logs (server operations, agent communication, etc.)

```yaml
# Zero Trust Proxy Application Logging
logging:
  level: "INFO"                    # DEBUG, INFO, WARN, ERROR, FATAL
  format: "console"                # console (human-readable) or json (structured)
  output: "stdout"                 # stdout, stderr, or file path
  component: "zero-trust-proxy"    # Component name for structured logging
```

**Format Options:**
- **`console`**: Human-readable format with colors (good for development)
- **`json`**: Structured JSON format (good for production and log aggregation)

**Output Options:**
- **`stdout`**: Standard output (default)
- **`stderr`**: Standard error
- **File path**: e.g., `/var/log/app.log` (file output support coming soon)

#### **2. Caddy Logging (`caddy.logging` section)**

Controls Caddy's HTTP access logs and operational logs

```yaml
caddy:
  logging:
    enabled: true                  # Enable Caddy logging
    level: "INFO"                  # Caddy log level
    format: "console"              # console or json
    output: "stdout"               # stdout, stderr, or file path
    
    # HTTP access log fields to include
    include:
      - "ts"                       # Timestamp
      - "request>method"           # HTTP method
      - "request>uri"              # Request URI
      - "status"                   # HTTP status code
      - "duration"                 # Request duration
    
    # Fields to exclude (for security)
    exclude:
      - "request>headers>Authorization"
      - "request>headers>Cookie"
    
    # Custom fields for all Caddy logs
    fields:
      service: "caddy-proxy"
    
    # Log sampling for high traffic
    sampling_first: 100            # Log first 100 requests fully
    sampling_thereafter: 100       # Then log every 100th request
```

## **Example Configurations by Use Case**

### **Development Setup**

**Recommended**: `server-logging-simple.yaml` + `agent-config.yaml`
- Console format for easy reading
- DEBUG level logging for detailed troubleshooting
- All logs to stdout
- No log sampling

**Server Configuration:**
```yaml
logging:
  level: "DEBUG"
  format: "console"
  output: "stdout"

caddy:
  logging:
    enabled: true
    level: "INFO"
    format: "console"
    output: "stdout"
```

**Agent Configuration:**
```yaml
logging:
  level: "DEBUG"
  format: "console"
  output: "stdout"
  component: "zero-trust-agent-dev"
  fields:
    service: "zero-trust-agent"
    environment: "development"
```

### **Production Setup**

**Recommended**: `server-logging-production.yaml` + `agent-logging-config.yaml`
- JSON format for log aggregation
- Separate log files for application and access logs
- Comprehensive field inclusion
- Security-conscious field exclusion
- Log sampling for high traffic

**Server Configuration:**
```yaml
logging:
  level: "INFO"
  format: "json"
  output: "/var/log/zero-trust-proxy/server.log"
  fields:
    service: "zero-trust-proxy"
    environment: "production"
    datacenter: "us-east-1"

caddy:
  logging:
    enabled: true
    format: "json"
    output: "/var/log/zero-trust-proxy/access.log"
    include:
      - "ts"
      - "request>method"
      - "request>uri"
      - "request>host"
      - "request>remote_ip"
      - "status"
      - "duration"
      - "size"
    exclude:
      - "request>headers>Authorization"
      - "request>headers>Cookie"
    sampling_first: 1000
    sampling_thereafter: 50
```

**Agent Configuration:**
```yaml
logging:
  level: "INFO"
  format: "json"
  output: "/var/log/zero-trust-proxy/agent.log"
  component: "zero-trust-agent-prod"
  fields:
    service: "zero-trust-agent"
    environment: "production"
    datacenter: "us-east-1"
    deployment: "kubernetes"
    pod_name: "${POD_NAME:-unknown}"
    node_name: "${NODE_NAME:-unknown}"
```

### **Homelab/Self-Hosted Setup**

**Recommended**: `server-config.yaml` + `agent-homelab-config.yaml`
- Console format for easy troubleshooting
- INFO level for normal operation
- All logs to stdout (captured by Docker)
- Minimal log sampling

**Server Configuration:**
```yaml
logging:
  level: "INFO"
  format: "console"
  output: "stdout"
  component: "zero-trust-proxy"
  fields:
    service: "zero-trust-proxy"
    environment: "homelab"

caddy:
  logging:
    enabled: true
    level: "INFO"
    format: "console"
    output: "stdout"
```

**Agent Configuration:**
```yaml
logging:
  level: "INFO"
  format: "console"
  output: "stdout"
  component: "zero-trust-agent-homelab"
  fields:
    service: "zero-trust-agent"
    environment: "homelab"
    location: "synology-nas"
```

## **Log Aggregation Integration**

### **ELK Stack (Elasticsearch, Logstash, Kibana)**

Use JSON format with structured fields:

```yaml
logging:
  format: "json"
  fields:
    service: "zero-trust-proxy"
    environment: "production"
    cluster: "prod-cluster"

caddy:
  logging:
    format: "json"
    include: ["ts", "request>method", "request>uri", "status", "duration"]
```

### **Grafana Loki**

Works well with both console and JSON formats. JSON provides better querying:

```yaml
logging:
  format: "json"
  output: "stdout"  # Captured by Promtail

caddy:
  logging:
    format: "json"
    output: "stdout"
```

### **Prometheus + Grafana**

Use structured logging to expose metrics:

```yaml
logging:
  format: "json"
  fields:
    service: "zero-trust-proxy"
    
caddy:
  logging:
    format: "json"
    include: ["status", "duration", "size"]  # For response time and error rate metrics
```

## **Field Reference**

### **Application Log Fields**

| Field | Description | Example |
|-------|-------------|---------|
| `ts` | Timestamp | `2025-06-23T19:34:04.337+03:00` |
| `level` | Log level | `info`, `error`, `debug` |
| `msg` | Log message | `Agent connected successfully` |
| `component` | Component name | `zero-trust-proxy` |
| `fields` | Custom fields | `{"user_id": "123", "action": "login"}` |

### **Caddy Access Log Fields**

| Field | Description | Example |
|-------|-------------|---------|
| `ts` | Timestamp | `1640995200.123` |
| `request>method` | HTTP method | `GET`, `POST` |
| `request>uri` | Request URI | `/api/v1/status` |
| `request>host` | Host header | `api.example.com` |
| `request>remote_ip` | Client IP | `192.168.1.100` |
| `status` | HTTP status | `200`, `404`, `500` |
| `duration` | Request duration | `0.123` (seconds) |
| `size` | Response size | `1024` (bytes) |

## **Security Considerations**

### **Sensitive Data Exclusion**

Always exclude sensitive headers from logs:

```yaml
caddy:
  logging:
    exclude:
      - "request>headers>Authorization"   # OAuth tokens, Basic auth
      - "request>headers>Cookie"          # Session cookies
      - "request>headers>X-Api-Key"       # API keys
      - "request>headers>X-Auth-Token"    # Authentication tokens
      - "request>body"                    # Request body (may contain secrets)
```

### **PII (Personal Identifiable Information)**

Be careful with fields that might contain PII:

```yaml
caddy:
  logging:
    exclude:
      - "request>headers>X-User-Email"    # User email addresses
      - "request>uri"                     # May contain user IDs in path
    # Instead, use sanitized versions or hashed values in custom fields
```

## **Performance Considerations**

### **Log Sampling**

For high-traffic environments, use sampling:

```yaml
caddy:
  logging:
    sampling_first: 1000        # Log first 1000 requests fully
    sampling_thereafter: 100    # Then log every 100th request
```

### **File vs. Stdout**

- **Stdout**: Better for containers and log aggregation systems
- **Files**: Better for traditional deployments with log rotation

## 🚨 Troubleshooting

### **Common Issues**

1. **Certificate Errors**: Regenerate certificates with the provided script
2. **Connection Issues**: Check server address and firewall settings
3. **Service Registration**: Verify agent configuration and server connectivity
4. **WebSocket Failures**: Ensure `websocket: true` is set for WebSocket services

### **Validation Commands**

```bash
# Verify certificate validity
openssl verify -CAfile config/certs/ca.crt config/certs/server.crt
openssl verify -CAfile config/certs/ca.crt config/certs/agent.crt

# Check configuration syntax
docker-compose config

# Test service connectivity
curl -k https://localhost:8443/health
curl -k https://localhost:9443/api/services
```

## 📚 Additional Resources

- **[Docker Deployment Guide](../docs/deployment/docker.md)** - Comprehensive Docker documentation
- **[Troubleshooting Guide](../docs/troubleshooting.md)** - Common issues and solutions
- **[Agent Configuration](../docs/agent/configuration.md)** - Detailed agent configuration
- **[Server Configuration](../docs/server/configuration.md)** - Detailed server configuration

## 🤝 Contributing Examples

Have a working configuration you'd like to share? Please contribute!

1. **Fork the repository**
2. **Add your example** with clear documentation
3. **Test thoroughly** in your environment
4. **Submit a pull request** with description
