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
- **[`server-logging-config.yaml`](server-logging-config.yaml)** - Comprehensive Caddy logging configuration for production
- **[`server-logging-simple.yaml`](server-logging-simple.yaml)** - Simple Caddy logging setup for development

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

### **Caddy Logging Configuration**

The Zero Trust Proxy now supports comprehensive Caddy logging configuration. Use [`server-logging-config.yaml`](server-logging-config.yaml) for production or [`server-logging-simple.yaml`](server-logging-simple.yaml) for development.

#### **Development Setup (Simple)**
```yaml
caddy:
  logging:
    enabled: true
    level: "INFO"
    format: "console"      # Easy to read in terminal
    output: "stdout"       # Output to Docker logs
    
    include:               # Basic fields to log
      - "status"
      - "method" 
      - "uri"
      - "duration"
    
    exclude:               # Exclude sensitive data
      - "request>headers>Authorization"
      - "request>headers>Cookie"
```

#### **Production Setup (Comprehensive)**
```yaml
caddy:
  logging:
    enabled: true
    level: "INFO"
    format: "json"                          # Structured logging
    output: "/var/log/caddy-access.log"     # Persistent file logging
    
    include:                                # Detailed request tracking
      - "user_id"
      - "duration"
      - "size"
      - "status"
      - "method"
      - "uri"
      - "host"
      - "request>remote_ip"
      - "request>headers>User-Agent"
      - "common_log"
    
    exclude:                                # Security: exclude sensitive data
      - "request>headers>Authorization"
      - "request>headers>Cookie"
      - "request>headers>X-API-Key"
      - "request>body"
      - "resp_headers>Set-Cookie"
    
    fields:                                 # Custom context fields
      component: "zero-trust-caddy-proxy"
      environment: "production"
      version: "1.0.0"
    
    # Optional: Log sampling for high traffic
    sampling_first: 100
    sampling_thereafter: 50
```

#### **Hot Reload Support**

Caddy logging configuration supports hot reload - changes to logging settings are applied without server restart:

```bash
# Edit your server configuration
nano config/server.yaml

# The logging configuration will be automatically updated
# Check logs for confirmation:
# "Caddy logging configuration changed, updating Caddy config..."
# "Caddy logging configuration updated successfully"
```

### **Agent Configuration**

Basic agent setup ([`agent-config.yaml`](agent-config.yaml)):
```yaml
agent:
  id: "your-agent-id"                    # Must match certificate CN
  name: "Your Agent Name"

server:
  address: "your-server:8443"            # Your server address
  
services:
  - id: "web-service"
    hosts: ["app.example.com"]
    protocol: "http"
    upstreams:
      - address: "localhost:3000"
```

### **Homelab Configuration**

The homelab example ([`agent-homelab-config.yaml`](agent-homelab-config.yaml)) demonstrates:
- **Multi-service setup** with different protocols
- **WebSocket support** for real-time applications
- **Multiple hostnames** per service
- **Real IP addresses** and container names

## 🔐 Certificate Management

### **Automated Certificate Generation**

Use the provided script for easy certificate generation:

```bash
# Make script executable (if not already)
chmod +x examples/generate-certificates.sh

# Generate all certificates
./examples/generate-certificates.sh
```

This script will:
1. Create `config/certs/` directory
2. Generate CA certificate and key
3. Generate server certificate and key
4. Generate agent certificate and key
5. Set proper file permissions
6. Verify certificate validity

### **Manual Certificate Generation**

If you prefer manual generation:

```bash
# Generate CA
docker run --rm -v $(pwd)/config/certs:/certs \
  ghcr.io/devhatro/zero-trust-proxy/certgen:latest \
  --ca /certs/ca.crt --ca-key /certs/ca.key \
  --out /certs --name root --type ca

# Generate server certificate
docker run --rm -v $(pwd)/config/certs:/certs \
  ghcr.io/devhatro/zero-trust-proxy/certgen:latest \
  --ca /certs/ca.crt --ca-key /certs/ca.key \
  --out /certs --name server --type server

# Generate agent certificate
docker run --rm -v $(pwd)/config/certs:/certs \
  ghcr.io/devhatro/zero-trust-proxy/certgen:latest \
  --ca /certs/ca.crt --ca-key /certs/ca.key \
  --out /certs --name agent --type agent
```

## 🌐 Service Configuration Examples

### **Basic Web Application**
```yaml
- id: "web-app"
  hosts: ["app.example.com"]
  protocol: "http"
  upstreams:
    - address: "web-app:3000"
```

### **WebSocket Application**
```yaml
- id: "websocket-app"
  hosts: ["ws.example.com"]
  websocket: true
  protocol: "http"
  upstreams:
    - address: "websocket-app:4000"
```

### **Load Balanced Service**
```yaml
- id: "api-service"
  hosts: ["api.example.com"]
  protocol: "https"
  upstreams:
    - address: "api-1:8080"
      weight: 70
    - address: "api-2:8080"
      weight: 30
  load_balancing:
    policy: "weighted_round_robin"
```

### **Multiple Hostnames (Homelab Style)**
```yaml
- id: "synology"
  hosts:
    - nas.example.com
    - drive.example.com
    - photos.example.com
  websocket: true
  protocol: "https"
  upstreams:
    - address: "192.168.1.100:443"
```

## 🔧 Customization Tips

### **Environment-Specific Changes**

1. **Update Server Address**: Change `server.address` in agent config to your server's IP/hostname
2. **Modify Service Hostnames**: Update `hosts` arrays to match your domain names
3. **Adjust Backend Addresses**: Change `upstreams.address` to point to your actual services
4. **Certificate Paths**: Ensure certificate paths match your deployment structure

### **Production Considerations**

1. **Log Levels**: Use `WARN` or `ERROR` for production to reduce log noise
2. **Health Checks**: Enable health checks for critical services
3. **Load Balancing**: Configure appropriate weights and policies
4. **WebSocket Support**: Enable only for services that need real-time features

### **Security Best Practices**

1. **Certificate Security**: Keep private keys secure with proper permissions (600)
2. **Network Isolation**: Use Docker networks to isolate components
3. **API Access**: Keep server API on localhost for security
4. **Regular Updates**: Update certificates before expiration

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
