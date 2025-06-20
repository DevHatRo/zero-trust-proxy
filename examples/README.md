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
sed -i 's/<server public ip>:8443/YOUR_SERVER_IP:8443/' config/agent.yaml

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
./bin/certgen -client-ca -client-id test1 -intermediate-ca -root-ca -server-ca -server-ip 127.0.0.1,<server public ip>
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
