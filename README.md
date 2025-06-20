# 🛡️ Zero Trust Reverse Proxy

**Enterprise-grade zero trust proxy with mTLS authentication, multi-service support, load balancing, health checks, advanced routing, and intelligent streaming capabilities.**

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Architecture-Zero%20Trust-red.svg)](#architecture)

## 🌟 Key Features

- **🔒 Security First**: mTLS authentication, zero trust architecture, TLS 1.3 support
- **🚀 Enterprise Performance**: Intelligent streaming (50GB+ files), dynamic timeouts, connection pooling
- **⚖️ Advanced Load Balancing**: Multiple algorithms, health checks, session affinity
- **🎯 Smart Routing**: Path-based routing, middleware chains, header manipulation
- **📊 Observability**: Comprehensive logging, Prometheus metrics, health endpoints
- **🔄 Configuration Management**: Hot reload, multi-service support, YAML configuration

## 🏗️ Architecture

The Zero Trust Proxy uses a secure tunnel architecture with mTLS authentication:

```
Client → Caddy → Server (mTLS) → Agent → Backend Services
```

### **Data Flow**
1. **Client** requests go through **Caddy** (reverse proxy with advanced routing)
2. **Caddy** forwards to **Server Internal API** (127.0.0.1:9443 with enhanced headers)
3. **Server** establishes encrypted **mTLS tunnel** to appropriate **Agent**
4. **Agent** load balances requests to **Backend Services** with health checks

## 🚀 Quick Start

### Prerequisites
- **Go 1.22+** for building from source
- **Caddy v2.7.6+** for reverse proxy
- **Valid TLS certificates** for mTLS authentication

### 1. Build Components
```bash
# Build all components
go build -o bin/server ./cmd/server
go build -o bin/agent ./cmd/agent
go build -o bin/certgen ./cmd/certgen
```

### 2. Generate Certificates
```bash
# Generate CA and certificates
./bin/certgen -client-ca -client-id test1 -intermediate-ca -root-ca -server-ca -server-ip 127.0.0.1,8.8.8.8
```

### 3. Start Server
```bash
./bin/server --listen :8443 --cert certs/server.crt --key certs/server.key --ca certs/ca.crt
```

### 4. Start Agent
```bash
./bin/agent --server 127.0.0.1:8443 --cert certs/agent1.crt --key certs/agent1.key --ca certs/ca.crt --id agent1
```

## 🐳 Docker Quick Start

For Docker deployment with real-world examples:

```bash
# Get the examples
curl -O https://raw.githubusercontent.com/devhatro/zero-trust-proxy/main/examples/docker-compose.yml
curl -O https://raw.githubusercontent.com/devhatro/zero-trust-proxy/main/examples/generate-certificates.sh

# Generate certificates
chmod +x generate-certificates.sh && ./generate-certificates.sh

# Deploy with Docker
docker-compose up -d
```

See **[Docker Deployment Guide](docs/deployment/docker.md)** and **[Examples](examples/)** for complete setup.

## ⚙️ Configuration Examples

### Basic Agent Configuration
```yaml
agent:
  id: "production-agent-01"
  name: "Production Agent"

server:
  address: "server.example.com:8443"
  cert: "certs/agent.crt"
  key: "certs/agent.key"
  ca_cert: "certs/ca.crt"

services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "localhost:3000"
        weight: 100
        health_check:
          path: "/health"
          interval: "30s"
```

### Advanced Multi-Service Configuration
```yaml
services:
  # Web application with load balancing
  - id: "webapp-service"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "10.0.1.100:3000"
        weight: 70
      - address: "10.0.1.101:3000"
        weight: 30
    load_balancing:
      policy: "weighted_round_robin"
      health_check_required: true
    
  # API Gateway with WebSocket support
  - id: "api-gateway"
    hostname: "api.example.com"
    protocol: "https"
    websocket: true
    upstreams:
      - address: "backend-1:8080"
      - address: "backend-2:8080"
```

## 🔧 Command Line Usage

### Server
```bash
./bin/server --listen :8443 --api :9443 --cert certs/server.crt --key certs/server.key --ca certs/ca.crt --log-level INFO
```

### Agent
```bash
./bin/agent --server server.example.com:8443 --cert certs/agent.crt --key certs/agent.key --ca certs/ca.crt --id agent1 --config config/agent.yaml
```

### Certificate Generator
```bash
./bin/certgen --ca certs/ca.crt --ca-key certs/ca.key --out certs --name agent1 --type agent --days 365
```

## 📖 Documentation

For comprehensive documentation, visit the **[docs/](docs/)** directory:

### 🚀 **Getting Started**
- **[Complete Documentation Index](docs/README.md)** - Full documentation overview
- **[Basic Configuration](docs/deployment/docker.md)** - Simple setup examples

### 🔧 **Components**
- **[Agent Documentation](docs/agent/)** - Agent configuration and features
- **[Server Documentation](docs/server/)** - Server setup and management

### 🌟 **Advanced Features**
- **[WebSocket Support](docs/websocket-configuration.md)** - Real-time communication setup
- **[HTTP Redirect Features](docs/http-redirect-features.md)** - HTTP to HTTPS redirection

### 🚀 **Deployment**
- **[Docker Deployment](docs/deployment/docker.md)** - Container-based deployment

## 🛠️ Load Balancing & Routing

### Load Balancing Algorithms
- **round_robin**: Equal distribution across upstreams
- **weighted_round_robin**: Distribution based on weights
- **least_conn**: Route to server with least connections
- **ip_hash**: Consistent routing based on client IP

### Middleware Support
- **reverse_proxy**: Backend forwarding
- **rate_limit**: Request throttling
- **cache**: Response caching
- **headers**: Header manipulation
- **cors**: Cross-origin requests
- **auth**: Authentication (JWT, OAuth2)

## 📊 Monitoring & Security

### Health & Monitoring
- **Health Endpoints**: `/agent/health`, `/agent/ready`
- **Prometheus Metrics**: Performance and usage statistics
- **Structured Logging**: JSON logging with contextual icons
- **Real-time Monitoring**: Channel usage and connection statistics

### Security Features
- **mTLS Authentication**: Mutual TLS between all components
- **Certificate Validation**: CA-based trust and client certificate validation
- **Zero Trust Architecture**: Encrypted tunnels with no implicit trust
- **Network Isolation**: Backend services remain isolated from direct internet access

## 🎨 Icon System

The system features contextual logging with meaningful icons:
- 🚀🤖🔧✅💥 - Startup/Lifecycle
- 🔌🔗📞💔🗑️ - Connections
- 🌐📡🎉📤📥 - HTTP/WebSocket
- 🔐🔑🖥️👤⚙️ - Certificates
- 💓✅❌⚠️🚨 - Health/Status

## 🚨 Troubleshooting

### Quick Debug Commands
```bash
# Check certificate validity
openssl x509 -in certs/agent.crt -text -noout

# Test connectivity
curl -k --cert certs/client.crt --key certs/client.key https://server:8443

# Debug logging
LOG_LEVEL=DEBUG ./bin/agent --server server:8443 --id agent1
```

### Common Issues
- **Certificate Errors**: Verify certificate validity and CA chain
- **Connection Issues**: Check network connectivity and firewall rules
- **Configuration Issues**: Validate YAML syntax and required fields

For detailed troubleshooting, see **[docs/troubleshooting.md](docs/troubleshooting.md)**

## 📈 Performance Features

### Intelligent Streaming
- **Large File Support**: 50GB+ files with dynamic timeouts
- **Activity-based Timeouts**: Timeout resets with data flow  
- **Chunked Transfer**: 32KB chunks with acknowledgments
- **Progress Monitoring**: Real-time transfer statistics

### Optimization Features
- **Connection Pooling**: Keep-alive optimization
- **Request Pipelining**: Improved throughput
- **Adaptive Timeouts**: Dynamic timeout calculation
- **Backpressure Handling**: Channel pressure monitoring

## 🏢 Production Ready

### Enterprise Features
- **Multi-Region Support**: Deploy agents across regions
- **High Availability**: Redundant server deployment
- **Graceful Shutdowns**: Zero-downtime restarts
- **Resource Management**: Memory and connection limits
- **Audit Logging**: Comprehensive security logging

### Scaling Guidelines
- **Agents**: 1 agent per 100-500 concurrent connections
- **Upstreams**: 2-10 backends per service for redundancy
- **Health Checks**: 15-30 second intervals for production
- **Timeouts**: 30s-5min based on operation type

## 📝 License

**Apache 2.0 License** - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 🆘 Support & Community

- **🐛 Bug Reports**: [Report Issues](https://github.com/devhatro/zero-trust-proxy/issues/new)
- **💡 Feature Requests**: [Request Features](https://github.com/devhatro/zero-trust-proxy/issues/new?)
- **💬 Discussions**: [GitHub Discussions](https://github.com/devhatro/zero-trust-proxy/discussions)
- **📖 Documentation**: [Complete Docs](docs/README.md)

---

**Built with ❤️ for enterprise zero trust networking** 🛡️ 
 

 
