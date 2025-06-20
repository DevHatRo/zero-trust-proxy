# 🐳 Docker Deployment Guide

This guide covers deploying the Zero Trust Proxy system using Docker and Docker Compose with real-world examples.

## 📦 Docker Images

The Zero Trust Proxy provides official Docker images:

- **Server**: `ghcr.io/devhatro/zero-trust-proxy/server:latest`
- **Agent**: `ghcr.io/devhatro/zero-trust-proxy/agent:latest`

## 🚀 Quick Start with Docker Compose

### Complete Docker Compose Setup

Create a `docker-compose.yml` file:

```yaml
---
version: '3.8'

services:
  # Zero Trust Server
  zero-trust-server:
    image: ghcr.io/devhatro/zero-trust-proxy/server:latest
    container_name: zero-trust-server
    restart: unless-stopped
    ports:
      - "8443:8443"    # Agent connections
      - "9443:9443"    # Internal API (if needed externally)
      - "80:80"        # HTTP (Caddy integrated)
      - "443:443"      # HTTPS (Caddy integrated)
    volumes:
      - ./config:/config
      - ./config/certs:/certs:ro
    environment:
      - LOG_LEVEL=INFO
    networks:
      - zero-trust-network

  # Zero Trust Agent
  zero-trust-agent:
    image: ghcr.io/devhatro/zero-trust-proxy/agent:latest
    container_name: zero-trust-agent
    restart: unless-stopped
    volumes:
      - ./config:/config
    environment:
      - LOG_LEVEL=INFO
      - ZERO_TRUST_SERVER=zero-trust-server:8443
    networks:
      - zero-trust-network
      - backend-network  # Access to backend services
    depends_on:
      - zero-trust-server

networks:
  zero-trust-network:
    driver: bridge
  backend-network:
    driver: bridge
```

## ⚙️ Configuration Files

### Server Configuration

Create `config/server.yaml`:

```yaml
# 0Trust Server Configuration

# Log level configuration
log_level: "INFO"

# Hot reload configuration
hot_reload:
  enabled: true                  # Enable hot configuration reloading
  watch_config: true            # Watch config file for changes
  debounce_delay: "100ms"       # Delay before reloading after file change
  graceful_timeout: "30s"       # Timeout for graceful reload operations
  reload_signal: "SIGHUP"       # Optional: reload on signal

# Core server settings
server:
  listen_addr: ":8443"
  cert_file: "/config/certs/server.crt"
  key_file: "/config/certs/server.key"
  ca_file: "/config/certs/ca.crt"

# API server settings (for HTTP proxy from Caddy)
api:
  listen_addr: "localhost:9443"

# Caddy reverse proxy settings
caddy:
  admin_api: "http://localhost:2019"
  config_dir: "/config/caddy"
  storage_dir: "/config/caddy/storage"
```

### Agent Configuration

Create `config/agent.yaml`:

```yaml
# Zero Trust Agent Configuration

# Hot reload configuration
hot_reload:
  enabled: true
  watch_config: true

# Log level
log_level: "INFO"

# Agent identity
agent:
  id: "docker-agent"
  name: "Docker Agent"
  region: "local"
  tags:
    - "docker"
    - "homelab"

# Server connection
server:
  address: "zero-trust-server:8443"  # Use container name for internal communication
  ca_cert: "/config/certs/ca.crt"
  cert: "/config/certs/agent.crt"
  key: "/config/certs/agent.key"

# Service definitions
services:
  - id: "web-app"
    name: "Web Application"
    hosts:
      - "app.example.com"
    protocol: "http"
    upstreams:
      - address: "web-app:3000"
    routes:
      - match:
          path: "/*"
        handle:
          - type: "reverse_proxy"
```

## 🏠 Real-World Homelab Example

Based on a production Synology homelab setup:

### Production Docker Compose

```yaml
---
version: '3.8'

services:
  # Zero Trust Server (Public-facing)
  zero-trust-server:
    image: ghcr.io/devhatro/zero-trust-proxy/server:latest
    container_name: zero-trust-server
    restart: unless-stopped
    ports:
      - "8443:8443"    # Agent connections
      - "80:80"        # HTTP traffic
      - "443:443"      # HTTPS traffic
    volumes:
      - /root/docker/config:/config
      - /root/docker/config/certs:/certs:ro
    environment:
      - LOG_LEVEL=INFO
    networks:
      - zero-trust-network

  # Zero Trust Agent (On-premises)
  zero-trust-agent:
    image: ghcr.io/devhatro/zero-trust-proxy/agent:latest
    container_name: zero-trust-agent
    restart: unless-stopped
    volumes:
      - /volume1/docker/config:/config
    environment:
      - LOG_LEVEL=WARN
    networks:
      - zero-trust-network
      - homelab-network
    depends_on:
      - zero-trust-server

networks:
  zero-trust-network:
    driver: bridge
  homelab-network:
    external: true  # Connects to existing homelab network
```

### Production Agent Configuration

Real-world multi-service homelab setup:

```yaml
# Production Homelab Agent Configuration

hot_reload:
  enabled: true
  watch_config: true

log_level: WARN

agent:
  id: "synology"
  name: "Synology Agent"
  region: "local"
  tags:
    - "homelab"
    - "synology"

server:
  address: "195.201.146.166:8443"  # Public server IP
  ca_cert: "/config/certs/ca.crt"
  cert: "/config/certs/agent.crt"
  key: "/config/certs/agent.key"

# Multiple service definitions
services:
  # Media Management Services via Traefik
  - id: "traefik"
    name: "Internal Proxy Traefik"
    hosts:
      - portal.local.example.com
    protocol: http
    upstreams:
      - address: "traefik:80"
    routes:
      - match:
          path: "/*"
        handle:
          - type: "reverse_proxy"

  # Home Assistant with WebSocket Support
  - id: "homeassistant"
    name: "Home Assistant"
    hosts:
      - assistant.local.example.com
    websocket: true
    protocol: http
    upstreams:
      - address: "172.30.10.120:8123"
    routes:
      - match:
          path: "/*"
        handle:
          - type: "reverse_proxy"

  # Pi-hole DNS Admin
  - id: "pihole"
    name: "Pi-hole DNS"
    hosts:
      - pihole.local.example.com
    websocket: true
    protocol: http
    upstreams:
      - address: "172.30.13.254:80"
    routes:
      - match:
          path: "/*"
        handle:
          - type: "reverse_proxy"

  # Synology NAS Services
  - id: "synology"
    name: "Synology NAS"
    hosts:
      - nas.example.com
      - drive.example.com
      - file.example.com
      - photo.example.com
      - download.example.com
      - cam.example.com
    websocket: true
    protocol: https
    upstreams:
      - address: "172.23.0.1:443"
    routes:
      - match:
          path: "/*"
        handle:
          - type: "reverse_proxy"

  # Plex Media Server
  - id: "plex"
    name: "Plex Media Server"
    hosts:
      - plex.local.example.com
    websocket: true
    protocol: http
    upstreams:
      - address: "172.23.0.1:32400"
    routes:
      - match:
          path: "/*"
        handle:
          - type: "reverse_proxy"
```

## 🔐 Certificate Setup for Docker

### Generate Certificates for Docker Deployment

```bash
# Create certificate directory
mkdir -p config/certs

# Generate CA certificate
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

### Certificate Permissions

```bash
# Set proper permissions
chmod 600 config/certs/*.key
chmod 644 config/certs/*.crt
chown -R $(id -u):$(id -g) config/certs/
```

### 4. Deploy Services

```bash
# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f zero-trust-server
docker-compose logs -f zero-trust-agent
```
