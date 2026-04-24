# Docker Deployment

This guide covers building and running the Zero Trust Proxy with Docker Compose.

> **Note**: There are no pre-built Docker images. You build the custom Caddy binary and agent from source.

## Dockerfile — Server (custom Caddy)

```dockerfile
FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /bin/caddy ./cmd/caddy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /bin/caddy /usr/local/bin/caddy
EXPOSE 80 443 8443
ENTRYPOINT ["caddy", "run", "--config", "/config/Caddyfile", "--adapter", "caddyfile"]
```

## Dockerfile — Agent

```dockerfile
FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /bin/agent ./cmd/agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /bin/agent /usr/local/bin/agent
ENTRYPOINT ["agent"]
```

## Docker Compose

```yaml
services:
  caddy:
    build:
      context: .
      dockerfile: Dockerfile.caddy
    container_name: zero-trust-caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "8443:8443"
    volumes:
      - ./config:/config:ro
    networks:
      - zero-trust

  agent:
    build:
      context: .
      dockerfile: Dockerfile.agent
    container_name: zero-trust-agent
    restart: unless-stopped
    command:
      - "--server=caddy:8443"
      - "--cert=/config/certs/agent.crt"
      - "--key=/config/certs/agent.key"
      - "--ca=/config/certs/ca.crt"
      - "--id=docker-agent"
      - "--config=/config/agent.yaml"
    volumes:
      - ./config:/config:ro
    networks:
      - zero-trust
      - backend
    depends_on:
      - caddy

networks:
  zero-trust:
    driver: bridge
  backend:
    driver: bridge
```

## Config Files

### config/Caddyfile

```caddyfile
{
    zerotrust_agents {
        listen    :8443
        cert_file /config/certs/server.crt
        key_file  /config/certs/server.key
        ca_file   /config/certs/ca.crt
    }
}

:443 {
    route {
        zerotrust_router { request_timeout 2m }
    }
}
```

### config/agent.yaml

```yaml
agent:
  id: "docker-agent"

server:
  address: "caddy:8443"
  cert:    "/config/certs/agent.crt"
  key:     "/config/certs/agent.key"
  ca_cert: "/config/certs/ca.crt"

log_level: "INFO"
hot_reload:
  enabled: true

services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "http"
    upstreams:
      - address: "web-app:3000"
```

## Certificate Setup

```bash
# Build certgen
go build -o bin/certgen ./cmd/certgen

mkdir -p config/certs

# CA
./bin/certgen --out config/certs --name ca --type ca

# Server cert
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name server --type server

# Agent cert
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name agent --type agent

# Set permissions
chmod 600 config/certs/*.key
chmod 644 config/certs/*.crt
```

## Deploy

```bash
# Build images and start
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f caddy
docker compose logs -f agent
```

## Homelab Example (Multi-Service Agent)

```yaml
# config/agent.yaml
agent:
  id: "homelab"

server:
  address: "my-vps.example.com:8443"
  cert:    "/config/certs/agent.crt"
  key:     "/config/certs/agent.key"
  ca_cert: "/config/certs/ca.crt"

log_level: "WARN"
hot_reload:
  enabled: true

services:
  - id: "homeassistant"
    hostname: "ha.example.com"
    websocket: true
    protocol: http
    upstreams:
      - address: "192.168.1.10:8123"

  - id: "nas"
    hostname: "nas.example.com"
    websocket: true
    protocol: https
    upstreams:
      - address: "192.168.1.20:443"

  - id: "plex"
    hostname: "plex.example.com"
    websocket: true
    protocol: http
    upstreams:
      - address: "192.168.1.20:32400"
```
