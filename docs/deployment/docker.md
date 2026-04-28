# Docker Deployment

This guide covers building and running the Zero Trust Proxy with Docker Compose.

> **Note**: There are no pre-built Docker images. You build the
> server and agent from source.

## Dockerfile — Server

Two Dockerfiles ship with the repo:

- `cmd/zero-trust-proxy/Dockerfile` — production image. Expects a
  prebuilt static binary at
  `bin/zero-trust-proxy-server-linux-${TARGETARCH}` (run
  `./scripts/build.sh` first). Smaller and faster to build.
- `cmd/zero-trust-proxy/Dockerfile.dev` — self-contained multi-stage
  build, no prerequisites. Useful for one-shot `docker build .` or CI
  smoke jobs.

```bash
# production (prebuilt binary)
./scripts/build.sh
docker build -f cmd/zero-trust-proxy/Dockerfile -t zero-trust-proxy:latest .

# one-shot (no prerequisites)
docker build -f cmd/zero-trust-proxy/Dockerfile.dev -t zero-trust-proxy:dev .
```

## Dockerfile — Agent

```dockerfile
FROM golang:1.25 AS builder
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
  server:
    build:
      context: .
      dockerfile: Dockerfile.server
    container_name: zero-trust-proxy
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
      - "--server=server:8443"
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
      - server

networks:
  zero-trust:
    driver: bridge
  backend:
    driver: bridge
```

## Config files

### `config/server.yaml`

```yaml
listen:
  http: ":80"
  https: ":443"
  http_redirect: true

tls:
  mode: manual
  manual:
    cert_file: /config/certs/public.crt
    key_file:  /config/certs/public.key

agents:
  listen:    ":8443"
  cert_file: /config/certs/server.crt
  key_file:  /config/certs/server.key
  ca_file:   /config/certs/ca.crt
  check_addr: ":2020"

router:
  request_timeout: 2m

logging:
  level: info
  format: json
```

For Let's Encrypt instead of `manual`:

```yaml
tls:
  mode: acme
  acme:
    storage_dir: /config/acme
    email: ops@example.com
```

### `config/agent.yaml`

```yaml
agent:
  id: "docker-agent"

server:
  address: "server:8443"
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

## Certificate setup

```bash
# Build certgen
go build -o bin/certgen ./cmd/certgen

mkdir -p config/certs

# CA
./bin/certgen --out config/certs --name ca --type ca

# Server cert (presented on :8443 to agents)
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name server --type server

# Agent cert
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name agent --type agent

chmod 600 config/certs/*.key
chmod 644 config/certs/*.crt
```

## Deploy

```bash
docker compose up -d
docker compose ps
docker compose logs -f server
docker compose logs -f agent
```

## Homelab example (multi-service agent)

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
