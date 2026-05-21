# Zero Trust Proxy Examples

Ready-to-use deployment and configuration examples for the Zero Trust
Proxy system.

## File overview

### Docker deployment

- [`docker-compose.yml`](docker-compose.yml) — server + agent stack with
  log rotation and persistent ACME storage.
- [`docker-compose-homelab.yml`](docker-compose-homelab.yml) — real-world
  homelab layout (public VPS server + on-prem Synology agent).

### Agent configuration

- [`agent-config.yaml`](agent-config.yaml) — basic agent with multiple
  service examples (HTTP, WebSocket, load-balanced API).
- [`agent-homelab-config.yaml`](agent-homelab-config.yaml) — homelab
  agent wired to real services.
- [`agent-logging-config.yaml`](agent-logging-config.yaml) — agent
  logging tuned for production.

The **server** has no example file here — copy
[`../config/server.yaml.example`](../config/server.yaml.example), which
documents every field of the current schema.

## Quick start (Docker)

```bash
cd zero-trust-proxy

# 1. Generate certificates (see the root README for certgen usage)
./bin/certgen --out config/certs --name ca     --type ca
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name server --type server
./bin/certgen --ca config/certs/ca.crt --ca-key config/certs/ca.key \
              --out config/certs --name agent  --type agent

# 2. Stage the configs
cp examples/docker-compose.yml ./
cp config/server.yaml.example  config/server.yaml
cp examples/agent-config.yaml  config/agent.yaml

# 3. Edit config/server.yaml and config/agent.yaml for your environment,
#    then deploy
docker compose up -d
```

## Homelab deployment

```bash
cp examples/docker-compose-homelab.yml ./docker-compose.yml
cp examples/agent-homelab-config.yaml  ./config/agent.yaml
cp config/server.yaml.example          ./config/server.yaml

# Point the agent at your server
sed -i 's/195.201.146.166:8443/YOUR_SERVER_IP:8443/' config/agent.yaml

docker compose up -d
```

## Server configuration

`config/server.yaml` drives the `zero-trust-proxy` binary. The schema is
`listen` / `tls` / `agents` / `router` / `logging` / `metrics` — see
[`../config/server.yaml.example`](../config/server.yaml.example) and
[the server reference](../docs/server/README.md). For Let's Encrypt set
`tls.mode: acme`; the example `docker-compose.yml` mounts a writable
`acme-data` volume at `/config/acme` for the issued certificates.

## Agent configuration

`agent-config.yaml` shows agent identity, the mTLS connection to the
server, and `services` definitions with upstreams, load balancing, and
WebSocket support. Key fields to customize:

```yaml
agent:
  id: "production-agent-01"           # must match the agent certificate CN

server:
  address: "server.example.com:8443" # your server's mTLS address
  cert:    "/config/certs/agent.crt"
  key:     "/config/certs/agent.key"
  ca_cert: "/config/certs/ca.crt"
```

See the [agent reference](../docs/agent/README.md) for the full schema
and [WebSocket configuration](../docs/websocket-configuration.md) for
WebSocket services.

## Logging

Both binaries use a single `logging` block:

```yaml
logging:
  level:  info      # debug | info | warn | error
  format: console   # console (human-readable) | json (log aggregation)
```

HTTP access logging on the server is toggled with `logging.access_log`
(see `config/server.yaml.example`).

## Troubleshooting

Common issues:

1. **Certificate errors** — regenerate with `certgen` and confirm the
   agent certificate CN matches `agent.id`.
2. **Connection issues** — check the server address and that `:8443` is
   reachable from the agent.
3. **Service registration** — verify agent config and server
   connectivity in the logs.
4. **WebSocket failures** — ensure `websocket: true` is set on the
   service.

```bash
# Verify certificates
openssl verify -CAfile config/certs/ca.crt config/certs/server.crt
openssl verify -CAfile config/certs/ca.crt config/certs/agent.crt

# Validate the server config without starting it
./bin/zero-trust-proxy validate --config config/server.yaml

# Check compose syntax
docker compose config
```

## Additional resources

- [Docker deployment guide](../docs/deployment/docker.md)
- [Troubleshooting guide](../docs/troubleshooting.md)
- [Server reference](../docs/server/README.md)
- [Agent reference](../docs/agent/README.md)
- [Hot reload](../docs/hot-reload.md)
