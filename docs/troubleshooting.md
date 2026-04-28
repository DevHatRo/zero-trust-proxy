# Troubleshooting

This guide covers common issues with `zero-trust-proxy` (server) and
`agent`.

## Quick diagnostics

```bash
# Check what's running
ps aux | grep -E "(zero-trust-proxy|agent)"

# Check listening ports
sudo netstat -tlnp | grep -E ':(80|443|8443|2020)'

# Validate config without starting
./bin/zero-trust-proxy validate --config config/server.yaml
```

### Debug logging

```bash
# Server: set logging.level in YAML
# logging:
#   level: debug
./bin/zero-trust-proxy run --config config/server.yaml

# Agent: --log-level flag overrides the YAML
./bin/agent --log-level DEBUG --config config/agent.yaml

# Or via env
export LOG_LEVEL=DEBUG
```

## Certificate issues

### `tls: bad certificate`, `certificate verify failed`

```bash
# Inspect server / agent / CA
openssl x509 -in certs/server.crt -text -noout | grep -E "(Validity|Subject|Issuer)"
openssl x509 -in certs/agent1.crt -text -noout | grep -E "(Validity|Subject|Issuer)"

# Verify chain
openssl verify -CAfile certs/ca.crt certs/server.crt
openssl verify -CAfile certs/ca.crt certs/agent1.crt

# Check expiry
openssl x509 -in certs/server.crt -noout -dates
openssl x509 -in certs/agent1.crt -noout -dates
```

Regenerate as needed:

```bash
./bin/certgen --ca certs/ca.crt --ca-key certs/ca.key \
              --out certs --name server --type server
./bin/certgen --ca certs/ca.crt --ca-key certs/ca.key \
              --out certs --name agent1 --type agent

chmod 600 certs/*.key
chmod 644 certs/*.crt
```

## Agent ↔ server connection

### Agent cannot connect

```bash
# Connectivity
nc -zv server.example.com 8443

# Server listening?
sudo netstat -tlnp | grep :8443

# Firewall
sudo ufw status | grep 8443
```

Open ports if needed:

```bash
sudo ufw allow 8443/tcp   # agent mTLS
sudo ufw allow 443/tcp    # public HTTPS
sudo ufw allow 80/tcp     # redirect / ACME challenge
```

### HTTP 503 from the public listener

503 means no agent has registered the requested `Host`. Confirm the
agent is connected and that the service hostname matches exactly
(case-insensitive). Agent log lines to look for:

```
agent: registered with server
service_add host=app.example.com agent=agent1
```

### HTTP 504

The router timed out waiting for the agent's response. Increase
`router.request_timeout` in `config/server.yaml` if uploads or
long-running calls legitimately exceed the default 2 minutes.

## Service registration

```bash
# Bring the agent up against your config
./bin/agent --config config/agent.yaml

# Backend reachable from the agent host?
curl -H "Host: app.example.com" http://localhost:3000/health
```

Health-check tuning lives in `config/agent.yaml`:

```yaml
health_check:
  path: "/health"
  interval: "60s"
  timeout: "10s"
  unhealthy_threshold: 5
```

## Hot reload

### Agent: file changes ignored

```bash
# Trigger a reload manually
touch config/agent.yaml

# Watch the agent log for the reload event
# If nothing fires: confirm hot_reload.enabled: true
ls -la config/agent.yaml          # must be readable by the agent uid
lsof config/agent.yaml             # check for an editor lock
```

### Server: SIGHUP ignored

The server logs the field that prevented the reload. Listen-address
and TLS-mode changes always require a restart — see `docs/hot-reload.md`
for the full list.

```bash
kill -HUP $(pgrep zero-trust-proxy)
journalctl -u zero-trust-proxy -n 20
```

## WebSocket

```bash
curl -v \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  https://app.example.com/
```

Service must have `websocket: true` and the backend must accept
WebSocket upgrades. WebSocket upgrade requires HTTP/1.1 — Go's stdlib
HTTP/2 server does not expose `Hijacker`. Browsers downgrade
automatically for the `Upgrade` request.

```bash
wscat -c ws://localhost:3000/    # confirm backend accepts WS
```

## Performance

### High memory usage

```bash
top -p $(pgrep -d, -f "zero-trust-proxy|agent")
ps aux | grep -E "(zero-trust-proxy|agent)" | awk '{print $6}'
```

Tighten upstream connection limits via `load_balancing.max_connections`
in the agent config; tune systemd `MemoryMax` for the unit.

### Slow responses

```bash
time curl https://app.example.com/

# Connection counts on each listener
ss -tuln | grep -E ':(80|443|8443)'
```

Increase upstream `timeout` and `keep_alive_timeout` in the agent
config if backends are slow under load.

## Docker

```bash
# Logs
docker logs zero-trust-proxy
docker logs zero-trust-agent

# Inspect / network
docker inspect zero-trust-proxy
docker network inspect zero-trust-network
```

Mount config and certs read-only:

```bash
docker run -v $(pwd)/config:/config:ro -v $(pwd)/certs:/config/certs:ro ...
```

## Log levels

- **INFO** — normal operations (startup, service registration)
- **WARN** — potential issues (health-check failures, retries)
- **ERROR** — failures (connection drops, invalid config)
- **DEBUG** — file-watch events, per-request dispatch

## Network debugging

```bash
sudo tcpdump -i any port 8443      # agent control plane
sudo tcpdump -i any port 443       # public HTTPS
strace -e network ./bin/agent --config config/agent.yaml
dig +trace app.example.com
```

## Process debugging

```bash
dlv exec ./bin/zero-trust-proxy -- run --config config/server.yaml
dlv exec ./bin/agent             -- --config config/agent.yaml
kill -SIGQUIT $(pgrep agent)       # full goroutine dump on stderr
```

## Support

- Bug reports: <https://github.com/devhatro/zero-trust-proxy/issues>
- Discussions: <https://github.com/devhatro/zero-trust-proxy/discussions>
- Docs index: [README](README.md)
