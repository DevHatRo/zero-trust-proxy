# Hot Reload

This document describes the hot-reload system used by the agent and the
SIGHUP-based reload supported by the `zero-trust-proxy` server.

## Agent

The agent watches `config/agent.yaml` via `fsnotify` and applies
changes without restarting. Implementation lives in
`internal/common/hotreload.go`. Components opt in by implementing the
`ConfigReloader` interface.

```yaml
hot_reload:
  enabled: true
  watch_config: true
  debounce_delay: "100ms"
  graceful_timeout: "30s"
```

```bash
export ZERO_TRUST_SERVER="server.example.com:8443"
export LOG_LEVEL=DEBUG
```

The agent applies these changes online:

- add / remove / update services (`service_add`, `service_update`,
  `service_remove`)
- upstream addresses, weights, load-balancing policy
- health-check path, interval, timeout
- WebSocket toggle
- log level

Service config example:

```yaml
services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "localhost:3000"
        weight: 100
```

## Server (`zero-trust-proxy`)

The server reloads on `SIGHUP`, re-reading the YAML config file passed
via `--config` and applying changes to the running process.

```bash
kill -HUP $(pgrep zero-trust-proxy)
```

| Field | Reloadable? |
|-------|-------------|
| `router.request_timeout` | yes — applied immediately |
| `logging.level`, `logging.format` | yes |
| `tls.manual.cert_file` / `tls.manual.key_file` (file content change) | yes — atomic-pointer hot swap (planned in follow-up; current build re-reads on SIGHUP) |
| `tls.sni[*].cert_file` / `key_file` | yes (same) |
| `listen.http`, `listen.https` | **no — restart required** |
| `tls.mode` | **no — restart required** |
| `agents.listen` | **no — restart required** |
| `tls.acme.storage_dir` | **no — restart required** |

The reload path validates the new config first; if validation fails or
a restart-only field changed, the SIGHUP is logged and ignored — the
server keeps running on its current config.

### Implementation hooks

- `internal/server/signals.go` — wires SIGHUP to `Server.Reload`
- `internal/server/reload.go` — diff + apply
- `internal/serverconfig/validate.go` — validation gate

## ConfigReloader interface (agent)

```go
type ConfigReloader interface {
    ReloadConfig() error
    GetConfigPath() string
    IsHotReloadEnabled() bool
    GetComponentName() string
}
```

The shared `HotReloadManager` debounces rapid file events (default
100ms), watches both direct writes and atomic rename-style updates,
and rate-limits reload attempts to prevent storms.

## Testing

1. Start the server / agent with hot reload enabled.
2. Edit the config file (change log level, add a service).
3. For agent: changes flow automatically. For server: send SIGHUP.
4. Logs confirm the reload, including a delta of changed fields.

Example agent log output:

```
Hot reload enabled for agent: watching /config/agent.yaml for changes
Config file changed: /config/agent.yaml (event: WRITE)
Reloading configuration for agent
Configuration reloaded successfully (took 45ms)
Config changes: services 2 → 3, log_level INFO → DEBUG
```

## Troubleshooting

- **Permission errors** — the config file must be readable by the
  process owner.
- **File locking** — some editors hold an exclusive lock during write;
  the watcher retries.
- **Invalid config** — validation runs before any change is applied;
  the server logs the validation error and stays on the old config.
- **SIGHUP ignored** — almost always a restart-only field changed; the
  log line names the offending field.

Enable debug logging to see file-watcher events and validation
results:

```yaml
logging:
  level: debug
```

## Security

- Restrict permissions on the config file (`chmod 600`).
- Validate every change before applying — built-in.
- For production, monitor the access log on the config file directory
  and alert on unauthorized changes.
