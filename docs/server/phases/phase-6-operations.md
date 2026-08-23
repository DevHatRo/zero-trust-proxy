# Phase 6 — Operations: `/metrics` Auth & Admin API

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: proposed. Observes everything the earlier phases add — land
> last. No protocol change.

## 1. Goal

Close two operational gaps:

1. The Prometheus `/metrics` endpoint is **unauthenticated** — the
   config example (`config/server.yaml.example`) literally warns "Bind
   to a private interface — there is no auth on this endpoint."
2. There is **no way to inspect live proxy state** — which agents are
   connected, what they serve, how many sessions are open, when certs
   expire.

This phase adds auth to `/metrics` and a **read-only** admin API.

## 2. Architecture

```
   ┌──────────── existing metrics listener ───────────┐
   │  metrics.addr (e.g. 127.0.0.1:9100)              │
   │  /metrics  ──▶ [auth wrapper] ──▶ promhttp        │
   └───────────────────────────────────────────────────┘

   ┌──────────── NEW admin listener ───────────────────┐
   │  admin.addr (e.g. 127.0.0.1:9200)                 │
   │  /api/agents    ─┐                                │
   │  /api/services   ├─▶ [auth wrapper] ─▶ admin mux   │
   │  /api/sessions   │     (read-only JSON)            │
   │  /api/certs      │                                 │
   │  /api/health    ─┘                                 │
   └───────────────────────────────────────────────────┘
              │
              ▼  read-only accessors
       ztagents.App  (registry, wsManager, tcpManager, certStore)
```

Both listeners are separate `http.Server`s on separate addresses, both
bound to private interfaces by default. They are **not** the public
`:443` listener and carry no proxy traffic.

## 3. Auth wrapper

A single shared helper, used by both listeners:

```go
type authConfig struct {
    Type  string // none | bearer | basic
    Token string // resolved from *_env
    User  string // basic only
}

func withAuth(cfg authConfig, next http.Handler) http.Handler
```

- `bearer` — compares `Authorization: Bearer <t>` to `cfg.Token` with
  `subtle.ConstantTimeCompare`.
- `basic` — HTTP Basic; constant-time compare on the password.
- `none` — pass-through (only sensible when the listener is on
  loopback); the validator **warns** if `type: none` is paired with a
  non-loopback bind.

Failure → `401` with `WWW-Authenticate`. The token is never logged.

## 4. Admin API

Read-only JSON. Every endpoint is `GET`; a non-`GET` returns `405`.

### 4.1 Endpoints

| Endpoint | Returns |
|----------|---------|
| `GET /api/health` | proxy self-health: uptime, started-at, version, listener states |
| `GET /api/agents` | connected agents — `id`, `Meta` (name/region/tags from Phase 0), `healthy`, `inFlight`, connected-at, protocol version |
| `GET /api/services` | per agent, the registered services (hostname, protocol, backend, timeout) |
| `GET /api/sessions` | active WebSocket and TCP sessions — count + per-session id/host/age |
| `GET /api/certs` | agent-provided certs (Phase 3) — hostname, supplying agent, `NotAfter`, days-to-expiry |

`/api/certs` is empty unless Phase 3 shipped; `/api/agents` shows
`Meta` only for agents that sent it (Phase 0). The API degrades
gracefully when an earlier phase is absent.

### 4.2 Example response — `GET /api/agents`

```json
{
  "agents": [
    {
      "id": "edge-eu",
      "meta": { "name": "EU Edge", "region": "eu", "tags": ["prod"] },
      "healthy": true,
      "in_flight": 3,
      "protocol_version": 1,
      "connected_at": "2026-05-22T09:14:02Z",
      "service_count": 7
    }
  ],
  "count": 1
}
```

### 4.3 Read-only accessors

The handlers must not reach into `ztagents` internals. `ztagents.App`
gains small read-only methods alongside the existing
`AgentCount` / `WebSocketCount` / `AgentServiceCounts`:

```go
func (a *App) AgentDetails() []AgentDetail   // id, meta, health, counts
func (a *App) ServiceList() []ServiceEntry   // agentID + ServiceConfig
func (a *App) SessionList() []SessionEntry   // ws + tcp sessions
func (a *App) CertList() []CertEntry         // Phase 3 certStore, if present
```

Each takes the relevant read lock (`registry.mu.RLock`, etc.), copies
out plain structs, and releases — no live pointers escape into the
handler, consistent with how `registry.lookupServiceByHost` already
returns a *copy* of the service config.

## 5. Configuration

```yaml
metrics:
  addr: "127.0.0.1:9100"
  auth:
    type: bearer            # none | bearer | basic
    token_env: ZTP_METRICS_TOKEN

admin:
  addr: "127.0.0.1:9200"
  auth:
    type: bearer
    token_env: ZTP_ADMIN_TOKEN
```

```go
type MetricsConfig struct {
    Addr string      `yaml:"addr,omitempty"`
    Auth AuthConfig  `yaml:"auth,omitempty"`   // NEW
}

type AdminConfig struct {                       // NEW top-level block
    Addr string     `yaml:"addr,omitempty"`
    Auth AuthConfig `yaml:"auth,omitempty"`
}

type AuthConfig struct {
    Type     string `yaml:"type"`               // none | bearer | basic
    TokenEnv string `yaml:"token_env,omitempty"`
    User     string `yaml:"user,omitempty"`
}
```

Validation: `type` ∈ {none,bearer,basic}; `bearer`/`basic` require
`token_env` to resolve; **warn** when `type: none` is paired with a
non-loopback `addr`; `admin.addr` empty → the admin API is simply not
started.

## 6. Lifecycle

The admin listener follows the **exact pattern** of the existing
metrics listener in `internal/server/server.go` (lines 179–201):

```
Server.Start:
    if admin.addr != "":
        ln := net.Listen("tcp", admin.addr)
        s.adminSr = &http.Server{
            Handler:           withAuth(adminAuth, adminMux),
            ReadHeaderTimeout: 5 * time.Second,   // ← required, see §8
        }
        go s.adminSr.Serve(ln)

Server.Shutdown:
    s.adminSr.Shutdown(ctx)   // alongside metricsSr, before agents
```

`ReadHeaderTimeout` is **mandatory** — `make sec` rule `G112` flags any
`http.Server` without it, and `server.go:169,190` already sets it on
the public and metrics servers. The admin server must match.

## 7. Agent responsibilities

None. This phase is entirely server-side and observational.

## 8. Security considerations

- **Bind private by default.** Both listeners default to `127.0.0.1`;
  the validator warns on a `0.0.0.0` bind, especially with
  `auth.type: none`.
- **Read-only.** v1 exposes no mutating endpoint. "Disconnect an
  agent", "force a reload", "evict a session" each need their own
  authorization story (roles, audit log) and are deliberately
  deferred. A mutating API is a separate, later increment.
- **Constant-time auth.** Bearer/basic comparisons use
  `subtle.ConstantTimeCompare`.
- **No secret leakage.** The admin JSON never includes tokens, keys,
  session secrets, or provider credentials — only operational state.
  `/api/certs` reports `NotAfter` and the hostname, never key material.
- `G112` — see §6.

## 9. Implementation steps

1. `serverconfig`: `AuthConfig`, `AdminConfig`, `MetricsConfig.Auth` +
   validator (incl. the loopback/`none` warning).
2. `internal/server/auth.go` (or inline in `metrics.go`): the shared
   `withAuth` wrapper.
3. `internal/server/metrics.go`: wrap the existing metrics handler
   with `withAuth`.
4. `ztagents.App`: `AgentDetails`, `ServiceList`, `SessionList`,
   `CertList` read-only accessors + their copy-out structs.
5. `internal/server/admin.go`: the admin mux, handlers, JSON encoding;
   listener lifecycle wired into `Start`/`Shutdown`.
6. Docs `docs/server/admin-api.md`.

## 10. Testing strategy

- `/metrics` → `401` with no/invalid token, `200` with a valid token.
- Each admin endpoint → `401` without auth, `200` + stable JSON shape
  with auth; `405` on non-`GET`.
- JSON shape is asserted against a golden fixture so the contract is
  stable.
- Accessors return **copies** — mutating a returned struct does not
  affect registry state (assert).
- Lifecycle: the admin listener starts, serves, and shuts down cleanly
  on SIGTERM with **no leaked goroutines** (the project's server tests
  already assert goroutine counts).
- Validator: `type: none` + `0.0.0.0` bind → warning surfaces.

## 11. Future increments (out of scope)

- Mutating endpoints (disconnect agent, trigger reload, evict
  session) with role-based authz and an audit log.
- A small HTML status dashboard served off the admin listener.
- Streaming endpoints (live request/event tail) — would need
  hijack/flush handling like the public path.
