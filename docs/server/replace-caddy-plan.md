# Plan: replace Caddy with custom `zero-trust-proxy` server

> **Status:** complete. All ten steps landed; Caddy is removed from
> `go.mod`. This doc is retained as the project history of the
> migration.

## Goal

Replace the custom-Caddy server (`cmd/caddy` + `caddy.App`/`caddyhttp.MiddlewareHandler`
shells around `modules/ztagents` and `modules/ztrouter`) with a single
purpose-built binary `zero-trust-proxy` that owns TLS termination,
HTTP/HTTPS routing, agent mTLS, and the existing handler logic. No
changes to the agent ⟷ server JSON message protocol; agent binary stays
as is.

## Current Caddy responsibilities (must be preserved)

| Capability | Caddy provides via |
|---|---|
| HTTP/1.1 + HTTP/2 listener on `:443`, `:80` redirector | `caddyhttp` standard module + `Caddyfile.example` |
| TLS termination — manual files **or** ACME on-demand | `tls { on_demand }` + `storage file_system` |
| `ask` callback for ACME issuance | `localhost:2019/zero-trust/check-domain` (served by `ztagents/admin.go`) |
| Routing the single `zerotrust_router` handler | `caddyhttp` route block |
| Module lifecycle (Provision/Validate/Start/Stop) | `caddy.App` / `caddy.Module` interfaces on `ztagents.App`, `ztrouter.Handler` |
| Caddyfile + JSON config + adapter | `caddyconfig` + `httpcaddyfile` |
| Hot reload (`caddy reload`) | Caddy admin API |
| Hijacker (WebSocket, h1 streaming download) | `caddyhttp` ResponseWriter |
| `http.Flusher` (h2 streaming, SSE) | `caddyhttp` ResponseWriter |
| Graceful shutdown | Caddy admin |
| Logger plumbing | `internal/logger` (already independent) |

## Design decisions

1. **New binary `cmd/zero-trust-proxy/`**, replacing `cmd/caddy`. Same
   build target shape as today.
2. **Pure stdlib HTTP** (`net/http` + automatic HTTP/2). HTTP/3 deferred.
3. **Two listeners by default**:
   - `:80` — redirect-only handler (308 → `https://{host}{uri}`), bypass
     for `GET /.well-known/acme-challenge/*` (proxied to autocert handler
     when ACME is on).
   - `:443` — TLS listener wrapping the `ztrouter.Handler` (now plain
     `http.Handler`).
4. **TLS modes** (config-driven, mutually exclusive):
   - `manual`: single cert pair via `tls.LoadX509KeyPair`.
   - `sni`: `map[hostname]→cert pair`, selected via `Config.GetCertificate`.
   - `acme`: wrap `golang.org/x/crypto/acme/autocert.Manager`. `HostPolicy`
     calls `ztagents.Server.LookupAgent(host)` directly — no need for the
     `:2020` HTTP shim once the proxy is in-process. Legacy `:2020`
     endpoint kept as optional for external tooling.
5. **Keep `ztagents` and `ztrouter` packages, drop Caddy interfaces**.
   `ztagents.App` becomes `ztagents.Server` (still implementing
   `LookupAgent` etc.). `ztrouter.Handler` implements `http.Handler`.
6. **Single YAML config** at `config/server.yaml`. Schema:
   ```yaml
   listen:
     http: ":80"
     https: ":443"
     http_redirect: true
   tls:
     mode: acme            # manual | sni | acme | none
     manual: { cert_file, key_file }
     sni:
       "host": { cert_file, key_file }
     acme:
       storage_dir: /config/acme
       email: ops@example.com
       ca_url: ""          # optional (override Let's Encrypt)
   agents:
     listen: ":8443"
     cert_file: ...
     key_file: ...
     ca_file: ...
     check_addr: ":2020"   # optional legacy endpoint, "" disables
   router:
     request_timeout: 2m
   logging:
     level: info
     format: console
   ```
7. **Server lifecycle** — new `internal/server/` package:
   - `Server` owns: agent mTLS server, HTTPS server, HTTP redirector,
     optional ACME manager.
   - `Start(ctx)` brings up listeners in order: agents → HTTPS → HTTP.
   - `Shutdown(ctx)` reverses with per-listener deadline.
   - SIGINT/SIGTERM → graceful shutdown. SIGHUP → reload from disk via
     `internal/common/hotreload.go`. Reload is non-disruptive for cert
     files, router timeout, log level; restart-only for listen
     addresses, TLS mode change, ACME storage path.
8. **Concurrency invariants preserved verbatim**: `Agent.writeMu`,
   `ResponseHandlers` map, `WebSocketManager` 5-min timeout,
   register-before-101.
9. **mTLS for agents stays identical**. Only the `caddy.App` shell is
   removed; the `tls.Listen` + accept loop in `ztagents/app.go` is kept
   verbatim.
10. **Drop `caddyserver/caddy/v2` from go.mod**. Add
    `golang.org/x/crypto/acme/autocert`. `gopkg.in/yaml.v3` already
    present.

## Step-by-step implementation (with status)

### Step 1 — Config schema & parser  ✅ done
- `internal/serverconfig/{config,validate,load,config_test}.go` — landed
- Round-trip parse + validate (rejects acme+manual conflict, https
  without TLS, missing agent CA, bad log level, etc.) — 16 tests pass
- Example `config/server.yaml.example` — landed

### Step 2 — Decouple `modules/ztagents` from Caddy  ✅ done (additive)
- Added `ztagents.New(cfg serverconfig.AgentsConfig) (*App, error)` that
  bypasses `caddy.Context`. The Caddy `Provision` now delegates to the
  same private `provision()` so both worlds share one code path.
- All 33 `modules/ztagents` tests pass; legacy `cmd/caddy` still
  builds.

### Step 3 — Decouple `modules/ztrouter` from Caddy  ✅ done (additive)
- Added `ztrouter.New(app, requestTimeout) *Handler` and
  `Handler.HTTPHandler() http.Handler` — a stdlib-only adapter over
  the existing 3-arg `ServeHTTP`. The legacy Caddy interface remains
  in place; both wire paths share the same body.
- `modules/ztrouter` tests pass (36).

### Step 4 — Server orchestrator  ✅ done
- `internal/server/{server,signals,reload,duration,server_test}.go`
- `Server.Start` brings up agents → HTTPS → HTTP. `Shutdown` reverses
  with idempotency. `Reload` accepts router/logging changes; rejects
  listen/TLS-mode/agents.listen changes with a clear error.
- `Run` / `RunWithConfig` wire SIGINT/SIGTERM/SIGHUP.
- 10 server tests pass (live HTTPS dial against a real listener
  asserts 503 for unknown host; reload diff is exercised both ways).

### Step 5 — TLS + ACME  ✅ done
- `internal/server/tls.go`: `manual` / `sni` / `acme` / `none`.
- Cert pointer is `atomic.Pointer[tls.Certificate]` — ready for
  SIGHUP hot-swap (the swap itself lands when reload extends to TLS).
- ACME via `golang.org/x/crypto/acme/autocert`. `HostPolicy` calls
  the agent registry directly. `HTTPHandler(nil)` is mounted on the
  HTTP listener for HTTP-01 challenges.
- 4 TLS tests pass (none, manual, sni case-insensitive + miss, acme
  HostPolicy allow/deny).

### Step 6 — HTTP → HTTPS redirector  ✅ done
- `internal/server/redirect.go`: 308 + `/.well-known/acme-challenge/*`
  bypass to the autocert handler when present.
- 3 redirect tests pass.

### Step 7 — Entrypoint  ✅ done (legacy retained)
- `cmd/zero-trust-proxy/main.go` with `run | validate | version`.
  Flags: `--config`, `--http`, `--https`. Same `Version`/`BuildTime`
  ldflags pattern as the legacy binary.
- `Makefile` has `build-server` (default) + `build-caddy` (legacy).
- `scripts/build.sh` now ships `bin/zero-trust-proxy-server-linux-*`
  built from `./cmd/zero-trust-proxy`.
- `cmd/zero-trust-proxy/Dockerfile` mirrors the legacy one.
- `cmd/caddy/` retained until Step 9.
- Smoke-tested locally: `zero-trust-proxy version` and
  `zero-trust-proxy validate --config config/server.yaml.example` both
  succeed.

### Step 8 — Configs + docs  ✅ done
- `config/server.yaml.example`, `config/server.smoke.yaml` — landed.
- `CLAUDE.md`, `docs/README.md`, `docs/server/README.md`,
  `docs/hot-reload.md`, `docs/http-redirect-features.md`,
  `docs/troubleshooting.md` — rewritten to describe the new server.
- Legacy `config/Caddyfile.example` and `config/caddy.smoke.json`
  deleted in Step 9.

### Step 9 — Drop Caddy  ✅ done
- Removed every `caddy.*` import from `modules/ztagents`,
  `modules/ztrouter`, `internal/server`. Deleted
  `modules/{ztagents,ztrouter}/caddyfile.go` and their tests.
- Converted `Handler.RequestTimeout` to `time.Duration` and switched
  `Handler.ServeHTTP` to the stdlib two-arg `http.Handler` signature
  (no error return — failures already turn into HTTP responses).
- Deleted `cmd/caddy/`, `internal/server/duration.go`, the
  `acme_client.go` carrier (rolled into `tls.go`).
- `Makefile`: only `build-server`, `build-agent`, `build-certgen`
  remain. `scripts/build.sh`: targets `./cmd/zero-trust-proxy`.
- `go mod tidy` shrank `go.mod` from 173 lines to 19 (Caddy and ~150
  transitive deps gone). Direct deps are now: `fsnotify`, `uuid`,
  `golang.org/x/crypto`, `gopkg.in/yaml.v3`.

### Step 10 — Smoke + `make sec`  ✅ done
- `go test ./...` — 492 tests pass across 13 packages.
- `make sec` — exit 0, no new HIGH findings.
- Live smoke against `config/server.smoke.yaml`:
  - HTTPS listener `:18080` returns **503 No agent for host** for an
    unknown host (router + registry path verified).
  - mTLS listener `:18443` accepts connections (closes on absent
    client cert, as expected).
  - `:12020/zero-trust/check-domain?domain=…` returns 403 for an
    unregistered domain (the in-process ACME `HostPolicy` is wired to
    the same registry).
  - Graceful shutdown on SIGTERM, no leaked goroutines.

## Cutover ordering

Steps 1–7 land additively — both binaries (`bin/caddy` and
`bin/zero-trust-proxy`) build during the transition. Step 8–9 cuts
Caddy in a single commit.

## Risks / open questions

- Confirm nothing in `ztrouter` depends on Caddy beyond stdlib
  `Hijacker`/`Flusher`. Audit so far says no — re-verify before Step 3.
- ACME `HostPolicy` is consulted before issuance — equivalent to today's
  `on_demand_tls.ask`.
- Caddy's `/config/caddy-storage` layout differs from
  `autocert.DirCache`. One-shot manual migration; do not auto-migrate.
- Hot-reloadable cert swap must use atomic pointer, never a map being
  mutated.
- HTTP/2 hijack incompatibility (`net/http` h2 doesn't expose
  `Hijacker`) — current `download.go` already has the `Flusher`
  fallback; preserved.

## Out of scope

- HTTP/3 / QUIC.
- Metrics / Prometheus exporter (separate effort).
- Per-agent TLS configs at the public listener.
- Protocol changes — agent ⟷ server JSON wire format is untouched.
