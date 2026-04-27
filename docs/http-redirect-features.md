# HTTP Redirect and Protocol Binding

The server (`zero-trust-proxy`) and the agent service-config schema
both contribute to how HTTP and HTTPS traffic is handled.

## Server-side redirect

The new server has a global HTTP→HTTPS redirector configured in
`config/server.yaml`:

```yaml
listen:
  http: ":80"
  https: ":443"
  http_redirect: true
```

Behavior:

- Any request hitting `:80` is answered with a 308 Permanent Redirect
  to `https://{host}{uri}`.
- `GET /.well-known/acme-challenge/*` is exempted and forwarded to the
  ACME HTTP-01 handler when `tls.mode == acme` — see
  `internal/server/redirect.go:newRedirectHandler`.
- If you do not want a redirect, set `http_redirect: false`. The
  `:80` listener then either serves the ACME challenge handler (acme
  mode) or returns 400 ("HTTPS only").

## Service-level fields (agent config)

The agent's per-service config still carries `http_redirect` and
`listen_on` for backwards compatibility with older tooling. The
authoritative redirect now lives at the server's listener; these
service-level flags primarily inform the agent about how the upstream
should be reached.

```yaml
services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "https"
    websocket: true
    upstreams:
      - address: "localhost:3000"
        weight: 100
```

| Field | Purpose |
|-------|---------|
| `protocol` | `http` / `https` / `ws` / `wss` — informs the agent's TLS-to-backend decision |
| `websocket` | enables WebSocket upgrade handling for this service |
| `http_redirect` | (legacy) used by previous Caddy adapter — no effect on the new server, which redirects globally |
| `listen_on` | (legacy) used by previous Caddy adapter; the new server listens on whatever you configure under `listen:` |

## Common patterns

### HTTPS-only public app

```yaml
# server: redirect everything HTTP → HTTPS
listen:
  http: ":80"
  https: ":443"
  http_redirect: true

# agent: register the service
services:
  - id: "web-app"
    hostname: "app.example.com"
    protocol: "https"
    upstreams:
      - address: "localhost:3000"
```

### HTTPS-only — no HTTP listener at all

```yaml
listen:
  http: ""
  https: ":443"
  http_redirect: false
```

Drops port 80 entirely. Clients on HTTP get connection-refused.

### HTTP-only internal service

```yaml
listen:
  http: ":80"
  https: ""
  http_redirect: false
tls:
  mode: none
```

Useful for local dev or air-gapped clusters where TLS is terminated
elsewhere. Pair with `tls.mode: none` so no certificates are required.

## Implementation reference

- `internal/server/redirect.go` — the redirect handler.
- `internal/server/server.go:Start` — wires `:80` and `:443` listeners
  to the right handler based on `http_redirect` and ACME mode.
- `internal/server/tls.go:buildTLSConfig` — produces the optional
  `acmeHandler` that the redirector forwards challenges to.
- `modules/ztrouter/handler.go` — the `:443` handler that does the
  Host → agent lookup and proxies the request.

## Troubleshooting

- **Certificate errors** on `:443` — verify the cert paths in
  `tls.manual` / `tls.sni`, or that the ACME `HostPolicy` accepts the
  hostname (a host with no registered agent is rejected — see
  `internal/server/tls.go`).
- **Port conflicts** — `:80` / `:443` need either root or
  `CAP_NET_BIND_SERVICE`. Use `--http :8080 --https :8443` for local
  dev.
- **Redirect loops** — do not put a layer-4 proxy in front of `:80`
  that already strips TLS and forwards as HTTPS.
- **WebSocket upgrade fails** — confirm the service has `websocket:
  true`. The hijack path requires HTTP/1.1 (Go's stdlib HTTP/2 server
  does not expose `Hijacker`); browsers downgrade automatically for
  the `Upgrade` request.

## Migration from the legacy Caddy server

| Legacy Caddyfile | New `config/server.yaml` |
|------------------|--------------------------|
| `:80 { redir https://{host}{uri} 308 }` | `listen.http: ":80"` + `listen.http_redirect: true` |
| `tls { on_demand }` | `tls.mode: acme` + `tls.acme.storage_dir` |
| `tls /etc/cert.pem /etc/key.pem` | `tls.mode: manual` + `tls.manual` block |
| `zerotrust_router { request_timeout 2m }` | `router.request_timeout: 2m` |

See `docs/server/replace-caddy-plan.md` for the full migration plan.
