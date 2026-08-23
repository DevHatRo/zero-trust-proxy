# Feature Roadmap: zero-trust-proxy

> **Status:** proposed. Nothing here is implemented yet. This document
> is the design + implementation plan for the next round of features.
> It follows the same step-by-step format as
> [replace-caddy-plan.md](replace-caddy-plan.md).
>
> Revised 2026-05-22 after an architecture review — corrected the
> middleware wrap order, the Phase 0 register/validate ordering, the
> Phase 3 cert-store concurrency model and `GetConfigForClient`
> contract, the Phase 4 ACME effort estimate, and the Phase 5 failover
> guard.

## Why this exists

Today the proxy is a solid **tunnel + reverse proxy**: mTLS agent
control plane, `Host`-based routing, WebSocket / TCP / streaming,
ACME, HTTP/3, Prometheus metrics, SIGHUP hot reload.

It is **not yet "zero trust"** in the access-control sense. Any client
that reaches `:443` with a known `Host` is proxied straight through —
there is no identity, no policy, no rate limiting. The only trust
boundary enforced today is agent↔server mTLS.

This roadmap closes that gap and adds the operational features needed
to run the proxy as a real edge product.

## Feature overview

| # | Feature | Phase | Value | Effort | Protocol change |
|---|---------|-------|-------|--------|-----------------|
| 1 | Agent identity & control-plane hardening | 0 | High | M | Yes (additive) |
| 2 | Rate limiting & WAF / firewall | 1 | High | M | No |
| 3 | Access policy layer (identity-based) | 2 | Critical | L | Optional |
| 4 | Self-managed / agent-provided certificates | 3 | High | L | Yes (new types) |
| 5 | DNS entry automation & provider integrations | 4 | Medium | L | Yes (additive) |
| 6 | Multi-agent HA & cross-agent load balancing | 5 | Medium | M | Yes (additive) |
| 7 | Operations: `/metrics` auth & admin API | 6 | Medium | S | No |

Effort: S ≈ 1–2 days, M ≈ 3–5 days, L ≈ 1–2 weeks.

Each phase has a standalone detailed-architecture document under
[`docs/server/phases/`](phases/) — component design, data model, wire
formats, sequence flows, concurrency analysis, and a test strategy:

- Phase 0 — [Agent identity & control-plane hardening](phases/phase-0-agent-identity.md)
- Phase 1 — [Rate limiting & WAF / firewall](phases/phase-1-rate-limiting-waf.md) — **implemented** (`internal/security`)
- Phase 2 — [Access policy layer](phases/phase-2-access-policy.md)
- Phase 3 — [Self-managed / agent-provided certificates](phases/phase-3-agent-certificates.md)
- Phase 4 — [DNS entry automation](phases/phase-4-dns-automation.md)
- Phase 5 — [Multi-agent HA & load balancing](phases/phase-5-multi-agent-ha.md)
- Phase 6 — [Operations: metrics auth & admin API](phases/phase-6-operations.md)

The sections below are the consolidated summary; the per-phase docs
are the implementation reference.

Phases are ordered by dependency, not just value. Each phase is
independently shippable. The hard dependency edges:

- **Phase 0 first.** Phases 3, 4, 5 add new message types / struct
  fields. Phase 0 introduces protocol versioning + the per-agent
  hostname ACL that Phases 3–5 all reuse.
- Phases 1, 2, 6, 7 have no hard dependency on each other and can be
  reordered freely.
- Phase 3 (agent certs) and Phase 4 (DNS-01 ACME) both touch
  `internal/server/tls.go`; doing 3 before 4 avoids a merge conflict
  in the `GetCertificate` path.
- Phase 4 (DNS reconciliation) and Phase 5 (registry host-index) both
  wrap the same `service_add` / `service_remove` block in
  `modules/ztagents/handle.go`. Not a hard ordering constraint, but
  whichever lands second must rebase that handler carefully.

---

## Cross-cutting conventions

These apply to every phase. Decide them once.

1. **Protocol versioning.** Phase 0 adds a `protocol_version` integer
   to the `register` message. The server rejects agents whose version
   it cannot serve with an explicit `register_response` error. Every
   later phase that adds a message type bumps the constant and gates
   the feature on the negotiated version, so a new server stays
   compatible with an old agent (feature simply off) and vice versa.

2. **Secrets are never inline in YAML.** Provider credentials, session
   keys, auth tokens are referenced by environment-variable name, e.g.
   `token_env: ZTP_CF_TOKEN`. The loader resolves `*_env` fields at
   startup. `validate` fails if a referenced env var is unset. This
   keeps `make sec` clean and configs commit-safe.

3. **Config additions are additive + defaulted.** Every new block is
   optional; omitting it preserves today's behaviour exactly. `serverconfig.Defaults()`
   and `internal/serverconfig/validate.go` are extended in lockstep.

4. **Hot reload classification.** Each new config block is tagged in
   `internal/server/reload.go` as either hot-reloadable (SIGHUP applies
   it: policy rules, WAF rules, rate limits, DNS records) or
   restart-only (new listeners, listen addresses). See
   [docs/hot-reload.md](../hot-reload.md).

5. **Every phase ships:** config schema + validator + `server.yaml.example`
   update, unit tests per new package, a docs page under `docs/`, and a
   clean `make sec` run (no new HIGH findings).

6. **Middleware composition.** New request-path features are
   `http.Handler` middlewares composed in `internal/server/server.go`
   around `s.router`. Today's chain, outermost first, is
   `altSvc → accessLog → metrics → router`. Note the **code applies
   wrappers inner-to-outer** (`server.go:108-124`): `s.router` is
   wrapped by `metricsMiddleware`, then `accessLogMiddleware`, then
   `altSvcMiddleware` — so the wrapper applied *last* becomes the
   *outermost*. Target order, outermost first:

   ```
   accessLog → metrics → WAF → rateLimit → accessPolicy → altSvc → router
   ```

   To achieve that, the wrappers must be *applied* in the reverse
   order: `router → altSvc → accessPolicy → rateLimit → WAF →
   metrics → accessLog`. Cheap rejects (WAF deny, rate-limit 429) run
   before expensive work (auth, agent dispatch).

---

## Protocol changes — consolidated

All wire-protocol changes across the roadmap, in one place. The
envelope is `common.Message` in `internal/common/message.go`.

New fields on `Message`:

| Field | JSON | Added by | Purpose |
|-------|------|----------|---------|
| `Version` | `version,omitempty` | Phase 0 | protocol version (in `register`) |
| `Meta` | `meta,omitempty` | Phase 0 | agent name/region/tags (in `register`) |
| `Cert` | `cert,omitempty` | Phase 4 | agent-provided edge certificate |

New message `Type` values:

| Type | Added by | Direction |
|------|----------|-----------|
| `cert_add` / `cert_add_response` | Phase 4 | agent → server |
| `cert_update` / `cert_update_response` | Phase 4 | agent → server |
| `cert_remove` / `cert_remove_response` | Phase 4 | agent → server |

New fields on `types.ServiceConfig` (`internal/types/service.go`) —
all `omitempty`, so old agents simply omit them:

| Field | Added by | Purpose |
|-------|----------|---------|
| `Weight` | Phase 6 | cross-agent load-balancing weight |
| `PolicyRef` | Phase 3 | name of a server-defined access policy |
| `DNS` | Phase 5 | desired DNS record hints |

No existing field changes meaning. No message is removed. An old
agent against a new server, or vice versa, keeps working — the
feature is simply inactive.

---

# Phase 0 — Agent identity & control-plane hardening

### Goal

Today an agent presents a valid client cert, then sends `register`
with an **arbitrary** `ID`. The server trusts that ID and afterwards
lets the agent claim **any** hostname via `service_add`. A single
compromised or misconfigured agent can hijack another tenant's
hostname. There is also no protocol-version negotiation, so the
later phases would break old agents silently.

This phase makes agent identity verifiable and scoped.

### Configuration

Server `config/server.yaml`, extended `agents:` block:

```yaml
agents:
  listen: ":8443"
  cert_file: /config/certs/server.crt
  key_file:  /config/certs/server.key
  ca_file:   /config/certs/ca.crt

  # NEW — bind the register ID to the client cert.
  identity:
    # Where the agent ID must appear in the presented client cert.
    # cn  → cert Subject CommonName
    # san → a DNS SAN entry
    bind_to: cn            # cn | san | none (none = legacy, unverified)

  # NEW — per-agent hostname allow-list. An agent may only register
  # services for hostnames matching one of its patterns. Glob syntax.
  # An agent absent from this list is rejected unless allow_unlisted.
  acl:
    allow_unlisted: false
    agents:
      - id: "synology"
        allowed_hosts:
          - "*.local.example.com"
      - id: "edge-eu"
        allowed_hosts:
          - "*.eu.example.com"
          - "status.example.com"

  # NEW — certificate revocation. Either a CRL file or an inline
  # serial-number denylist; checked at TLS handshake.
  revocation:
    crl_file: /config/certs/revoked.crl   # optional
    denied_serials:                        # optional
      - "0A1B2C3D"
```

Agent `config/agent.yaml` — no new required fields. The agent already
carries `agent.id`, `agent.name`, `agent.region`, `agent.tags`; this
phase starts actually **sending** name/region/tags so the admin API
(Phase 7) can display them.

### Agent responsibilities

- In `Agent.Connect()` (`internal/agent/agent.go`), include in the
  `register` message: `Version` (the compiled `common.ProtocolVersion`
  constant) and `Meta` (name, region, tags from `AgentSettings`).
- The agent's `agent.id` **must** match its client cert per the
  server's `bind_to` setting — document this; `certgen` should stamp
  the CN with the agent ID.
- Handle a `register_response` carrying an `Error` (version too old,
  identity mismatch, revoked) by logging clearly and exiting non-zero
  rather than retrying forever.

### Server responsibilities

- **Handshake identity check** — `modules/ztagents/handle.go`,
  `handleAgentConnection`: after the connection is accepted, read
  `conn.(*tls.Conn).ConnectionState().PeerCertificates[0]`. When the
  first message (`register`) arrives, verify `msg.ID` against the cert
  per `identity.bind_to`. Mismatch → send `register_response{Error}`,
  close.
- **Validate before registering — ordering bug to fix.** Today
  `handleAgentConnection` calls `a.rt.registry.add(agent)`
  (`handle.go:35-36`) *before* doing any validation, then sends the
  ack. The identity, protocol-version, and ACL-membership checks must
  all run and pass **before** `registry.add` — otherwise an
  unverified agent is briefly live in the registry and routable. Fix:
  validate first, `registry.add` only on success.
- **Protocol version** — reject `msg.Version` outside the supported
  range with a clear `register_response` error.
- **Hostname ACL** — in `handleAgentMessage`, `service_add` /
  `service_update`: reject a hostname the agent's ACL entry does not
  cover. Send `service_add_response{Error}`. Load the ACL into
  `runtime` at provision time; compile globs once.
- **Revocation** — wire `tls.Config.VerifyPeerCertificate` (in
  `loadTLSConfig`, `modules/ztagents/app.go`) to reject certs whose
  serial is in `denied_serials` or the CRL.
- Store `Meta` on the in-memory `Agent` struct for the admin API.

### Protocol changes

Additive: `Version int` and `Meta *AgentMeta` on `common.Message`,
populated only in `register`. New `common.ProtocolVersion` constant.
`AgentMeta{ Name, Region string; Tags []string }`.

### Implementation steps

1. Add `ProtocolVersion` constant + `Version` / `Meta` fields +
   `AgentMeta` type to `internal/common/message.go`. Unit-test
   round-trip JSON.
2. Extend `serverconfig`: `IdentityConfig`, `ACLConfig`,
   `RevocationConfig` structs + `Defaults()` + `validate.go` (reject
   unknown `bind_to`, malformed globs, unreadable CRL).
3. `modules/ztagents`: load ACL + revocation into `runtime`; add a
   `peerIdentity()` helper; enforce in `handleAgentConnection` and
   `handleAgentMessage`. Reorder `handleAgentConnection` so identity +
   version + ACL checks run *before* `registry.add`.
4. `internal/agent/agent.go`: send `Version` + `Meta` in `register`;
   handle error `register_response`.
5. Update `cmd/certgen` docs / output so the agent cert CN carries the
   agent ID.
6. Docs: `docs/server/agent-identity.md`. Update `CLAUDE.md` message
   protocol section.

### Files touched

`internal/common/message.go`, `internal/serverconfig/{config,validate,load}.go`,
`modules/ztagents/{app,handle,agent}.go`, `internal/agent/agent.go`,
`cmd/certgen/*`, `config/server.yaml.example`.

### Tests

- ACL: agent allowed host → accepted; disallowed → `service_add`
  rejected with error.
- Identity: register ID ≠ cert CN → connection rejected.
- Version: out-of-range version → `register_response` error.
- Revocation: denied serial → handshake fails.
- Back-compat: `bind_to: none` + `allow_unlisted: true` reproduces
  today's behaviour.

### Risks / open questions

- **Existing fleets.** Agents whose cert CN ≠ agent ID break under
  `bind_to: cn`. Mitigation: ship with `bind_to: none` default; flip
  to `cn` is an opt-in, documented breaking change. Provide a
  `bind_to: san` escape hatch.
- CRL parsing/rotation: start with the inline `denied_serials` list;
  treat `crl_file` as a fast follow if it complicates the phase.

---

# Phase 1 — Rate limiting & WAF / firewall

### Goal

Give the edge cheap, pre-auth abuse protection: per-IP / per-host
rate limits and a basic request firewall (IP allow/deny, header and
path rules, request-size caps). Runs **before** the access-policy
layer so floods are rejected without touching identity code.

### Configuration

Server `config/server.yaml`, new `security:` block:

```yaml
security:
  rate_limit:
    enabled: true
    # Default bucket applied to every request.
    default:
      key: ip               # ip | host | ip+host | identity
      rate: 100/s           # tokens per second
      burst: 200
    # Per-host overrides; first hostname-glob match wins.
    overrides:
      - hosts: ["api.example.com"]
        key: ip
        rate: 20/s
        burst: 40

  firewall:
    enabled: true
    # Evaluated top-down, first match wins; default is allow.
    rules:
      - name: "block-known-scanners"
        action: deny          # deny | allow
        when:
          paths: ["/.env", "/.git/*", "/wp-admin/*"]
      - name: "office-only-admin"
        action: allow
        when:
          hosts: ["admin.example.com"]
          source_cidrs: ["203.0.113.0/24"]
      - name: "deny-other-admin"
        action: deny
        when:
          hosts: ["admin.example.com"]
    max_request_bytes: 33554432   # 32 MiB; 0 = unlimited
```

Agent: none. This is a pure server / edge concern.

### Agent responsibilities

None.

### Server responsibilities

- New package `internal/security`:
  - `ratelimit.go` — sharded token-bucket limiter keyed per
    `default.key`. In-memory; sharded `map` + periodic TTL eviction of
    idle buckets to bound memory. Exposes `Allow(key) bool`.
  - `firewall.go` — compiled rule list; `Decision(r *http.Request)`
    returns allow/deny. Glob match on host/path, CIDR match on source.
  - `middleware.go` — two `http.Handler` wrappers: WAF (deny → 403,
    oversize → 413) and rate-limit (→ 429 with `Retry-After`).
- Wire both into the middleware chain in `internal/server/server.go`,
  outermost-but-after-logging (see cross-cutting order).
- Source IP comes from `r.RemoteAddr` — the proxy is the TLS
  termination point, so client-supplied `X-Forwarded-For` is **not**
  trusted here (consistent with `setForwardedHeaders` in
  `modules/ztrouter/handler.go`).
- Metrics: `ztp_ratelimit_rejected_total`, `ztp_firewall_denied_total`
  (labelled by rule name) in `internal/server/metrics.go`.
- SIGHUP hot-reloads rules and limits (no listener change).

### Protocol changes

None.

### Implementation steps

1. `serverconfig`: `SecurityConfig` / `RateLimitConfig` /
   `FirewallConfig` + a `rate` parser (`"100/s"`, `"60/m"`) + validator
   (reject bad CIDRs, bad globs, unknown `key`/`action`).
2. `internal/security/ratelimit.go` + tests (burst, refill, eviction,
   concurrency under `-race`).
3. `internal/security/firewall.go` + tests (rule precedence, CIDR,
   glob, size cap).
4. `internal/security/middleware.go`; wire in `server.go`; add metrics.
5. `reload.go`: classify `security:` as hot-reloadable.
6. Docs: `docs/server/rate-limiting-firewall.md`.

### Files touched

`internal/serverconfig/*`, new `internal/security/*`,
`internal/server/{server,reload,metrics}.go`, `config/server.yaml.example`.

### Tests

Limiter math under `-race`; firewall rule precedence; middleware
returns 403/413/429 with correct headers; hot reload swaps rules
without dropping connections.

### Risks / open questions

- **Single-instance only.** In-memory buckets do not coordinate across
  multiple proxy instances. Documented limitation for v1; a shared
  backend (Redis) is a later option — design `ratelimit.go` behind a
  `Limiter` interface so the backend is swappable.
- Memory growth under IP churn — bounded by TTL eviction; pick a
  conservative idle TTL (e.g. 10 min) and cap shard count.

---

# Phase 2 — Access policy layer

### Goal

The headline zero-trust feature: an **identity-based access decision
on every inbound request**, before it is dispatched to an agent.
Cloudflare-Access-style. Supports machine identity (service tokens)
and human identity (OIDC / SSO), evaluated against a rule set.

### Configuration

Server `config/server.yaml`, new `access:` block:

```yaml
access:
  enabled: true

  # Signs the session cookie. Referenced by env var, never inline.
  session:
    secret_env: ZTP_SESSION_SECRET   # >=32 bytes
    cookie_name: ztp_session
    ttl: 8h

  # Machine identity. Tokens are stored hashed; presented by clients
  # in the Authorization: Bearer header or X-ZTP-Token.
  service_tokens:
    - name: ci-deploy
      hash: "sha256:9f86d0818..."     # sha256 of the token
      groups: ["ci"]

  # Human identity via OIDC. Zero or more providers.
  identity_providers:
    - name: google
      type: oidc
      issuer: https://accounts.google.com
      client_id_env: ZTP_GOOGLE_CLIENT_ID
      client_secret_env: ZTP_GOOGLE_CLIENT_SECRET
      scopes: ["openid", "email", "profile"]

  # Rules evaluated top-down, first match wins. No match → default_action.
  default_action: deny
  rules:
    - name: "public-marketing-site"
      when: { hosts: ["www.example.com"] }
      action: allow                     # no auth required

    - name: "ci-uploads-api"
      when: { hosts: ["api.example.com"], paths: ["/upload/*"] }
      action: allow
      require: { groups: ["ci"] }        # service token in group ci

    - name: "internal-apps"
      when: { hosts: ["*.internal.example.com"] }
      action: allow
      require:
        identity_provider: google
        emails_domain: ["example.com"]   # any @example.com user
```

Optional per-service hint (Phase 0 ACL already proves the agent owns
the host). Agent `config/agent.yaml`, per service:

```yaml
services:
  - id: dashboard
    hosts: ["dash.example.com"]
    access_policy: internal-apps        # names a server-defined rule
```

This pushes a `PolicyRef` in `service_add`. The server honours it
**only** if `access.allow_agent_policy: true`; otherwise server-side
`rules` are authoritative. Default: server-authoritative.

### Agent responsibilities

- Enforcement: **none**. The agent is on the customer network and is
  the less-trusted side; access decisions stay at the proxy.
- Optionally forward a `PolicyRef` string from `services[].access_policy`
  in the `service_add` message — a convenience so operators can
  co-locate the policy name with the service.

### Server responsibilities

Everything. New package `internal/policy`:

- `engine.go` — compiled rule set; `Evaluate(req, identity) Decision`.
- `rule.go` — rule schema, host/path glob + method matching, `require`
  predicate evaluation (groups, emails, email domains, IP CIDRs).
- `token.go` — service-token verification (constant-time hash compare).
- `session.go` — signed session cookie (JWT or HMAC); issue / verify /
  refresh / clear.
- `oidc.go` — OIDC discovery, the auth-code flow, JWKS fetch + cache,
  ID-token validation. Generic OIDC covers Google, Okta, Azure AD,
  Auth0, Keycloak.
- `middleware.go` — the `http.Handler`:
  1. Resolve identity: valid session cookie, else service token, else
     anonymous.
  2. `engine.Evaluate`. `allow` → next handler. `deny` → 403.
     `require auth` + anonymous browser request → 302 to the IdP.
  3. Reserve a `/.ztp/` path namespace on the public listener for
     `/.ztp/oauth/callback`, `/.ztp/logout`. `ztrouter` must treat
     `/.ztp/*` as proxy-owned and never dispatch it to an agent.

- Wire the middleware into the chain in `server.go` after rate-limit,
  before the router.
- Metrics: `ztp_access_allowed_total`, `ztp_access_denied_total`,
  `ztp_access_auth_redirect_total`.
- SIGHUP hot-reloads `rules`, `service_tokens`; provider / session
  changes are restart-only (live sessions depend on the secret).

### Protocol changes

Optional: `PolicyRef string` on `types.ServiceConfig` (additive,
`omitempty`). Only consulted when `access.allow_agent_policy: true`.

### Implementation steps

1. **2a — engine + service tokens.** `internal/policy/{engine,rule,token}.go`.
   No external IdP yet — `require` supports `authenticated` +
   `groups`, identity comes from service tokens only. Middleware
   wired, returns 403 on deny. Fully unit-testable offline.
2. **2b — sessions.** `session.go`: signed cookie issue/verify.
   `default_action` + `allow` (no-auth) rules.
3. **2c — OIDC.** `oidc.go`: discovery, auth-code flow, JWKS cache,
   `/.ztp/oauth/callback`. `ztrouter` reserves `/.ztp/*`.
4. **2d — predicates.** `emails`, `emails_domain`, `source_cidrs`,
   per-provider routing.
5. `serverconfig`: `AccessConfig` + nested structs + validator
   (env-var presence, rule references, glob syntax).
6. Reconcile with the **dormant agent-side structs**
   `SecurityConfig` / `AuthConfig` / `CORSConfig` in
   `internal/agent/config.go` — Caddy-era leftovers. Audit whether
   they are enforced anywhere; either wire CORS into this phase or
   delete them so there is one access model, not two.
7. Docs: `docs/server/access-policy.md`.

### Files touched

New `internal/policy/*`, `internal/serverconfig/*`,
`internal/server/{server,reload,metrics}.go`, `modules/ztrouter/handler.go`
(reserve `/.ztp/*`), `internal/types/service.go` (`PolicyRef`),
`internal/agent/{config,agent}.go` (forward `access_policy`),
`config/server.yaml.example`.

### Tests

Rule precedence + default action; service-token allow/deny + group
match; session cookie tamper rejection; OIDC flow against a mock IdP
(discovery + JWKS + callback); `/.ztp/*` never reaches the router;
constant-time token compare.

### Risks / open questions

- **OIDC is the heavy part.** Decide: hand-rolled (`crypto/...` +
  `encoding/json`, zero deps, matches the project's lean `go.mod`) vs.
  `coreos/go-oidc` (battle-tested, +deps). Recommendation: hand-roll
  discovery + JWKS; it is ~300 lines and keeps `go.mod` lean. Flag for
  decision.
- Session secret rotation invalidates all sessions — acceptable;
  document it.
- Per-request cost: glob + map lookups, O(rules). JWKS cached. Add a
  small positive-decision cache keyed by (identity, host, path-prefix)
  only if profiling shows a need — do not build it speculatively.
- **Decision needed:** is policy ever defined per-service by the agent
  operator, or always server-side? Recommendation: server-side
  authoritative, `allow_agent_policy` off by default.

---

# Phase 3 — Self-managed / agent-provided certificates

### Goal

Today the public-facing certificate comes only from the server
(`manual` / `sni` / `acme`). Some operators want to **manage their own
edge certificate on the agent side** — their own CA, their own ACME,
or a corporate PKI — and have the agent **push that certificate to the
server** over the existing mTLS channel. Optionally the same mechanism
configures **mTLS at the public edge** for that hostname (require a
client cert from end users), feeding verified client identity into the
Phase 2 access policy.

### Configuration

Server `config/server.yaml` — accept agent-provided certs:

```yaml
tls:
  mode: sni                    # existing modes still apply as fallback
  # NEW
  allow_agent_certs: true      # accept cert_add from agents
  persist_agent_keys: false    # keep agent-pushed keys in memory only
```

Agent `config/agent.yaml`, new per-service `edge_tls:` block (distinct
from the existing `tls:` block, which configures the *backend* leg):

```yaml
services:
  - id: dashboard
    hosts: ["dash.example.com"]
    upstreams: [{ address: "http://127.0.0.1:3000" }]

    edge_tls:
      mode: provide            # provide | none
      cert_file: /certs/dash.crt
      key_file:  /certs/dash.key
      auto_reload: true        # re-push when the files change on disk

      # Optional: require client certs from END USERS for this host.
      client_auth: require     # none | request | require
      client_ca_file: /certs/users-ca.crt
```

### Agent responsibilities

- On startup and on `service_add`, if `edge_tls.mode: provide`, read
  the cert + key (and optional client CA), and send a `cert_add`
  message carrying `{ hostname, cert_pem, key_pem, client_ca_pem,
  client_auth }`.
- The agent obtains the cert however it likes — static files, its own
  ACME client, corporate PKI, self-signed for dev. All of that is
  transparent to the server.
- With `auto_reload: true`, watch the cert files (the agent already
  has file-watch infrastructure in `internal/common/hotreload.go`) and
  send `cert_update` on change — this is the rotation path.
- On service removal / shutdown, send `cert_remove`.

### Server responsibilities

- New cert store — `modules/ztagents/certstore.go` (or
  `internal/server`): `map[hostname] → atomic.Pointer[agentCert]`,
  where `agentCert` bundles the parsed `tls.Certificate`, optional
  client-CA pool, and `client_auth` mode. The `atomic.Pointer` makes
  *updating an entry* lock-free, but the **map itself** is read by
  `GetCertificate` / `GetConfigForClient` on every TLS handshake while
  `cert_add` / `cert_remove` mutate it — guard the map with a
  `sync.RWMutex`, or swap the whole map atomically via a single
  `atomic.Pointer[map[string]*agentCert]`. Never mutate a map a TLS
  closure reads concurrently.
- Handle `cert_add` / `cert_update` / `cert_remove` in
  `handleAgentMessage`. On add/update **validate**:
  - cert + key parse and pair correctly;
  - a SAN covers the hostname;
  - cert is not expired;
  - **the hostname is within the agent's Phase 0 ACL** — an agent may
    only supply certs for hostnames it is allowed to serve.
  Reject with `cert_add_response{Error}` on any failure.
- `internal/server/tls.go`: the public listener's `GetCertificate`
  closure consults the agent cert store **first**, then falls back to
  manual / sni / acme. Hot-swap is the `atomic.Pointer` store.
- **Per-SNI client auth.** `ClientAuth` is a per-`tls.Config` field, not
  per-certificate, so requiring client certs for one hostname needs
  `tls.Config.GetConfigForClient`. It must return a **clone of the
  whole** `bundle.tlsConfig` (`tlsConfig.Clone()`), then override only
  `ClientAuth` + `ClientCAs` from the agent cert entry for
  `ClientHelloInfo.ServerName`. A bare config carrying only
  `ClientCAs` would drop `GetCertificate`, `MinVersion`, and the
  ALPN / `NextProtos` setup — breaking cert selection and HTTP/2 for
  that host. When a client cert is verified, stash the identity on a
  **new field of `common.RequestInfo`** — `internal/common/reqctx.go`
  today carries only `AgentID` — so the Phase 2 policy engine can
  match on it.
- Never write agent-pushed keys to disk unless `persist_agent_keys:
  true`. Default in-memory only.
- Metrics: `ztp_agent_certs` gauge; `ztp_agent_cert_expiry_seconds`
  per hostname.

### Protocol changes

**New** message types `cert_add` / `cert_update` / `cert_remove` (+
`_response`). **New** `Cert *CertData` field on `common.Message`:

```go
type CertData struct {
    Hostname    string `json:"hostname"`
    CertPEM     []byte `json:"cert_pem"`
    KeyPEM      []byte `json:"key_pem"`
    ClientCAPEM []byte `json:"client_ca_pem,omitempty"`
    ClientAuth  string `json:"client_auth,omitempty"` // none|request|require
}
```

Gated on the Phase 0 protocol version.

### Implementation steps

1. `internal/common/message.go`: `CertData` + `Cert` field +
   `cert_*` type constants; bump `ProtocolVersion`.
2. `modules/ztagents/certstore.go`: store + validation helpers + tests.
3. `modules/ztagents/handle.go`: handle `cert_*`; enforce ACL; emit
   `_response`.
4. `internal/server/tls.go`: `GetCertificate` consults the store;
   `GetConfigForClient` for per-SNI client auth.
5. `internal/common/reqctx.go`: carry verified client-cert identity.
6. `internal/agent/config.go`: `EdgeTLSConfig` struct.
7. `internal/agent/agent.go`: read cert files, push `cert_add`, watch
   + `cert_update`, `cert_remove` on teardown.
8. `serverconfig` + validator: `allow_agent_certs`, `persist_agent_keys`.
9. Docs: `docs/server/agent-certificates.md`.

### Files touched

`internal/common/{message,reqctx}.go`, `modules/ztagents/{handle,app}.go`
+ new `certstore.go`, `internal/server/tls.go`,
`internal/serverconfig/*`, `internal/agent/{config,agent}.go`,
`config/{server,agent}.yaml.example`.

### Tests

cert/key pair validation; SAN-covers-hostname; expired-cert reject;
ACL reject (agent supplies a cert for a host it does not own); SNI
selection prefers the agent cert; `GetConfigForClient` enforces
`require` and rejects a missing client cert; rotation via
`cert_update` hot-swaps without dropping connections; key never
touches disk when `persist_agent_keys: false`.

### Risks / open questions

- **Private keys cross the wire.** Mitigated: the mTLS channel is
  already encrypted and authenticated; ACL scopes which hostnames an
  agent may supply. Still — call it out in the security review and in
  `docs/`. Keep `persist_agent_keys` off by default.
- `GetConfigForClient` runs per handshake — keep it a cheap map
  lookup. Pre-build the cloned-and-overridden `tls.Config` per host
  *when the cert is stored*, not per connection; no PEM parsing on the
  hot path.
- **`cert_*` messages share the single agent connection.** The server
  reads agent messages with one serial `decoder.Decode` loop
  (`handle.go:46-59`); a multi-KB cert blob briefly blocks request
  multiplexing on that connection while it decodes. Acceptable —
  certs are small and pushed rarely — but keep `CertData` lean and do
  not pad the chain beyond what is needed.
- Interaction with `mode: acme`: if a hostname has both an
  agent-provided cert and ACME, the agent cert wins (it is checked
  first). Document the precedence: **agent → sni → manual → acme**.
- `make sec` `G402` exemption is for the agent→backend leg; this
  feature does not change that — the security-auditor should confirm.

---

# Phase 4 — DNS entry automation & provider integrations

### Goal

Two related capabilities, both driven by registered services:

1. **Record management** — when a service registers, automatically
   create / update the public DNS record (`A` / `AAAA` / `CNAME`)
   pointing the hostname at the proxy; delete it on service removal.
2. **DNS-01 ACME** — solve the ACME DNS-01 challenge via the provider
   API, which unlocks **wildcard certificates** and certificate
   issuance without exposing port 80.

Supported providers behind one interface: **Cloudflare** and **AWS
Route 53** first (most common), then **Google Cloud DNS**,
**DigitalOcean**, **Azure DNS**.

### Configuration

Server `config/server.yaml`, new `dns:` block:

```yaml
dns:
  enabled: true
  # The value records should resolve to. Auto-detected if omitted.
  public_address: "203.0.113.10"      # or a CNAME target hostname

  providers:
    - name: cf-main
      type: cloudflare
      token_env: ZTP_CF_TOKEN
      zones: ["example.com"]

    - name: aws-eu
      type: route53
      access_key_env: ZTP_AWS_KEY
      secret_key_env: ZTP_AWS_SECRET
      zones: ["eu.example.com"]

  # Record management on service_add / service_remove.
  manage_records: true
  record_ttl: 300

  # Use DNS-01 for ACME (enables wildcards). Requires tls.mode: acme.
  acme_challenge: dns-01              # http-01 | dns-01
```

Agent `config/agent.yaml`, optional per-service hint:

```yaml
services:
  - id: dashboard
    hosts: ["dash.example.com"]
    dns:
      record_type: A          # A | AAAA | CNAME
      proxied: false          # Cloudflare orange-cloud toggle
      target: ""              # override public_address for this host
```

### Agent responsibilities

- Enforcement / API calls: **none**. The agent does not hold DNS
  credentials and does not know the proxy's public IP.
- Optionally forward a `DNS` hint (`record_type`, `proxied`, `target`)
  in `service_add` so the operator can express intent next to the
  service. The server decides whether to honour it.

### Server responsibilities

- New package `internal/dns`:
  - `provider.go` — the interface:
    ```go
    type Provider interface {
        UpsertRecord(ctx, zone, name, rtype, value string, ttl int) error
        DeleteRecord(ctx, zone, name, rtype string) error
        UpsertTXT(ctx, zone, name, value string) error   // ACME DNS-01
        DeleteTXT(ctx, zone, name string) error
    }
    ```
  - `cloudflare.go`, `route53.go`, `gcloud.go`, `digitalocean.go`,
    `azure.go` — one file per provider.
  - `manager.go` — zone→provider routing (longest-suffix match), record
    reconciliation, retry/backoff.
- Hook reconciliation into `service_add` / `service_remove` handling in
  `modules/ztagents` (or react to registry change events). On add:
  upsert the record; on remove: delete it. Reconciliation is
  best-effort and async — a DNS failure must **not** block service
  registration; log + metric instead.
- **DNS-01 ACME.** `golang.org/x/crypto/acme/autocert` does not expose
  a DNS-01 hook. This phase must either drop to the lower-level
  `golang.org/x/crypto/acme` client and drive the order manually, or
  adopt `go-acme/lego`. This is the single biggest design decision in
  the phase — see Risks.
- Auto-detect `public_address` when omitted (outbound IP probe), but
  prefer explicit config.
- Metrics: `ztp_dns_records_managed`, `ztp_dns_sync_errors_total`
  (labelled by provider).

### Protocol changes

Optional `DNS *DNSHint` on `types.ServiceConfig` (additive).

### Implementation steps

1. **4a — interface + two providers.** `internal/dns/provider.go` +
   `cloudflare.go` + `route53.go` + `manager.go` (zone routing).
   Unit-test against recorded API fixtures.
2. **4b — record reconciliation.** Hook `service_add` / `service_remove`;
   async best-effort upsert/delete; metrics.
3. **4c — DNS-01 ACME.** Integrate the chosen ACME path with
   `UpsertTXT` / `DeleteTXT`; wildcard support; `internal/server/tls.go`.
4. **4d — remaining providers.** `gcloud.go`, `digitalocean.go`,
   `azure.go`.
5. `serverconfig`: `DNSConfig` + validator (env-var presence, known
   provider types, zones non-empty).
6. Docs: `docs/server/dns-automation.md` with a per-provider
   credential-scope table (least-privilege token examples).

### Files touched

New `internal/dns/*`, `internal/serverconfig/*`,
`internal/server/tls.go`, `modules/ztagents/handle.go` (or a registry
event hook), `internal/types/service.go`, `config/{server,agent}.yaml.example`.

### Tests

Per-provider client against recorded fixtures (no live API in CI);
zone longest-suffix routing; reconciliation idempotency (upsert twice
= one record); DNS failure does not block `service_add`; DNS-01
issues a cert against the ACME staging directory or Pebble.

### Risks / open questions

- **ACME library choice.** `autocert` cannot do DNS-01. Hand-rolling
  on `x/crypto/acme` keeps `go.mod` lean but is **more work than just
  "TXT records"**: `autocert.Manager` today also provides automatic
  renewal scheduling, the on-disk cert cache (`autocert.DirCache`),
  and OCSP stapling for free. Driving `x/crypto/acme` directly means
  reimplementing the renewal timer, a cert cache, and the
  order/authz/polling/CSR handling. Treat this as the upper end of the
  `L` estimate. `go-acme/lego` is turnkey but a large dependency and
  ships its own provider set that overlaps `internal/dns`.
  **Recommendation:** drive `x/crypto/acme` directly and reuse
  `internal/dns` providers for the TXT records — one provider
  abstraction, lean deps — but explicitly budget for rebuilding the
  renewal + cache layer `autocert` gave us. Flag for decision before 4c.
- **Credentials.** Provider API tokens are powerful. Enforce env-var
  references; document least-privilege scopes (e.g. Cloudflare token
  limited to `DNS:Edit` on the specific zone).
- **Ownership.** Record management assumes the proxy owns the zone.
  Guard with explicit `zones:` config; never touch a record outside a
  configured zone.
- **Decision needed:** should DNS run server-side (recommended — the
  server knows its public IP and holds creds centrally) or could an
  agent that owns its domain do it? Recommendation: server-side; the
  agent only sends a hint.

---

# Phase 5 — Multi-agent HA & cross-agent load balancing

### Goal

Today `registry.lookupServiceByHost` returns the **first** agent that
has the host — if two agents register the same hostname the winner is
nondeterministic, and there is no failover. This phase makes the same
hostname servable by N agents with health-aware load balancing and
failover.

> Note: this is **cross-agent** balancing. The agent already does
> **upstream** balancing within a service (`LoadBalancingConfig` in
> `internal/agent/config.go`) — that is a separate, lower layer and is
> unchanged.

### Configuration

Server `config/server.yaml`, extended `router:` block:

```yaml
router:
  request_timeout: 2m
  # NEW
  balancing: round_robin       # round_robin | random | least_conn
  health:
    ping_interval: 15s
    max_missed_pongs: 3        # mark agent unhealthy, skip it
  failover:
    enabled: true
    max_attempts: 2            # retry on the next healthy agent
```

Agent: optional `weight` per service for weighted balancing.

### Agent responsibilities

- To run hot/hot, simply register the **same hostname from multiple
  agents** — no new behaviour required.
- Optionally send a `Weight` in `service_add` (weighted balancing).
- Keep answering server-initiated `ping` with `pong` (the `ping` /
  `pong` types already exist; only the *server-initiated* direction is
  new).

### Server responsibilities

- **Registry index.** `modules/ztagents/registry.go`: add a secondary
  index `map[host] → []*Agent`, maintained on `service_add` /
  `service_remove` / agent disconnect. `lookupServiceByHost` becomes
  `pickAgent(host)` applying `router.balancing` over the **healthy**
  agents for that host.
- **Health tracking.** A server-side per-agent ticker sends `ping`
  every `ping_interval`; an agent missing `max_missed_pongs` is marked
  unhealthy and excluded from `pickAgent` until a pong arrives.
- **Failover.** `modules/ztrouter/handler.go`: if dispatch to the
  chosen agent fails at the connection level (write error / broken
  conn), retry on the next healthy agent, up to `failover.max_attempts`.
  Retry only when **all three** hold: nothing has been written to the
  client yet; the client connection has **not been hijacked**
  (WebSocket upgrades and streaming downloads hijack the conn — once
  hijacked there is no clean fallback, even on a connect-level error);
  and the failure is a connect/establish error. Never replay a request
  whose response has already started streaming.
- `least_conn` needs a per-agent in-flight counter. Increment before
  dispatch and **decrement via `defer`** so the count stays correct
  even on panic or an early `return` in `ServeHTTP`. An atomic int is
  fine; the `defer` placement is the part that matters.
- Metrics: `ztp_agents_healthy`, `ztp_failover_total`,
  `ztp_agent_inflight` gauge.

### Protocol changes

Optional `Weight int` on `types.ServiceConfig` (additive). Server →
agent `ping` (existing type, new direction).

### Implementation steps

1. `registry.go`: host→[]agent index; keep it consistent on every
   add/remove/disconnect path. Tests for index integrity.
2. Selection strategies (`round_robin`, `random`, `least_conn`) behind
   a `Picker` interface; per-agent in-flight counter.
3. Server-initiated health pings + healthy/unhealthy state on `Agent`.
4. `handler.go`: failover retry loop with the "response not yet
   started" guard.
5. `serverconfig`: `balancing` / `health` / `failover` + validator.
6. Docs: `docs/server/multi-agent-ha.md`.

### Files touched

`modules/ztagents/{registry,app,handle,agent}.go`,
`modules/ztrouter/handler.go`, `internal/serverconfig/*`,
`internal/server/metrics.go`, `config/server.yaml.example`.

### Tests

Index integrity across add/remove/disconnect; each balancing strategy;
unhealthy agent skipped, recovers on pong; failover picks the next
agent; failover does **not** fire once the response body has started;
concurrency under `-race`.

### Risks / open questions

- **Hot path + concurrency.** The registry is on every request. The
  go-concurrency conventions apply (`Agent.writeMu`, the
  `ResponseHandlers` map). Keep the host index under the existing
  `registry.mu`; do not add a second lock-ordering.
- **Session affinity.** Cross-agent round-robin can break sticky
  backends. Out of scope for v1 — document it; affinity by client IP
  is a later option.
- Failover correctness is subtle — the guard has three parts (nothing
  written, not hijacked, connect-level failure) and all are mandatory;
  non-idempotent methods are only safe to retry on a pure connect
  failure.

---

# Phase 6 — Operations: `/metrics` auth & admin API

### Goal

Two operational gaps: the Prometheus `/metrics` endpoint is
unauthenticated (the config example literally warns about it), and
there is no way to inspect live proxy state. This phase adds auth to
`/metrics` and a read-only admin API.

### Configuration

```yaml
metrics:
  addr: "127.0.0.1:9100"
  # NEW
  auth:
    type: bearer              # none | bearer | basic
    token_env: ZTP_METRICS_TOKEN

# NEW — read-only admin API.
admin:
  addr: "127.0.0.1:9200"
  auth:
    type: bearer
    token_env: ZTP_ADMIN_TOKEN
```

### Agent responsibilities

None.

### Server responsibilities

- `internal/server/metrics.go`: an auth wrapper on the metrics handler
  (constant-time token compare / basic-auth check).
- New `internal/server/admin.go`: a separate authenticated listener
  exposing read-only JSON:
  - `GET /api/agents` — connected agents: ID, `Meta` (name/region/tags
    from Phase 0), health, connect time.
  - `GET /api/services` — registered services per agent.
  - `GET /api/sessions` — active WebSocket / TCP sessions.
  - `GET /api/certs` — agent-provided certs + expiry (Phase 3).
  - `GET /api/health` — proxy self-health.
  Reuses `App.AgentServiceCounts`, `App.WebSocketCount`, plus small new
  read-only accessors on `ztagents.App`.
- Lifecycle: register the listener in `Server.Start` /
  `Server.Shutdown` next to the metrics listener (same pattern as
  `internal/server/server.go` lines 179–201). The admin `http.Server`
  must set `ReadHeaderTimeout` (consistent with `server.go:169,190`),
  or `make sec` flags `G112`.
- Read-only first. Mutating actions (disconnect an agent, trigger
  reload) are a deliberate later increment.

### Protocol changes

None.

### Implementation steps

1. `metrics.go`: auth wrapper + config.
2. `serverconfig`: `MetricsAuth`, `AdminConfig` + validator.
3. `internal/server/admin.go`: handlers + auth + lifecycle wiring.
4. Read-only accessors on `ztagents.App` for agent/session detail.
5. Docs: `docs/server/admin-api.md`.

### Files touched

`internal/server/{metrics,server,admin}.go`,
`internal/serverconfig/*`, `modules/ztagents/app.go`,
`config/server.yaml.example`.

### Tests

`/metrics` returns 401 without a token, 200 with one; admin endpoints
require auth; JSON shape is stable; the listener shuts down cleanly
with no leaked goroutines.

### Risks / open questions

- Keep the admin API **read-only** for v1. Mutating endpoints need
  their own authz design.
- Bind admin + metrics to private interfaces by default; the validator
  should warn on a `0.0.0.0` bind.

---

## Suggested delivery order

```
Phase 0  Agent identity & control-plane hardening   ← do first (protocol versioning)
Phase 1  Rate limiting & WAF                         ← fast standalone win
Phase 2  Access policy layer                         ← headline feature
Phase 3  Agent-provided certificates                 ← needs Phase 0 ACL
Phase 4  DNS automation                              ← largest; ACME-lib decision
Phase 5  Multi-agent HA                              ← hot-path refactor, do when stable
Phase 6  Operations: metrics auth & admin API        ← observes everything above
```

Phases 1, 5, 6 can move earlier if priorities shift; 0 → {3,4} and
4c's ACME-library choice are the only hard ordering constraints.

## Decisions needed before starting

1. **Phase 0 `bind_to` default** — ship `none` (no break) and make
   `cn` opt-in? (Recommended: yes.)
2. **Phase 2 OIDC** — hand-rolled vs. `coreos/go-oidc`? (Recommended:
   hand-rolled, keep `go.mod` lean.)
3. **Phase 2** — server-authoritative policy only, or allow
   agent-pushed policy? (Recommended: server-authoritative,
   `allow_agent_policy` off by default.)
4. **Phase 4 ACME** — drive `x/crypto/acme` directly vs. adopt
   `go-acme/lego`? (Recommended: `x/crypto/acme` + reuse `internal/dns`.)
5. **Phase 4 DNS ownership** — server-side only, or allow agent-side?
   (Recommended: server-side; agent sends a hint.)

## Out of scope

- HTTP/3 / QUIC — already shipped.
- Distributed / multi-instance state (shared rate-limit buckets,
  shared sessions). Single-instance for now; interfaces are designed
  to allow a shared backend later.
- Device posture / endpoint checks.
- A full WAF rule engine (ModSecurity-class). Phase 1 is a basic
  firewall, not a managed rule set.
- Per-service session affinity in cross-agent balancing.
- Mutating admin API endpoints.
- Protocol transport change — stays JSON-over-mTLS; all additions are
  additive and version-gated.
