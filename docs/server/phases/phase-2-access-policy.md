# Phase 2 — Access Policy Layer

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: proposed. The headline zero-trust feature. Benefits from
> Phase 0 (identity plumbing) but does not hard-depend on it.

## 1. Goal

Make an **identity-based access decision on every inbound request**,
at the proxy, before the request is dispatched to an agent. This is
the Cloudflare-Access analogue and the feature that makes the product
name accurate.

Two identity classes:

- **Machine** — service tokens (a hashed bearer secret) for CI, cron,
  API clients.
- **Human** — OIDC / SSO (Google, Okta, Azure AD, Auth0, Keycloak —
  any compliant IdP) with a signed session cookie.

Decisions are driven by an ordered **rule set**: match on host / path /
method, require an identity predicate, allow or deny.

## 2. Architecture overview

```
                         ┌──────────────────────────────────────┐
                         │        access policy middleware       │
 request ───────────────▶│                                       │
                         │  1. resolve identity                  │
                         │     ├─ session cookie  → session.go   │
                         │     ├─ Bearer / X-ZTP-Token → token.go │
                         │     └─ none → anonymous                │
                         │  2. engine.Evaluate(req, identity)     │
                         │     → allow / deny / require-auth      │
                         │  3a. allow        → next handler       │
                         │  3b. deny         → 403                │
                         │  3c. require-auth → 302 to IdP  ───────┼──▶ oidc.go
                         └───────────────────────────────────────┘
                                          │
   reserved /.ztp/* endpoints (NOT proxied to agents):
     /.ztp/oauth/callback   ── handles the IdP redirect
     /.ztp/logout           ── clears the session cookie
```

New package `internal/policy`:

| File | Responsibility |
|------|----------------|
| `engine.go` | compiled rule set; `Evaluate` |
| `rule.go` | rule schema, match + `require` predicate evaluation |
| `identity.go` | the `Identity` type, resolution order |
| `token.go` | service-token verification |
| `session.go` | signed session cookie issue / verify / clear |
| `oidc.go` | OIDC discovery, auth-code flow, JWKS cache |
| `middleware.go` | the `http.Handler`, `/.ztp/*` routing |

## 3. Identity model

```go
// Identity is the resolved caller. Anonymous when Source == SourceNone.
type Identity struct {
    Source   IdentitySource // none | service_token | session | client_cert
    Subject  string         // token name, OIDC `sub`, or cert CN
    Email    string         // OIDC only
    Groups   []string       // token groups, or OIDC groups claim
    Provider string         // IdP name, for service_token = ""
}
```

Resolution order in `middleware.go`, first hit wins:

1. **Session cookie** present and signature valid → `SourceSession`.
2. Else **`Authorization: Bearer <t>`** or **`X-ZTP-Token: <t>`**
   matches a configured token → `SourceServiceToken`.
3. Else (Phase 3 interplay) a **verified TLS client cert** on the
   connection → `SourceClientCert`.
4. Else **anonymous** (`SourceNone`).

A request can carry both a cookie and a token; the cookie wins because
it is the cheaper check and the more specific session.

## 4. Rule engine

### 4.1 Schema

```go
type Rule struct {
    Name    string
    Match   Match      // when: hosts / paths / methods
    Action  Action     // allow | deny
    Require *Require   // nil = no identity needed (public)
}

type Match struct {
    Hosts   []glob
    Paths   []glob
    Methods map[string]bool
}

type Require struct {
    Authenticated    bool      // any non-anonymous identity
    Groups           []string  // identity must hold one of these
    Emails           []string  // exact email allow-list
    EmailsDomain     []string  // email domain allow-list
    IdentityProvider string    // must have come from this IdP
    SourceCIDRs      []*net.IPNet
}
```

### 4.2 Evaluation

```
Evaluate(req, id):
  for rule in rules (in order):
      if not rule.Match.matches(req):  continue
      if rule.Action == deny:          return Deny
      if rule.Require == nil:          return Allow            // public
      if id.satisfies(rule.Require):   return Allow
      if id.Source == SourceNone:      return RequireAuth      // browser → login
      return Deny                                              // authed, wrong identity
  return defaultAction                                         // no rule matched
```

Key subtlety: an **authenticated but unauthorized** caller gets `Deny`
(403), not another login redirect — re-authenticating will not help.
Only an **anonymous** caller on an auth-required rule gets
`RequireAuth`.

`RequireAuth` is downgraded to `Deny` (401) for non-browser requests
(no `Accept: text/html`, or an XHR) — APIs get a status code, not a
redirect to a login page.

### 4.3 Performance

Per request: one pass over rules; each rule is glob + map lookups.
O(rules), no allocation on the hot path (compiled globs, pre-parsed
CIDRs). JWKS is cached (§6.3). A positive-decision cache keyed by
`(identity, host, path-prefix)` is **deliberately not built** until
profiling shows a need — premature.

## 5. Service tokens

Tokens are **never stored in plaintext**. Config carries
`hash: "sha256:<hex>"`. On a request:

```
presented := header value
sum       := sha256(presented)
for t in tokens:
    if subtle.ConstantTimeCompare(sum, t.hash) == 1: → Identity{token}
```

`ConstantTimeCompare` over the full hash list avoids a timing oracle
on which token (or prefix) is valid. Token rotation = add the new
hash, deploy, remove the old hash.

## 6. OIDC / SSO

### 6.1 Login flow (authorization code)

```
browser                proxy (/.ztp/...)              IdP
  │  GET app, no cookie    │                            │
  │◀── 302 to IdP authz ───│  state+nonce minted,       │
  │     ?state=&nonce=     │  stashed in a short-lived   │
  │                        │  signed cookie             │
  │──── login at IdP ─────────────────────────────────▶ │
  │◀── 302 /.ztp/oauth/callback?code=&state= ───────────│
  │─── GET callback ──────▶│  verify state == cookie    │
  │                        │  POST code→token  ───────▶ │
  │                        │◀── id_token (JWT) ─────────│
  │                        │  verify sig (JWKS),        │
  │                        │  iss, aud, exp, nonce      │
  │                        │  mint session cookie       │
  │◀── 302 back to app ────│  (original URL from state) │
  │─── GET app + cookie ──▶│  session valid → Allow     │
```

- **`state`** — CSRF defence; also carries the original request URL so
  the user lands back where they started. Stored HMAC-signed in a
  temporary cookie, compared on callback.
- **`nonce`** — replay defence; embedded in the auth request and
  asserted to equal the `nonce` claim in the returned ID token.
- **PKCE** (`code_challenge`) — used when the IdP supports it; harmless
  when it does not.

### 6.2 ID-token validation

A returned `id_token` is accepted only if **all** hold: signature
verifies against a JWKS key; `iss` equals the configured issuer; `aud`
contains the client ID; `exp` is in the future; `nbf`/`iat` sane;
`nonce` matches. The `email`/`groups` claims then populate `Identity`.

### 6.3 JWKS cache

`oidc.go` fetches `<issuer>/.well-known/openid-configuration` once at
startup (and lazily re-fetches `jwks_uri` on an unknown `kid`). Keys
are cached in memory with a refresh interval; a `kid` miss triggers one
forced refresh before the token is rejected (handles IdP key
rotation).

### 6.4 Library decision

Recommendation: **hand-roll** discovery + JWKS + JWT validation on
`crypto/*` + `encoding/json` (~300 lines). It keeps `go.mod` lean —
consistent with the post-migration dependency diet — and the surface
needed is small. `coreos/go-oidc` is the fallback if validation
corner-cases prove costly. *Roadmap decision #2.*

## 7. Sessions

The session cookie is a **signed, self-contained token** — no
server-side session store, so it survives a proxy restart and needs no
shared state across replicas.

- **Format** — a compact JWT (`HS256`) or an HMAC-tagged payload.
  Claims: `sub`, `email`, `groups`, `provider`, `iat`, `exp`.
- **Signing key** — `session.secret_env` (≥32 bytes). Rotating the
  secret invalidates all live sessions — acceptable, documented.
- **Cookie flags** — `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`,
  `Max-Age` = `session.ttl`. `Lax` lets the post-login top-level
  redirect carry the cookie while still blocking CSRF on cross-site
  POSTs.
- **`/.ztp/logout`** clears the cookie (`Max-Age=0`) and optionally
  redirects to the IdP end-session endpoint.

## 8. The `/.ztp/` reserved namespace

`/.ztp/*` is **proxy-owned** and must never be dispatched to an agent.
`modules/ztrouter/handler.go` gets an early guard at the top of
`ServeHTTP`:

```go
if strings.HasPrefix(r.URL.Path, "/.ztp/") {
    http.NotFound(w, r) // should have been handled upstream
    return
}
```

In practice the access middleware (which sits *before* the router)
owns `/.ztp/oauth/callback` and `/.ztp/logout` and never falls through
to the router for them. The router guard is defence-in-depth so a
config with `access.enabled: false` cannot accidentally proxy the
namespace to a backend. Document that `/.ztp/` is reserved and a
backend cannot expose paths under it.

## 9. Configuration

```yaml
access:
  enabled: true

  session:
    secret_env: ZTP_SESSION_SECRET   # >=32 bytes
    cookie_name: ztp_session
    ttl: 8h

  service_tokens:
    - name: ci-deploy
      hash: "sha256:9f86d0818..."
      groups: ["ci"]

  identity_providers:
    - name: google
      type: oidc
      issuer: https://accounts.google.com
      client_id_env: ZTP_GOOGLE_CLIENT_ID
      client_secret_env: ZTP_GOOGLE_CLIENT_SECRET
      scopes: ["openid", "email", "profile"]

  default_action: deny
  allow_agent_policy: false          # honour agent-pushed PolicyRef?

  rules:
    - name: public-marketing
      when: { hosts: ["www.example.com"] }
      action: allow
    - name: ci-uploads
      when: { hosts: ["api.example.com"], paths: ["/upload/*"] }
      action: allow
      require: { groups: ["ci"] }
    - name: internal-apps
      when: { hosts: ["*.internal.example.com"] }
      action: allow
      require:
        identity_provider: google
        emails_domain: ["example.com"]
```

Optional agent-side hint (`internal/agent/config.go`), forwarded as
`PolicyRef` in `service_add`, honoured only if
`allow_agent_policy: true`:

```yaml
services:
  - id: dashboard
    hosts: ["dash.example.com"]
    access_policy: internal-apps     # names a server rule
```

Validation: every `*_env` var resolves; `default_action` ∈
{allow,deny}; each rule `require` references a real provider; globs and
CIDRs compile; `session.secret` ≥ 32 bytes; provider `issuer` is
https.

## 10. Agent vs server responsibility

| Concern | Owner |
|---------|-------|
| Access decision / enforcement | **Server** — the agent is on the customer network, the less-trusted side |
| IdP integration, sessions, callbacks | **Server** |
| Rule set | **Server** (authoritative). Agent may *name* a server-defined rule via `PolicyRef`; never inline rules |
| Forwarding `access_policy` → `PolicyRef` | Agent (convenience only) |

Default and recommendation: **server-authoritative**,
`allow_agent_policy: false`. *Roadmap decision #3.*

## 11. Reconciling the dormant agent structs

`internal/agent/config.go` still defines Caddy-era
`SecurityConfig` / `AuthConfig` / `CORSConfig`. Step 6 below audits
whether anything enforces them today (grep says they are parsed but
inert). Outcome: either **delete** them so there is exactly one access
model (this phase), or wire **CORS only** into this phase as a
per-service response-header concern. Do not ship two parallel auth
models.

## 12. Implementation steps

1. **2a — engine + tokens.** `engine.go`, `rule.go`, `token.go`,
   `identity.go`, `middleware.go`. `require` supports
   `authenticated` + `groups`; identity = service tokens only. Returns
   403 on deny. Fully offline-testable.
2. **2b — sessions.** `session.go`: cookie issue/verify; wire
   `default_action` and public (no-`require`) rules.
3. **2c — OIDC.** `oidc.go`: discovery, auth-code flow, JWKS cache,
   `/.ztp/oauth/callback`, `/.ztp/logout`. Router reserves `/.ztp/*`.
4. **2d — predicates.** `emails`, `emails_domain`, `source_cidrs`,
   `identity_provider` routing; `RequireAuth`-vs-`Deny` browser
   detection.
5. `serverconfig`: `AccessConfig` + nested structs + validator.
6. Audit & reconcile the dormant agent-side `SecurityConfig` /
   `AuthConfig` / `CORSConfig`.
7. `internal/types/service.go`: `PolicyRef`; agent forwards it.
8. Metrics; docs `docs/server/access-policy.md`.

## 13. Concurrency & reload

- The compiled rule set + token table live behind an
  `atomic.Pointer`; SIGHUP swaps them — `rules` and `service_tokens`
  are hot-reloadable.
- `identity_providers` and `session` changes are **restart-only**:
  live session cookies are signed with the current secret and OIDC
  flows hold in-flight `state` cookies.
- JWKS cache: one `sync.RWMutex`; refresh under the write lock,
  lookups under the read lock.

## 14. Security considerations

- **Open redirect** — the post-login return URL comes from the signed
  `state`, never from a raw query param; reject absolute URLs to other
  hosts.
- **CSRF** — `state` on the OIDC flow; `SameSite=Lax` on the session
  cookie.
- **Token timing** — constant-time compare over all token hashes.
- **Cookie theft** — `Secure` + `HttpOnly`; short `ttl`; `/.ztp/logout`.
- **Secret handling** — session secret and client secrets via env
  vars only; never logged, never in config files.
- **Fail closed** — if the engine cannot evaluate (e.g. a provider is
  unreachable mid-flow), the request is denied, not allowed.

## 15. Testing strategy

- Rule precedence, `default_action`, public vs require, authed-but-
  unauthorized → 403 (not a redirect loop).
- Service token: valid → allow; wrong → deny; constant-time compare.
- Session: tampered signature rejected; expired rejected; round-trip
  claims.
- OIDC against a **mock IdP** (in-process httptest): discovery
  document, JWKS, code→token, callback; assert `state`/`nonce`
  enforcement and that a forged `state` is rejected.
- `/.ztp/*` never reaches the router (assert with `access.enabled`
  both true and false).
- Browser vs API: `RequireAuth` → 302 for `Accept: text/html`, 401
  otherwise.
