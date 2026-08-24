# Access Policy Layer

The `access:` block makes an identity-based decision on **every**
inbound request, at the proxy, before the request is dispatched to an
agent. Identity comes from a **service token** (machines: CI, cron,
API clients) or a **signed session cookie** (humans — minted by the
browser login flow: **email one-time code** and/or **OIDC / SSO** via
`identity_providers`, both below). Decisions are driven by an ordered
rule set.

Disabled by default; an absent block changes nothing. The middleware
runs after the edge firewall and rate limiter (cheap rejects first)
and before the router:

```text
accessLog → metrics → WAF → rateLimit → accessPolicy → router
```

## Configuration

```yaml
access:
  enabled: true

  session:
    secret: "${ZTP_SESSION_SECRET}"   # env-expanded; >= 32 bytes
    cookie_name: ztp_session         # default
    ttl: 8h                          # default

  service_tokens:
    - name: ci-deploy
      hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
      groups: ["ci"]

  default_action: deny               # no rule matched → deny (zero trust)

  rules:                             # ordered; first match wins
    - name: public-www
      when: { hosts: ["www.example.com"] }
      action: allow                  # no require = public

    - name: ci-uploads
      when: { hosts: ["api.example.com"], paths: ["/upload/*"] }
      action: allow
      require: { groups: ["ci"] }    # service token in group ci

    - name: office-only
      when: { hosts: ["intranet.example.com"] }
      action: allow
      require: { source_cidrs: ["203.0.113.0/24"] }
```

The `emails` / `emails_domain` / `identity_provider` clauses require a
login flow that can establish a human identity: configure **email OTP**
or an **OIDC provider** (both below). Without any login flow they are
rejected at validation as dead config, and `require.identity_provider`
must name a configured `identity_providers` entry.

## Email one-time-code login (email OTP)

Cloudflare-style "one-time PIN": a browser hitting an email-scoped
rule enters their address, receives a short-lived 6-digit code, and
exchanging it mints the session cookie. No identity provider or app
registration needed. Exactly one mail sender must be configured —
plain SMTP or the [Brevo](https://www.brevo.com) transactional API:

```yaml
access:
  email_otp:
    enabled: true
    from: "auth@example.com"
    code_ttl: 10m                     # default
    # Sender option A — SMTP submission (STARTTLS):
    smtp:
      host: smtp.fastmail.com
      port: 587                       # default
      username: auth@example.com
      password: "${ZTP_SMTP_PASSWORD}"
    # Sender option B — Brevo API (mutually exclusive with smtp):
    # brevo:
    #   api_key: "${ZTP_BREVO_API_KEY}"

  rules:
    - name: media-apps
      when: { hosts: ["*.home.example.com"] }
      action: allow
      require: { emails: ["you@example.com"] }   # or emails_domain
```

Flow and safeguards:

- Anonymous browsers on an email-scoped rule are redirected to
  `/.ztp/login` (the original path survives the round-trip as a
  sanitized **relative** return path — no open redirect).
- A code is **only sent when the address could satisfy at least one
  rule**, but the response is byte-identical either way — no account
  enumeration, and the proxy cannot be used to mail-bomb strangers.
- Codes are stored hashed, compared in constant time, **single-use**,
  expire after `code_ttl`, allow 5 verification attempts, and issuance
  is limited to 3 sends per address per 10 minutes.
- Successful verification mints a session with `provider:
  "email_otp"` and the verified email; `/.ztp/logout` ends it.
- Sessions last `session.ttl` (default 8h) — sign in once per device,
  not per request.

Generate a token + hash pair:

```bash
TOKEN=$(openssl rand -hex 32)
echo "token (give to the client): $TOKEN"
echo "hash  (put in config):      sha256:$(printf %s "$TOKEN" | shasum -a 256 | cut -d' ' -f1)"
```

Clients present it as `Authorization: Bearer <token>` or
`X-ZTP-Token: <token>`. Rotation: add the new hash, deploy, remove the
old one. Verification is constant-time over the whole token table.

## OIDC / SSO login (`identity_providers`)

Configure one or more OpenID Connect providers (Google, Okta, Azure AD,
Auth0, Keycloak, …). Each protected host presents a **Sign in with
&lt;name&gt;** button; the browser runs a standard **authorization-code
flow with PKCE**, and a verified ID token mints the session cookie. The
implementation is dependency-free (discovery + JWKS are hand-rolled).

```yaml
identity_providers:
  - name: google
    issuer: https://accounts.google.com     # discovery base
    client_id: "${ZTP_GOOGLE_CLIENT_ID}"
    client_secret: "${ZTP_GOOGLE_CLIENT_SECRET}"
    scopes: [openid, email, profile]         # openid always included
    groups_claim: groups                     # ID-token claim for groups
```

- **Redirect URI**: register `https://<host>/.ztp/oauth/callback` with
  the provider for every host the flow runs on (the callback lands on
  the same host that started it, so the session cookie is set there).
  A single sign-in host, or a wildcard registration, keeps this simple.
- **Security**: `state` (CSRF), `nonce` (ID-token replay), and PKCE
  `S256` are all enforced. The per-attempt flow state lives only in a
  signed, `SameSite=Lax`, short-lived cookie — no server-side login
  store. The ID token is verified end to end: RS256 signature against
  the provider's JWKS (cached, refreshed on key rotation), `iss`,
  `aud == client_id`, `exp`, and `nonce`.
- **Identity**: `sub` becomes the session subject, `email` (only if
  `email_verified`) and the `groups_claim` array populate the
  `emails` / `emails_domain` / `groups` clauses. `require.identity_provider`
  pins a rule to a specific provider by name.
- Only the confidential auth-code flow and RSA-signed ID tokens are
  supported. Discovery and JWKS are cached for one hour.

Email OTP and OIDC can be enabled together — the login page then offers
both, and a rule's clauses decide which identities it accepts.

## Evaluation semantics

For the first rule whose `when` matches (hosts: exact/`*`/`*.suffix`;
paths matched after percent-decoding and dot-segment collapse;
clauses AND-ed):

| Case | Result |
|------|--------|
| `action: deny` | 403 |
| `action: allow`, no `require` | allowed (public) |
| `require` satisfied | allowed |
| `require` fails, caller anonymous, predicate is identity-based | authentication demanded — browsers are redirected to the login chooser (`/.ztp/login`) when any login flow is configured, else get an explanatory `401` page; APIs get `401` + `WWW-Authenticate` |
| `require` fails otherwise | 403 — re-authenticating would not help |
| no rule matched | `default_action` |

Methods are matched case-normalized, and an empty `require` block is a
validation error (it would mean "no requirement" — fail-open).

Notable subtleties:

- An **authenticated but unauthorized** caller gets 403, never a login
  redirect loop.
- A `require` with **only** `source_cidrs` is a network predicate:
  failing it is 403 for everyone — logging in cannot fix a source IP.
- `require` clauses are AND-ed; values inside one clause are any-of.
  Available: `authenticated`, `groups`, `emails`, `emails_domain`,
  `identity_provider`, `source_cidrs` (matched against the TCP peer
  address, never forwarding headers).

## Per-service policy hints (`allow_agent_policy`)

Rules are **server-authoritative** by default: the proxy decides, and an
agent has no say. As a convenience, an agent may tag a service with
`access_policy: <rule-name>` (see the agent docs) to ask that a named
server rule apply to that service's host — so an operator can define a
rule once without listing every host in its `when.hosts`.

This is honoured **only** when the server sets `access.allow_agent_policy:
true` (default `false`). Even then it can only ever **grant** access in a
gap the server left denied — it can never override a server-authoritative
decision:

- The agent hint is consulted **only when the request hit the default
  `deny`** — i.e. no explicit rule matched *and* `default_action` is
  `deny`. An explicit `allow`/`deny` rule wins over it, and a
  `default_action: allow` wins over it (an agent cannot restrict a host
  the operator chose to leave open).
- The named rule must be an **allow rule that carries an identity
  `require`**. A public (no-`require`) rule, a `deny` rule, a
  network-only `require` (satisfiable anonymously), or an unknown name is
  ignored and logged — an agent can never borrow a rule to grant
  unauthenticated access.
- The referenced rule's own **`when` path/method scope is honoured**
  (only its host clause is treated as this host), then its `require` is
  evaluated as normal: satisfied → allow; anonymous browser → login;
  otherwise 403. Outside the rule's path/method scope the request stays
  at the default deny.

`allow_agent_policy` is restart-only. Leave it off unless you explicitly
trust agents to reference policies by name.

## The `/.ztp/` namespace

`/.ztp/*` is proxy-owned: `/.ztp/logout` clears the session,
`/.ztp/login` is the login chooser, `/.ztp/otp/request` + `/.ztp/otp/verify`
drive the one-time-code flow (when `email_otp` is enabled), and
`/.ztp/oauth/login` + `/.ztp/oauth/callback` drive the OIDC auth-code
flow (when `identity_providers` are configured). A backend can never
expose paths under it: the access middleware handles the namespace when
enabled, and the router independently 404s it as defence-in-depth when
disabled.

## Secrets

Secret-bearing values (`session.secret`, provider credentials) accept
either an inline value or a whole-value environment reference in the
form `"${VAR}"` — the env form is recommended so secrets stay out of
the YAML file. `validate` fails if a referenced variable is unset, and
the session secret must be at least 32 bytes. Rotating the session
secret invalidates all live sessions.

## Hot reload

`rules` and `service_tokens` hot-reload on SIGHUP (atomic snapshot
swap). `enabled`, `session`, `email_otp`, and `identity_providers` are
restart-only — live cookies are signed with the current secret, and the
OTP store/sender are built once at startup.

## Metrics

| Metric | Meaning |
|--------|---------|
| `ztp_access_allowed_total` | requests allowed through |
| `ztp_access_denied_total{rule}` | denials, labeled by rule (`_default` for the default action) |
| `ztp_access_auth_required_total` | anonymous requests answered with an auth demand |
| `ztp_access_auth_redirect_total` | browsers redirected to an OIDC provider |
| `ztp_access_oidc_login_total` | successful OIDC logins |
| `ztp_access_oidc_error_total` | OIDC discovery / exchange / verification failures |
