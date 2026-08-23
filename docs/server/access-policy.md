# Access Policy Layer

The `access:` block makes an identity-based decision on **every**
inbound request, at the proxy, before the request is dispatched to an
agent. Identity comes from a **service token** (machines: CI, cron,
API clients) or a **signed session cookie** (humans — minted by the
OIDC login flow, which ships in the next increment). Decisions are
driven by an ordered rule set.

Disabled by default; an absent block changes nothing. The middleware
runs after the edge firewall and rate limiter (cheap rejects first)
and before the router:

```
accessLog → metrics → WAF → rateLimit → accessPolicy → router
```

## Configuration

```yaml
access:
  enabled: true

  session:
    secret_env: ZTP_SESSION_SECRET   # env var, >= 32 bytes; never inline
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

**Not available yet — rejected at validation until the OIDC login flow
ships**: `identity_providers`, and the `identity_provider`, `emails`,
and `emails_domain` require clauses. They all depend on browser login,
which is the next increment; accepting them today would produce config
that silently can never match (or, worse, rules no human could ever
satisfy). The validator names the limitation explicitly rather than
letting the config lie.

Generate a token + hash pair:

```bash
TOKEN=$(openssl rand -hex 32)
echo "token (give to the client): $TOKEN"
echo "hash  (put in config):      sha256:$(printf %s "$TOKEN" | shasum -a 256 | cut -d' ' -f1)"
```

Clients present it as `Authorization: Bearer <token>` or
`X-ZTP-Token: <token>`. Rotation: add the new hash, deploy, remove the
old one. Verification is constant-time over the whole token table.

## Evaluation semantics

For the first rule whose `when` matches (hosts: exact/`*`/`*.suffix`;
paths matched after percent-decoding and dot-segment collapse;
clauses AND-ed):

| Case | Result |
|------|--------|
| `action: deny` | 403 |
| `action: allow`, no `require` | allowed (public) |
| `require` satisfied | allowed |
| `require` fails, caller anonymous, predicate is identity-based | authentication demanded — browsers get the login flow (an explanatory 401 until a provider is configured), APIs get `401` + `WWW-Authenticate` |
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

## The `/.ztp/` namespace

`/.ztp/*` is proxy-owned (`/.ztp/logout` clears the session; the OIDC
callback lands there next). A backend can never expose paths under it:
the access middleware handles the namespace when enabled, and the
router independently 404s it as defence-in-depth when disabled.

## Secrets

All secrets are env-referenced (`*_env`), never inline in YAML.
`validate` fails if a referenced variable is unset, and the session
secret must be at least 32 bytes. Rotating the session secret
invalidates all live sessions.

## Hot reload

`rules` and `service_tokens` hot-reload on SIGHUP (atomic snapshot
swap). `enabled`, `session`, and `identity_providers` are restart-only
— live cookies are signed with the current secret.

## Metrics

| Metric | Meaning |
|--------|---------|
| `ztp_access_allowed_total` | requests allowed through |
| `ztp_access_denied_total{rule}` | denials, labeled by rule (`_default` for the default action) |
| `ztp_access_auth_required_total` | anonymous requests answered with an auth demand |
