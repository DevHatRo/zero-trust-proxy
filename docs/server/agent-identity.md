# Agent Identity & Control-Plane Hardening

By default, any agent presenting a client certificate signed by
`agents.ca_file` may register **any** ID and claim **any** hostname.
The `agents.identity`, `agents.acl`, and `agents.revocation` blocks
close that gap: they bind the register ID to the certificate, scope
each agent to an allow-list of hostnames, and let you cut a single
leaked certificate without rotating the CA.

All three default off / allow-all — an unconfigured server behaves
exactly as before.

## Registration flow

Every check runs **before** the agent enters the registry, so a
rejected agent is never routable, even briefly:

```
TLS handshake (mTLS) ── revoked serial? ──▶ handshake fails
        │
   register message
        │
  ① protocol version in range?   ──▶ register_response{Error}, close
  ② ID matches cert (bind_to)?   ──▶ register_response{Error}, close
  ③ in ACL / unlisted allowed?   ──▶ register_response{Error}, close
        │
  registry.add ── ack ── message loop
        │
  service_add ──▶ ④ hostname within the agent's allowed_hosts?
                     miss → service_add_response{Error};
                     the service is NOT stored, the connection stays up
```

A rejected agent logs the reason and **exits non-zero** instead of
retrying forever — a rejection is a configuration problem, not a
transient failure.

## Configuration

```yaml
agents:
  # ... listener/cert fields ...

  identity:
    bind_to: cn          # cn | san | none (default none)

  acl:
    allow_unlisted: false
    agents:
      - id: "synology"
        allowed_hosts: ["*.local.example.com"]
      - id: "edge-eu"
        allowed_hosts: ["*.eu.example.com", "status.example.com"]

  revocation:
    crl_file: /config/certs/revoked.crl
    denied_serials: ["0A1B2C3D"]
```

**ACL glob semantics are label-aware**: `*` matches exactly one DNS
label. `*.eu.example.com` matches `a.eu.example.com` but not
`eu.example.com` or `a.b.eu.example.com`. (Deliberately tighter than
the edge firewall's `*.suffix` matcher — the ACL is an authorization
boundary.) An agent listed with `allowed_hosts` may only `service_add`
matching hostnames; unlisted agents (when permitted) are unrestricted.

`cmd/certgen` already stamps the agent certificate's CN with the agent
ID (`--client-id <id>`), so certs it generated are `bind_to: cn`
compatible. For `bind_to: san`, the agent ID must be the first DNS SAN.

## Rollout without breaking your fleet

1. **Ship defaults** (`bind_to: none`, `allow_unlisted: true`) —
   nothing changes.
2. **Observe**: watch `ztp_agent_identity_mismatch_total`. It counts
   agents whose ID differs from their cert CN *even in none mode*
   (each mismatch also logs a warning naming the agent).
3. **Rotate**: re-issue certs with `certgen` so CN = agent ID for any
   mismatching agent.
4. **Flip**: once the mismatch metric stays zero, set `bind_to: cn`
   and populate the ACL with `allow_unlisted: false`. This is the
   deliberate breaking change.

## Protocol versioning

`register` now carries `version` (this build: 1) plus optional agent
metadata (name/region/tags, for observability only — never used for
authorization). The server accepts `[MinSupportedVersion,
ProtocolVersion]`; a missing version (older agents) is treated as
version 1. When a future phase requires new message types, raising
`MinSupportedVersion` cleanly rejects old agents at register time
instead of failing late and confusingly.

## Hot reload

| Block | SIGHUP |
|-------|--------|
| `revocation` (serials + CRL re-read) | **reloadable** — applies to new handshakes; a broken CRL keeps the previous set |
| `identity.bind_to`, `acl` | restart-only — compiled into the listener at startup; already-connected agents keep their compiled ACL either way |

## Metrics

| Metric | Meaning |
|--------|---------|
| `ztp_agent_identity_mismatch_total` | register ID ≠ cert identity (counted even in `none` mode) |
| `ztp_agent_register_rejected_total{reason}` | rejections by `version` \| `identity` \| `acl` (revoked certs fail the handshake and never reach register) |
