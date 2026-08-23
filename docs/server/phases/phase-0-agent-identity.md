# Phase 0 — Agent Identity & Control-Plane Hardening

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: proposed. Prerequisite for Phases 3, 4, 5.

## 1. Problem & threat model

The agent control plane today (`modules/ztagents`) authenticates an
agent by **one fact only**: it presents a client certificate that
chains to `agents.ca_file`. After that:

- The agent sends `register` with a free-text `ID`. The server stores
  whatever string arrives (`handle.go:30-36`). The ID is never checked
  against the certificate.
- The agent then sends `service_add` for **any hostname**. The
  registry accepts it (`handle.go:87-95`). Nothing scopes an agent to
  a set of hostnames.
- There is no protocol version on the wire, so a future server that
  speaks new message types cannot tell an old agent apart from a new
  one — it can only fail late and confusingly.

| Threat | Today | After Phase 0 |
|--------|-------|---------------|
| A compromised agent (valid cert) registers `bank.example.com` and intercepts its traffic | Succeeds | Rejected — hostname outside the agent's ACL |
| Two agents fight over the same hostname | Last writer wins silently | Still allowed if both ACLs permit it (that is Phase 5); cross-tenant theft is blocked |
| A leaked agent cert is reused by an attacker | Works until the CA is rotated (rotates *all* agents) | Cert serial added to the denylist; only that agent is cut |
| A new server with new message types meets an old agent | Undefined behaviour | Clean `register_response` error, agent exits non-zero |

Phase 0 is a **prerequisite**: Phases 3–5 add message types and reuse
the per-agent hostname ACL. Land it first.

## 2. Where it sits

```
        TCP accept
            │
            ▼
   ┌─────────────────────┐   tls.Config.VerifyPeerCertificate
   │   TLS handshake     │◀── ① revocation check (serial / CRL)
   │  (mTLS, RequireAndVerifyClientCert)
   └─────────┬───────────┘
             │ PeerCertificates[0] now available
             ▼
   ┌─────────────────────┐
   │ read 1st message    │
   │  (must be register) │
   └─────────┬───────────┘
             ▼
   ② protocol-version check ──fail──▶ register_response{Error}, close
             ▼
   ③ identity check (ID vs cert) ──fail──▶ register_response{Error}, close
             ▼
   ④ ACL membership check ──fail──▶ register_response{Error}, close
             ▼
   registry.add(agent)          ◀── only reached on success
             ▼
   register_response{OK}
             ▼
   message loop: service_add ──▶ ⑤ per-hostname ACL check
```

Checks ②③④ all run **before** `registry.add`. This is a fix to an
ordering bug: `handleAgentConnection` currently calls
`a.rt.registry.add(agent)` at `handle.go:35-36`, *then* sends the ack
— an unverified agent is briefly live and routable.

## 3. Data model

### 3.1 Wire protocol additions (`internal/common/message.go`)

```go
// ProtocolVersion is the wire-protocol version this build speaks.
// Bumped by any phase that adds a message type. The server accepts
// agents within [MinSupportedVersion, ProtocolVersion].
const (
    ProtocolVersion     = 1
    MinSupportedVersion = 1
)

// Message gains two fields, populated only in `register`.
type Message struct {
    // ... existing fields ...
    Version int        `json:"version,omitempty"`
    Meta    *AgentMeta `json:"meta,omitempty"`
}

// AgentMeta is descriptive agent metadata for the admin API (Phase 6).
// It is NOT trusted for authorization — only the cert + ACL are.
type AgentMeta struct {
    Name   string   `json:"name,omitempty"`
    Region string   `json:"region,omitempty"`
    Tags   []string `json:"tags,omitempty"`
}
```

`Version`/`Meta` are `omitempty`; an old agent omits them and the
server reads `Version == 0`, which it maps to "legacy / version 1"
during a grace window (see §7).

### 3.2 Server config (`internal/serverconfig/config.go`)

```go
type AgentsConfig struct {
    // ... existing fields ...
    Identity   IdentityConfig   `yaml:"identity,omitempty"`
    ACL        ACLConfig        `yaml:"acl,omitempty"`
    Revocation RevocationConfig `yaml:"revocation,omitempty"`
}

type IdentityConfig struct {
    BindTo string `yaml:"bind_to"` // "cn" | "san" | "none"
}

type ACLConfig struct {
    AllowUnlisted bool            `yaml:"allow_unlisted"`
    Agents        []AgentACLEntry `yaml:"agents"`
}

type AgentACLEntry struct {
    ID           string   `yaml:"id"`
    AllowedHosts []string `yaml:"allowed_hosts"` // glob patterns
}

type RevocationConfig struct {
    CRLFile       string   `yaml:"crl_file,omitempty"`
    DeniedSerials []string `yaml:"denied_serials,omitempty"` // hex
}
```

### 3.3 In-memory agent (`modules/ztagents/agent.go`)

```go
type Agent struct {
    // ... existing fields ...
    Meta        AgentMeta // from register
    Version     int       // negotiated protocol version
    CertSerial  string    // hex serial of the presented client cert
    allowedHost []glob    // compiled ACL patterns for this agent
}
```

`allowedHost` is resolved once at register time so the hot path
(`service_add`) is a pre-compiled glob match, not a config walk.

## 4. Configuration

```yaml
agents:
  listen: ":8443"
  cert_file: /config/certs/server.crt
  key_file:  /config/certs/server.key
  ca_file:   /config/certs/ca.crt

  identity:
    bind_to: cn          # cn | san | none

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

Validation (`internal/serverconfig/validate.go`):

- `bind_to` ∈ {`cn`,`san`,`none`}; empty → defaults to `none`.
- Every `allowed_hosts` pattern must compile as a glob.
- Duplicate ACL `id` → error.
- `crl_file`, if set, must be readable and parse as a DER/PEM CRL.
- Each `denied_serials` entry must be valid hex.
- `allow_unlisted: false` with an empty `agents` list → warning (no
  agent could ever connect).

## 5. Component design

### 5.1 Identity extraction — `peerIdentity()`

A new helper in `modules/ztagents`:

```go
// peerIdentity returns the identity string the agent ID must match,
// per the configured bind mode. ok=false when bind_to=none.
func peerIdentity(cert *x509.Certificate, mode string) (id string, ok bool)
```

- `cn`  → `cert.Subject.CommonName`.
- `san` → the first `cert.DNSNames` entry (documented: agent ID lives
  in SAN[0]).
- `none`→ returns `ok=false`; the caller skips the identity check.

The client cert is reached via
`conn.(*tls.Conn).ConnectionState().PeerCertificates[0]`. Because the
listener is `tls.RequireAndVerifyClientCert` (`app.go:222`), the slice
is guaranteed non-empty by the time the first message is read.

### 5.2 Revocation — `VerifyPeerCertificate`

`loadTLSConfig` (`modules/ztagents/app.go`) gains a
`VerifyPeerCertificate` callback built from `RevocationConfig`:

```go
cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
    leaf, err := x509.ParseCertificate(rawCerts[0])
    if err != nil { return err }
    if revoked.Has(leaf.SerialNumber) {
        return fmt.Errorf("client certificate revoked")
    }
    return nil
}
```

`revoked` is a set built from `denied_serials` plus parsed CRL serials.
It is held behind an `atomic.Pointer` so a SIGHUP can swap it (CRL
re-read) without a listener restart.

### 5.3 ACL evaluation

Two enforcement points, both in `modules/ztagents/handle.go`:

1. **At register** — resolve the agent's `AgentACLEntry` by ID. If
   absent and `allow_unlisted == false` → reject. Compile its
   `AllowedHosts` into `agent.allowedHost`.
2. **At `service_add` / `service_update`** — `msg.Service.Hostname`
   must match at least one pattern in `agent.allowedHost`. Miss →
   `service_add_response{Error: "hostname not permitted for agent"}`.

Glob semantics: `*` matches one DNS label, `**` is not supported;
`*.eu.example.com` matches `a.eu.example.com` but not `eu.example.com`
or `a.b.eu.example.com`. Use a small label-aware matcher, not
`filepath.Match` (which treats `.` as ordinary and `*` as greedy).

## 6. Connection lifecycle (detailed sequence)

```
agent                              server (handleAgentConnection)
  │                                  │
  │── TCP SYN ──────────────────────▶│  listener.Accept()
  │◀═ TLS handshake ════════════════▶│  RequireAndVerifyClientCert
  │      (client cert sent)          │  + VerifyPeerCertificate  ──┐
  │                                  │     revoked? ──────────────┘─▶ close
  │                                  │
  │── register{ID,Version,Meta} ────▶│  decoder.Decode(&initial)
  │                                  │  initial.Type == "register"?
  │                                  │  ──┐ version in range?
  │◀── register_response{Error} ─────│ ◀─┘  no  → write error, close
  │                                  │  ──┐ peerIdentity == ID?
  │◀── register_response{Error} ─────│ ◀─┘  no  → write error, close
  │                                  │  ──┐ ACL entry exists / unlisted ok?
  │◀── register_response{Error} ─────│ ◀─┘  no  → write error, close
  │                                  │  registry.add(agent)        ← only here
  │◀── register_response{ID} ────────│  ack
  │                                  │
  │── service_add{host} ────────────▶│  host ∈ agent.allowedHost?
  │◀── service_add_response{Error} ──│  no → reject (service not added)
  │── service_add{host} ────────────▶│  yes → registry stores it
  │◀── service_add_response{ok} ─────│
```

## 7. Migration & rollout

A hard cutover breaks every existing fleet whose cert CN ≠ agent ID.
Staged rollout:

1. **Ship defaults off.** `bind_to: none`, `acl.allow_unlisted: true`.
   Behaviour is byte-for-byte today's. New code is dormant.
2. **Observe.** Add a metric `ztp_agent_identity_mismatch_total` that
   increments when ID ≠ cert identity *even in `none` mode* (log only,
   do not reject). Operators see how many agents would break.
3. **Re-issue certs.** `cmd/certgen` is updated so an agent cert's CN
   is the agent ID. Operators rotate agents onto compliant certs.
4. **Flip.** Once the mismatch metric is zero, set `bind_to: cn` and
   `allow_unlisted: false`. This is the documented breaking change.

`Version == 0` (an agent built before Phase 0) is treated as version 1
during a grace window controlled by `MinSupportedVersion`. When a
later phase needs to *require* version ≥ 2, raise `MinSupportedVersion`
and old agents are cleanly rejected.

## 8. Failure modes

| Condition | Server action | Log level |
|-----------|---------------|-----------|
| Revoked cert serial | TLS handshake fails | debug (handshake noise) |
| First message not `register` | close, no response | error |
| `Version` > `ProtocolVersion` | `register_response{Error}` | warn |
| `Version` < `MinSupportedVersion` | `register_response{Error}` | warn |
| ID ≠ cert identity (`bind_to≠none`) | `register_response{Error}` | warn |
| Agent not in ACL, `allow_unlisted=false` | `register_response{Error}` | warn |
| `service_add` host outside ACL | `service_add_response{Error}`, service not stored, connection stays up | warn |

A bad `service_add` does **not** drop the connection — the agent may
have other valid services. Only register-time failures close the conn.

## 9. Implementation steps

1. `internal/common/message.go`: `ProtocolVersion`,
   `MinSupportedVersion`, `Version`, `Meta`, `AgentMeta`. JSON
   round-trip test.
2. `internal/serverconfig`: `IdentityConfig`, `ACLConfig`,
   `AgentACLEntry`, `RevocationConfig`; `Defaults()`; `validate.go`.
3. `modules/ztagents`: glob matcher; `peerIdentity()`; revocation set
   + `VerifyPeerCertificate`; load ACL into `runtime`.
4. `modules/ztagents/handle.go`: reorder `handleAgentConnection` —
   version → identity → ACL → `registry.add`; enforce per-host ACL in
   `service_add`/`service_update`.
5. `internal/agent/agent.go`: send `Version` + `Meta` in `register`;
   handle an error `register_response` (log, exit non-zero).
6. `cmd/certgen`: stamp CN = agent ID; document the SAN option.
7. Metrics: `ztp_agent_identity_mismatch_total`,
   `ztp_agent_register_rejected_total{reason}`.
8. Docs: `docs/server/agent-identity.md`; update `CLAUDE.md` protocol
   section. SIGHUP classification for `revocation.crl_file` (reloadable)
   in `internal/server/reload.go`.

## 10. Testing strategy

- **Unit** — glob matcher (label semantics, edge cases);
  `peerIdentity` per mode; revocation-set membership; config validator.
- **Integration** (real `tls.Listen`, like `internal/server` tests):
  - allowed host → `service_add` accepted.
  - disallowed host → `service_add` rejected, connection survives,
    other services on the same agent still work.
  - ID ≠ CN under `bind_to: cn` → register rejected, agent absent from
    registry.
  - revoked serial → handshake fails, no `Agent` created.
  - version out of range → `register_response{Error}`.
  - **ordering**: a rejected agent never appears in `AgentCount()` —
    assert the registry stays empty.
- **Back-compat** — `bind_to: none` + `allow_unlisted: true` +
  `Version: 0` reproduces today's behaviour exactly.
- `-race` on the SIGHUP CRL swap concurrent with handshakes.

## 11. Open questions

- **`bind_to` default** — recommended `none`, opt-in to `cn`. (Roadmap
  decision #1.)
- **CRL refresh** — file re-read on SIGHUP only, or a periodic timer?
  Recommend SIGHUP-only for v1; a timer is a fast follow.
- **ACL source** — inline YAML now. A future option is per-agent ACLs
  delivered out-of-band (e.g. encoded in the cert as a custom
  extension) so the server config does not grow per agent. Out of
  scope for Phase 0.
