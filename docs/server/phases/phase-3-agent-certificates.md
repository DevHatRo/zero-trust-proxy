# Phase 3 — Self-Managed / Agent-Provided Certificates

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: proposed. Depends on Phase 0 (the per-agent hostname ACL
> gates which hostnames an agent may supply a cert for).

## 1. Goal

Today the public-facing TLS certificate is server-owned: `manual`,
`sni`, or `acme` (`internal/server/tls.go`). This phase lets an
operator **manage the edge certificate on the agent side** — their own
CA, their own ACME client, a corporate PKI, or a static file — and
have the **agent push that certificate to the server** over the
existing mTLS control channel.

Optionally the same mechanism turns on **mTLS at the public edge** for
a hostname: the server requests/requires a client certificate from end
users and feeds the verified identity into the Phase 2 access policy.

## 2. Why push, not pull

The agent already holds an authenticated, encrypted channel to the
server (the mTLS control connection). Reusing it means:

- no new inbound port, no new credential;
- the server never needs filesystem access to the operator's certs;
- rotation is a message, not a deploy.

The cost — a private key transits the channel — is bounded by the
channel already being mTLS-encrypted and by the Phase 0 ACL scoping
*which* hostnames an agent may speak for. See §9.

## 3. Architecture

```
 agent                                   server
 ┌───────────────┐                       ┌──────────────────────────┐
 │ edge_tls cfg  │                       │  handleAgentMessage      │
 │  cert_file ───┼── read ──┐            │   case cert_add/_update: │
 │  key_file     │          │ cert_add   │     validate ──┐         │
 │  client_ca    │          ├──────────▶ │     ACL check  │         │
 │               │          │            │     store ─────┼───┐     │
 │ file watcher ─┼─ change ─┘  cert_update│                │   │     │
 │  (hotreload)  │          cert_remove   │                ▼   │     │
 └───────────────┘                       │      certStore (host→cert)│
                                         │                │         │
        public TLS handshake             │   tls.Config.GetCertificate
        client ─────────────────────────▶│   + GetConfigForClient ◀─┘
                                         └──────────────────────────┘
```

New unit: **`certStore`** (`modules/ztagents/certstore.go`). New
message family: **`cert_add` / `cert_update` / `cert_remove`**.

## 4. Data model

### 4.1 Wire (`internal/common/message.go`)

```go
type Message struct {
    // ... existing ...
    Cert *CertData `json:"cert,omitempty"`
}

type CertData struct {
    Hostname    string `json:"hostname"`
    CertPEM     []byte `json:"cert_pem"`               // leaf + chain
    KeyPEM      []byte `json:"key_pem"`
    ClientCAPEM []byte `json:"client_ca_pem,omitempty"` // edge mTLS
    ClientAuth  string `json:"client_auth,omitempty"`   // none|request|require
}
```

New `Type` values: `cert_add`, `cert_update`, `cert_remove` and their
`_response`s. All gated on the Phase 0 `ProtocolVersion`.

### 4.2 Server-side stored form

```go
// agentCert is the validated, ready-to-serve form of one CertData.
type agentCert struct {
    cert       tls.Certificate   // parsed leaf+chain+key
    clientCAs  *x509.CertPool    // nil unless edge mTLS requested
    clientAuth tls.ClientAuthType
    perHostCfg *tls.Config       // pre-built; see §6.2
    agentID    string            // which agent supplied it
    expiry     time.Time         // leaf NotAfter, for metrics
}

type certStore struct {
    mu    sync.RWMutex
    byHost map[string]*atomic.Pointer[agentCert]
}
```

The `atomic.Pointer` per entry makes a rotation (`cert_update`)
lock-free for readers. The **map itself** is read by `GetCertificate`
on every handshake while `cert_add`/`cert_remove` mutate it, so the
map is guarded by `certStore.mu` (RWMutex). Lookups take `RLock`;
add/remove take `Lock`. Never mutate a map a TLS closure reads
concurrently.

## 5. Message handling & validation

`cert_add` and `cert_update` run the same validation pipeline in
`handleAgentMessage`; any failure → `cert_*_response{Error}` and the
store is left unchanged:

```
1. parse        tls.X509KeyPair(CertPEM, KeyPEM)         → key matches cert?
2. leaf         x509.ParseCertificate(leaf)
3. SAN cover    leaf.VerifyHostname(Hostname) == nil     → cert is for this host?
4. validity     now ∈ [NotBefore, NotAfter]              → not expired/not-yet?
5. ACL          Hostname ∈ agent.allowedHost (Phase 0)   → agent owns this host?
6. client CA    if ClientCAPEM: parse into a CertPool
7. build        assemble agentCert, pre-build perHostCfg (§6.2)
8. store        certStore add/replace under mu.Lock
```

Step 5 is the security pivot: an agent may only supply a certificate
for a hostname its Phase 0 ACL already permits it to serve. Without
Phase 0 this feature would let any agent serve a cert for any host.

`cert_remove` deletes the entry under `mu.Lock`. On agent disconnect,
`handleAgentConnection`'s cleanup path removes **all** entries whose
`agentID` matches (mirrors `tcpManager.ReleaseAgent`).

## 6. Serving the certificate

### 6.1 Selection precedence

`internal/server/tls.go` `buildTLSConfig` already produces a
`GetCertificate` closure per mode. It is wrapped so the agent store is
consulted **first**:

```
GetCertificate(chi):
    if c := certStore.lookup(chi.ServerName); c != nil:
        return &c.cert
    return <existing manual|sni|acme closure>(chi)
```

Documented precedence: **agent → sni → manual → acme**. A hostname with
both an agent cert and ACME is served the agent cert.

### 6.2 Per-SNI client authentication

`ClientAuth` and `ClientCAs` are fields of `tls.Config`, **not** of a
certificate — so "require a client cert for `dash.example.com` only"
cannot be done from `GetCertificate`. It needs
`tls.Config.GetConfigForClient`, which returns a whole `*tls.Config`
per connection chosen by SNI.

The returned config **must be a clone of the full base config**:

```go
base := bundle.tlsConfig // the real listener config

cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
    c := certStore.lookup(chi.ServerName)
    if c == nil || c.clientAuth == tls.NoClientCert {
        return nil, nil // nil = use the base config unchanged
    }
    return c.perHostCfg, nil // pre-built clone, see below
}
```

`perHostCfg` is built **once, when the cert is stored** (step 7 of §5),
not per handshake:

```go
perHostCfg := base.Clone()      // keeps GetCertificate, MinVersion, NextProtos (h2)
perHostCfg.ClientAuth = c.clientAuth
perHostCfg.ClientCAs  = c.clientCAs
```

A bare `&tls.Config{ClientCAs: ...}` would drop `GetCertificate`,
`MinVersion`, and the ALPN `NextProtos` that the stdlib sets for
HTTP/2 — breaking cert selection and h2 for that host. Cloning the base
is mandatory.

When a client cert is verified, the middleware/handler stashes the
identity on a **new field of `common.RequestInfo`**
(`internal/common/reqctx.go` today carries only `AgentID`) so the
Phase 2 policy engine's `SourceClientCert` path can read it.

## 7. Agent side

### 7.1 Config (`internal/agent/config.go`)

A **new** per-service `edge_tls` block, distinct from the existing
`tls` block (which configures the *backend* leg — leave it untouched):

```yaml
services:
  - id: dashboard
    hosts: ["dash.example.com"]
    upstreams: [{ address: "http://127.0.0.1:3000" }]
    edge_tls:
      mode: provide              # provide | none
      cert_file: /certs/dash.crt
      key_file:  /certs/dash.key
      auto_reload: true
      client_auth: require       # none | request | require
      client_ca_file: /certs/users-ca.crt
```

```go
type EdgeTLSConfig struct {
    Mode         string `yaml:"mode"`            // provide | none
    CertFile     string `yaml:"cert_file"`
    KeyFile      string `yaml:"key_file"`
    AutoReload   bool   `yaml:"auto_reload"`
    ClientAuth   string `yaml:"client_auth,omitempty"`
    ClientCAFile string `yaml:"client_ca_file,omitempty"`
}
```

### 7.2 Lifecycle

- **On `service_add`** (or startup) with `mode: provide` — read the
  three files, send `cert_add`.
- **Rotation** — with `auto_reload`, register the cert/key paths with
  the agent's existing file watcher (`internal/common/hotreload.go`).
  On change: re-read, send `cert_update`. The server hot-swaps the
  `atomic.Pointer` — no dropped connections.
- **On service removal / shutdown** — send `cert_remove`.

The agent does not care *how* the cert came to exist — static files,
its own ACME client, corporate PKI, a dev self-signed cert. All of
that is the operator's concern and invisible to the server.

## 8. Server config

```yaml
tls:
  mode: sni                  # existing modes remain as the fallback
  allow_agent_certs: true    # accept cert_* messages
  persist_agent_keys: false  # in-memory only (default)
```

- `allow_agent_certs: false` → `cert_*` messages are rejected with an
  error response; the feature is off.
- `persist_agent_keys: false` (default) → agent keys live only in
  process memory; a restart drops them and agents re-push on
  reconnect. `true` writes them to a private dir (opt-in, for fast
  restarts) — flagged in the security review.

## 9. Security considerations

- **Private keys cross the wire.** The control channel is already
  mTLS-encrypted and mutually authenticated; the Phase 0 ACL scopes
  which hostnames an agent may supply. Still, this is the feature's
  sharpest edge — call it out explicitly in the `make sec` review and
  in user docs. Keep `persist_agent_keys` off by default.
- **`cert_*` share the single agent connection.** Agent messages are
  read by one serial `decoder.Decode` loop (`handle.go:46-59`); a
  multi-KB cert blob briefly blocks request multiplexing on that
  connection while it decodes. Acceptable — certs are small and pushed
  rarely — but keep `CertData` lean (no padding the chain).
- **No trust validation of the leaf.** The server serves whatever the
  agent provides; browsers validate the chain. The server validates
  only SAN coverage + expiry + ACL — it does not require the cert to
  chain to any particular CA.
- **`G402` exemption unchanged.** The `make sec` `G402` carve-out is
  for the agent→backend leg; this feature does not touch it. The
  security-auditor should confirm during review.

## 10. Concurrency & failure modes

| Event | Behaviour |
|-------|-----------|
| `cert_update` during a live handshake | reader holds the old `atomic.Pointer`; new handshakes see the new cert |
| `cert_remove` during a live handshake | map `Lock` serializes; in-flight `RLock` lookup completed before the delete |
| Agent disconnect | all of that agent's entries removed in the cleanup path |
| Validation failure | store unchanged; `cert_*_response{Error}`; agent logs + may retry |
| `allow_agent_certs: false` | message rejected; falls back to the configured `tls.mode` |
| SNI with no agent cert | falls through to manual/sni/acme |

## 11. Implementation steps

1. `internal/common/message.go`: `CertData`, `Cert` field, `cert_*`
   constants; bump `ProtocolVersion`.
2. `modules/ztagents/certstore.go`: `agentCert`, `certStore`,
   validation pipeline, `perHostCfg` builder. Unit tests.
3. `modules/ztagents/handle.go`: `cert_add/_update/_remove` cases; ACL
   enforcement; agent-disconnect cleanup.
4. `internal/server/tls.go`: wrap `GetCertificate`; add
   `GetConfigForClient`.
5. `internal/common/reqctx.go`: new client-cert identity field on
   `RequestInfo`; populate it where the handshake completes.
6. `internal/agent/config.go`: `EdgeTLSConfig`.
7. `internal/agent/agent.go`: read edge certs, push `cert_add`, watch
   + `cert_update`, `cert_remove` on teardown.
8. `serverconfig` + validator: `allow_agent_certs`,
   `persist_agent_keys`.
9. Metrics: `ztp_agent_certs` gauge, `ztp_agent_cert_expiry_seconds`
   per host. Docs `docs/server/agent-certificates.md`.

## 12. Testing strategy

- Validation: good pair accepted; mismatched key rejected; SAN not
  covering the hostname rejected; expired rejected.
- ACL: an agent supplying a cert for a host outside its ACL → rejected
  (depends on Phase 0).
- Selection: SNI for a host with an agent cert serves the agent cert,
  not the ACME/manual one.
- `GetConfigForClient`: `require` rejects a connection with no client
  cert; `request` accepts both; the per-host clone still serves the
  right leaf and negotiates h2.
- Rotation: `cert_update` swaps the cert; an in-flight TLS connection
  is undisturbed; `-race` on update vs lookup.
- `persist_agent_keys: false` → assert no key material is written to
  disk.
