# Phase 4 — DNS Entry Automation & Provider Integrations

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: proposed. Touches `internal/server/tls.go`; land after
> Phase 3 to avoid a `GetCertificate` merge conflict.

## 1. Goal

Two related capabilities, both driven by service registrations:

1. **Record management** — when a service registers, automatically
   create/update the public DNS record (`A` / `AAAA` / `CNAME`) that
   points the hostname at the proxy; delete it on service removal.
2. **DNS-01 ACME** — solve the ACME DNS-01 challenge through the
   provider API, which unlocks **wildcard certificates** and issuance
   without exposing port 80.

One provider abstraction serves both. Starter providers: **Cloudflare**
and **AWS Route 53**; then **Google Cloud DNS**, **DigitalOcean**,
**Azure DNS**.

## 2. Architecture

```
                     internal/dns
   ┌───────────────────────────────────────────────────┐
   │  Provider (interface)                              │
   │    cloudflare.go  route53.go  gcloud.go  ...        │
   │                                                    │
   │  manager.go                                        │
   │    zone routing (longest-suffix)                   │
   │    reconcile queue + retry/backoff                 │
   └───────┬───────────────────────────────┬───────────┘
           │                               │
   record management                 DNS-01 solver
           │                               │
  service_add / service_remove      ACME order (x/crypto/acme)
  (hook in modules/ztagents)         UpsertTXT / DeleteTXT
           │                               │
           ▼                               ▼
   A/AAAA/CNAME at provider        _acme-challenge TXT at provider
```

The DNS subsystem is **server-side**. The server knows its own public
address and centrally holds provider credentials. The agent at most
sends a *hint* (§7); it never calls a provider API.

## 3. The Provider interface

```go
// Provider is one DNS provider account. Implementations are stateless
// apart from an API client + credentials.
type Provider interface {
    Name() string
    // Zones this provider is authoritative for (from config).
    Zones() []string

    // Record management.
    UpsertRecord(ctx context.Context, zone, name, rtype, value string, ttl int) error
    DeleteRecord(ctx context.Context, zone, name, rtype string) error

    // ACME DNS-01.
    UpsertTXT(ctx context.Context, zone, name, value string) error
    DeleteTXT(ctx context.Context, zone, name string) error
}
```

`name` is the FQDN of the record; `zone` is the apex the provider
hosts. Implementations translate to each API's record model (Cloudflare
zone IDs, Route 53 hosted-zone IDs + change batches, etc.) internally.

### 3.1 Per-provider notes

| Provider | Auth | Record API shape |
|----------|------|------------------|
| Cloudflare | scoped API token (`DNS:Edit` on the zone) | `PUT /zones/{id}/dns_records` |
| Route 53 | access key + secret (or IAM role) | `ChangeResourceRecordSets` batch |
| Google Cloud DNS | service-account JSON | `changes.create` |
| DigitalOcean | API token | `/v2/domains/{d}/records` |
| Azure DNS | service principal | `recordsets` PUT |

Each provider file is self-contained: an HTTP client, request signing,
and error mapping. No shared SDK — keeps `go.mod` lean.

## 4. The manager

`manager.go` is the only thing the rest of the server talks to.

### 4.1 Zone routing

A hostname is matched to a provider by **longest-suffix** zone match.
`api.eu.example.com` with zones `example.com` (provider A) and
`eu.example.com` (provider B) → provider B. A hostname under no
configured zone is **skipped** (logged at debug) — the proxy never
touches DNS it was not told it owns.

### 4.2 Reconciliation queue

Record management must never block or fail service registration. The
manager owns a small worker:

```
service_add  ─▶ enqueue{op:upsert, host, type, value}
service_remove ─▶ enqueue{op:delete, host, type}
                       │
                 worker goroutine
                       │  dequeue
                       ├─ route to provider by zone
                       ├─ call Upsert/DeleteRecord
                       └─ on error: retry with backoff
                          (max N attempts, then drop + metric)
```

The queue is buffered; if it is full the enqueue is dropped with a
metric rather than blocking the `service_add` handler. Operations are
**idempotent** — `UpsertRecord` twice yields one record — so a retry or
a duplicate enqueue is safe.

### 4.3 Record value

`A`/`AAAA` records point at `dns.public_address`. When omitted, the
manager auto-detects it once at startup (outbound UDP socket
`LocalAddr` trick, or an external echo) — but explicit config is
preferred and logged as such. A per-service hint may override the
target or force a `CNAME` (§7).

## 5. DNS-01 ACME

### 5.1 Why DNS-01

HTTP-01 (today, via `autocert`) cannot issue **wildcard** certs and
needs port 80 reachable. DNS-01 proves control by writing a TXT record
and works for `*.example.com`.

### 5.2 The ACME-library problem

`golang.org/x/crypto/acme/autocert` has **no DNS-01 hook**. `autocert`
currently gives the project, for free:

- automatic renewal scheduling,
- the on-disk certificate cache (`autocert.DirCache`),
- OCSP stapling.

Doing DNS-01 means dropping to the lower-level
`golang.org/x/crypto/acme` client and **driving the order manually**:
`AuthorizeOrder` → for each authz, `GetChallenge("dns-01")` →
`DNS01ChallengeRecord` → `UpsertTXT` → `Accept` → poll → `CreateOrderCert`
with a CSR. None of renewal, cache, or OCSP comes along — they must be
**rebuilt**. This is the single biggest cost in the phase and the
reason it sits at the upper end of the `L` estimate.

Alternative: `go-acme/lego` — turnkey, but a large dependency that
ships its own DNS-provider set overlapping `internal/dns`.

**Recommendation:** drive `x/crypto/acme` directly, reuse
`internal/dns` for the TXT records (one provider abstraction), and
budget explicitly for a small `internal/server/acme` that re-adds the
renewal timer + a cert cache. *Roadmap decision #4.*

### 5.3 Solver flow

```
need cert for *.example.com
        │
  acme client: AuthorizeOrder(["*.example.com"])
        │  authz → dns-01 challenge
        │  rec := DNS01ChallengeRecord(token)
        ▼
  manager.UpsertTXT(zone, "_acme-challenge.example.com", rec)
        │  wait for propagation (poll the authoritative NS)
        ▼
  acme client: Accept(challenge); poll authz → "valid"
        │
  CreateOrderCert(CSR)  → leaf + chain
        │
  manager.DeleteTXT(...)             ← cleanup
  store cert (cache) + schedule renewal at NotAfter - 30d
```

Renewal: a timer per cert fires before expiry and re-runs the flow.
The cert cache persists issued certs across restarts (replacing
`DirCache`).

## 6. Server configuration

```yaml
dns:
  enabled: true
  public_address: "203.0.113.10"     # A/AAAA target; auto-detected if ""
  manage_records: true
  record_ttl: 300
  acme_challenge: dns-01             # http-01 | dns-01

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
```

Validation: provider `type` is known; every `*_env` resolves; `zones`
non-empty and syntactically valid; no two providers claim the same
zone; `acme_challenge: dns-01` requires `tls.mode: acme` and at least
one provider.

## 7. Agent-side hint

Optional, per service — expresses operator intent next to the service;
the server decides whether to honour it.

```yaml
services:
  - id: dashboard
    hosts: ["dash.example.com"]
    dns:
      record_type: A        # A | AAAA | CNAME
      proxied: false        # Cloudflare orange-cloud
      target: ""            # override public_address
```

Forwarded as `DNS *DNSHint` on `types.ServiceConfig` (additive,
`omitempty`). The agent holds no credentials and performs no API call.

## 8. Agent vs server responsibility

| Concern | Owner |
|---------|-------|
| Provider credentials | **Server** (env vars) |
| Knowing the public IP | **Server** |
| Record create/update/delete | **Server** |
| DNS-01 TXT + ACME order | **Server** |
| Expressing record intent | Agent — hint only |

*Roadmap decision #5:* server-side DNS is recommended; the agent only
hints.

## 9. Failure modes

| Condition | Behaviour |
|-----------|-----------|
| Hostname under no configured zone | skipped, debug log — not an error |
| Provider API error | retried with backoff; after N attempts dropped + `ztp_dns_sync_errors_total` |
| Reconcile queue full | enqueue dropped + metric; never blocks `service_add` |
| DNS-01 propagation slow | solver polls the authoritative NS up to a deadline before `Accept` |
| `dns.enabled: false` | subsystem not started; ACME falls back to `http-01` |
| Two services, same host, different agents | idempotent upsert — one record; delete only when the **last** service for the host is removed (refcount in the manager) |

The last row matters with Phase 5 (multi-agent): the manager
refcounts hostnames so a `service_remove` from one agent does not
delete a record another agent still needs.

## 10. Implementation steps

1. **4a — interface + 2 providers.** `provider.go`, `cloudflare.go`,
   `route53.go`, `manager.go` (zone routing). Tests against recorded
   API fixtures.
2. **4b — reconciliation.** Queue + worker + retry/backoff; hook
   `service_add`/`service_remove` in `modules/ztagents`; hostname
   refcount; metrics.
3. **4c — DNS-01.** `internal/server/acme`: drive `x/crypto/acme`,
   wire `UpsertTXT`/`DeleteTXT`, rebuild renewal timer + cert cache;
   wildcard support; integrate into `internal/server/tls.go`.
4. **4d — remaining providers.** `gcloud.go`, `digitalocean.go`,
   `azure.go`.
5. `serverconfig`: `DNSConfig`, `DNSProvider` + validator.
6. `internal/types/service.go`: `DNSHint`; agent forwards it.
7. Docs `docs/server/dns-automation.md` with a per-provider
   least-privilege credential table.

## 11. Concurrency

- The manager worker is a single goroutine draining a buffered channel
  — provider calls are serialized, so no provider client needs to be
  goroutine-safe for writes. (Parallelize per-provider later if
  throughput demands.)
- The hostname refcount map is owned solely by the worker goroutine —
  no lock needed; all mutation is on that one goroutine.
- The ACME renewal timers run independently; cert-cache writes take a
  mutex shared with `tls.go`'s `GetCertificate` reads.

## 12. Security considerations

- **Credential blast radius.** A DNS provider token can repoint any
  record in its zones. Enforce env-var references; document
  least-privilege scopes (Cloudflare: token limited to `DNS:Edit` on
  exactly the configured zone; Route 53: an IAM policy scoped to the
  hosted-zone ARN).
- **Zone ownership guard.** The manager only ever touches a name that
  falls under a configured `zones` suffix. A misconfigured hostname
  cannot cause a write outside owned zones.
- No secrets in logs; provider errors are logged with the API status
  but never the token.

## 13. Testing strategy

- Per-provider: replay recorded request/response fixtures (no live API
  in CI); assert the correct API shape for upsert/delete/TXT.
- Zone routing: longest-suffix selection across overlapping zones; an
  unowned host is skipped.
- Reconciliation: upsert idempotency (twice → one record); a provider
  error does not fail `service_add`; queue-full path drops + counts.
- Refcount: two agents register the same host, one removes — record
  survives; both remove — record deleted.
- DNS-01: issue a cert against the ACME **staging** directory or a
  local Pebble; assert TXT is written then cleaned up; wildcard issued.
