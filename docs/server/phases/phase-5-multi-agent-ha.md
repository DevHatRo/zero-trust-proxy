# Phase 5 — Multi-Agent HA & Cross-Agent Load Balancing

> Detailed architecture. Parent: [feature-roadmap.md](../feature-roadmap.md).
> Status: proposed. Refactors the request hot path — land when the
> earlier phases are stable.

## 1. Goal

Today `registry.lookupServiceByHost` (`modules/ztagents/registry.go:47`)
ranges the agent map and returns the **first** agent that has the host.
Go map iteration is randomized, so with two agents registering the same
hostname the winner is nondeterministic, and there is no failover if
that agent's connection is broken.

This phase makes one hostname servable by **N agents** with:

- health-aware **load balancing** (round-robin / random / least-conn),
- **failover** to another healthy agent when dispatch fails,
- server-driven **health tracking** via ping/pong.

> Scope: this is **cross-agent** balancing. The agent already does
> **upstream** balancing *within* a service (`LoadBalancingConfig` in
> `internal/agent/config.go`). That lower layer is untouched.

## 2. Architecture

```
   request ──▶ ztrouter.ServeHTTP
                   │
                   ▼
            registry.pickAgent(host)         ◀── host→[]*Agent index
                   │                             + Picker strategy
                   │                             + health filter
          ┌────────┴─────────┐
          ▼                  ▼
   chosen agent        failover loop (handler.go)
   dispatch ──fail──▶  pick next healthy agent, retry
          │                  │  (guarded — §6)
          ▼                  ▼
     response            give up → 502/503
```

Three new pieces:

- **host index** — `registry` gains `byHost map[string][]*Agent`.
- **Picker** — a strategy interface over the healthy agents for a host.
- **health tracker** — a per-agent ping ticker + missed-pong counter.

## 3. Data model

### 3.1 Registry (`modules/ztagents/registry.go`)

```go
type registry struct {
    mu     sync.RWMutex
    agents map[string]*Agent       // existing: agentID → Agent
    byHost map[string][]*Agent     // NEW: hostname → agents serving it
    picker Picker                  // NEW: selection strategy
}
```

`byHost` is maintained in lockstep with service changes — it is a
**derived index**, never the source of truth. Every path that mutates
an agent's `Services` map also updates `byHost`:

- `service_add` → append the agent to `byHost[host]`.
- `service_remove` → remove the agent from `byHost[host]`.
- agent disconnect → remove the agent from every `byHost` slice it is
  in.

All of this happens under the existing `registry.mu` write lock — **no
new lock, no new lock ordering** (the project has a history of races
around `Agent.writeMu` / `ResponseHandlers`; do not add a second
mutex).

### 3.2 Agent health & load (`modules/ztagents/agent.go`)

```go
type Agent struct {
    // ... existing ...
    healthy     atomic.Bool   // false → excluded from pickAgent
    missedPongs atomic.Int32  // consecutive unanswered server pings
    inFlight    atomic.Int64  // active dispatches (for least_conn)
    lastPong    atomic.Int64  // unix nanos, for diagnostics
}
```

All atomics — read on the hot path (`pickAgent`) without taking
`registry.mu`, written by the health goroutine and the dispatch path.

### 3.3 Picker

```go
type Picker interface {
    // Pick returns one agent from candidates (already health-filtered
    // and non-empty), plus the remaining candidates for failover.
    Pick(candidates []*Agent) (chosen *Agent, rest []*Agent)
}
```

Implementations: `roundRobinPicker` (an atomic counter mod len),
`randomPicker`, `leastConnPicker` (min `inFlight`). `rest` is ordered
so the failover loop tries the next-best agent.

## 4. Selection flow

```
pickAgent(host):
    registry.mu.RLock()
    all := byHost[host]                 // copy the slice header
    registry.mu.RUnlock()

    healthy := filter(all, a => a.healthy.Load())
    if len(healthy) == 0:
        if len(all) > 0: return one anyway (last resort) — log "all unhealthy"
        return nil, false               // → 503 No agent for host

    chosen, rest := picker.Pick(healthy)
    return chosen, rest, true
```

The slice read is done under `RLock` and copied so the picker and the
failover loop work on a stable snapshot — an agent disconnecting
mid-request does not mutate the slice the router is iterating.

`lookupServiceByHost` keeps its signature for the per-service config
(timeout overrides) but is re-expressed on top of `pickAgent`.

## 5. Health tracking

A single server-side goroutine (started in `App.Start`) drives health
for all agents:

```
every health.ping_interval:
    for each agent in registry.snapshot():
        agent.SendMessage(ping{id: <uuid>})
        agent.missedPongs.Add(1)         // optimistically count as missed
    on pong received (handle.go "pong" case):
        agent.missedPongs.Store(0)
        agent.healthy.Store(true)
        agent.lastPong.Store(now)
    after sending, sweep:
        if agent.missedPongs >= health.max_missed_pongs:
            agent.healthy.Store(false)   // excluded until a pong arrives
```

The `pong` message type already exists; today the **server answers**
agent pings (`handle.go:137`). This phase adds the **server-initiated**
direction — the agent must already answer inbound `ping` (it does), so
no agent change is strictly required.

A flapping agent (recovers, fails, recovers) is handled naturally:
`healthy` tracks the latest state; `pickAgent` reads it per request.

## 6. Failover

In `modules/ztrouter/handler.go`, dispatch becomes a bounded loop:

```
chosen, rest := pickAgent(host)
attempts := []*Agent{chosen} ++ rest      // capped at failover.max_attempts
for i, agent := range attempts:
    err := dispatch(agent, ...)
    if err == nil:                 return       // success
    if not canFailover(...):       return error // see guard below
    log "failover", try next
return 502 Bad Gateway                            // all attempts failed
```

### 6.1 The failover guard — three mandatory conditions

A request may be retried on the next agent **only if all three** hold:

1. **Nothing has been written to the client yet.** Once
   `w.WriteHeader` / a body write has happened, the status line is
   gone — a retry would corrupt the response.
2. **The client connection has not been hijacked.** WebSocket upgrades
   (`handleWebSocketUpgrade`) and streaming downloads
   (`handleDownloadStream`) hijack the `net.Conn`. After a hijack
   there is no `http.ResponseWriter` to fall back through — even a
   pure connect-level error on the retry cannot be recovered cleanly.
3. **The failure is a connect/establish error** — `SendMessage`
   returned a write error, or the agent connection is known broken.
   A timeout *after* the request was accepted by the agent is **not**
   retried (the agent may have side-effected the backend).

```go
func canFailover(wroteHeader, hijacked bool, err error) bool {
    return !wroteHeader && !hijacked && isConnectError(err)
}
```

Non-idempotent methods (`POST`, etc.) are safe under this guard
*specifically because* condition 3 limits retries to failures that
happened before the agent could have touched the backend.

### 6.2 least-conn counter discipline

`leastConnPicker` reads `agent.inFlight`. The dispatch path must:

```go
agent.inFlight.Add(1)
defer agent.inFlight.Add(-1)   // MUST be deferred
```

The decrement is **deferred** so it runs even on a panic or an early
`return` in `ServeHTTP` (streaming, timeout, client-gone). A missed
decrement permanently biases the picker away from a healthy agent.

## 7. Configuration

```yaml
router:
  request_timeout: 2m
  balancing: round_robin        # round_robin | random | least_conn
  health:
    ping_interval: 15s
    max_missed_pongs: 3
  failover:
    enabled: true
    max_attempts: 2
```

Agent (optional): a per-service `weight` for weighted balancing,
forwarded as `Weight int` on `types.ServiceConfig`.

Validation: `balancing` is a known strategy; `ping_interval > 0`;
`max_missed_pongs ≥ 1`; `max_attempts ≥ 1`. All of `router.*` except
the listen-affecting fields are SIGHUP-reloadable (the picker strategy
can be swapped live; the health goroutine re-reads the interval).

## 8. Agent vs server responsibility

| Concern | Owner |
|---------|-------|
| Running N agents for one host | Operator — just register the same host from each agent |
| Answering server `ping` | Agent (already does) |
| Health tracking, marking unhealthy | **Server** |
| Selection / balancing | **Server** |
| Failover | **Server** |
| Optional `weight` | Agent — hint forwarded in `service_add` |

No new agent behaviour is required for hot/hot; `weight` is the only
optional addition.

## 9. Concurrency analysis

- `byHost` mutations and reads share `registry.mu` with the existing
  `agents` map — one lock, existing ordering, no deadlock surface
  added.
- `pickAgent` copies the candidate slice header under `RLock`, then
  releases the lock before calling the picker — the hot path holds the
  lock for microseconds.
- `healthy` / `missedPongs` / `inFlight` are atomics — read in
  `pickAgent` without any lock.
- The health goroutine only *reads* the registry (`snapshot()`) and
  writes per-agent atomics — it never takes `registry.mu` for write.
- Failover reuses the existing per-request `ResponseHandlers`
  discipline: each attempt gets its own `msgID` and its own handler,
  removed by the router's `defer` (`TakeResponseHandler`) — no handler
  leak across attempts.
- `-race` must cover: `pickAgent` vs `service_add`/`service_remove` vs
  agent disconnect vs the health sweep, all concurrent.

## 10. Failure modes

| Condition | Behaviour |
|-----------|-----------|
| All agents for a host unhealthy | last-resort pick one + log; still attempt (better than a hard 503) |
| No agent for a host at all | 503 (unchanged) |
| Chosen agent fails, guard allows | retry next, up to `max_attempts` |
| Chosen agent fails, response already streaming | no retry — connection closed, client sees a truncated response (unavoidable) |
| Agent disconnects mid-request | that request fails; the failover loop may catch it if the guard holds |
| `failover.enabled: false` | `pickAgent` still load-balances; a dispatch failure is a single 502 |

## 11. Implementation steps

1. `registry.go`: add `byHost`; maintain it on every add/remove/
   disconnect path; `pickAgent`; re-express `lookupServiceByHost`.
2. `agent.go`: add `healthy`/`missedPongs`/`inFlight`/`lastPong`
   atomics.
3. `Picker` interface + `roundRobin`/`random`/`leastConn`.
4. Health goroutine in `App.Start`; `pong` handling updates atomics;
   `App.Stop` stops it.
5. `handler.go`: failover loop + `canFailover` guard; `inFlight`
   inc/deferred-dec around dispatch.
6. `serverconfig`: `balancing`/`health`/`failover` + validator;
   `reload.go` classification.
7. Metrics: `ztp_agents_healthy`, `ztp_failover_total{result}`,
   `ztp_agent_inflight` gauge. Docs `docs/server/multi-agent-ha.md`.

## 12. Testing strategy

- **Index integrity** — property test: after any sequence of
  add/remove/disconnect, `byHost` exactly matches the union of agents'
  `Services`.
- **Strategies** — round-robin distributes evenly; least-conn picks
  the lowest `inFlight`; random is roughly uniform.
- **Health** — an agent missing `max_missed_pongs` is excluded from
  `pickAgent`; a later pong re-includes it.
- **Failover** — chosen agent's connection is broken → request lands
  on the next agent; assert `ztp_failover_total` incremented.
- **Guard** — once the response body has started, a forced failure is
  **not** retried; a hijacked (WebSocket) request is **not** retried.
- **Counter discipline** — after a panic / early return / client-gone,
  `inFlight` returns to its baseline (deferred decrement).
- `-race` across `pickAgent`, service churn, disconnects, and the
  health sweep concurrently.

## 13. Out of scope

- **Session affinity / sticky routing.** Cross-agent round-robin can
  break a backend that holds per-connection session state. Documented
  limitation; affinity-by-client-IP is a possible later option.
- Cross-replica coordination — each proxy replica tracks health
  independently.
- Weighted *health* (degraded vs healthy) — health is binary for v1.
