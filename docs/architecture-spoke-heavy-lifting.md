# Architecture Plan — Spokes Do the Heavy Lifting, Hub is a Reporting + Control Plane

> Status: **DRAFT / planning** (not yet implemented). Companion to
> `unified-443-hub` and the scaling findings from the 2026-07 load-test exercise.

## 1. Goal & principle

Push **all domain heavy-lifting to the spokes** (every spoke module), and reduce
the hub to two jobs:

1. **Reporting** — render fleet views from spoke-supplied **summaries**; fetch
   **detail on demand** when an operator drills into a specific spoke.
2. **Centralized control** — configuration push, command routing, approvals,
   key/tenancy management.

> One-liner: **spoke = worker (ingest → aggregate → summarize → delta → serve
> detail); hub = merge summaries + serve + command/config center.**

This is not a new architecture — it is the *original* one. The system drifted to
**relay mode** (spokes forward raw frames; the hub shapes them), which is why one
hub loop hits the ceilings below.

## 2. Why (the load-test findings)

A single hub is **one asyncio loop = one core**, and it holds all state in RAM.
Empirically it dies two ways under load:

| Ceiling | Cause (all trace to relay-mode) | Symptom observed |
|---|---|---|
| **RAM** | hub holds `fleet × clients` of *detail* resident (`simulations_cache`) | 100% mem + paging at ~800 synth spokes × 50 clients |
| **Read-path** | hub re-shapes the whole fleet per UI request on the loop (`service.py` shapers) | UI hangs while ingest is busy; recovers when load stops |
| **Ingest CPU** | full raw snapshots parsed/verified per frame | ~10–20K msg/s single-core (binds last) |

Restoring the spoke-as-worker boundary **removes the cause** of the first two
rather than guarding against them.

## 3. Target responsibilities

### Spoke (every module: cs/simulation, pxmx, dns, dhcp, netbox, opnsense, cppm, ldap, nw, le)
- **Near-realtime ingest** of local/agent data (agent ↔ spoke stays a firehose —
  it's LAN-local and cheap; it must never cross to the hub raw).
- **Own the detail** — maintain full per-entity state locally (source of truth
  for its domain).
- **Pre-process** — aggregate hosted agents, dedup, compute rollups.
- **Emit two channels to the hub** (see §4).
- **Serve detail on demand** to the hub (`request_response`) for drill-ins.
- **Honor backpressure** — conflate under pressure, send on relief.
- **Apply** hub config/commands.

### Hub
- Hold **per-spoke summaries** only → resident data becomes `O(spokes)`.
- **Render reporting** from summaries; **route drill-ins** to the owning spoke.
- **Config center** — push per-tenant/module config (already exists:
  `push_config_to_spoke` / `CS_CONFIG_UPDATE`).
- **Command center** — route commands to spokes/agents (already exists:
  `request_response` / relay).
- **Approvals / keys / tenancy** (already exists).
- **Self-protect** — admission control + memory guard + slow-down signal (the
  safety net; §7 Phase 1).

## 4. The two spoke→hub channels

1. **Heartbeat — realtime, tiny.** Liveness only. *Already exists* — unchanged.
2. **Pre-processed data — compact, delta-based, lower cadence.**
   - **Summary payload**: rollups the fleet views need (counts, health, tier
     distribution, VM/USB counts, error rollups) — NOT per-entity detail.
   - **Delta encoding**: split each record into **static facts** (hostname,
     platform, simulation_id, vmid, config — sent once / on change) vs
     **volatile fields** (online, last_seen, error_count — per tick). A ~2KB
     client record becomes a ~40-byte delta.
   - **Detail-on-demand**: the hub asks the owning spoke for full detail only
     when a user opens that spoke's view.

## 5. Shared framework (core) + per-module hooks

Because all spoke modules share `BaseControlPlane` / `BaseSpoke`, the
summary/detail/delta/backpressure machinery lives **once in core**, with
per-module hooks:

```
# core (shared): sequencing, resync, delta apply, backpressure, on-demand detail
class SummarizingSpokeMixin:
    def build_summary(self) -> dict:        # module implements
    def build_detail(self, selector) -> dict:  # module implements (drill-in)
    def apply_backpressure(self, level): ...   # conflate/slow cadence
    # core owns: seq numbers, full-resync-on-reconnect, delta framing, send loop
```

- **cs/simulation** summarizes clients/VMs/USB; detail = per-client / per-VM rows.
- **pxmx** summarizes nodes/VMs; detail = per-VM config.
- **netbox/dns/dhcp/...** each summarize their domain; detail on demand.

The hub side is symmetric: a generic **summary store** keyed by spoke + a generic
**drill-in router**; module-specific rendering reads the summary/detail blobs.

## 6. Sync protocol (the honest complexity)

The hub's copy becomes a **materialized view maintained by a change stream**
(replication / CDC). Required machinery:

- **Sequence numbers** per spoke stream; hub detects gaps.
- **Full re-baseline** on: spoke connect/reconnect, hub restart, detected gap, or
  a periodic interval. (Stateless snapshots never needed this — it's the price.)
- **Idempotent apply** + ordering on the hub.
- **Drill-in** = live round-trip to the spoke; **offline fallback** = last-known
  summary + "detail unavailable (spoke offline)".

## 7. Backpressure & self-protection (survive the ceiling)

- **Spoke conflation**: under the hub's slow-down signal, accumulate the delta
  locally and send one consolidated update on relief (latest-wins).
- **Hub slow-down signal**: `TELEMETRY_BACKOFF` / `RESUME` with hysteresis
  (high/low watermarks on loop-lag or inbound depth). Replaces the rate
  limiter's silent *drop* with a *throttle* (no data loss).
- **Hub admission control**: heavy data endpoints fast-return `503 + Retry-After`
  before shaping when overloaded; WebUI honors it and backs off polling.
- **Hub memory guard**: at a memory watermark, enter *protect mode* — reject new
  spoke connections, stop growing the summary store, surface the state. The hub
  **sheds instead of paging to death**; the shed-point becomes the observable,
  repeatable ceiling.

## 8. Phased delivery

- **Phase 0 — contracts + safety net.** Define summary/detail/delta/seq message
  contracts in core. Ship hub self-protection (§7) FIRST so the fleet survives
  during migration. *(Deliverable: the two payload shapes + admission/memory guard.)*
- **Phase 1 — cs reference implementation.** Migrate cs/simulation (the module
  that caused the pain): move `service.py` shaping to the spoke; hub holds cs
  summaries; drill-in fetches detail. Validate with the load-test harness
  (`scripts/loadtest_spokes.py`) — confirm RAM is now `O(spokes)` and the UI
  no longer hangs.
- **Phase 2 — roll out.** Each remaining module implements `build_summary` /
  `build_detail`. Hub renders from summaries per module.
- **Phase 3 — retire hub shapers.** Remove the hub-side read shaping once every
  module supplies summaries; hub read-path becomes summary-only.

Backward-compat during 1–3: the hub accepts **both** old raw relay and new
summary from mixed-version spokes (version gate), so rollout is incremental.

## 9. Validation

- The **load-test harness** is the measurement + regression tool. Success =
  push past the old ceiling and see the hub **shed (protect mode) not die**, and
  RAM/read-path scale with `O(spokes)` not `O(spokes × clients)`.
- Record **per-spoke summary RSS** → fleet ceiling = `usable_RAM ÷ per-spoke-summary-RSS`
  (much higher than today's per-spoke-*detail*-RSS).

## 10. Open questions

- Summary cadence + delta vs periodic full — per module?
- Drill-in caching (hub caches last detail fetch for N seconds?).
- Where does cross-module fan-out (global search, IPAM↔NAC sync) fit — summaries
  or on-demand?
- Does this compose with a future datastore (Phase-0 of the *other* roadmap), or
  make it unnecessary at the target scale?
