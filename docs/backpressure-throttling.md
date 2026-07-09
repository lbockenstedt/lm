# lm — Backpressure, Throttling & Graceful Degradation

The hub's **graceful-degradation control loop**: how a single-core event loop
survives a burst (or a DDoS) without going unresponsive. It throttles the
offending spoke first, backs off the whole fleet only if that wasn't enough,
pushes the merge work down to the spokes, and — as a last resort — sheds and
disconnects the loudest talkers. Every value here is read from the source; the
authoritative behaviour contracts live in
`core/tests/test_backpressure_ladder.py` (16 tests, cited per-guarantee in §10).

> Companion to [architecture-spoke-heavy-lifting.md](architecture-spoke-heavy-lifting.md)
> (the "spokes do the heavy lifting" principle) and [lm-hub.md](lm-hub.md).

---

## 1. Problem — why it exists

The hub is **one `asyncio` event loop = one core**. Every inbound frame costs
CPU on that one loop, and the two dominant costs are **`json.loads` of the frame
body** and the **HMAC-SHA256 verify** over its bytes. Together they are the
**parse-bound ceiling**: the loop can only parse+verify so many frames/second
before the tick starts returning late (loop-lag) and the WebUI/heartbeats
starve.

The crucial consequence: **coalescing happens AFTER parse.** By the time the hub
can merge two telemetry snapshots latest-wins, it has already paid the
`json.loads` + verify for both. So merging *reduces downstream work* but **cannot
relieve a parse-bound core** — the only thing that relieves the ceiling is
**not reading the frame at all** (pre-parse byte shed) or **closing the socket**
(source shed). This asymmetry is the reason the ladder is shaped the way it is,
and why running the ladder's own `O(spokes)` work under protect mode was what
"took the hub unresponsive at ~800 spokes" (`test_backpressure_ladder.py`
module docstring).

Design goals, in priority order:

1. **Graceful degradation** — throttle softly and keep the fleet *usable* under
   load instead of dropping everything.
2. **Offender-first, then fleet** — slow the loud talker(s) first; back off the
   whole fleet only if the aggregate is still hot. Spare quiet infra spokes.
3. **Push work to the spoke** — a throttled spoke coalesces/merges its own
   outbound updates locally and slows its send cadence. The hub does not do the
   merge work if it can avoid it (the whole point of the platform, see
   `architecture-spoke-heavy-lifting.md`).
4. **DDoS resistance** — a client that ignores the slow-down and keeps flooding
   is disconnected + quarantined so the hub stops spending parse+verify on it.

The whole system is **default-ON** (`backpressure.enabled = True`), tunable live
(each 1s tick re-reads config, no deploy), and its most aggressive levers
(DDoS disconnect) are **default-OFF** until the whole fleet speaks the protocol.

---

## 2. Message classification

Every frame belongs to one of three classes. The policy table is
`LabManagerHub._MSG_CLASS_DEFAULT` (`main.py:773`), config-overridable via
`global_config["backpressure"]["classes"]` (type → class), and resolved by
`_classify_message(payload_type, has_corr)` (`main.py:781`):

| Class | Meaning | Default types |
|---|---|---|
| **`must`** | Never dropped or coalesced — acks, replies, load-test probes. | `COMMAND_RESULT`, `LOADTEST_PROBE`, **and ANY frame carrying a `correlation_id`** (regardless of type — a reply someone is waiting on is never coalesced). |
| **`coalesce`** | Latest-wins, mergeable under pressure. | `CS_TELEMETRY`, `SPOKE_LOG` |
| **`skippable`** | A few may be dropped under pressure. | `HEARTBEAT` |

An unknown type defaults to `coalesce` (`main.py:792`). The
**correlation-id override is absolute**: `_classify_message(..., has_corr=True)`
returns `"must"` before it even looks at the type
(`test_classification`).

> **Accuracy note.** `_classify_message` is the canonical, unit-tested *policy*
> and the config surface, but the hot receive loop does **not** call it
> per-frame — it enforces the same classification *structurally* (and more
> cheaply) inline: correlation-bearing acks are handled + `continue`d before the
> rate limiter; `LOADTEST_PROBE` is handled above the limiter to *prove* survival
> (`main.py:3134`); `CS_TELEMETRY`/`SPOKE_LOG` route to the coalesce buffer; and
> heartbeats are handled/counted separately. The method exists so the policy is
> a single testable source and a config knob.

---

## 3. The escalation ladder

The ladder runs once per **1s tick** in `run_mps_loop`, which calls
`_apply_backpressure_ladder(loop_lag)` (`main.py:3756`) *after* per-spoke msg/s
is computed (so it can name the loud talkers). It signals only the **delta** —
`LM_BACKPRESSURE` is sent on a level change or a material interval change, never
every tick — so it never spams. `_load_level` is exposed in `/status`
(`0` normal · `1` offenders-throttled · `2` fleet-throttled · `3` hub-coalescing/protect).

The rungs, in order:

### Rung 1 — offender-first (`_load_level = 1`)
A single spoke whose measured rate is over `per_spoke_soft_mps` (**default 50/s**)
**or** that breached its TokenBucket this tick (`_rl_breached`, see §4) is an
**offender**. It's signalled `LM_BACKPRESSURE level=1` and told to coalesce
locally at `coalesce_min_interval_s` (**default 2s**). Fleet stays calm
(`test_rung1_offender_first_fleet_calm`).

### Rung 2 — fleet-wide slow-down (`_load_level = 2`)
Only if the **aggregate** is still hot does every *loud* spoke get slowed. Fleet
is tripped (hysteresis) by **any** of three signals (`main.py:3841`):

- **hub-process CPU** ≥ `fleet_cpu_soft` (**default 55 %/core**) — the earliest,
  truest saturation signal. This catches a *distributed* load: many spokes each
  *under* the rung-1 offender mark that together peg the core. That case ground
  the hub to 100 % with **nothing** throttled before CPU was added as a trip
  (`test_rung2_fleet_on_cpu_distributed_load`).
- **loop-lag** ≥ `fleet_lag_soft_s` (**default 0.15s**) — the tick returns late
  (`test_rung2_fleet_on_loop_lag`).
- **mps** ≥ `fleet_soft_mps` (**default 4000/s**) — raw throughput near the
  ceiling.

Fleet **clears** only when *all three* are calm: CPU ≤ `fleet_cpu_clear`
(**40**), lag ≤ `fleet_lag_clear_s` (**0.06**), and mps < `fleet_soft_mps * 0.6`.

**Loudest-first + fleet floor (spare the quiet).** Spokes are processed
**sorted by measured rate descending** (`main.py:3882`) so the per-tick signal
cap hits the loud talkers first (not connection order). Under fleet mode a spoke
is only throttled if its rate ≥ `fleet_min_mps` (**default 5/s**) — quiet infra
spokes at ~0.1/s are **never** touched
(`test_fleet_spares_quiet_spokes_and_throttles_loud`).

**Adaptive coalesce interval.** The interval a *fleet*-throttled spoke is asked
to conflate to scales **linearly** with CPU: `coalesce_min_interval_s` at
`fleet_cpu_soft` up to `coalesce_max_interval_s` (**default 15s**) at
`fleet_cpu_hard` (**default 85 %/core**) — `main.py:3865`. The hotter the hub,
the **harder** it pushes the fleet down (staler telemetry, but CPU stays out of
protect). It **re-signals** on a material interval change, so it is not a
one-shot (`test_adaptive_fleet_interval_scales_with_cpu`: 55 %→interval ≈ 2.0s,
85 %→interval ≥ 14.0s, re-sent).

### Rung 3 — hub-side coalesce drain (`_load_level ≥ 3` under protect)
The safety net for the *in-flight* burst before the spoke's slow-down lands.
When a spoke is in `_spoke_backoff`, its inbound `CS_TELEMETRY` is dropped into
`_coalesce_pending[sid] = (data, ts)` **latest-wins** (a prior un-drained
snapshot is merged away and counted) instead of ingested inline
(`main.py:3202`). `run_coalesce_drain_loop` (`main.py:4079`) then processes
**at most one latest snapshot per spoke** per cycle, **budgeted and time-boxed**
(§4/§8). Real merge work still belongs on the spoke; this only catches the burst.

### Rung 4 — protect mode → §5.

### Release damping (anti-flap)
A throttled spoke's *measured* rate collapses (it's coalescing), so it naturally
falls below the clear mark — evaluating release on that suppressed rate would
flap throttle↔release every window. So once throttled a spoke is **held for
`release_dwell_s` (default 20s)** before release is even considered, and only
released then if it has *genuinely* gone quiet
(`test_rung1_damping_holds_then_releases`). New offenders still engage
**instantly** — ramp down fast, release slow.

The ladder emits **one** WARNING summary line on any change of the throttled set
or fleet state (→ WebUI Logs view), naming the offenders; no change → silent
(`main.py:3934`).

---

## 4. Per-spoke rate limiting (TokenBucket)

Each connection gets a `TokenBucket(capacity, fill_rate)` (`main.py:287`),
created on every (re)connect from `_rate_limit_params()` (`main.py:4520`):

- **`capacity` (burst) — default 400**
- **`fill_rate` — default 200 msg/s**

Refills `fill_rate` tokens/sec up to `capacity`; `consume()` debits one token or
returns `False`. This is a **flood guard, not a shaper** — it sits well above any
legitimate spoke's peak (a relay spoke fanning many hosted agents + a reconnect
re-flush can legitimately burst to tens of msg/s). Aggregate overload (many
spokes each *under* this limit) is the **fleet** layer's job, not this bucket.

> **Stale-comment caveat.** The connect-site comment at `main.py:2809` still says
> "default burst=10 / 5 msg/s"; the *actual* default enforced by
> `_rate_limit_params` is **400 / 200** (`main.py:4536`). Trust the code.

Two watermarks, checked per non-correlation frame in the receive loop
(`main.py:3165`):

- **80 % soft watermark → signal.** When `tokens ≤ (1 − rl_soft_fraction) ×
  capacity` (i.e. ≥ 80 % of the burst consumed, `rl_soft_fraction` **default
  0.8**), the spoke is added to `_rl_breached`. On the next tick the ladder
  treats it as an **instant offender** and *tells it to slow down* — proactively,
  ahead of the 10s-average mps (`test_bucket_breach_triggers_slowdown_under_mps_mark`).
  This is the earliest, most precise offender detector. `_rl_breached` is
  snapshotted and cleared each tick (`main.py:3771`).
- **100 % hard limit → drop.** `consume()` returns `False` → the frame is
  dropped and counted in both `rate_limit_drops` (observability) and
  `_rl_harddrops` (per-tick, feeds DDoS).

**The contract:** *a correct client honors the 80 % signal and never reaches
100 %. A client that keeps hard-dropping after being told to slow is
broken or hostile* (`main.py:742`).

**DDoS escalation (`ddos_disconnect`, DEFAULT OFF).** In the ladder
(`main.py:3958`), a spoke that is **both** hard-dropping ≥ `ddos_min_harddrops`
this tick (**default 20**) **and** currently under throttle (`new_backoff`) has a
non-compliance clock started (`_noncompliant_since`). If it stays non-compliant
for `ddos_grace_s` (**default 30s**), `_disconnect_and_quarantine`
(`main.py:3988`) closes its socket with WS code **1013** ("Flooding after
slow-down — quarantined") and quarantines it for `quarantine_s` (**default
120s**). The clock is cleared the moment it stops flooding
(`test_ddos_stop_flooding_clears_clock`), so a compliant spoke's brief burst
self-corrects and never disconnects. Default-off because a *legacy* spoke that
can't honor `LM_BACKPRESSURE` would keep hard-dropping and get killed
(`test_ddos_disabled_by_default_never_disconnects`).

**Quarantine** (`_is_quarantined`, `main.py:4010`) is a monotonic-deadline dict,
pruned on read. A quarantined spoke is **refused reconnect** with WS 1013 in
`handle_connection` (`main.py:2688`) until the cooldown expires, so it can't
just reconnect and resume the flood (`test_quarantine_expires`).

---

## 5. Protect mode (the hard shed)

Protect is the OOM/CPU/loop-lag watermark guard in `run_mps_loop`
(`main.py:3650`), with enter-high/leave-low hysteresis + a `min_dwell_s`
(**default 15s**) exit hold. Entered when **any** of:

- memory ≥ `mem_high_pct` (**90 %**),
- loop-lag ≥ `loop_lag_high_s` (**0.75s**),
- hub-process CPU ≥ `cpu_high_pct` (**90 %/core**);

left only when memory ≤ 80 %, lag ≤ 0.25s, and CPU ≤ 70 % *all hold* past the
dwell. (Config subtree: `global_config["protect"]`.)

Two levers, because at a parse-bound core dropping-after-read is not enough:

### Pre-parse byte-size shed (surgical)
At the very top of the receive loop, **before `json.loads`**, a frame is dropped
if it is **large** (`len > shed_bytes`, **default 2048**) **and** its sender is a
**high-offered-rate offender** (`_spoke_offered[sid] ≥ protect_shed_min_mps`,
**default 50/s**) — `main.py:2956`. This is the *only* thing that relieves the
parse-bound ceiling: the expensive parse never happens. It is **surgical** —
small frames (heartbeats/acks < `shed_bytes`) still parse and flow, and legit
**low-rate** spokes' telemetry flows even during protect. The point is to shed
the *flood*, not everyone (an earlier blunt shed dropped real modules' traffic).

### Source shed (disconnect the loudest)
Because "dropping-after-read still costs the READ", the aggressive lever is
`_protect_source_shed` (`main.py:4021`, `protect_shed_source` **default ON**):
each tick it takes the **top-K** (`protect_shed_top_k`, **default 20**) spokes by
**TRUE offered rate** (`_spoke_offered`, counted *before* any shed at
`main.py:2947`) above `protect_shed_min_mps`, closes each socket (WS **1013**
"Hub overloaded — shedding loudest talkers"), and briefly quarantines it
(`protect_quarantine_s`, **default 30s**). Freeing the loop lets real spokes'
heartbeats through (modules stay ONLINE) and keeps `/status` responsive. A
sustained flood self-limits into a survivable sawtooth. Low-rate real modules
are never eligible (`test_protect_source_shed_disconnects_loudest_spares_quiet`),
and it can be disabled (`test_protect_source_shed_can_be_disabled`).

### The ladder stands (mostly) down under protect
When `_protect_mode` is set, `_apply_backpressure_ladder` **early-returns**
(`main.py:3783`): it drops the coalesce buffer (snapshots are superseded anyway)
and does **not** run its full `O(spokes)` signalling — running that here is what
compounded the overload at ~800 spokes. But it does two cheap things first:
still **throttle the loudest talkers** to the max interval (bounded top-K, so the
loud spokes aren't left un-signalled with CPU pegged —
`test_protect_throttles_loudest_spares_quiet`), then **source-shed**. The
`run_coalesce_drain_loop` likewise drops its buffer under protect rather than
running hundreds of ingests (`main.py:4097`).

---

## 6. Spoke-side cooperation

The design pushes the merge work to the spoke. The base handler is
`LMControlPlane.apply_backpressure(level, coalesce, min_interval_s)`
(`core/src/messaging/control_plane.py:1341`), invoked from the `LM_BACKPRESSURE`
command handler (`control_plane.py:1228`). It records the signal
(`_bp_level` / `_bp_coalesce` / `_bp_min_interval`); **domain modules override it
to do the real conflation** (combine adjacent ~identical snapshots, latest-wins).

Any send loop scales its cadence via `_bp_send_interval(base_period)`
(`control_plane.py:1362`) = `max(base_period, _bp_min_interval)` — a no-op when
not throttled. Concretely, the **cs `lm-spoke`** telemetry relay honors it: it
sleeps `self._bp_send_interval(interval)` between `CS_TELEMETRY` frames
(`cs/lm-spoke/src/control_plane.py:374`), so a hub slow-down directly stretches
its send interval.

Signal levels: `0` resume · `1` this spoke is the offender · `2` fleet-wide
(`control_plane.py:1352`). `_signal_backoff` (`main.py:4059`) sends
`{level, coalesce: level>0, min_interval_s, reason}`.

> **Gap to note.** The **cs `webui-spoke`** relay
> (`cs/webui-spoke/lm_relay.py:356`) sleeps a **fixed** `self.telemetry_interval`
> and does **not** yet consult `_bp_send_interval` — so it does not slow under
> `LM_BACKPRESSURE`. Worth wiring for parity (follow-up).

---

## 7. Sig-verify-over-raw-bytes — raising the ceiling (the flag-day)

Because the ceiling is parse+verify CPU, the biggest single win was changing the
wire format so the receiver **verifies the exact received bytes and parses
once**, instead of re-serialising the parsed dict to re-compute the HMAC.

**Wire form: `<sig>.<body>`** (`security/signer.py:24`, `encode_frame`):

- `body` = compact JSON (`separators=(',',':')`), serialized **once**.
- `sig` = `HMAC-SHA256(secret, body_bytes).hexdigest()`, or `""` when unsigned
  (bootstrap heartbeats before the spoke has a key).

**Receiver** (`main.py:2970`): `split_frame` → `json.loads(body)` **once** →
`verify_signature(spoke_id, body_str.encode(), sig)` over those **raw bytes**
(`signer.verify_bytes`, `signer.py:106`). No re-serialization, **no
`sort_keys`** — signing order is irrelevant because the receiver checks the exact
bytes, not a canonical re-serialization. That per-frame `json.dumps` was
"the per-frame json.dumps that dominated hub ingest CPU"
(`signer.py:99`); removing it is the ~30 %-cheaper ingest that **raised the
parse-bound ceiling** the whole ladder defends.

**Flag-day.** The signature is computed over exact bytes, so **sender and
receiver must be byte-compatible** — all four repos must deploy together:

| Repo | Where |
|---|---|
| lm (hub + core spokes) | `core/src/security/signer.py` |
| cs | via vendored `core/` |
| pxmx (agent) | `pxmx/agent/src/security_utils.py` → `agent.py:1877` (verify) / `1242+` (encode) |
| bugfixer (hub agent) | `bugfixer/hub_agent.py:117` (`encode_frame`) / `113` (`verify_bytes`) |

A spoke on the old format sending to a new hub (or vice-versa) would mismatch;
hence the atomic cutover. The agent path even accepts either raw `{…}` or
`<sig>.<body>` defensively (`pxmx/agent/src/agent.py:1830`).

---

## 8. Configuration reference

All knobs live under `global_config["backpressure"]` (ladder) and
`global_config["rate_limit"]` / `["protect"]`, read **fresh each tick** so a
change applies live (no deploy). Defaults are from `_backpressure_params`
(`main.py:794`), `_rate_limit_params` (`main.py:4520`), and the protect guard
(`main.py:3655`).

### Ladder — `global_config["backpressure"]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Master switch; off → resume everyone, no throttling. |
| `per_spoke_soft_mps` | `50` | Rung-1: a spoke over this msg/s is an offender. |
| `per_spoke_clear_mps` | `25` | Release threshold below which a throttled spoke may clear (with dwell). |
| `fleet_cpu_soft` | `55` | Rung-2 engage: hub-process %/core (earliest saturation signal). |
| `fleet_cpu_clear` | `40` | Rung-2 clear (all three must be calm). |
| `fleet_cpu_hard` | `85` | CPU at which throttled spokes are asked for the MAX slow-down. |
| `fleet_lag_soft_s` | `0.15` | Rung-2 engage: loop-lag (s). |
| `fleet_lag_clear_s` | `0.06` | Rung-2 clear: loop-lag (s). |
| `fleet_soft_mps` | `4000` | Rung-2 engage: aggregate msg/s. |
| `fleet_min_mps` | `5` | Under fleet mode, only throttle spokes ≥ this (spare quiet infra). |
| `coalesce_min_interval_s` | `2` | Min slow-down interval (offenders, and fleet at `fleet_cpu_soft`). |
| `coalesce_max_interval_s` | `15` | Max slow-down interval (fleet at `fleet_cpu_hard`). |
| `hub_drain_interval_s` | `1` | Rung-3 drain cadence. |
| `hub_drain_budget` | `100` | Max spokes drained per cycle (rest stay coalesced). |
| `hub_drain_max_s` | `0.1` | Time-box (s) on a drain cycle. |
| `max_signals_per_tick` | `100` | Cap on `LM_BACKPRESSURE` sends/tick (spreads a fleet transition over ticks). |
| `release_dwell_s` | `20` | Hold a throttled spoke this long before considering release (anti-flap). |
| `rl_soft_fraction` | `0.8` | Bucket fraction consumed → 80 % soft-watermark signal. |
| `ddos_disconnect` | `false` | Enable disconnect+quarantine of persistent flooders. |
| `ddos_grace_s` | `30` | How long a signalled spoke may keep hard-dropping before disconnect. |
| `ddos_min_harddrops` | `20` | Min hard-drops/tick to count as flooding. |
| `quarantine_s` | `120` | DDoS reconnect cooldown. |
| `protect_shed_source` | `true` | Under protect, disconnect the loudest talkers. |
| `protect_shed_top_k` | `20` | Max spokes source-shed per tick. |
| `protect_shed_min_mps` | `50` | Only spokes offering ≥ this (frames/s) are shed-eligible. |
| `protect_quarantine_s` | `30` | Short reconnect cooldown for a source-shed spoke. |
| `classes` | (see §2) | Optional `{type: class}` override map. |

### Per-spoke bucket — `global_config["rate_limit"]`

| Key | Default | Meaning |
|---|---|---|
| `capacity` | `400` | Burst — clamped ≥ 1. |
| `fill_rate` | `200` | msg/s refill — clamped ≥ 0.1. |

### Protect guard — `global_config["protect"]`

| Key | Default | Meaning |
|---|---|---|
| `mem_high_pct` / `mem_low_pct` | `90` / `80` | Enter/leave on memory %. |
| `cpu_high_pct` / `cpu_low_pct` | `90` / `70` | Enter/leave on hub-process %/core. |
| `loop_lag_high_s` / `loop_lag_low_s` | `0.75` / `0.25` | Enter/leave on loop-lag. |
| `min_dwell_s` | `15` | Min time in protect before exit (anti-flap). |
| `shed_bytes` | `2048` | Pre-parse shed applies only to frames larger than this. |

### WebUI "Backpressure Tuning" panel (System → Hub Status)
`WebUI/main.js` exposes a subset live: `_BP_DEFAULTS` / `_BP_FIELDS`
(`main.js:2066`), `loadBackpressureConfig` / `saveBackpressureConfig` /
`resetBackpressureConfig`. Save POSTs `{config:{backpressure: merged}}` to
`/setup/config` (a **top-level replace** of the subtree — so Save merges onto the
last-loaded subtree to preserve knobs not shown in the panel, `main.js:2112`).
It applies on the next 1s tick. A light sanity check enforces
`fleet_cpu_clear < fleet_cpu_soft < fleet_cpu_hard` (`main.js:2119`). Panel
fields: the three CPU marks, coalesce min/max, release dwell, per-spoke soft,
fleet-min, protect-shed min/top-k, ddos grace, and the ddos-disconnect toggle.

---

## 9. Observability

- **Per-node throttle badge** — `_renderSpokeAgentRow` (`main.js:1844`): a
  spoke/agent tile shows **⚠ Offending** (level 1, red, pulsing) or **⏳ Throttled**
  (level ≥ 2, orange), read from `backpressure.spoke_levels[id]` in `/status`.
- **Hub Status backpressure line** (`main.js:1975`): level + FLEET/offenders
  label, throttled count, hub-queue depth, and telemetry `received / processed /
  coalesced` (coalesced = "merged latest-wins, **not** dropped").
- **`/status` payload** (`get_system_metrics`, `main.py:4580`): `load_level`,
  `backpressure.{level, fleet, fleet_interval_s, spokes_throttled, spoke_levels,
  quarantined, coalesce_pending, telemetry_received/processed/coalesced}`, plus
  `rate_limit_drops` (per spoke + total) and the live `rate_limit` knobs.
- **Probe counters** — `probe_counts` / `probe_gaps`: the `LOADTEST_PROBE`
  must-process path (`main.py:3134`) proves zero must-process loss even while
  telemetry is being coalesced; a gap here is a real bug.
- **Logs** — the ladder writes one WARNING summary on any throttle-set change
  (→ HubLogHandler → WebUI Logs); DDoS/source-shed events are ERROR + a
  `record_spoke_event` (`ddos_quarantine` / `protect_shed` / `quarantine_reject`).
- **Display grace (unrelated but adjacent):** `is_spoke_in_contact` /
  `spokes_in_contact` (`main.py:1215`) treat a spoke as online if connected *or*
  seen within `display.online_grace_s` (**default 180s**), so a transient loop
  stall or a throttle-induced quiet period never flips a tile offline.
  **Command routing still uses `active_connections` directly** (must be
  live-accurate).

---

## 10. Behaviour guarantees (tested)

Each bullet is a contract in `core/tests/test_backpressure_ladder.py`:

- **Classification** incl. the absolute correlation-id → `must` override —
  `test_classification`.
- **Offender-first, fleet stays calm** — `test_rung1_offender_first_fleet_calm`.
- **Release damping holds then releases** (no flap when a throttled spoke's rate
  collapses) — `test_rung1_damping_holds_then_releases`.
- **Fleet engages on distributed CPU load** (sub-offender spokes pegging the
  core) — `test_rung2_fleet_on_cpu_distributed_load`.
- **Fleet engages on loop-lag** — `test_rung2_fleet_on_loop_lag`.
- **Bucket 80 % breach = instant offender** ahead of the mps average —
  `test_bucket_breach_triggers_slowdown_under_mps_mark`.
- **Under protect: throttle loudest, spare quiet, drop the coalesce buffer** —
  `test_protect_throttles_loudest_spares_quiet`.
- **Fleet spares quiet infra, throttles the loud** —
  `test_fleet_spares_quiet_spokes_and_throttles_loud`.
- **Protect source-shed disconnects top-K loudest + quarantines, spares quiet;
  can be disabled** — `test_protect_source_shed_disconnects_loudest_spares_quiet`,
  `test_protect_source_shed_can_be_disabled`.
- **DDoS: within grace not yet disconnected; sustained → disconnect+quarantine;
  stopping clears the clock; disabled-by-default never disconnects** —
  `test_ddos_flood_within_grace_not_yet_disconnected`,
  `test_ddos_sustained_flood_disconnects_and_quarantines`,
  `test_ddos_stop_flooding_clears_clock`,
  `test_ddos_disabled_by_default_never_disconnects`.
- **Quarantine expires + prunes on read** — `test_quarantine_expires`.
- **Adaptive fleet interval scales with CPU and re-signals** —
  `test_adaptive_fleet_interval_scales_with_cpu`.

---

## 11. Tuning / recommended production values

- **Start with the defaults.** They were calibrated from the 2026-07 load test:
  a single node at ~6000 msg/s pegged CPU while mps/lag were still under the old
  8000/0.30 marks and *nothing* throttled — which is why `fleet_cpu_soft = 55`
  (CPU is the earliest signal) and `fleet_soft_mps` was dropped to 4000.
- **CPU marks are the primary dial.** To keep the hub further from protect at
  scale, **lower** `fleet_cpu_soft` (engage sooner) and/or **raise**
  `coalesce_max_interval_s` (push the fleet down harder → staler telemetry, but
  CPU stays out of protect). Keep `fleet_cpu_clear < fleet_cpu_soft <
  fleet_cpu_hard < 90` (the protect line).
- **Don't use the per-spoke bucket as a shaper.** `rate_limit.capacity/fill_rate`
  (400/200) must stay **above** any legit relay spoke's peak — it's a flood
  guard. Aggregate overload is the fleet layer's job. Raise it as fan-out grows;
  never tune it down to "shape" normal traffic.
- **`fleet_min_mps` protects quiet infra.** Keep it a few × your quietest real
  spoke's rate so DNS/DHCP/LE-style spokes are never throttled.
- **Enable `ddos_disconnect` only once the whole fleet honors
  `LM_BACKPRESSURE`.** Until then a legacy spoke that can't back off would be
  disconnected as a "flooder". Note the **webui-spoke relay gap** (§6) — it does
  not yet honor the signal, so enabling DDoS while it's deployed risks
  disconnecting it under load.
- **`release_dwell_s` trades responsiveness for stability.** Longer dwell =
  fewer flaps but a slower return to full cadence after a burst.
- **Watch `telemetry_coalesced` vs `_processed`.** High coalesced with zero
  `probe_gaps` = the system working as designed (merging, not losing). Any
  `probe_gaps` = a real must-process loss to investigate.
