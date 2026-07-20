# Dongle quarantine — never-connected client → QT the bus + shed the VM

Status: **implemented** (Chunks 1–3 done, pushed to cs + lm + pxmx).
- ✅ **Chunk 1** (relay connectivity fields) — done, pushed (cs + lm).
- ✅ **Chunk 2** (5-strike permanent quarantine, pxmx agent) — done, pushed.
- ✅ **Chunk 3** (trigger + shed + alarms + un-QT + exclusion-sim config) — done, pushed.
  - cs spoke: `SimQuotaEngine._quarantine_sweep` detects T2 clients that never
    connected (no SSID/IP) past the 1h grace window, not running an exclusion sim,
    and dispatches `quarantine_dongle_and_destroy` to the agent. Storm guard:
    >20% per host failed (≥3 T2 clients) → bulk alarm, no mass shed
    (`QT_BULK_THRESHOLD`/`QT_BULK_MIN_HOST`). Registry `first_seen` (grace T0) +
    `ever_connected` (latch on first IP/SSID). `qt_state` relayed in CS_TELEMETRY.
  - lm hub: two alert sources — `bulk_dongle_failure` + `single_bus_failing`
    (`alert_engine.SOURCES`/`_LABEL`, `_eval_tenant` reads relayed `qt_state`
    from `simulations_cache`; SRCL labels in the alert-rules dropdown).
  - qt_exclude_sims: global admin config (store `get/set_qt_exclude_sims`;
    sim-quota-defaults GET/PUT carry it; `_pool_config` pushes the resolved set
    — per-tenant csc override else global; spoke applies into local csc).
    "Dongle Quarantine — Exclusion Sims" card in Setup → Simulations → Sim Quotas.
  - Remove-from-QT: "✕ Remove" button on the per-bus quarantine badge (cs spoke
    USB card) → agent `clear_usb_quarantine` (pops the bus entry, resets strikes).

Working doc. Plan/decisions below.

## Goal (one line)

A T2 (USB-dongle) sim client that's **supposed** to be online but **never
connects to an SSID or never gets an IP** → **quarantine its USB bus + destroy
the VM**; if a free eligible dongle exists, the provision loop re-clones onto
it, else do nothing. Track per-bus failures; **5 strikes → permanent QT** (no
auto-recovery, never re-picked). Operator can manually un-QT when fixed.

## Locked decisions (this session)

- **Scope: T2 only** (USB-dongle clients). Wired T1/T3 have no swappable dongle;
  no-IP there isn't fixable by a dongle swap.
- **Trigger = never connected to an SSID OR never got an IP** (either = failed).
- **Heartbeat rides a dedicated backend network**, separate from the sim net →
  the client heartbeats fine even when its sim dongle is dead. So "no IP" is
  **not** detectable from heartbeat absence — it must be **relayed in the
  heartbeat payload** (`connected_ssid` + IP + `gateway_reachable`).
- **Action: destroy + reclone** (no hotplug swap; no spare-pool definition). The
  provision loop's existing "reclone onto a free eligible non-quarantined bus"
  IS the pull-from-inventory. No free bus → do nothing.
- **5-strike keyed by bus/port id** (the sysfs USB bus path, e.g. `3-1.2`), NOT
  by vidpid. A bad *port* accumulates strikes and goes permanent; a dongle
  moved to a fresh port starts a fresh count. Matches the existing bus-keyed
  quarantine.
- **Storm guard = an ALARM, not silent rate-limit:**
  - **>20% of clients failed per host** → alarm "bulk failure" (infrastructure,
    not dongles — do NOT mass-QT).
  - **A single bus failing** (accumulating strikes) → alarm "single bus failing."
  - Tell the user just that.
- **Manual un-QT**: operator can remove a bus from QT (incl. permanent) when
  fixed — extends the existing `clear_usb_quarantine` command.

## Locked (resolved this session)

- **Grace window = 1 hour** after the agent reports the VM provisioned (clone +
  boot) before "never connected" is declared.
- **Exclusion set is admin-configurable** (`qt_exclude_sims`), default =
  `{dhcp_fail, assoc_fail, ssidpw_fail, auth_fail, port_flap}` (the
  connectivity-breaking exclusive sims). **QT fires when a client fails (no
  SSID/no IP) AND is running a sim NOT in `qt_exclude_sims`.** `dns_fail` and all
  traffic sims (download/iperf/www_traffic/ping_test) expect an IP → no-IP there
  IS a real QT candidate. Lives in `central_sites_config` (per-tenant) + a global
  default, same store shape as `sim_quotas`.

---

## What exists today

### Client status relay (traced hop-by-hop)

| Field | Reaches hub today? | Where dropped |
|---|---|---|
| `connected_ssid` | **YES** — `simulation.sh:476` → spoke reg `client_registry.py:194` → relay row `client_rows.py:97` → hub `service.py:247` | — |
| `gateway_reachable` | **NO** — persisted at spoke (`client_registry.py:194`, `data_models.py:25`) but `build_client_rows()` (`client_rows.py:89-109`) omits it from the row → absent from the `CS_TELEMETRY` frame | spoke→hub, `client_rows.py` |
| explicit IP | **NO** — does not exist. Hub already has a slot (`service.py:242` reads `c.get("ip")`/`c.get("ip_address")`/`config.address`, all empty today) | never existed; add at 3 hops |

- Client payload built at `simulation.sh:470-503` (`report_status()`), written to
  `client-status.json`, POSTed by `dashboard.sh:223` to `POST /api/status`.
  `connected_ssid` from `nmcli -t -f active,ssid dev wifi` (`:476`);
  `gateway_reachable` from the gateway-ping in the main loop.
- Spoke `api_status()` → `client_registry.apply_status()` (`client_registry.py:180-205`)
  merges a fixed key list (`:194`) into the registry entry — this is the choke
  point for what the spoke persists.
- Spoke→hub relay: `_cs_telemetry_relay_loop()` (`control_plane.py:397-512`)
  every 10 s attaches `payload["clients"] = build_client_rows(cs_mod)`
  (`client_rows.py:39-128`). **This row dict is the choke point for what reaches
  the hub.**
- Hub: `_handle_cs_telemetry()` (`main.py:3204-3285`) stores the whole frame in
  `simulations_cache`; `_build_clients_data()` (`simulations/service.py:216-265`)
  rebuilds the Clients view (has the `ip` slot at `:242`, `connected_ssid` at
  `:247`, no `gateway_reachable`).

### USB-dongle quarantine subsystem (traced)

- **State file** `/var/lib/pxmx/usb_quarantine.json`, keyed by **bus_path**.
  Entry shape today (`usb_quarantine.py:146`): `{fails, since, reason}`.
  `fails` is written straight to `QUARANTINE_MAX_FAILS=3` (one-shot, no gradual
  accumulation). No `vidpid`, no `permanent`, no strike counter.
- **Write fn** `quarantine_bus(bus, reason)` (`usb_quarantine.py:138-147`),
  sole caller `usb_provision.py:1386`. No-ops if `fails >= MAX` (`:144`).
- **Trigger today**: dmesg kernel USB errors only — ≥3 in 180 s
  (`scan_dmesg_usb_errors` `usb_quarantine.py:114-135`; fired at
  `usb_provision.py:1376-1390`). **No "client never got IP" trigger exists.**
- **Auto-recovery**: a sweep at the top of each provision cycle
  (`usb_provision.py:1237-1254`); pops the entry once
  `now - since >= QUARANTINE_RECOVERY_S=3600` (`usb_quarantine.py:38`). Recovery
  **deletes** the entry — it does not mark it recovered. So re-quarantine after
  recovery starts from an empty entry (no history kept).
- **Bus eligibility** (the one place the loop honors QT): `usb_provision.py:1519-1542`,
  gate at `1539-1542`: `if int(qentry.get("fails",0)) >= QUARANTINE_MAX_FAILS:
  culled["quarantined"].append(...); continue`.
- **Clear command** `clear_usb_quarantine` — dispatch `cs_commands.py:178-180` →
  `pve_cmds.py:591-619` (by `bus_path`: one; without: all; no by-vmid variant).
  Twin impl `usb_quarantine.clear_quarantine` (`:75-91`) called by
  `cs_sim._provision_unassigned` (`cs_sim.py:527-535`, all-clear "unstick").
- **Telemetry**: `_cs_usb_telemetry` (`usb_provision.py:985-1023`) sends
  `usb_state` (with `bus_to_vmid`/`vidpid_by_bus`) + `quarantine` per host; the
  spoke already receives this. Badge countdown at `usb_provision.py:1001-1017`.
- **Structural model** for a strike counter: `destroy_fails.json`
  (`record_destroy_fail` `usb_quarantine.py:150-188`, threshold
  `DESTROY_MAX_FAILS=3`) — a per-VMID counter; ours is per-bus.
- **Note**: `client_registry.record_tiers_batch` (`client_registry.py:394-424`)
  persists tier/has_usb per hostname — NOT bus_path. The spoke does NOT persist
  bus_path per client today; vmid↔bus is resolved via
  `usb_state_store.bus_for_vmid(vmid)` (`usb_state_store.py:243-244`) or the
  live `usb_state` telemetry snapshot. (Build detail: the spoke resolves
  hostname→vmid→bus from the telemetry it already receives.)

---

## Design

### A. Relay the connectivity fields to the hub (additive, low-risk)

- **IP**: add to client payload (`simulation.sh:492`, alongside
  `connected_ssid` — `ip -4 addr show <simiface>`), to spoke registry merge
  keys (`client_registry.py:194`), to the relay row (`client_rows.py:89-109`).
  Hub slot already ready (`service.py:242`) — no hub change.
- **`gateway_reachable`**: add to the relay row (`client_rows.py`) + one line at
  hub `service.py:~247`. Already persisted at the spoke.
- **`connected_ssid`**: already there — no work.

### B. The decision loop lives at the SPOKE (not the agent)

The no-IP/no-SSID signal lives at the spoke (relayed client status), not the
agent. The agent only executes QT+destroy. Key simplification: **the client
heartbeats over the dedicated backend network even with no sim IP**, so the
spoke sees a failed T2 client as *online* with `ip=""` + `connected_ssid=""`.
No provision-timestamp correlation needed — the registry sees it.

- **Detection (per T2 client)**: `online` AND `tier == "t2"` (has_usb) AND
  `ip == ""` AND `connected_ssid` empty AND **`ever_connected` is False** (it
  NEVER got an IP/SSID since first seen — distinguishes never-connected from a
  mid-run drop, which is out of scope) AND `(now - first_seen) >= 3600`
  (1 h grace) AND the client's active sim is NOT in `qt_exclude_sims`.
  → needs two new registry fields: `first_seen` (set once on first heartbeat)
  and `ever_connected` (latched True the first time `ip` or `connected_ssid`
  is non-empty). Both added in `client_registry.apply_status`.
- **Storm guard before acting**: if >20% of T2 clients on that host are failed
  → raise the "bulk failure" alarm and DO NOT QT/shed (it's infrastructure).
  If a single bus is accumulating strikes → raise "single bus failing."
  (Per-host = per-spoke unless the spoke spans hosts — confirm via map.)
- If the candidate survives the guard: resolve hostname→vmid→bus (from the
  host's `usb_state` telemetry the spoke already receives), then dispatch a
  **new agent long-op** to that host's pxmx agent: `quarantine_dongle_and_destroy`
  (see E). Both the dmesg trigger and this no-IP trigger funnel through the
  same strike-aware `quarantine_bus`.
- Reclone is NOT commanded: destroying V frees it; the agent's existing provision
  loop re-clones onto a free eligible non-permanent bus on its next pass. No
  free bus → nothing happens (correct).

### C. 5-strike permanent quarantine (extend `usb_quarantine.json`)

- **Entry shape** (`usb_quarantine.py:146`): keep `{fails, since, reason}` (so
  the existing eligibility gate + badge keep working) and ADD
  `{strikes, permanent, first_strike, last_strike}`.
- **Strike increment** in `quarantine_bus(bus, reason)` (`usb_quarantine.py:138-147`):
  load the existing entry; `strikes = entry.get("strikes",0)+1`;
  `last_strike = now`; if `strikes >= 5` → `permanent=True`, `fails=MAX`;
  else `fails=MAX` (still QT'd for the 1h window). The idempotency guard at
  `:144` must be relaxed so a re-quarantine (after recovery) still increments —
  see D for how strikes survive recovery.
- **Eligibility** (`usb_provision.py:1539-1542`): add `or qentry.get("permanent")`
  so a permanent bus is never re-picked.
- **Recovery sweep** (`usb_provision.py:1244-1254`): instead of
  `quarantine.pop(bus)`, for a non-permanent entry **reset `fails=0`** (making
  the bus eligible again for a retry) but **PRESERVE `strikes`/`permanent`/
  `first_strike`/`last_strike`**. Permanent entries are skipped entirely
  (`if entry.get("permanent"): continue`) — they never auto-clear. This keeps
  one file (no separate strike store) and lets strikes accumulate across
  recovery cycles while a non-permanent bus still gets its 1h retry.
- **Badge/telemetry** (`usb_provision.py:1001-1017`): surface `permanent` +
  `strikes` so the UI distinguishes "recovers in N" from "permanent (5 strikes)"
  and shows the strike count.

### D. Manual un-QT (extends `clear_usb_quarantine`)

- Keep the existing command clearable-by-bus and clear-all (`pve_cmds.py:591-619`).
  A permanent entry MUST be operator-clearable (it's the only manual recovery
  path — see `cs_sim.py:528-535` comment). Clearing a bus also resets its
  `strikes`/`permanent`/`first_strike`/`last_strike` (full reset, back to a
  clean bus). No new command needed; just ensure the clear path wipes the new
  fields too (both `pve_cmds.py` and `usb_quarantine.clear_quarantine`).
- UI: a "Remove from QT" action on the quarantine badge (surfaces the QT reason
  + strike count + permanent flag).

### E. New spoke→agent command

- A command like `quarantine_dongle_and_destroy` taking `{vmid, bus_path, reason}`
  (or two: reuse an existing destroy-vm path + `quarantine_bus`). The agent
  calls `quarantine_bus(bus, reason)` (which now counts strikes) then
  `cs_sim.destroy_vm(vmid)`. (Check at build whether the spoke already has a
  destroy-vm command to the agent, or destroys via the hub/pxmx API — the
  existing `usb_missing_timeout` teardown at `usb_provision.py:1945-1998`
  destroys via `cs_sim.destroy_vm`; this is a *present-but-no-IP* condition, not
  a missing-dongle one, so it's a new trigger, not a reuse of that path.)

---

## Build chunks (in order, when "make it" is given)

### Chunk 1 — relay the connectivity fields (no behavior change)
- Client: add IP to `simulation.sh:492` payload + `dashboard.sh` overlay.
- Spoke: add `ip` to registry merge keys (`client_registry.py:194`); add `ip`
  + `gateway_reachable` to `build_client_rows` (`client_rows.py:89-109`).
- Hub: add `gateway_reachable` line at `service.py:~247` (IP slot already there).
- Bump `simulation.sh` `version=` header on edit. Tests: spoke relay row carries
  ip + gateway_reachable; hub view surfaces both.

### Chunk 2 — 5-strike permanent quarantine (agent-side, no new trigger)
- Extend `usb_quarantine.json` entry shape; `quarantine_bus` strike increment +
  permanent; eligibility honors `permanent`; recovery sweep preserves strikes
  (reset `fails=0`, skip permanent); clear command resets new fields.
- Badge/telemetry surface `permanent` + `strikes`.
- Tests: 5 quarantines → permanent; permanent survives recovery sweep; clear
  resets; eligibility skips permanent. (Targeted tests only — WIPE hazard:
  `test_update_recovery`/`stale_restart`/`test_spoke_update_*` git-reset the real
  lm repo.)

### Chunk 3 — the no-IP trigger + shed (spoke loop + new agent command)
- Spoke loop: per-T2-client "provisioned at T0, no SSID+no IP within 1 h,
  not in `qt_exclude_sims`" candidate; storm guard (>20%/host → bulk alarm;
  single bus → alarm); resolve hostname→vmid→bus; dispatch the new agent
  command. Add `qt_exclude_sims` to the config/store + a Config UI editor
  (defaults editor, alongside sim-quota defaults).
- New agent command `quarantine_dongle_and_destroy` (QT bus via `quarantine_bus`
  → destroy vmid).
- New alarm rows for "bulk failure" / "single bus failing" (reuse the existing
  alert rules surface — see [[reports-alerts-infra-status]]).
- Operator "Remove from QT" UI action wired to `clear_usb_quarantine`.
- Lab: a T2 client whose dongle is dead → never SSID/IP → QT+shed; reclone onto
  a free bus; 5 dead cycles → permanent; >20% failed on a host → bulk alarm, no
  mass-QT.

## Non-goals / open
- T1/T3 wired clients out of scope (no dongle to QT).
- vidpid-keyed "true dongle identity" QT deferred (strike is bus/port-keyed by
  decision; a bad dongle moved ports gets a fresh count).
- MAC/OUI work is the IoT-quota feature, not this.
- Hotplug swap explicitly out (destroy+reclone only).