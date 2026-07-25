# Generating Alerts — the Negative-Simulation Playbook

**Read this before creating, modifying, or "fixing" any alert-driving simulation.**

This system generates **negative alerts**: the client simulations *intentionally
break* connectivity or a service so the wireless controller (Aruba **Central** /
Juniper **Mist**) observes the fault and raises its own health **alert** or
**insight**. The broken condition **is the product** — do **not** repair it, add
retries, or "harden" the sim to succeed. A sim that connects cleanly is a bug.

Each alert has **two independent levers**:

1. **Config** (`simulation.conf`) — the *break mechanism* on each client: which
   bad targets to hit (`[address]`) and how hard (`[simulation]` intensity knobs).
2. **Engine Quota Settings** (WebUI → Simulations → **Config → Engine**) — *how
   many* clients break, *where* (site / SSID cell), and the closed-loop learner
   that finds the minimum that keeps the alert firing. A quota links a Central/
   Mist alert to the sim that produces it.

Both are required: config makes one client break; the quota puts enough broken
clients in the right place for the controller to cross its alert threshold.

---

## How the controller decides to fire (the mental model)

- Alerts fire on a **rate/count threshold over a time window**, observed by the
  controller — e.g. a DNS-failure alert needs on the order of **~200 failed
  lookups per 5-minute window**, and in practice **5–10 clients together** (no
  single client trips it alone). Exact thresholds are environment-specific and
  are meant to be **discovered by the learner**, not hard-coded.
- It is a **closed loop**: the adaptive quota engine + knob learner adjust client
  **count** and per-client **intensity** against the *observed* alert state,
  absorbing real-world noise (reconnects, dead clients, roaming). This is a
  **live, non-sterile environment** — precomputed "fire N/min" values do not
  hold; only feedback against the real alert does.
- **Per-client safety ceiling:** breaking must not DOS the sim client itself. The
  concurrency cap (`dns_max_inflight`, default 100) bounds CPU regardless of the
  learned rate. Set it to a client's safe ceiling; the learner works below it.
- **Exclusive sims** (`multi_capable=False` in `SIM_META`) monopolize a client —
  one failure sim per client. Traffic sims (`ping_test`, `download`, …) are the
  ambient pool the engine draws exclusive clients from.

---

## Alert → simulation → how to break it

| Central alert (example) | Sim id | How it breaks the system | Config it reads |
|---|---|---|---|
| **DNS Server Failed to Respond** | `dns_fail` | Fires background `dig`s at UNREACHABLE / bogus servers so lookups time out / fail | `[address]` `dns_bad_ip_1-3` (RFC1918 blackholes) + `dns_bad_record_1-3`; `[simulation]` `dns_fail_rate`, `dns_fail_duration`, `dns_max_inflight` |
| **DNS latency / slow DNS** | `dns_latency` | Fires `dig`s at SLOW responders so lookups are delayed (distinct from *failure*) | `[address]` `dns_latency_1-3`; `[simulation]` `dns_latency_rate`, `dns_latency_duration`, `dns_max_inflight` |
| **DHCP Discover Timeout / CLIENT_DHCP_FAILURE** | `dhcp_fail` | Fires crafted DHCPDISCOVERs (forged client-id) at a dead server so DISCOVER never completes; the client's real lease is untouched | dead-server target is in `dhcp_fail.sh` / `dhcp_fire.py` |
| **DHCP Pool Exhausted** | `dhcp_fail` | Enough clients hammering DISCOVER exhausts the pool | quota **count** is the lever |
| **WPA Passphrase is Incorrect** | `ssidpw_fail` | Repeatedly associates with a PSK one char off (`<ssidpw>_fail`); 1X clients corrupt `dot1x_password` | uses the bucket's real `ssidpw` / `dot1x_password`, corrupted at runtime |
| **Client Association Failure / Client Disconnected / Wireless Client Roam** | `assoc_fail` | Cycles the WLAN interface up/down repeatedly so association keeps failing | — (nmcli/radio) |
| **Auth Failure (blocked MAC / invalid creds)** | `auth_fail` | Flaps the WLAN with a blocked MAC / invalid creds; toggles the radio | — (nmcli/radio) |
| **Maximum Associations** | *count-driven* (pair with `assoc_fail`/presence) | Enough clients associated to one AP/cell crosses the max-assoc threshold | quota **count** on the SSID cell is the lever |
| **Port Flap (wired)** | `port_flap` | Bounces the wired interface up/down (`ip link`); mgmt interface is guarded/skipped | — |

`SUGGESTED_ALERT_SIM` (in `sim_quota.py`) pre-fills the alert→sim linkage in the
UI (e.g. `CLIENT_DHCP_FAILURE → dhcp_fail`); it is a suggestion the tenant can
override per-quota.

---

## The two levers in detail

### 1. Config (`simulation.conf`) — the per-client break

- **`[address]`** — the bad targets the sim aims at. These are *supposed* to be
  broken: `dns_bad_ip_*` are unreachable RFC1918 blackholes, `dns_latency_*` are
  slow responders, etc. Editing these changes *what* fails.
- **`[simulation]` intensity knobs** — how hard each client pushes:
  - `dns_fail_rate` / `dns_latency_rate` (lookups per minute; the client floors at
    ~200/min).
  - `dns_fail_duration` / `dns_latency_duration` (seconds per burst).
  - `dns_max_inflight` (max concurrent `dig` processes — the client CPU ceiling;
    env var `DNS_MAX_INFLIGHT` overrides per manual run).
- Config is the source of truth on the **hub**, pushed to spokes, then to clients
  (`sim_config.py`; the hub is the sole GitHub client). Per-client overrides live
  in `user-overrides.conf` `[username]`.

### 2. Engine Quota Settings (Config → Engine)

A **sim quota** row ties a Central/Mist alert to the sim that produces it and
governs the fleet-level break:

- **Tied to alert/insight** + **Alert ID** — the controller alert this quota
  drives (prefixed `Central:` / `Mist:`).
- **Simulation** — the sim id (`dns_fail`, `ssidpw_fail`, …).
- **Site / SSID cell** — where the clients break (e.g. `MIA-PSK`, `MIA-ACD`).
- **Count**, or **Min / Max** for an **Adaptive** / **Learning** row — how many
  clients run the sim. The engine fills from the online pool and self-heals.
- **Adaptive (keep firing)** — production consumer: ramps client count UP to keep
  the alert alive, capped at Max, seeded from the learned operating point.
- **Learning** — the lab: ramps up AND down to find the floor, tunes the
  `SIM_KNOBS` intensity knobs down to the minimum that still fires, and publishes
  the learned count + knobs. Mutually exclusive with Adaptive.
- The learned operating point per alert is surfaced in the editor (default Min to
  it; warn if Max is below it).

---

## Adding a brand-new alert / sim (checklist for an operator or AI)

To make the system break in a *new* way and drive a new controller alert:

1. **Name the controller alert** — the exact string Central/Mist raises for the
   condition.
2. **Choose or build the sim:**
   - Existing sim maps? Use it (see `SUGGESTED_ALERT_SIM` / the table above).
   - New sim? Add ALL of these (use the `dns_fail`→`dns_latency` split as the
     reference template — see git history):
     - `clients/linux/<sim>.sh` — the client break script (fire-and-forget, floors
       intensity, respects `dns_max_inflight`-style caps).
     - `sim_primitives.py` — a `sim_<name>` primitive + register in `PRIMITIVES`
       (this is what makes it appear in `available_sims`).
     - `sim_quota.py` **`SIM_META`** (`category: "failure"`, `multi_capable: False`)
       and, if tunable, **`SIM_KNOBS`** (`<sim>_rate` / `<sim>_duration`, floors) —
       in **both** the cs spoke copy AND the `lm/core/src/simulations/` twin.
     - `sim_config.py` toggle/flag key lists; `common.sh` `CS_OVERRIDE_KEYS`;
       `simulation.sh` config-read + dispatch; `dashboard.sh` display — both
       `common.sh` copies.
     - The WebUI lists in **both** `sim-views.js` copies (`CS_CONTROL_FLAGS`,
       `CS_ONOFF_KEYS`, `CS_SIM_SECTION_FIELDS`, `CS_SIM_BUCKET_FIELDS`).
     - Optionally `SUGGESTED_ALERT_SIM` (alert→sim) and `demo_scenarios.FAILURE_FLAGS`.
3. **Set the config** — the bad targets in `[address]`, the intensity knobs in
   `[simulation]` (plus the per-bucket `<sim>=on` where clients should run it).
4. **Add the quota** (Config → Engine) — Tied to the alert, pick the sim, set the
   site/cell and Count (or Adaptive/Learning Min/Max).
5. **Let the learner converge** — enable Learning; it finds the minimum client
   count + knob intensity that holds the alert. Expect **hours**, because the
   controller's alert has latency (the learner waits ≥30 min per knob step).

---

## Guardrails — do not undo the breakage

- **These sims are supposed to fail.** Never add retries, longer timeouts to
  "succeed", or connectivity self-healing to a failure sim — that silences the
  alert it exists to produce.
- **Don't hard-code a firing rate/count.** The environment is live and noisy; use
  the Learning/Adaptive loop against the *observed* alert instead.
- **Respect the per-client ceiling.** Cap concurrency (`dns_max_inflight`) so a
  break doesn't DOS the sim client — a pegged client stops emitting the fault and
  the alert *drops*, which is self-defeating.
- **Keep the twins in sync.** `sim_quota.py` has a hub+spoke copy; `sim-views.js`
  and `common.sh` each have two copies. A change to one without the other diverges
  the fleet.
- **A missing sim script isn't a "fix" opportunity.** If a sim isn't firing, check
  assignment (Config → Engine State: clients assigned to the quota), the served
  scripts (Setup → Diagnostics → repo status), and the config knobs — not the
  breakage logic.

See also: `cs.md` (Simulations module), the Sim-Quota editor help, and the
per-sim knob tables in `sim_quota.py` (`SIM_META` / `SIM_KNOBS`).
