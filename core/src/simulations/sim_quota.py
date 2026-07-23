"""Sim-Quota config foundation — hub twin of ``cs/lm-spoke/src/sim_quota.py``.

Same schema / validation / resolution + ``SIM_META`` + ``SUGGESTED_ALERT_SIM``.
The hub holds the per-tenant ``central_sites_config`` (with ``sim_quotas``) and
serves the catalog to the WebUI. In **centralized** mode it parses the tenant's
``sim_conf_content`` (raw INI text in the store); in **distributed** mode the
route forwards ``CS_GET_SIM_QUOTA_CATALOG`` to the cs spoke, which reads
``simulation.conf`` directly. Sims are pulled from the simulation config (not a
hardcoded list); the alert→sim linkage is a tenant user action; the global
catalog supplies per-sim metadata defaults + suggested linkage.

Keep this file in sync with the cs twin. The schema/validation block is
intentionally byte-identical so hub and spoke agree on the contract.
"""
from __future__ import annotations

import configparser
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("SimQuota")

# ── Schema (byte-identical to cs/lm-spoke/src/sim_quota.py) ───────────────
SIM_QUOTA_KEYS = ("alert_id", "alert_type", "sim_id", "count", "site",
                  "multi_capable", "rehome", "enabled", "learning", "learn_knobs")
ALERT_TYPES = ("alert", "insight")

# ── Source prefix — the seam between Central and Mist ──────────────────────
# Central and Mist are SEPARATE products. A sim-quota row's ``alert_id`` carries
# a ``Central:``/``Mist:`` prefix so the shared SimQuotaEngine can route a row to
# the product that observed its alert (fire a Central: row against ``data["central"]``,
# a Mist: row against ``data["mist"]``) and so two rows for the SAME sim at the
# SAME site — one per product — are distinct ledger/adaptive states that keep
# SEPARATE clients. Legacy bare ids (no prefix) are treated as Central — every
# pre-Mist row is Aruba. The prefix is a Setup/picker/catalog concern only; the
# spoke's bare ``alert_type_counts``, the dashboard Checks view, and reports all
# stay on the bare id (the prefix is stripped before any comparison there).
SOURCE_PREFIXES = {"central": "Central", "mist": "Mist"}
# Reverse lookup is case-insensitive on the stored source name.
_PREFIX_TO_SOURCE = {"central": "central", "mist": "mist"}


def parse_alert_source(alert_id: str) -> Tuple[str, str]:
    """Split a (possibly prefixed) ``alert_id`` into ``(source, bare_id)``.

    ``"Central:DNS Fail"`` → ``("central", "DNS Fail")``;
    ``"Mist:ap_offline"`` → ``("mist", "ap_offline")``;
    ``"DNS Fail"`` (legacy / untethered-display) → ``("central", "DNS Fail")``.
    An unknown/empty prefix falls back to ``central`` (bare). Returns the source
    as the canonical lowercase key (``"central"``/``"mist"``)."""
    aid = str(alert_id or "").strip()
    if ":" in aid:
        prefix, _, rest = aid.partition(":")
        src = _PREFIX_TO_SOURCE.get(prefix.strip().lower())
        if src and rest.strip():
            return src, rest.strip()
    return "central", aid


def prefixed_alert_id(source: str, bare_id: str) -> str:
    """Render a bare alert id with its product prefix for the picker/catalog:
    ``prefixed_alert_id("mist", "ap_offline")`` → ``"Mist:ap_offline"``.
    An unknown/empty source defaults to Central. A bare_id that is ALREADY
    prefixed is returned unchanged (idempotent)."""
    src = str(source or "central").strip().lower()
    if src not in SOURCE_PREFIXES:
        src = "central"
    bid = str(bare_id or "").strip()
    cur_src, cur_bare = parse_alert_source(bid)
    if cur_src != "central" or bid != cur_bare:
        # already prefixed (and not a bare-that-looks-prefixed) — keep as-is
        return bid
    return f"{SOURCE_PREFIXES[src]}:{bid}" if bid else bid

SIM_META: Dict[str, Dict[str, object]] = {
    "dns_fail":    {"category": "failure", "multi_capable": False},
    "dhcp_fail":   {"category": "failure", "multi_capable": False},
    "assoc_fail":  {"category": "failure", "multi_capable": False},
    "auth_fail":   {"category": "failure", "multi_capable": False},
    "ssidpw_fail": {"category": "failure", "multi_capable": False},
    "port_flap":   {"category": "failure", "multi_capable": False},
    "ping_test":   {"category": "traffic", "multi_capable": True},
    "download":    {"category": "traffic", "multi_capable": True},
    "www_traffic": {"category": "traffic", "multi_capable": True},
    "iperf":       {"category": "traffic", "multi_capable": True},
}

SUGGESTED_ALERT_SIM: Dict[str, str] = {
    "CLIENT_DHCP_FAILURE": "dhcp_fail",
    "CLIENT_ASSOCIATION_FAILURE": "assoc_fail",
    "CLIENT_DISCONNECTED": "assoc_fail",
    "WIRELESS_CLIENT_ROAM": "assoc_fail",
    "DHCP_POOL_EXHAUSTED": "dhcp_fail",
    "CLIENT_DNS_FAILURE": "dns_fail",
}

# ── Tunable intensity knobs per sim (config-value learner) ────────────────
# The knob-floor learner (hub ``_knob_step``) ratchets these ``[simulation]``-
# section values DOWN one at a time to discover the minimum that still fires the
# sim's alert. Each entry: ``key`` (the simulation.conf ``[simulation]`` name the
# client reads), ``min``/``max`` sweep bounds, ``step``, and ``start`` (the
# known-firing high end the learner begins at). Only sims listed here can be
# knob-learned; add a sim by declaring its 1–4 numeric knobs. The client reads
# these unchanged (e.g. ``dns_fail.sh`` already reads ``dns_fail_rate`` /
# ``dns_fail_duration`` and clamps rate ≥200). Byte-identical to the cs twin.
SIM_KNOBS: Dict[str, List[Dict[str, int]]] = {
    "dns_fail": [
        {"key": "dns_fail_rate",     "min": 200, "max": 3000, "step": 200, "start": 3000},
        {"key": "dns_fail_duration", "min": 120, "max": 600,  "step": 60,  "start": 600},
    ],
}


def knobs_for_sim(sim_id: str) -> List[Dict[str, int]]:
    """The ordered tunable knob specs for a sim (empty list if it has none)."""
    return [dict(k) for k in SIM_KNOBS.get(str(sim_id or "").strip(), [])]


KNOB_SETTLE_S = 1800.0  # ≥30 min — Central alert latency floor (see adaptive_step)


def knob_step(st: Dict[str, Any], knobs: List[Dict[str, int]], firing,
              now: float, settle: float = KNOB_SETTLE_S) -> Dict[str, Any]:
    """Advance one tick of the coordinate-descent floor search over ``knobs``
    (``SIM_KNOBS[sim]``). Pure — returns a NEW state dict so the caller can diff
    before/after. Shared by the hub controller and the unit test.

    One knob moves per settle window. Ratchet the ACTIVE knob DOWN while
    ``firing`` is True (probe lower); when a down-step loses the alert
    (``firing`` False) step back UP one and record that recovered value as the
    knob's floor, then advance to the next knob; hitting ``min`` while still
    firing floors it at ``min`` and advances. ``firing`` None → hold (never move
    blind). Once every knob is floored it keeps cycling — the same up/down logic
    re-seeks the floor as conditions drift, and a floored knob that loses the
    alert simply ramps back UP to recover.

    State shape: ``{values:{key:int}, floors:{key:int|None}, active:int,
    mode:str, last_change:float}``, keyed per quota by the caller."""
    if not knobs:
        return dict(st)
    st = dict(st)
    values = dict(st.get("values") or {})
    floors = dict(st.get("floors") or {})
    # Cold start: seed each knob at its known-firing high end and arm the settle
    # clock so even the first move waits a full window (let Central confirm firing
    # at the start level).
    if not values:
        for kn in knobs:
            values[kn["key"]] = int(kn.get("start", kn.get("max", kn["min"])))
            floors.setdefault(kn["key"], None)
        return {"values": values, "floors": floors, "active": 0,
                "mode": "learning", "last_change": now}
    active = int(st.get("active") or 0) % len(knobs)
    last = float(st.get("last_change") or 0)
    _all_floored = all(floors.get(kn["key"]) is not None for kn in knobs)
    if firing is None or (now - last) < settle:  # hold
        st.update(values=values, floors=floors, active=active,
                  mode=("stable" if _all_floored else "learning"))
        return st
    kn = knobs[active]
    key = kn["key"]
    mn, mx, step = int(kn["min"]), int(kn["max"]), max(1, int(kn["step"]))
    cur = int(values.get(key, kn.get("start", mx)))
    if firing is True:
        nv = cur - step
        if nv < mn:                     # min still fires → that's the floor
            values[key] = mn
            floors[key] = mn
            active = (active + 1) % len(knobs)
        else:                           # keep probing lower on this knob
            values[key] = nv
    else:                               # firing False → this value lost the alert
        rv = min(mx, cur + step)        # step back up to the last firing level
        values[key] = rv
        prev = floors.get(key)
        floors[key] = rv if prev is None else min(int(prev), rv)
        active = (active + 1) % len(knobs)
    st.update(values=values, floors=floors, active=active, last_change=now,
              mode=("stable" if all(floors.get(k2["key"]) is not None
                                    for k2 in knobs) else "learning"))
    return st


# ── Coercion + validation (byte-identical to the cs twin) ─────────────────
def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int(v: Any, default: int = 1) -> int:
    try:
        n = int(str(v).strip())
        return n if n >= 1 else default
    except Exception:
        return default


def normalize_quota(raw: Any) -> Dict[str, Any]:
    """Coerce a raw quota dict to the canonical shape; drop unknown keys.

    A PRESENCE quota (``sim_id`` empty, "Clients Associated") homes N clients
    to a site and runs NO sim — it only guarantees N clients are associated to
    the site (re-homing ``wsite`` if ``rehome``). Presence quotas are ALWAYS
    multi-capable (they don't consume the client for sim purposes; other
    stackable sims may pack onto a presence-homed client)."""
    if not isinstance(raw, dict):
        return {}
    sim_id = str(raw.get("sim_id") or "").strip()
    meta = SIM_META.get(sim_id, {})
    alert_type = str(raw.get("alert_type") or "alert").strip().lower()
    if alert_type not in ALERT_TYPES:
        alert_type = "alert"
    is_presence = not sim_id
    q = {
        "alert_id": str(raw.get("alert_id") or "").strip(),
        "alert_type": alert_type,
        "sim_id": sim_id,
        "count": _as_int(raw.get("count"), 1),
        "site": str(raw.get("site") or "").strip(),
        "multi_capable": True if is_presence
        else _as_bool(raw.get("multi_capable"), bool(meta.get("multi_capable", False))),
        "rehome": _as_bool(raw.get("rehome"), False),
        "enabled": _as_bool(raw.get("enabled"), False),
        # `learning` ON = this row is the "learning lab" that runs the full
        # thermostat (down-ratchet to find the floor, settle floor+20%, record a
        # publishable learned_op). OFF (default) = a consumer: up-only, seeds/lifts
        # from the tenant/global learned operating point, never down-ratchets (never
        # risks stopping a firing alert). See design doc §9 / adaptive_step.
        "learning": _as_bool(raw.get("learning"), False),
        # `learn_knobs` ON = the config-value learner tunes this sim's
        # [simulation] intensity knobs (SIM_KNOBS[sim_id]) one at a time, DOWN to
        # the floor that still fires the alert. Orthogonal to `learning` (which
        # modulates client count); a no-op for a sim with no declared knobs.
        "learn_knobs": _as_bool(raw.get("learn_knobs"), False),
    }
    # Adaptive-controller fields (design doc §9) — carried through only when the
    # quota declares them, so a fixed-count quota stays exactly as before. The
    # hub-side controller reads min/max/step/settle/buffer and modulates `count`.
    for k in ("min", "max", "step", "settle", "buffer"):
        if raw.get(k) is not None:
            q[k] = raw.get(k)
    return q


def quota_dedup_key(q: Dict[str, Any]) -> str:
    """The dedup/identity key for a normalized quota.

    A sim quota is keyed by ``alert_type:alert_id:site``. A presence quota
    (``sim_id`` empty — "Clients Associated") has no alert, so it's keyed by
    site alone — one presence count per site, independent of the sim-quota
    namespace. An UNTETHERED sim quota (``sim_id`` set but no ``alert_id`` — the
    row's "Tied to alert/insight" box is off) has no alert to key on, so it's
    keyed by ``sim:{sim_id}:{site}``. The engine's ``_quota_key`` mirrors this."""
    if not q.get("sim_id"):
        return f"presence::{q.get('site', '')}"
    if not q.get("alert_id"):
        return f"sim:{q.get('sim_id', '')}:{q.get('site', '')}"
    return f"{q.get('alert_type', 'alert')}:{q.get('alert_id', '')}:{q.get('site', '')}"


def validate_sim_quotas(
    quotas: Any, available_sims: List[str] | None = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Normalize + validate a ``sim_quotas`` list.

    A SIM quota (``sim_id`` set) whose ``sim_id`` must be in *available_sims*
    (when provided). An alert/insight linkage is OPTIONAL: a tethered sim quota
    carries an ``alert_id``; an UNTETHERED one (the row's "Tied to alert/insight"
    box off) has no ``alert_id`` and just keeps N clients running the sim at the
    site — like a PRESENCE quota, which needs a ``site`` and NO sim/alert.
    Duplicate keys (``quota_dedup_key``) collapse last-wins."""
    clean: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen: Dict[str, Dict[str, Any]] = {}
    sim_set = set(available_sims or [])
    for i, raw in enumerate(quotas or []):
        q = normalize_quota(raw)
        if not q["sim_id"]:
            if not q["site"]:
                errors.append(f"quota #{i}: presence quota (Clients Associated) "
                              f"requires a site — dropped")
                continue
        else:
            # alert_id is optional now (untethered quota) — no error when blank.
            if sim_set and q["sim_id"] not in sim_set:
                errors.append(
                    f"quota #{i} ({q['alert_id']}): sim_id '{q['sim_id']}' "
                    f"not in available sims — dropped")
                continue
        seen[quota_dedup_key(q)] = q
    clean = list(seen.values())
    return clean, errors


def resolve_effective_quotas(
    tenant_quotas: Any, available_sims: List[str] | None = None,
) -> List[Dict[str, Any]]:
    clean, _ = validate_sim_quotas(tenant_quotas, available_sims)
    return [q for q in clean if q["enabled"]]


def merge_effective_quotas(
    global_quotas: Any, tenant_quotas: Any,
) -> List[Dict[str, Any]]:
    """Merge platform-wide default quotas with a tenant's overrides.

    SIM quotas merge per ``(alert_type, alert_id)``: if the tenant declares ANY
    quota row for that alert (enabled OR disabled), the tenant OWNS that alert —
    its enabled rows are used and the global default for that alert is
    suppressed (so a tenant can explicitly turn an alert OFF by adding a
    disabled row). Alerts the tenant hasn't touched inherit the global
    default's enabled rows.

    PRESENCE quotas (``sim_id`` empty — "Clients Associated", N clients homed
    to a site, no sim) merge per SITE: a tenant presence row for a site (enabled
    OR disabled) makes the tenant own that site's presence — its enabled row is
    used and the global presence for that site is suppressed; sites the tenant
    hasn't touched inherit the global presence. So a tenant can "17 on MIA"
    globally and "10 on DFW" locally, or disable MIA to drop the global MIA
    presence.

    Both sides are validated + deduped (last-wins per ``quota_dedup_key``)
    before the merge; the result is enabled-only. The cs spoke's SimQuotaEngine
    consumes the resulting list.
    """
    g_clean, _ = validate_sim_quotas(global_quotas, list(SIM_META.keys()))
    # Tenant side is filtered against the full SIM_META primitive set (NOT the
    # bucket-derived available_sims — a sim not yet placed in any bucket is still
    # runnable via a per-client override) so a quota pointing at a non-existent
    # sim_id (typo, or a sim removed from SIM_META) is dropped here, and a
    # sim-config refresh that removes a sim re-merges cleanly without it.
    t_clean, t_errs = validate_sim_quotas(tenant_quotas, list(SIM_META.keys()))
    if t_errs:
        logger.warning("merge_effective_quotas: tenant quota errors: %s", t_errs)

    def _grp_sim(qs: List[Dict[str, Any]]) -> Dict[tuple, List[Dict[str, Any]]]:
        # Tethered quotas own their (alert_type, alert_id) across sites; an
        # untethered quota (no alert_id) owns its (sim_id, site) instead.
        m: Dict[tuple, List[Dict[str, Any]]] = {}
        for q in qs:
            key = ((q["alert_type"], q["alert_id"]) if q.get("alert_id")
                   else ("__sim__", q["sim_id"], q["site"]))
            m.setdefault(key, []).append(q)
        return m
    def _grp_site(qs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        m: Dict[str, List[Dict[str, Any]]] = {}
        for q in qs:
            m.setdefault(q["site"], []).append(q)
        return m

    g_sim = [q for q in g_clean if q["sim_id"]]
    g_pres = [q for q in g_clean if not q["sim_id"]]
    t_sim = [q for q in t_clean if q["sim_id"]]
    t_pres = [q for q in t_clean if not q["sim_id"]]

    out: List[Dict[str, Any]] = []
    # SIM quotas — ownership keyed on ALL rows (enabled+disabled) so a tenant's
    # disabled row suppresses the global default for that alert; enabled-only out.
    gmap_all, tmap_all = _grp_sim(g_sim), _grp_sim(t_sim)
    for key, rows in tmap_all.items():
        out.extend(r for r in rows if r.get("enabled"))
    for key, rows in gmap_all.items():
        if key not in tmap_all:
            out.extend(r for r in rows if r.get("enabled"))
    # PRESENCE quotas — ownership per site (a tenant presence row for a site,
    # enabled or disabled, suppresses the global presence for that site).
    gsite, tsite = _grp_site(g_pres), _grp_site(t_pres)
    for site, rows in tsite.items():
        out.extend(r for r in rows if r.get("enabled"))
    for site, rows in gsite.items():
        if site not in tsite:
            out.extend(r for r in rows if r.get("enabled"))
    return out


# ── Adaptive harvest controller (design doc §9) — PURE helpers ──────────────
# Module-level so they're importable + testable. routes.py wires the async
# apply/loop around ``store``; these are the stateless bits.
def adaptive_is_on(q: Dict[str, Any]) -> bool:
    """A quota is adaptive when it declares a max above its min. Fixed-count
    quotas (no min/max, or min==max) are left untouched."""
    try:
        return int(q.get("max")) > int(q.get("min") or 1)
    except (TypeError, ValueError):
        return False


def adaptive_key(q: Dict[str, Any]) -> str:
    """The controller-state key for an adaptive quota."""
    return f"{q.get('alert_type', 'alert')}:{q.get('alert_id', '')}:{q.get('site', '')}"


def ceil_to_int(x: float) -> int:
    """``ceil`` for positive floats without a math import."""
    xi = int(x)
    return xi + 1 if x > xi else xi


def _alert_key(q: Dict[str, Any]) -> str:
    """The per-ALERT key (no site) used to share learned operating points across
    a tenant's sites and the global registry: ``alert_type:alert_id``."""
    return f"{q.get('alert_type', 'alert')}:{q.get('alert_id', '')}"


def _derived_mode(phase: str) -> str:
    """Map an internal thermostat phase to the UI-facing mode badge."""
    if phase == "stable":
        return "stable"
    if phase == "at_max":
        return "at_max"
    if phase == "held":
        return "held"  # parked at a known-good after a Reset-to-known-good
    return "learning"


def adaptive_step(st: Dict[str, Any], q: Dict[str, Any], firing, now: float,
                  applied_op: int | None = None) -> Dict[str, Any]:
    """Advance one controller tick (design §9). ``firing`` is True/False/None
    (None = unknown → hold). ``applied_op`` is the effective learned operating
    point for this alert (max of this tenant's learning-ON stable learned_op and
    the global published value) — used to SEED a cold start so a consumer/lab
    begins near the known-good count instead of ramping from min.

    Two behaviors, gated by ``q["learning"]``:

    * **learning ON (the lab):** full thermostat. ``up_find`` ramps +step until
      firing → ``down_floor`` ratchets −step while still firing (floor = lowest
      count that fires, re-learned fresh each cycle) → on the first non-firing
      step, floor = last firing count, restore target → ``up_confirm`` adds +step
      until it re-fires → ``stable`` settles at ``ceil(floor*(1+buffer))`` and
      records ``learned_op``. From ``stable`` the lab keeps learning: it re-probes
      down (drift down) or ramps up (drift up) on later ticks.

    * **learning OFF (the consumer):** up-only. Seed from ``applied_op``; not
      firing → +step until firing; firing → HOLD (never down-ratchet, never risk
      stopping the alert). Produces no ``learned_op``.

    A settle window (≥30 min, floored for Central's reporting latency) gates
    every change. Returns the next state dict
    ``{target, floor, phase, learned_op, mode, last_change}``."""
    mn = int(q.get("min") or 1)
    mx = max(mn, int(q.get("max") or mn))
    step = max(1, int(q.get("step") or 1))
    # Central reports alerts with LATENCY — often 30+ min. The controller must
    # not change the target (up OR down) faster than that, or it ramps to max
    # long before Central ever confirms firing (the "at max, not firing" false
    # alarm). Floor the settle window at 30 min regardless of the config.
    settle = max(1800.0, float(q.get("settle") or 1800.0))
    buffer = float(q.get("buffer") if q.get("buffer") is not None else 0.20)
    learning = _as_bool(q.get("learning"), False)

    target = st.get("target")
    floor = st.get("floor")
    phase = st.get("phase") or "up_find"
    learned_op = st.get("learned_op")
    last = float(st.get("last_change") or 0)
    # Learning-lifecycle metadata for the "known-good operating point" record:
    # when this learning run began (for time-to-stable), when it last went stable,
    # and an optional HOLD deadline set by a Reset-to-known-good (hold the target
    # untouched until then — e.g. the 1h post-reset window so all clients spin up
    # and every sim fires before we resume ratcheting).
    learning_started_at = float(st.get("learning_started_at") or 0)
    stable_since = float(st.get("stable_since") or 0)
    time_to_stable_s = st.get("time_to_stable_s")
    hold_until = float(st.get("hold_until") or 0)

    if target is None:  # cold start — seed from the known-good op if any
        seed = applied_op if applied_op else mn
        target = max(mn, min(mx, int(seed)))
        floor = None
        learned_op = None
        phase = "up_find"
        learning_started_at = now  # start the time-to-stable clock
        stable_since = 0.0
        time_to_stable_s = None
        # Start the settle clock now so even the FIRST change waits a full
        # 30-min window (give Central time to confirm firing at the start level).
        last = now
    target = max(mn, min(mx, int(target)))
    if not learning_started_at:
        learning_started_at = now  # backfill for pre-metadata states

    def _stable_at(fl: int) -> None:
        """Enter `stable`: record learned_op + the time-to-stable, and park target
        at floor+buffer. A stable transition is when the known-good is captured."""
        nonlocal floor, learned_op, target, phase, last, stable_since, time_to_stable_s
        floor = fl
        learned_op = max(mn, ceil_to_int(float(fl) * (1 + buffer)))
        target = min(mx, learned_op)
        phase = "stable"
        last = now
        # Only stamp time-to-stable on the FIRST entry into stable this run (not
        # on later re-probes that briefly leave + re-enter stable during drift).
        if not stable_since:
            stable_since = now
            time_to_stable_s = int(max(0.0, now - learning_started_at))

    def _ret() -> Dict[str, Any]:
        return {"target": max(mn, min(mx, int(target))), "floor": floor,
                "phase": phase, "learned_op": learned_op, "learning": learning,
                "mode": _derived_mode(phase), "last_change": last,
                "learning_started_at": learning_started_at,
                "stable_since": stable_since or None,
                "time_to_stable_s": time_to_stable_s,
                "hold_until": hold_until or None}

    # HOLD: a Reset-to-known-good parks the target at the recorded count and sets
    # hold_until. While holding we make NO changes (let the fleet converge). When
    # the hold expires we fall through to normal logic — the lab then resumes
    # learning from the known-good; a consumer just keeps holding (up-only).
    if hold_until and now < hold_until:
        phase = "held"
        return _ret()
    if hold_until and now >= hold_until:
        hold_until = 0.0
        # Resuming after the hold: treat the parked count as the current stable
        # baseline so the lab re-probes DOWN from it (drift tracking), not from min.
        if phase == "held":
            phase = "stable"
            last = now

    if (now - last) >= settle:
        if firing is None:
            pass  # unknown → hold
        elif learning:
            # ── learning lab: full thermostat ───────────────────────────────
            if firing is True:
                if phase == "up_find":
                    # found firing from below — start ratcheting down
                    floor = target
                    target = max(mn, target - step)
                    phase = "down_floor"; last = now
                elif phase == "down_floor":
                    if target <= mn:
                        _stable_at(mn)  # still firing at min → floor is min
                    else:
                        floor = target          # lower count still fires
                        target = max(mn, target - step)
                        last = now
                elif phase == "up_confirm":
                    _stable_at(target)  # re-fired → floor confirmed
                elif phase == "stable":
                    # continuous re-learning: re-probe DOWN to track drift
                    floor = target
                    target = max(mn, target - step)
                    phase = "down_floor"; last = now
                elif phase == "at_max":
                    # Ramped to the ceiling while the firing signal was missing,
                    # now it IS firing — the real firing point is at/below max, so
                    # ratchet DOWN to find the floor instead of holding at max
                    # forever. (Bug: a quota that hit at_max during a firing outage
                    # never came back down once firing was detected again — it sat
                    # underfilled at max. There was no at_max→stable path despite
                    # the old comment claiming one.)
                    floor = target
                    target = max(mn, target - step)
                    phase = "down_floor"; last = now
            else:  # firing is False
                if phase == "down_floor":
                    # over-stepped: the last firing count was target+step
                    floor = target + step
                    target = floor  # restore to the firing count
                    phase = "up_confirm"; last = now
                elif phase == "up_confirm":
                    # not re-firing yet (latency/hysteresis) — keep adding back
                    if target >= mx:
                        phase = "at_max"
                    else:
                        target = min(mx, target + step); last = now
                elif phase == "stable":
                    # drift UP: learned_op no longer fires — re-find the floor
                    if target >= mx:
                        phase = "at_max"
                    else:
                        target = min(mx, target + step)
                        phase = "up_find"; last = now
                else:  # up_find / at_max
                    if target >= mx:
                        phase = "at_max"
                    else:
                        target = min(mx, target + step)
                        phase = "up_find"; last = now
        else:
            # ── consumer: up-only, never down-ratchet ───────────────────────
            if firing is True:
                phase = "stable"  # hold — never risk stopping the alert
            else:  # not firing
                if target >= mx:
                    phase = "at_max"
                else:
                    target = min(mx, target + step)
                    phase = "up_find"; last = now

    return _ret()


def known_good_from_state(q: Dict[str, Any], st: Dict[str, Any],
                          knobs: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Build a "known-good operating point" record from a STABLE controller state
    — the thing the operator sees ("exactly what it took") and that a
    Reset-to-known-good restores to. Returns None unless the state is stable with
    a learned_op. ``knobs`` = the simulation.conf intensity values the knob-floor
    learner settled on for this alert's sims (what was modified to make it work).

    Shape: ``{alert, alert_type, alert_id, site, count, clients, knobs,
    time_to_stable_s, achieved_at, buffer}``."""
    try:
        if (st or {}).get("phase") != "stable":
            return None
        op = (st or {}).get("learned_op")
        if op is None:
            return None
        return {
            "alert":        _alert_key(q),
            "alert_type":   q.get("alert_type"),
            "alert_id":     q.get("alert_id"),
            "site":         q.get("site", ""),
            "count":        int(op),          # learned client count
            "clients":      int(op),
            "knobs":        dict(knobs or {}),  # simulation.conf values it took
            "time_to_stable_s": st.get("time_to_stable_s"),
            "achieved_at":  st.get("stable_since"),
            "buffer":       float(q.get("buffer") if q.get("buffer") is not None else 0.20),
        }
    except Exception:  # noqa: BLE001
        return None


def seed_state_to_known_good(kg: Dict[str, Any], learning: bool, now: float,
                             hold_s: int = 3600) -> Dict[str, Any]:
    """Return a controller state parked at a known-good operating point, for a
    Reset-to-known-good. ``learning`` ON → HOLD at the known-good count for
    ``hold_s`` (default 1h: let every client come up + every sim fire) then the
    lab resumes learning from there. ``learning`` OFF → jump to the count and
    hold (consumer; up-only stable). The count is stamped as ``learned_op`` so a
    resumed lab re-probes DOWN from it rather than from min."""
    count = int(kg.get("count") or kg.get("learned_op") or 1)
    return {
        "target":       count,
        "floor":        count,
        "learned_op":   count,
        "phase":        "held" if learning else "stable",
        "learning":     bool(learning),
        "mode":         "held" if learning else "stable",
        "last_change":  now,
        "learning_started_at": now,
        "stable_since": now if not learning else 0.0,
        "time_to_stable_s": kg.get("time_to_stable_s"),
        "hold_until":   (now + int(hold_s)) if learning else None,
    }


def apply_adaptive_targets(quotas: List[Dict[str, Any]],
                           state: Dict[str, Any],
                           global_learned: Dict[str, Any] | None = None
                           ) -> List[Dict[str, Any]]:
    """Replace each adaptive quota's ``count`` with the controller's current
    target (from ``state`` keyed by ``adaptive_key``), lifted by the effective
    learned operating point for the alert. Pure (no store) — routes.py wraps
    this with the async store read so the push path and the state view apply the
    same target.

    ``applied_op[alert]`` = max of this tenant's learning-ON stable rows'
    ``learned_op`` for that alert and the global published value
    (``global_learned[alert_key].op``). Highest wins across multiple learners.

    * learning-ON row: ``count`` = its own thermostat ``target`` (the probe).
    * learning-OFF row: ``count`` = ``max(its target, applied_op)`` — seeds/lifts
      from the learned op, up-only (a higher op lifts it; a lower one never
      drops it, so a firing site stays firing). Cold start (no state) seeds from
      ``applied_op`` (or ``min`` when none exists yet).

    Non-adaptive quotas are left untouched."""
    global_learned = global_learned or {}
    adaptive = [q for q in quotas if adaptive_is_on(q)]
    if not adaptive:
        return quotas

    # applied_op per alert = max(own learning-ON stable learned_op, global op)
    applied_op: Dict[str, int] = {}
    for q in adaptive:
        if not _as_bool(q.get("learning"), False):
            continue
        st = state.get(adaptive_key(q)) or {}
        if st.get("phase") == "stable" and st.get("learned_op") is not None:
            ak = _alert_key(q)
            cur = applied_op.get(ak)
            val = int(st["learned_op"])
            if cur is None or val > cur:
                applied_op[ak] = val
    for ak, gv in global_learned.items():
        if not isinstance(gv, dict):
            continue
        gop = gv.get("op")
        if gop is None:
            continue
        try:
            gval = int(gop)
        except (TypeError, ValueError):
            continue
        cur = applied_op.get(ak)
        if cur is None or gval > cur:
            applied_op[ak] = gval

    for q in adaptive:
        st = state.get(adaptive_key(q)) or {}
        ak = _alert_key(q)
        op = applied_op.get(ak)
        if _as_bool(q.get("learning"), False):
            # lab runs its own probe target
            tgt = st.get("target")
            q["count"] = int(tgt) if tgt is not None else int(q.get("min") or 1)
        else:
            # consumer: up-only, seed/lift from applied_op, never drop
            tgt = st.get("target")
            if tgt is None:  # cold start
                q["count"] = int(op) if op is not None else int(q.get("min") or 1)
            else:
                base = int(tgt)
                q["count"] = max(base, int(op)) if op is not None else base
    return quotas


# ── Catalog from raw INI text (hub centralized mode) ──────────────────────
def _parse_ini(text: str) -> configparser.ConfigParser:
    p = configparser.ConfigParser()
    p.optionxform = str  # preserve key case
    if text:
        try:
            p.read_string(text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sim_quota: parse INI failed: %s", exc)
    return p


def _bucket_sections(sim_conf: configparser.ConfigParser) -> List[str]:
    return [s for s in (sim_conf.sections() if sim_conf is not None else [])
            if s.startswith("s") and s[1:].isdigit()]


def available_sims_from_ini(sim_conf_text: str) -> List[Dict[str, Any]]:
    """Sims the Sim-Quota UI may offer, derived from the tenant's
    ``simulation.conf`` INI text (bucket sections ∩ runnable SIM_META keys)."""
    flags = list(SIM_META.keys())
    sim_conf = _parse_ini(sim_conf_text)
    bucket_flags: List[str] = []
    seen = set()
    for sec in _bucket_sections(sim_conf):
        for key in sim_conf.options(sec):
            if key in flags and key not in seen:
                seen.add(key)
                bucket_flags.append(key)
    ordered = bucket_flags + [f for f in flags if f not in seen]
    return [
        {"sim_id": f,
         "category": SIM_META.get(f, {}).get("category", "failure"),
         "multi_capable": bool(SIM_META.get(f, {}).get("multi_capable", False)),
         "has_knobs": f in SIM_KNOBS}
        for f in ordered
    ]


def available_sites_from_ini(
    sim_conf_text: str, central_site_mappings: Dict[str, str] | None = None,
) -> List[str]:
    sites: set[str] = set()
    sim_conf = _parse_ini(sim_conf_text)
    for sec in _bucket_sections(sim_conf):
        w = sim_conf.get(sec, "wsite", fallback="").strip()
        if w:
            sites.add(w)
    for k, v in (central_site_mappings or {}).items():
        if k:
            sites.add(str(k))
        if v:
            sites.add(str(v))
    return sorted(sites)


def sim_quota_catalog_from_ini(
    sim_conf_text: str, central_site_mappings: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    return {
        "sims": available_sims_from_ini(sim_conf_text),
        "sites": available_sites_from_ini(sim_conf_text, central_site_mappings),
        "suggested": dict(SUGGESTED_ALERT_SIM),
        "meta": {k: dict(v) for k, v in SIM_META.items()},
    }