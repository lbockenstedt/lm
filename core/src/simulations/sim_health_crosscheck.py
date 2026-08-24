"""Per-client Sim Health cross-check (Fleet Health metric 2, wiring adapter).

Engine-INDEPENDENT by design. This does NOT touch the adaptive controller loop,
``_alert_firing`` (which is per site/alert/insight), or quota state. It answers a
single per-client question by cross-referencing our sim clients against Central's
CLIENT payload:

  * A client running a NETWORK-REQUIRED (traffic) sim should just show up in
    Central's client list — it connected. Working ⇔ its MAC is in ``present_macs``
    (from ``aruba.list_clients``).
  * A client running a FAILURE sim will never appear as a healthy connected
    client; instead it should show up in the "failed clients" list. Working ⇔ its
    MAC is in ``failing_macs``.

Site / alert / insight simulations are explicitly OUT OF SCOPE here — those stay
in the engine's per-site path and are never scored per client.

Because Central's per-cycle view is noisy (a client that IS erroring may not be
in the failed list on any single poll, and a connected client can blip out for a
cycle), the raw per-cycle observation is fed through ``SimHealthTrend`` — a
client only counts as not-working after a FULL trend window with no confirming
observation. This module just produces the per-cycle observation; the trend does
the smoothing.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional, Sequence

# Canonical failure-sim ids (mirror routes.py demo-scenario failure preset,
# routes.py:3363). A client whose active sim set intersects this is EXPECTED to
# be failing, so we score it against Central's failed-client list rather than its
# connected-client list.
FAILURE_SIMS = frozenset({
    "dns_fail", "dhcp_fail", "assoc_fail", "auth_fail",
    "ssidpw_fail", "mac_auth_fail", "port_flap",
})


def norm_mac(mac: object) -> str:
    """Normalize a MAC for set membership: lowercase hex, separators stripped.

    Central and the in-guest adapter inventory format MACs differently
    (``AA:BB:..`` vs ``aa-bb-..`` vs ``aabb..``); compare on the bare hex.
    Returns "" for anything without hex digits (placeholders like "—").
    """
    s = "".join(ch for ch in str(mac or "").lower() if ch in "0123456789abcdef")
    return s if len(s) >= 12 else ""


def _client_macs(client: Mapping) -> list[str]:
    """All normalized MACs a client presents (its adapter inventory + any top
    level ``mac``). Central may see any of the client's radios, so we match on
    the union."""
    macs = []
    top = norm_mac(client.get("mac"))
    if top:
        macs.append(top)
    for ad in (client.get("adapters") or []):
        if isinstance(ad, Mapping):
            m = norm_mac(ad.get("mac"))
            if m:
                macs.append(m)
    return macs


def _active_sims(client: Mapping) -> set[str]:
    """The sim ids currently expected on this client (active_simulations, else
    the single pinned simulation_id)."""
    act = client.get("active_simulations")
    if isinstance(act, (list, tuple, set)) and act:
        return {str(s) for s in act}
    sid = client.get("simulation_id")
    return {str(sid)} if sid else set()


def expects_failing(client: Mapping, failure_sims: Iterable[str] = FAILURE_SIMS) -> bool:
    """True when the client runs at least one failure sim (so it should appear in
    Central's FAILED-client list, not its connected-client list)."""
    fs = set(failure_sims)
    return bool(_active_sims(client) & fs)


def observe_clients(
    trend,
    tenant_id: str,
    clients: Sequence[Mapping],
    present_macs: Iterable[str],
    failing_macs: Iterable[str],
    *,
    failure_sims: Iterable[str] = FAILURE_SIMS,
    now: Optional[float] = None,
) -> dict:
    """Feed one cycle of Central cross-check observations into ``trend`` and
    return this tenant's Sim Health rollup.

    * ``present_macs`` — normalized-or-raw MACs Central currently lists as
      connected clients (``aruba.list_clients``). Raw values are normalized here.
    * ``failing_macs`` — MACs Central currently lists as failed/erroring clients.
      Pass an empty set if that source is unavailable; failure-sim clients then
      simply accrue no confirming observation and age out over the trend window
      (i.e. absence of the failed-client feed makes failure sims look not-working
      — callers must supply it before trusting failure-sim numbers).

    Only clients with at least one usable MAC and at least one active sim are
    scored; everything else (no sims, placeholder MACs) drops out of both
    numerator and denominator. Returns ``trend.rollup(...)``.
    """
    present = {norm_mac(m) for m in present_macs}
    present.discard("")
    failing = {norm_mac(m) for m in failing_macs}
    failing.discard("")

    active_keys: list[str] = []
    for c in clients:
        if not _active_sims(c):
            continue
        macs = _client_macs(c)
        if not macs:
            continue
        key = macs[0]
        want_fail = expects_failing(c, failure_sims)
        if want_fail:
            working = any(m in failing for m in macs)
        else:
            working = any(m in present for m in macs)
        trend.observe(tenant_id, key, working, now=now)
        active_keys.append(key)

    return trend.rollup(tenant_id, active_keys, now=now)
