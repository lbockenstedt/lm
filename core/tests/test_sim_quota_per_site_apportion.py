"""Per-site apportionment: a site-scoped quota is split ONLY across the spokes
that actually hold clients for that site, not every bound cs spoke.

Regression: ``_push_config`` split an alert-tied quota's count EVENLY across
ALL bound cs spokes (``even=bool(q.get("alert_id"))``), so a tenant with a
bound spoke whose clients are all elsewhere (a DAL-only spoke) still got a
share of the MIA target, filled 0, and the tenant total landed short — the
alert may not fire even though the MIA spokes could have covered it. With
per-site apportionment, the DAL spoke gets 0 for MIA and the MIA spokes split
the full target.

The spoke's per-site pool rides its CS_TELEMETRY frame (``pool_by_site``); the
hub reads it from ``simulations_cache``. When no telemetry places the site on
any spoke (cold cache / just-connected), the split falls back to the legacy
even-across-all so it's never worse than today.

Drives ``hub._push_sim_quotas`` (a callable seam) and inspects the per-spoke
``effective_sim_quotas`` counts the hub pushed.
"""
import asyncio

from fastapi import FastAPI

from simulations.routes import register_simulations_routes


def _q(alert_id, site, count, sim_id=None):
    return {"sim_id": sim_id or alert_id, "alert_type": "alert",
            "alert_id": alert_id, "site": site, "count": count, "enabled": True}


class _Store:
    """In-memory simulations_store for the effective-merge + push. The tenant
    opts out of global defaults (ignore_global_quotas) so its own sim_quotas
    are the effective set; adaptive/knobs/global state are empty so the
    configured count is what's pushed."""

    def __init__(self, csc):
        self._csc = csc

    async def get_central_sites_config(self, tenant_id):
        return dict(self._csc.get(tenant_id, {"sim_quotas": [],
                                              "ignore_global_quotas": True}))

    async def get_sim_quota_defaults(self):
        return []

    async def get_adaptive_state(self, tenant_id):
        return {}

    async def get_global_learned_values(self):
        return {}

    async def get_github_config(self, tenant_id):
        return None

    async def get_sim_shareable_global(self):
        return {}

    async def get_knob_learn_state(self, tenant_id):
        return {}


class _ApportionHub:
    """Stub hub: N bound cs spokes, a recording drain-aware push, and a
    per-spoke ``simulations_cache`` entry carrying ``pool_by_site`` (the
    per-site pool the telemetry would have cached). ``pushed[sid]`` collects
    every CS_CONFIG_UPDATE payload sent to that spoke."""

    def __init__(self, spokes):
        # spokes: {sid: {"pool_by_site": {site: n}, "clients": [<rows>]}}
        self._spokes = spokes
        self.simulations_store = None  # set by _build
        self.simulations_cache = {sid: data for sid, data in spokes.items()}
        self.active_connections = set(spokes)
        self.pushed = {}  # sid -> [payload, ...]
        self.state = type("State", (), {"system_state": {}})()

    def get_client_sim_spokes(self, tenant_id):
        return list(self._spokes)

    def get_client_sim_spoke(self, tenant_id):
        return next(iter(self._spokes)) if self._spokes else None

    async def _drain_aware_config_push(self, sid, cmd_type, payload, timeout=5.0):
        self.pushed.setdefault(sid, []).append(payload)
        return {"status": "ok", "queued": False, "result": {"status": "ok"}}


def _build(spokes, csc):
    app = FastAPI()
    hub = _ApportionHub(spokes)
    hub.simulations_store = _Store({"10": csc})
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return hub


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _mia_quota_count_for(hub, sid):
    """The MIA alert-tied quota's apportioned count in the LAST push to sid."""
    payload = hub.pushed[sid][-1]
    eff = payload.get("effective_sim_quotas") or []
    mia = [q for q in eff if q.get("alert_id") == "dns_fail"]
    return int(mia[0]["count"]) if mia else None


def test_per_site_apportion_excludes_non_serving_spoke():
    # 3 bound spokes: 2 hold MIA clients, 1 holds only DAL clients. MIA target
    # 30 must split across the 2 MIA spokes (15/15) and give DAL 0 — NOT 10/10/10.
    hub = _build(
        spokes={"cs-MIA-1": {"pool_by_site": {"MIA": 32}, "clients": ["c"] * 32},
                "cs-MIA-2": {"pool_by_site": {"MIA": 32}, "clients": ["c"] * 32},
                "cs-DAL-1": {"pool_by_site": {"DAL": 32}, "clients": ["c"] * 32}},
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("dns_fail", "MIA", 30)]})
    _run(hub._push_sim_quotas("10"))
    assert _mia_quota_count_for(hub, "cs-MIA-1") == 15
    assert _mia_quota_count_for(hub, "cs-MIA-2") == 15
    assert _mia_quota_count_for(hub, "cs-DAL-1") == 0  # DAL gets NONE of MIA's target


def test_alias_resolution_matches_central_site_to_wsite_pool():
    # Quota site is the central site "MIA"; spokes report the wsite "MIA-PSK"
    # in pool_by_site. site_mappings {"MIA-PSK": "MIA"} makes them co-refer, so
    # the MIA spokes are eligible and DAL (wsite "DAL-PSK" → "DAL") is not.
    hub = _build(
        spokes={"cs-MIA-1": {"pool_by_site": {"MIA-PSK": 32}, "clients": ["c"] * 32},
                "cs-MIA-2": {"pool_by_site": {"MIA-PSK": 32}, "clients": ["c"] * 32},
                "cs-DAL-1": {"pool_by_site": {"DAL-PSK": 32}, "clients": ["c"] * 32}},
        csc={"ignore_global_quotas": True,
             "site_mappings": {"MIA-PSK": "MIA", "DAL-PSK": "DAL"},
             "sim_quotas": [_q("dns_fail", "MIA", 30)]})
    _run(hub._push_sim_quotas("10"))
    assert _mia_quota_count_for(hub, "cs-MIA-1") == 15
    assert _mia_quota_count_for(hub, "cs-MIA-2") == 15
    assert _mia_quota_count_for(hub, "cs-DAL-1") == 0


def test_cold_cache_falls_back_to_even_across_all():
    # No pool_by_site in the telemetry cache (just-connected / cold). Must NOT
    # zero-out every spoke — fall back to the legacy even split so a spoke
    # never gets 0 for a quota it could fill. 30 across 3 → 10/10/10.
    hub = _build(
        spokes={"cs-MIA-1": {"clients": ["c"] * 32},
                "cs-MIA-2": {"clients": ["c"] * 32},
                "cs-DAL-1": {"clients": ["c"] * 32}},
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("dns_fail", "MIA", 30)]})
    _run(hub._push_sim_quotas("10"))
    assert _mia_quota_count_for(hub, "cs-MIA-1") == 10
    assert _mia_quota_count_for(hub, "cs-MIA-2") == 10
    assert _mia_quota_count_for(hub, "cs-DAL-1") == 10  # legacy: everyone gets a share


def test_presence_quota_proportional_to_site_pool():
    # Presence / untethered (no alert_id) → proportional to the per-site pool,
    # not even. MIA-1 has 32 MIA clients, MIA-2 has 16 → 48 total, target 12 →
    # 8/4, DAL gets 0 (no MIA pool).
    hub = _build(
        spokes={"cs-MIA-1": {"pool_by_site": {"MIA": 32}, "clients": ["c"] * 32},
                "cs-MIA-2": {"pool_by_site": {"MIA": 16}, "clients": ["c"] * 16},
                "cs-DAL-1": {"pool_by_site": {"DAL": 32}, "clients": ["c"] * 32}},
        csc={"ignore_global_quotas": True,
             "sim_quotas": [{"sim_id": "", "alert_type": "alert", "alert_id": "",
                             "site": "MIA", "count": 12, "enabled": True}]})
    _run(hub._push_sim_quotas("10"))
    payload = hub.pushed["cs-MIA-1"][-1]
    eff = payload.get("effective_sim_quotas") or []
    pres = [q for q in eff if not q.get("alert_id")]
    counts = {sid: next((q["count"] for q in (hub.pushed[sid][-1].get("effective_sim_quotas") or [])
                         if not q.get("alert_id")), None)
              for sid in ("cs-MIA-1", "cs-MIA-2", "cs-DAL-1")}
    # 12 across 48 (32/16) → 8 and 4; DAL 0. Sum must equal the target.
    assert counts["cs-MIA-1"] == 8
    assert counts["cs-MIA-2"] == 4
    assert counts["cs-DAL-1"] == 0
    assert sum(counts.values()) == 12