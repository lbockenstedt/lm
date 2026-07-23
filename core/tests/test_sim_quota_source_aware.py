"""Phase 4 — the shared SimQuotaEngine is source-aware (Central vs Mist).

Central and Mist are separate products; their quota rows live in split configs
(``central_sites_config.sim_quotas`` for ``Central:`` rows,
``mist_sites_config.sim_quotas`` for ``Mist:`` rows) but the engine unions them
at runtime. The ``Central:``/``Mist:`` prefix on each row's ``alert_id`` is the
only seam: it makes the two products' rows distinct dedup/adaptive keys (so a
Central ``dns_fail`` and a Mist ``dns_fail`` learn independently and keep
separate clients), while the BARE id is what firing compares against the
dashboard check id — and firing reads ONLY the row's own source's status block
(``central_status`` vs ``mist_status``), so a Mist quota never fires on a
Central check or vice versa.

These tests pin the two load-bearing hub-side behaviors:
  (1) ``_effective_sim_quotas`` UNIONS central + mist rows — both prefixed keys
      survive validate/merge.
  (2) ``_alert_firing`` is source-aware — a row fires on its OWN source's
      status, and does NOT fire (None) when only the OTHER source reports the
      check (cross-source isolation).

The harness mirrors ``test_sim_quota_reconcile_push``: register the routes
against a stub hub + store, then drive ``hub._effective_sim_quotas`` and
``hub._alert_firing`` (exposed as test seams alongside the loop).
"""
import asyncio

from fastapi import FastAPI

from simulations.routes import register_simulations_routes


# ── quota dict helper ──────────────────────────────────────────────────────
def _q(alert_id, site, count, sim_id="dns_fail"):
    return {"sim_id": sim_id, "alert_type": "alert",
            "alert_id": alert_id, "site": site, "count": count, "enabled": True}


class _Store:
    """In-memory simulations_store holding the tenant's split central/mist
    sites configs + the adaptive/knobs/global state the effective-merge reads.
    github_config returns None (best-effort in _push_config)."""

    def __init__(self, csc_by_tenant, msc_by_tenant):
        self._csc = csc_by_tenant
        self._msc = msc_by_tenant

    async def get_central_sites_config(self, tenant_id):
        return dict(self._csc.get(tenant_id, {"sim_quotas": [],
                                              "ignore_global_quotas": True}))

    async def get_mist_sites_config(self, tenant_id):
        return dict(self._msc.get(tenant_id, {"sim_quotas": [],
                                              "ignore_global_quotas": True}))

    async def get_sim_quota_defaults(self):
        return []  # tenant opts out of globals → not consulted, but defined

    async def get_adaptive_state(self, tenant_id):
        return {}  # no adaptive state → count stays as configured

    async def get_global_learned_values(self):
        return {}

    async def get_github_config(self, tenant_id):
        return None


class _Hub:
    """Stub hub: empty simulations_cache (no distributed spokes — firing reads
    ONLY the centralized hub status blocks), per-source hub status dicts, and
    a state with no get_spoke_tenant (so _spokes_for_tenant returns [])."""

    def __init__(self, central_status=None, mist_status=None):
        self.simulations_store = None  # set by _build
        self.simulations_cache = {}
        self.active_connections = {}
        self.central_hub_status = central_status or {}
        self.mist_hub_status = mist_status or {}
        # No get_spoke_tenant → _spokes_for_tenant iterates an empty cache → [].
        self.state = type("State", (), {"system_state": {}})()


def _build(csc=None, msc=None, central_status=None, mist_status=None):
    app = FastAPI()
    hub = _Hub(central_status=central_status, mist_status=mist_status)
    hub.simulations_store = _Store({"10": csc or {}}, {"10": msc or {}})
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


# ── _effective_sim_quotas unions central + mist rows ────────────────────────

def test_effective_sim_quotas_unions_central_and_mist_rows():
    # Central row in central_sites_config, Mist row in mist_sites_config —
    # both dns_fail@MIA but distinct sources. The union must keep BOTH.
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        msc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Mist:dns_fail", "MIA", 3)]})
    eff = _run(hub._effective_sim_quotas("10"))
    keys = {f"alert:{q['alert_id']}:{q['site']}" for q in eff}
    assert "alert:Central:dns_fail:MIA" in keys
    assert "alert:Mist:dns_fail:MIA" in keys
    # Counts preserved per row (no adaptive state → count as configured).
    by_key = {f"alert:{q['alert_id']}:{q['site']}": q for q in eff}
    assert by_key["alert:Central:dns_fail:MIA"]["count"] == 5
    assert by_key["alert:Mist:dns_fail:MIA"]["count"] == 3


# ── _alert_firing is source-aware ───────────────────────────────────────────

def _ok_status(site, check_id):
    """A centralized hub status block: one site with one check firing (ok)."""
    return {"status": {site: {check_id: {"status": "ok"}}},
            "site_mappings": {}}


def test_alert_firing_mist_row_fires_only_on_mist_status():
    # Only Mist's hub status reports dns_fail firing at MIA. A Mist quota must
    # fire (True); a Central quota must NOT fire (None — no central status).
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        msc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Mist:dns_fail", "MIA", 3)]},
        mist_status={"10": _ok_status("MIA", "dns_fail")})
    mist_fire = _run(hub._alert_firing("10", _q("Mist:dns_fail", "MIA", 3)))
    central_fire = _run(hub._alert_firing("10", _q("Central:dns_fail", "MIA", 5)))
    assert mist_fire is True       # own source reports it → firing
    assert central_fire is not True  # cross-source: no central status → hold (None)


def test_alert_firing_central_row_fires_only_on_central_status():
    # Only Central's hub status reports dns_fail firing at MIA. A Central quota
    # must fire (True); a Mist quota must NOT fire (None — no mist status).
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        msc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Mist:dns_fail", "MIA", 3)]},
        central_status={"10": _ok_status("MIA", "dns_fail")})
    central_fire = _run(hub._alert_firing("10", _q("Central:dns_fail", "MIA", 5)))
    mist_fire = _run(hub._alert_firing("10", _q("Mist:dns_fail", "MIA", 3)))
    assert central_fire is True
    assert mist_fire is not True


def test_alert_firing_both_sources_fire_on_their_own_status():
    # Both sources report dns_fail firing at MIA. Both rows fire independently —
    # the prefix routes each to its own status block; neither leaks to the other.
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        msc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Mist:dns_fail", "MIA", 3)]},
        central_status={"10": _ok_status("MIA", "dns_fail")},
        mist_status={"10": _ok_status("MIA", "dns_fail")})
    assert _run(hub._alert_firing("10", _q("Central:dns_fail", "MIA", 5))) is True
    assert _run(hub._alert_firing("10", _q("Mist:dns_fail", "MIA", 3))) is True