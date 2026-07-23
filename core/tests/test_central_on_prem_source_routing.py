"""Phase 3 — the shared SimQuotaEngine routes ``central_on_prem`` to its OWN
telemetry, never cloud Central's (the engine-layer "no stepping on each other").

Central On-Prem is a third Aruba Central instance — the same API/``ArubaClient``
as cloud Central, but a separate config/poller/telemetry bucket. At the engine
layer the only seam is the ``Central On-Prem:`` prefix on a quota row's
``alert_id``: ``parse_alert_source`` maps it to the ``central_on_prem`` source,
and firing reads ONLY that source's hub status block
(``central_on_prem_hub_status``) — never ``central_hub_status`` (cloud) and never
``mist_hub_status``. Cloud Central and Central On-Prem monitoring the SAME site
thus keep separate client-count baselines and never cross-fire.

These tests pin the three load-bearing engine behaviors for the on-prem source:
  (1) ``_effective_sim_quotas`` UNIONS central + mist + central_on_prem rows —
      all three prefixed keys survive validate/merge.
  (2) ``_alert_firing`` routes a ``Central On-Prem:`` row to on-prem telemetry
      ONLY — it fires when on-prem status reports the check, and does NOT fire
      (None) when only cloud Central reports it (cross-instance isolation).
  (3) The reverse + symmetric cases hold: a ``Central:`` row fires on cloud
      Central only (not on-prem); both reporting → both fire on their own status.
      Existing central/mist routing is unchanged (``data_key = source`` is
      exactly equivalent for ``central``/``mist``).

The harness mirrors ``test_sim_quota_source_aware``: register the routes against
a stub hub + store (extended with the on-prem sites-config getter and the on-prem
hub status slot), then drive ``hub._effective_sim_quotas`` and
``hub._alert_firing``.
"""
import asyncio

from fastapi import FastAPI

from simulations.routes import register_simulations_routes


# ── quota dict helper ──────────────────────────────────────────────────────
def _q(alert_id, site, count, sim_id="dns_fail"):
    return {"sim_id": sim_id, "alert_type": "alert",
            "alert_id": alert_id, "site": site, "count": count, "enabled": True}


class _Store:
    """In-memory simulations_store holding the tenant's THREE split sites
    configs (central / mist / central_on_prem) + the adaptive/knobs/global state
    the effective-merge reads. github_config returns None (best-effort push)."""

    def __init__(self, csc_by_tenant, msc_by_tenant, opc_by_tenant):
        self._csc = csc_by_tenant
        self._msc = msc_by_tenant
        self._opc = opc_by_tenant

    async def get_central_sites_config(self, tenant_id):
        return dict(self._csc.get(tenant_id, {"sim_quotas": [],
                                              "ignore_global_quotas": True}))

    async def get_mist_sites_config(self, tenant_id):
        return dict(self._msc.get(tenant_id, {"sim_quotas": [],
                                             "ignore_global_quotas": True}))

    async def get_central_on_prem_sites_config(self, tenant_id):
        return dict(self._opc.get(tenant_id, {"sim_quotas": [],
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
    ONLY the centralized hub status blocks), per-source hub status dicts, and a
    state with no get_spoke_tenant (so _spokes_for_tenant returns [])."""

    def __init__(self, central_status=None, mist_status=None,
                 on_prem_status=None):
        self.simulations_store = None  # set by _build
        self.simulations_cache = {}
        self.active_connections = {}
        self.central_hub_status = central_status or {}
        self.mist_hub_status = mist_status or {}
        self.central_on_prem_hub_status = on_prem_status or {}
        # No get_spoke_tenant → _spokes_for_tenant iterates an empty cache → [].
        self.state = type("State", (), {"system_state": {}})()


def _build(csc=None, msc=None, opc=None, central_status=None,
           mist_status=None, on_prem_status=None):
    app = FastAPI()
    hub = _Hub(central_status=central_status, mist_status=mist_status,
               on_prem_status=on_prem_status)
    hub.simulations_store = _Store({"10": csc or {}}, {"10": msc or {}},
                                  {"10": opc or {}})
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


# ── _effective_sim_quotas unions central + mist + central_on_prem rows ──────
def test_effective_sim_quotas_unions_all_three_sources():
    # One dns_fail@MIA row per source, in its OWN sites config. The union must
    # keep all THREE — distinct prefixed keys → distinct ledger/adaptive state.
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        msc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Mist:dns_fail", "MIA", 3)]},
        opc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central On-Prem:dns_fail", "MIA", 4)]})
    eff = _run(hub._effective_sim_quotas("10"))
    keys = {f"alert:{q['alert_id']}:{q['site']}" for q in eff}
    assert "alert:Central:dns_fail:MIA" in keys
    assert "alert:Mist:dns_fail:MIA" in keys
    assert "alert:Central On-Prem:dns_fail:MIA" in keys
    # Counts preserved per row (no adaptive state → count as configured).
    by_key = {f"alert:{q['alert_id']}:{q['site']}": q for q in eff}
    assert by_key["alert:Central:dns_fail:MIA"]["count"] == 5
    assert by_key["alert:Mist:dns_fail:MIA"]["count"] == 3
    assert by_key["alert:Central On-Prem:dns_fail:MIA"]["count"] == 4


# ── _alert_firing is source-aware for central_on_prem ────────────────────────
def _ok_status(site, check_id):
    """A centralized hub status block: one site with one check firing (ok)."""
    return {"status": {site: {check_id: {"status": "ok"}}},
            "site_mappings": {}}


def test_alert_firing_on_prem_row_fires_only_on_on_prem_status():
    # Only on-prem's hub status reports dns_fail firing at MIA. An on-prem quota
    # must fire (True); a cloud Central quota must NOT fire (None — no cloud
    # status) — the two Central instances never cross-fire.
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        opc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central On-Prem:dns_fail", "MIA", 4)]},
        on_prem_status={"10": _ok_status("MIA", "dns_fail")})
    on_prem_fire = _run(hub._alert_firing("10",
                                          _q("Central On-Prem:dns_fail", "MIA", 4)))
    cloud_fire = _run(hub._alert_firing("10",
                                        _q("Central:dns_fail", "MIA", 5)))
    assert on_prem_fire is True          # own source reports it → firing
    assert cloud_fire is not True        # cross-instance: no cloud status → hold


def test_alert_firing_cloud_row_fires_only_on_cloud_status():
    # Reverse: only cloud Central reports dns_fail firing. A cloud quota fires;
    # an on-prem quota does NOT — even though they share the same API/client, the
    # engine routes each to its own telemetry bucket.
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        opc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central On-Prem:dns_fail", "MIA", 4)]},
        central_status={"10": _ok_status("MIA", "dns_fail")})
    cloud_fire = _run(hub._alert_firing("10",
                                         _q("Central:dns_fail", "MIA", 5)))
    on_prem_fire = _run(hub._alert_firing("10",
                                          _q("Central On-Prem:dns_fail", "MIA", 4)))
    assert cloud_fire is True
    assert on_prem_fire is not True


def test_alert_firing_both_central_instances_fire_on_their_own_status():
    # Both cloud Central AND on-prem report dns_fail at MIA. Both rows fire
    # independently — the prefix routes each to its own status block; neither
    # leaks to the other (the core no-stepping guarantee).
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        opc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central On-Prem:dns_fail", "MIA", 4)]},
        central_status={"10": _ok_status("MIA", "dns_fail")},
        on_prem_status={"10": _ok_status("MIA", "dns_fail")})
    assert _run(hub._alert_firing("10",
                                   _q("Central:dns_fail", "MIA", 5))) is True
    assert _run(hub._alert_firing("10",
                                   _q("Central On-Prem:dns_fail", "MIA", 4))) is True


def test_alert_firing_mist_routing_unchanged_with_on_prem_present():
    # Adding the on-prem source must not perturb existing central/mist routing.
    # Mist fires on mist status; Central holds (no cloud status) — same as the
    # pre-on-prem behavior pinned in test_sim_quota_source_aware.
    hub = _build(
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central:dns_fail", "MIA", 5)]},
        msc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Mist:dns_fail", "MIA", 3)]},
        opc={"ignore_global_quotas": True,
             "sim_quotas": [_q("Central On-Prem:dns_fail", "MIA", 4)]},
        mist_status={"10": _ok_status("MIA", "dns_fail")})
    assert _run(hub._alert_firing("10", _q("Mist:dns_fail", "MIA", 3))) is True
    assert _run(hub._alert_firing("10",
                                   _q("Central:dns_fail", "MIA", 5))) is not True
    assert _run(hub._alert_firing("10",
                                   _q("Central On-Prem:dns_fail", "MIA", 4))) is not True