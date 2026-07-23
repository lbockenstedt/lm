"""Hub Mist routes + service twins (Mist Phase 2).

Central and Mist are separate products; these mirror the Central routes/service
without sharing code. Covers: the ``mist.from_config`` helper branches
(test / available / browse when not configured), the service reads
(``get_mist_data`` / ``get_mist_status_data`` / ``_mist_site_rows`` / centralized
``_hub_mist`` synthetic spoke), and the ``save_mist`` route-level host guard
(Mist's API host is constrained to a known public region set — reject anything
else so a tenant user can't point the hub's outbound Mist calls at an arbitrary
endpoint).
"""
import asyncio

from fastapi import FastAPI
from starlette.testclient import TestClient

from simulations import mist as _mist
from simulations.routes import register_simulations_routes
from simulations.service import SimulationsService
import access as access_mod


# ── mist from_config helper branches ────────────────────────────────────────

def test_test_mist_not_configured_returns_missing():
    row = asyncio.run(_mist.test_mist_from_config({}))
    assert row["token_valid"] is False
    assert row["token_state"] == "missing"
    assert row["spoke_name"] == "Hub (centralized)"


def test_browse_mist_not_configured_returns_empty_set():
    res = asyncio.run(_mist.browse_mist_from_config({}))
    assert res["status"] == "SUCCESS"
    for k in ("sites", "alerts", "insights", "clients"):
        assert res[k] == []
    assert "warning" in res


def test_get_mist_available_failure_returns_empty_catalog(monkeypatch):
    async def boom(self):
        raise RuntimeError("boom")
    monkeypatch.setattr(_mist.MistClient, "available_checks", boom)
    cfg = {"api_token": "tok", "org_id": "org-1", "host": "api.mist.com"}
    res = asyncio.run(_mist.get_mist_available_from_config(cfg))
    assert res["alerts"] == [] and res["insights"] == []
    assert "warning" in res and "boom" in res["warning"]


# ── service twins ───────────────────────────────────────────────────────────

class _Hub:
    """Minimal hub stub: a simulations_cache, online set, tenant lookup, and the
    centralized mist_hub_status dict."""
    def __init__(self, cache, mist_hub_status=None, tenant="acme"):
        self.simulations_cache = cache
        self.active_connections = set(cache)  # all cached spokes online
        self.mist_hub_status = mist_hub_status or {}
        self.central_hub_status = {}

        class _state:
            @staticmethod
            def get_spoke_tenant(sid):
                return tenant

            @staticmethod
            def get_tenant(tid):
                return {"name": tid} if tid else None

        self.state = _state

    def _primary_key(self, sid):
        return sid

    def get_client_sim_spoke(self, tenant_id):
        return None


def test_get_mist_data_relays_mist_block_per_spoke():
    hub = _Hub({"s1": {"spoke_name": "S1", "mist": {"status": {"MIA": {"ap_offline": {"status": "ok"}}}}}})
    svc = SimulationsService(hub)
    data = asyncio.run(svc.get_mist_data("acme"))
    assert data["spokes"][0]["mist_status"]["status"]["MIA"]["ap_offline"]["status"] == "ok"


def test_get_mist_data_adds_hub_centralized_synthetic_spoke():
    hub = _Hub({}, mist_hub_status={"acme": {"status": {"MIA": {"ap_offline": {"status": "ok"}}}}})
    svc = SimulationsService(hub)
    data = asyncio.run(svc.get_mist_data("acme"))
    assert len(data["spokes"]) == 1
    assert data["spokes"][0]["spoke_name"] == "Hub (centralized)"
    assert data["spokes"][0]["mist_status"]["status"]["MIA"]["ap_offline"]["status"] == "ok"


def test_mist_site_rows_tally_ok_fail_unknown():
    hub = _Hub({})
    svc = SimulationsService(hub)
    rows = svc._mist_site_rows({
        "status": {"MIA": {"ap_offline": {"status": "ok"},
                           "dns_fail": {"status": "error"},
                           "weird": {"status": "no_data"}},
                   "DFW": {}},
        "site_mappings": {"MIA": "Mist-MIA"},
        "mist_clients_by_site": {"MIA": 7},
    })
    by = {r["wsite"]: r for r in rows}
    assert by["MIA"]["check_ok"] == 1 and by["MIA"]["check_fail"] == 1 and by["MIA"]["check_unknown"] == 1
    assert by["MIA"]["mist_site"] == "Mist-MIA"
    assert by["MIA"]["wireless_clients"] == 7
    # DFW has no checks → all zero, wsite preserved.
    assert by["DFW"]["check_ok"] == 0 and by["DFW"]["wireless_clients"] == 0


def test_get_mist_status_data_merges_token_valid():
    hub = _Hub({"s1": {"spoke_name": "S1", "mist": {"token_valid": True,
                  "status": {"MIA": {"ap_offline": {"status": "ok"}}}}}})
    svc = SimulationsService(hub)
    data = asyncio.run(svc.get_mist_status_data("acme"))
    assert data["token_valid"] is True
    assert data["spokes"][0]["sites"][0]["wsite"] == "MIA"


# ── save_mist route-level host guard ────────────────────────────────────────

class _MistStore:
    def __init__(self):
        self.configs = {}

    async def set_mist_config(self, tenant_id, cfg):
        self.configs[tenant_id] = dict(cfg or {})

    async def get_mist_config(self, tenant_id):
        return dict(self.configs.get(tenant_id, {}))


class _RouteHub(_Hub):
    def __init__(self, store):
        super().__init__({})
        self.simulations_store = store


class _Holder:
    def __init__(self):
        self.current = None


def _cs_user(tenant):
    return {"user": {"user_id": "u", "auth_type": "local",
                     "permissions": {"cs": True}, "tenants": [tenant],
                     "tenant_id": tenant, "protected": False}}


def _build_sim():
    store = _MistStore()
    hub = _RouteHub(store)
    holder = _Holder()
    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: holder.current,
        resolve_tenant_fn=lambda req: (holder.current or {}).get("user", {}).get("tenant_id"),
        is_admin_fn=access_mod.is_admin,
        check_tenant_access_fn=access_mod.check_tenant_access,
        sessions=None,
        has_cs_access_fn=access_mod.has_cs_access,
        is_tenant_admin_fn=access_mod.is_tenant_admin,
    )
    return TestClient(app), store, holder


def test_save_mist_rejects_unknown_host():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    for bad in ["api.evil.com", "127.0.0.1", "localhost", "https://10.0.0.5"]:
        r = c.post("/sim/api/aggregate/mist",
                   json={"hub_mist_config": {"host": bad, "api_token": "t", "org_id": "o"}})
        assert r.status_code == 400, f"{bad!r} should be 400, got {r.status_code}: {r.text}"
        assert "acme" not in store.configs


def test_save_mist_accepts_known_region_host():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    r = c.post("/sim/api/aggregate/mist",
               json={"hub_mist_config": {"host": "api.eu.mist.com",
                                         "api_token": "t", "org_id": "o"}})
    assert r.status_code == 200, r.text
    assert store.configs["acme"]["host"] == "api.eu.mist.com"


def test_save_mist_coerces_pasted_https_and_defaults_empty():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    # pasted https:// prefix stripped to the known host
    r = c.post("/sim/api/aggregate/mist",
               json={"hub_mist_config": {"host": "https://api.mist.com/",
                                         "api_token": "t", "org_id": "o"}})
    assert r.status_code == 200, r.text
    assert store.configs["acme"]["host"] == "api.mist.com"
    # empty host defaults to api.mist.com
    r2 = c.post("/sim/api/aggregate/mist",
                json={"hub_mist_config": {"api_token": "t", "org_id": "o"}})
    assert r2.status_code == 200, r2.text
    assert store.configs["acme"]["host"] == "api.mist.com"