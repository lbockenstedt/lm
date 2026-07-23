"""Hub Central On-Prem routes + service twins (Central On-Prem Phase 4).

Central On-Prem is a third Aruba Central instance — the SAME Aruba Central API/
``ArubaClient`` as cloud Central, but a separate config slot + status slot so
the two never step on each other. These mirror the Central routes/service (reusing
the same ``test_central_from_config`` / ``browse_all_from_config`` /
``get_central_available_from_config`` helpers since the Aruba API is identical)
and cover the route-level differences: the on-prem config slot, the on-prem hub
status slot, the ``central_on_prem_api`` processing-mode dispatch, and the
``source=central_on_prem`` browse-history tag.

Covers:
  - ``save_central_on_prem`` SSRF guard (rejects internal/plain-http cluster_url,
    same guard as cloud Central; accepts new_central creds with no cluster_url).
  - ``get_central_on_prem_status`` merges ``hub_central_on_prem_config``.
  - ``get_central_on_prem_browse`` centralized mode runs ``browse_all_from_config``
    against the ON-PREM config and records history with ``source=central_on_prem``
    (not ``central``); distributed mode forwards ``CS_CENTRAL_ON_PREM_BROWSE``
    (no spoke → empty set + warning, proving the distributed branch is taken).
  - service ``get_central_on_prem_data`` relays the ``central_on_prem`` block per
    spoke + the centralized hub synthetic spoke.
"""
import asyncio

from fastapi import FastAPI
from starlette.testclient import TestClient

from simulations import aruba as _aruba
from simulations.routes import register_simulations_routes
from simulations.service import SimulationsService
import access as access_mod


# ── test_central_from_config reused unchanged (same Aruba API) ──────────────
def test_test_central_on_prem_not_configured_returns_missing():
    # The on-prem test route reuses cloud Central's test_central_from_config
    # (the Aruba Central API is identical) — not-configured → missing row.
    row = asyncio.run(_aruba.test_central_from_config({}))
    assert row["token_valid"] is False
    assert row["token_state"] == "missing"
    assert row["spoke_name"] == "Hub (centralized)"


# ── service twins ───────────────────────────────────────────────────────────
class _Hub:
    """Minimal hub stub: a simulations_cache, online set, tenant lookup, and the
    three per-source hub status dicts (central / mist / central_on_prem)."""

    def __init__(self, cache, on_prem_hub_status=None, tenant="acme"):
        self.simulations_cache = cache
        self.active_connections = set(cache)  # all cached spokes online
        self.central_hub_status = {}
        self.mist_hub_status = {}
        self.central_on_prem_hub_status = on_prem_hub_status or {}

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


def test_get_central_on_prem_data_relays_on_prem_block_per_spoke():
    hub = _Hub({"s1": {"spoke_name": "S1",
                       "central_on_prem": {"status": {"MIA": {"dns_fail": {"status": "ok"}}}}}})
    svc = SimulationsService(hub)
    data = asyncio.run(svc.get_central_on_prem_data("acme"))
    assert data["spokes"][0]["central_status"]["status"]["MIA"]["dns_fail"]["status"] == "ok"


def test_get_central_on_prem_data_adds_hub_centralized_synthetic_spoke():
    hub = _Hub({}, on_prem_hub_status={"acme": {"status": {"MIA": {"dns_fail": {"status": "ok"}}}}})
    svc = SimulationsService(hub)
    data = asyncio.run(svc.get_central_on_prem_data("acme"))
    assert len(data["spokes"]) == 1
    assert data["spokes"][0]["spoke_name"] == "Hub (centralized)"
    assert data["spokes"][0]["central_status"]["status"]["MIA"]["dns_fail"]["status"] == "ok"


def test_get_central_on_prem_status_data_merges_token_valid():
    hub = _Hub({"s1": {"spoke_name": "S1",
                       "central_on_prem": {"token_valid": True,
                          "status": {"MIA": {"dns_fail": {"status": "ok"}}}}}})
    svc = SimulationsService(hub)
    data = asyncio.run(svc.get_central_on_prem_status_data("acme"))
    assert data["token_valid"] is True
    assert data["spokes"][0]["sites"][0]["wsite"] == "MIA"
    # The on-prem status block has the SAME shape as cloud Central's, so the
    # shared _central_site_rows renderer is reused (central_clients_by_site key).
    assert data["hub_central_on_prem_config"] == {}


# ── route harness ───────────────────────────────────────────────────────────
class _OnPremStore:
    """In-memory store with the on-prem config/sites slots + the processing-mode
    + sim-conf + history methods the routes read. Records every alert/insight
    item via record_alert_insight_seen so the browse source-tag can be asserted."""

    def __init__(self):
        self.configs = {}
        self.sites = {}
        self.modes = {}
        self.history = []  # items recorded by _record_alert_insight_history

    async def get_central_on_prem_config(self, tenant_id):
        return dict(self.configs.get(tenant_id, {}))

    async def set_central_on_prem_config(self, tenant_id, cfg):
        self.configs[tenant_id] = dict(cfg or {})

    async def get_central_on_prem_sites_config(self, tenant_id):
        return dict(self.sites.get(tenant_id, {}))

    async def set_central_on_prem_sites_config(self, tenant_id, cfg):
        self.sites[tenant_id] = dict(cfg or {})

    async def get_central_sites_config(self, tenant_id):
        return {}

    async def get_mist_sites_config(self, tenant_id):
        return {}

    async def get_processing_modes(self, tenant_id):
        return dict(self.modes.get(tenant_id, {}))

    async def set_processing_mode(self, tenant_id, feature, value):
        self.modes.setdefault(tenant_id, {})[feature] = value

    @staticmethod
    def central_on_prem_api_is_centralized(modes):
        return str((modes or {}).get("central_on_prem_api") or "").strip().lower() != "distributed"

    async def get_sim_conf_content(self, tenant_id):
        return ""

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

    async def record_alert_insight_seen(self, items):
        self.history.extend(items)

    async def get_alert_insight_history(self):
        return list(self.history)


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
    store = _OnPremStore()
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


# ── save_central_on_prem SSRF guard (same guard as cloud Central) ───────────
def test_save_central_on_prem_rejects_internal_cluster_url():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    for bad in ["http://127.0.0.1", "https://10.0.0.5", "https://localhost"]:
        r = c.post("/sim/api/aggregate/central-on-prem",
                   json={"hub_central_on_prem_config": {"cluster_url": bad,
                        "api_version": "classic", "client_id": "cid",
                        "client_secret": "sec", "refresh_token": "r"}})
        assert r.status_code == 400, f"{bad!r} should be 400, got {r.status_code}: {r.text}"
        assert "acme" not in store.configs


def test_save_central_on_prem_accepts_new_central_no_cluster_url():
    # new_central uses a fixed HPE token URL and ignores cluster_url, so the SSRF
    # guard is skipped (no cluster_url) → accepted + stored + mode persisted.
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    r = c.post("/sim/api/aggregate/central-on-prem",
               json={"mode": "central",
                     "hub_central_on_prem_config": {"api_version": "new_central",
                        "client_id": "cid", "client_secret": "sec"}})
    assert r.status_code == 200, r.text
    assert store.configs["acme"]["client_id"] == "cid"
    assert store.configs["acme"]["mode"] == "central"
    body = r.json()
    assert body["saved"] is True


def test_save_central_on_prem_coerces_poll_interval_floor():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    r = c.post("/sim/api/aggregate/central-on-prem",
               json={"hub_central_on_prem_config": {"api_version": "new_central",
                        "client_id": "cid", "client_secret": "sec",
                        "poll_interval_s": 10}})
    assert r.status_code == 200, r.text
    # floored at 60s (same as cloud Central).
    assert store.configs["acme"]["poll_interval_s"] == 60


# ── get_central_on_prem_status merges hub_central_on_prem_config ───────────
def test_get_central_on_prem_status_merges_hub_config():
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    # Seed an on-prem config so the status route merges it into the response.
    store.configs["acme"] = {"api_version": "new_central", "client_id": "cid",
                             "client_secret": "sec", "mode": "central"}
    r = c.get("/sim/api/aggregate/central-on-prem-status")
    assert r.status_code == 200, r.text
    body = r.json()
    # mode is surfaced; the secret-bearing creds are under hub_central_on_prem_config.
    assert body["mode"] == "central"
    assert body["hub_central_on_prem_config"]["client_id"] == "cid"


# ── browse: centralized runs browse_all_from_config + tags central_on_prem ─
def test_browse_centralized_records_history_with_on_prem_source(monkeypatch):
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    # centralized by default → browse_all_from_config runs against the on-prem
    # config. Stub it to return a known alert so we can assert the source tag.
    store.configs["acme"] = {"api_version": "new_central", "client_id": "cid",
                             "client_secret": "sec"}

    async def fake_browse(cc):
        assert cc is store.configs["acme"] or cc == store.configs["acme"], \
            "browse must run against the ON-PREM config, not cloud Central's"
        return {"status": "SUCCESS", "sites": [], "clients": [],
                "devices_by_site": {}, "clients_by_site": [],
                "alerts": [{"name": "AP_DOWN", "site": "MIA"}],
                "insights": []}

    monkeypatch.setattr(_aruba, "browse_all_from_config", fake_browse)
    # The route imported the name into its module namespace at registration
    # time; patch the routes module's reference too.
    import simulations.routes as _r
    monkeypatch.setattr(_r, "browse_all_from_config", fake_browse)
    r = c.get("/sim/api/aggregate/central-on-prem-browse")
    assert r.status_code == 200, r.text
    # The alert was recorded with source=central_on_prem (NOT central) so the
    # picker offers it as "Central On-Prem:AP_DOWN" and the engine fires it
    # against on-prem telemetry only.
    assert any(it["source"] == "central_on_prem" and it["id"] == "AP_DOWN"
               for it in store.history), store.history


def test_browse_distributed_forwards_cs_central_on_prem_browse(monkeypatch):
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    # distributed mode → the centralized branch must be SKIPPED (no
    # browse_all_from_config call) and the spoke-forward branch taken; with no
    # spoke connected it returns the empty set + warning (proving the branch).
    store.modes["acme"] = {"central_on_prem_api": "distributed"}

    def fail_browse(cc):
        raise AssertionError("browse_all_from_config must NOT run in distributed mode")

    import simulations.routes as _r
    monkeypatch.setattr(_r, "browse_all_from_config", fail_browse)
    r = c.get("/sim/api/aggregate/central-on-prem-browse")
    assert r.status_code == 200, r.text
    body = r.json()
    for k in ("sites", "alerts", "insights", "clients"):
        assert body[k] == []
    assert "Central On-Prem browse unavailable" in (body.get("warning") or "")


# ── available: centralized reuses get_central_available_from_config ────────
def test_available_centralized_reuses_central_helper(monkeypatch):
    c, store, holder = _build_sim()
    holder.current = _cs_user("acme")
    store.configs["acme"] = {"api_version": "new_central", "client_id": "cid",
                             "client_secret": "sec"}
    seen = {}

    async def fake_avail(cc):
        seen["cc"] = cc
        return {"alerts": [{"id": "AP_DOWN"}], "insights": [], "hardware": [],
                "warning": None}

    import simulations.routes as _r
    monkeypatch.setattr(_r, "get_central_available_from_config", fake_avail)
    r = c.get("/sim/api/acme/central-on-prem/available")
    assert r.status_code == 200, r.text
    assert seen["cc"] == store.configs["acme"]  # on-prem config, not cloud Central's
    assert r.json()["alerts"][0]["id"] == "AP_DOWN"