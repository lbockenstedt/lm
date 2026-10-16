"""Simulations → Spoke Management must never show or touch another tenant's
spokes — not even for a Global Admin. The list is scoped to the requested
tenant (admins additionally see unbound spokes so they can assign them), and
per-spoke routes 404 for a spoke bound to a different tenant."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations.routes import register_simulations_routes


class _State:
    def __init__(self):
        self.system_state = {
            "module_metadata": {
                "cs-a": {"tenant_id": "A", "module_type": "Client-Sim"},
                "cs-b": {"tenant_id": "B", "module_type": "Client-Sim"},
                "cs-free": {"module_type": "Client-Sim"},
                "pxmx-a": {"tenant_id": "A", "module_type": "hypervisor"},
            },
            "approved_modules": {"cs-a": True, "cs-b": True, "cs-free": False},
        }
        self.tenant_state = {"tenants": {"A": {}, "B": {}}}
        self.labels = {}

    def get_approved_modules(self):
        return self.system_state["approved_modules"]

    def get_spoke_tenant(self, sid):
        return self.system_state["module_metadata"].get(sid, {}).get("tenant_id")

    def get_tenant(self, tid):
        return None

    def set_module_name(self, sid, label):
        self.labels[sid] = label

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self):
        self.state = _State()
        self.spoke_module_types = {}
        self.active_connections = {}
        self.simulations_cache = {"cs-b": {"timestamp": 1, "secret": 1}}
        self.simulations_store = object()

    def _primary_key(self, sid):
        return sid


def _client(admin=True, user_tenants=None):
    app = FastAPI()
    hub = _Hub()
    sess = {"user": {"tenants": user_tenants or []}}
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: sess,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: admin,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return TestClient(app), hub


def _ids(resp):
    assert resp.status_code == 200, resp.text
    return sorted(s["spoke_id"] for s in resp.json()["spokes"])


def test_admin_list_is_scoped_to_selected_tenant():
    c, _ = _client(admin=True)
    assert _ids(c.get("/sim/api/spokes?tenant_id=A")) == ["cs-a", "cs-free"]
    assert _ids(c.get("/sim/api/spokes?tenant_id=B")) == ["cs-b", "cs-free"]


def test_non_admin_list_only_own_selected_tenant_approved():
    c, _ = _client(admin=False, user_tenants=["A", "B"])
    assert _ids(c.get("/sim/api/spokes?tenant_id=A")) == ["cs-a"]
    assert _ids(c.get("/sim/api/spokes?tenant_id=B")) == ["cs-b"]


def test_config_diag_rejects_other_tenants_spoke():
    c, _ = _client(admin=True)
    assert c.get("/sim/api/A/spokes/cs-b/config-diag?tenant_id=A").status_code == 404


def test_admin_mutation_rejects_other_tenants_spoke_but_allows_unbound():
    c, hub = _client(admin=True)
    r = c.patch("/sim/api/A/spokes/cs-b/label?tenant_id=A", json={"label": "x"})
    assert r.status_code == 404
    assert "cs-b" not in hub.state.labels
    r = c.patch("/sim/api/A/spokes/cs-free/label?tenant_id=A", json={"label": "x"})
    assert r.status_code == 200
    r = c.patch("/sim/api/A/spokes/cs-a/label?tenant_id=A", json={"label": "y"})
    assert r.status_code == 200
    r = c.delete("/sim/api/spokes/cs-b?tenant_id=A")
    assert r.status_code == 404
