"""LE install-target tenant scope in routes/net_services.py: the
``/api/le/targets/available`` filter and ``_le_guard_target`` (used by the
per-target deploy and add-target routes).

A tenant-admin may deploy a certificate only to a target bound to one of their
own tenants, and the target list shows only those. Tenant ids compare
canonically (fleet rule 6.1), so a spoke tagged "ACME" is a target of a user
assigned "acme", while another tenant's spoke stays refused.
"""
import os
import sys
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.net_services import register  # noqa: E402

SPOKE_TENANTS = {"nac-acme": "ACME", "nac-other": "other"}


class FakeHub:
    CERT_CAPABLE_MODULES = {"nac", "hub"}

    def __init__(self):
        self.spoke_module_types = {sid: "nac" for sid in SPOKE_TENANTS}
        self.spoke_module_types["le-1"] = "certificates"
        self.active_connections = set(self.spoke_module_types)
        self.pushed = []
        self.state = SimpleNamespace(system_state={"module_names": {}},
                                     get_spoke_tenant=lambda sid: SPOKE_TENANTS.get(sid, ""))

    def _primary_key(self, sid):
        return sid

    def get_all_spokes_by_type(self, module_type):
        return [s for s, t in self.spoke_module_types.items() if t == module_type]

    def get_spoke_by_type(self, module_type):
        return next(iter(self.get_all_spokes_by_type(module_type)), None)

    def get_spoke_for_agent(self, aid, fallback_hypervisor=False):
        return ""

    async def _distribute_one_cert(self, le_sid, domain, targets):
        self.pushed.append(targets)
        return [{"status": "SUCCESS"}]


def _client():
    hub = FakeHub()
    sess = {"user": {"tenants": ["acme"], "tenant_id": "acme"}}
    app = FastAPI()
    ctx = SimpleNamespace(_session_user=lambda request: sess, _is_admin=lambda s: False,
                          _filter_session=None, _filter_tenant=None,
                          _effective_tenant=lambda request, explicit=None: "acme")
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app), hub


def test_available_targets_match_tenant_in_any_capitalisation():
    c, _ = _client()
    targets = c.get("/api/le/targets/available").json()["targets"]
    assert [t.get("identifier") for t in targets] == ["nac-acme"]


def test_deploy_to_own_target_in_any_capitalisation_never_another_tenants():
    c, hub = _client()
    own = c.post("/api/le/certs/example.com/distribute",
                 json={"module_type": "nac", "identifier": "nac-acme"})
    assert own.status_code == 200, own.text
    other = c.post("/api/le/certs/example.com/distribute",
                   json={"module_type": "nac", "identifier": "nac-other"})
    assert other.status_code == 403
    assert hub.pushed == [[{"module_type": "nac", "identifier": "nac-acme"}]]
