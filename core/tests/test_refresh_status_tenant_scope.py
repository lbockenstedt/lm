"""The VM Server refresh-status chip (``GET /tenant/templates/refresh-status``)
is scoped to the header tenant picker. The Simulations views are per-tenant, so
a global admin viewing tenant A must NOT see tenant B's in-flight refreshes.

- admin + ``?tenant=acme``  → only acme's hosts
- admin + no tenant         → all tenants (global view)
- tenant-admin             → confined to own tenants, then to the selected one
"""
import os
import sys
import time
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.templates import register  # noqa: E402


class FakeHub:
    def __init__(self):
        self.template_refresh_hosts = {
            "t1|a-acme": {"tid": "t1", "agent_id": "a-acme", "host": "node-a",
                          "status": "restoring", "tenant_id": "acme",
                          "updated_at": time.time()},
            "t2|a-globex": {"tid": "t2", "agent_id": "a-globex", "host": "node-b",
                            "status": "restoring", "tenant_id": "globex",
                            "updated_at": time.time()},
        }


def _client(role, tenants):
    app = FastAPI()
    hub = FakeHub()
    is_admin = role == "admin"
    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": {"permissions": {"role": role},
                                            "tenants": tenants},
                                   "username": role},
        _is_admin=lambda sess: is_admin,
    )
    register(app, hub, ctx)
    return TestClient(app)


def _tenants(resp):
    return sorted((h.get("tenant_id") or "") for h in resp.json()["hosts"])


def test_admin_scopes_to_selected_tenant():
    c = _client("admin", ["acme", "globex"])
    r = c.get("/tenant/templates/refresh-status?tenant=acme")
    assert r.status_code == 200, r.text
    assert _tenants(r) == ["acme"]


def test_admin_without_tenant_sees_all():
    c = _client("admin", ["acme", "globex"])
    r = c.get("/tenant/templates/refresh-status")
    assert _tenants(r) == ["acme", "globex"]


def test_tenant_admin_confined_then_narrowed():
    # A tenant-admin owning both tenants is narrowed to the selected one.
    c = _client("tenant_admin", ["acme", "globex"])
    r = c.get("/tenant/templates/refresh-status?tenant=globex")
    assert _tenants(r) == ["globex"]


def test_tenant_admin_never_sees_other_tenants():
    # Owning only acme, a tenant-admin never sees globex — even with no picker
    # value (confined to their own tenants).
    c = _client("tenant_admin", ["acme"])
    r = c.get("/tenant/templates/refresh-status")
    assert _tenants(r) == ["acme"]
