"""_instance_crud list tenant scoping — GET /setup/<product>?tenant=<id>.

The list endpoint only applied its tenant filter to NON-admins, so an admin
viewing a tenant-scoped surface saw every tenant's entries. That surfaced on the
NW Scan tab: selecting a tenant with no nw agent still listed another tenant's
scan-credential sets, inviting a scan configured with credentials that the
executor then (correctly) refuses to use.

``?tenant=`` is an opt-in narrowing applied to every caller, admins included:
that tenant's own entries plus shared ones. Omitting it preserves the previous
behavior exactly, so the other products sharing _instance_crud are unaffected.
"""
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.nw as nw

SHARED = "tenant-shared"


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}

    def get_spoke_tenant(self, sid):
        return None

    def _mark_dirty(self):
        pass


class _Hub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self):
        self.state = _State()
        self.spoke_module_types = {}
        self.active_connections = {}

    def _primary_key(self, sid):
        return sid


def _build(is_admin=True, own_tenants=()):
    hub = _Hub()
    app = FastAPI()
    app.state.hub = hub
    sess = {"user": {"user_id": "u", "tenants": list(own_tenants),
                     "permissions": {"admin": is_admin}}}
    ctx = SimpleNamespace(
        _session_user=lambda req: sess,
        _is_admin=lambda s: is_admin,
        _is_tenant_admin=lambda s: not is_admin,
        _filter_nw=lambda *a, **k: [],
    )
    nw.register(app, hub, ctx)
    return TestClient(app), hub


def _seed(hub):
    hub.state.system_state["global_config"]["nw_scan_credentials"] = [
        {"id": "c-admin", "name": "Admin - Aruba", "tenant_id": "tenant-admin"},
        {"id": "c-lrb", "name": "Admin - LRB", "tenant_id": "tenant-lrb"},
        {"id": "c-shared", "name": "Shared", "tenant_id": SHARED},
        {"id": "c-none", "name": "Unassigned", "tenant_id": ""},
    ]


@pytest.fixture(autouse=True)
def _shared_tenant(monkeypatch):
    # Both the module-level cache (read by access.tenant_is_shared, which backs
    # spoke_visible_to_session) and the accessor must agree, or the admin and
    # non-admin paths disagree about which tenant is shared.
    monkeypatch.setattr(nw.access, "_SHARED_TENANT_ID", SHARED)
    monkeypatch.setattr(nw.access, "shared_tenant_id", lambda: SHARED)


def _ids(resp):
    return sorted(i["id"] for i in resp.json()["instances"])


def test_admin_without_tenant_param_sees_everything():
    """Unchanged legacy behavior — other products rely on this."""
    c, hub = _build()
    _seed(hub)
    assert _ids(c.get("/setup/nw-scan-credentials")) == [
        "c-admin", "c-lrb", "c-none", "c-shared"]


def test_admin_with_tenant_param_sees_only_that_tenant_plus_shared():
    """THE REGRESSION: selecting tenant-admin must not list LRB's credentials."""
    c, hub = _build()
    _seed(hub)
    got = _ids(c.get("/setup/nw-scan-credentials?tenant=tenant-admin"))
    assert got == ["c-admin", "c-shared"]
    assert "c-lrb" not in got


def test_tenant_param_excludes_unassigned_instances():
    """An unassigned instance is admin-only by the shared-tenant invariant."""
    c, hub = _build()
    _seed(hub)
    assert "c-none" not in _ids(c.get("/setup/nw-scan-credentials?tenant=tenant-admin"))


def test_tenant_default_is_treated_as_unscoped():
    """'default' is the admin's global view, not a literal tenant name."""
    c, hub = _build()
    _seed(hub)
    assert _ids(c.get("/setup/nw-scan-credentials?tenant=default")) == [
        "c-admin", "c-lrb", "c-none", "c-shared"]


def test_tenant_with_no_credentials_gets_empty_list():
    c, hub = _build()
    _seed(hub)
    assert _ids(c.get("/setup/nw-scan-credentials?tenant=tenant-empty")) == ["c-shared"]


def test_non_admin_visibility_filter_still_applies_without_param():
    """Pre-existing non-admin scoping is untouched."""
    c, hub = _build(is_admin=False, own_tenants=["tenant-admin"])
    _seed(hub)
    got = _ids(c.get("/setup/nw-scan-credentials"))
    assert got == ["c-admin", "c-shared"]


def test_non_admin_cannot_widen_scope_with_tenant_param():
    """The param narrows; it never re-admits another tenant's entries."""
    c, hub = _build(is_admin=False, own_tenants=["tenant-admin"])
    _seed(hub)
    assert _ids(c.get("/setup/nw-scan-credentials?tenant=tenant-lrb")) == ["c-shared"]


def test_no_shared_tenant_configured_does_not_admit_unassigned(monkeypatch):
    """An empty shared-tenant id must not match the unassigned ("") entries."""
    monkeypatch.setattr(nw.access, "_SHARED_TENANT_ID", "")
    monkeypatch.setattr(nw.access, "shared_tenant_id", lambda: "")
    c, hub = _build()
    _seed(hub)
    assert _ids(c.get("/setup/nw-scan-credentials?tenant=tenant-admin")) == ["c-admin"]
