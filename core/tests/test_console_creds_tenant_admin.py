"""Tenant-scoped ``GET /api/console/credentials`` for a Tenant Admin.

A Tenant Admin now sees the 🔑 Credentials view, but READ-ONLY and confined to
THEIR tenant: the endpoint returns the auto-login credentials that will actually
be pushed to that tenant's console spokes (the tenant's own vault bucket + the
shared global ``__admin__`` slot). They never see the global LOCAL legacy
passwords, and the delete-only POST stays Global-Admin-only. This exercises the
route end-to-end with a fake cred_vault so no real Azure vault is needed.
"""
import sys
import types
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Fake security.encryption: identity JSON codec so any local-blob path is inert.
_fake_enc = types.ModuleType("security.encryption")
_fake_enc.hub_encryption = SimpleNamespace(
    encrypt=lambda s: (s.encode() if isinstance(s, str) else s),
    decrypt=lambda b: b,
)
sys.modules.setdefault("security", types.ModuleType("security"))
sys.modules["security.encryption"] = _fake_enc

# Fake cred_vault: vault "available"; console-type secrets exist per bucket so a
# tenant's bucket returns its own login and __admin__ returns a shared login.
_fake_cv = types.ModuleType("cred_vault")
_fake_cv.ADMIN_BUCKET = "__admin__"

_BY_BUCKET = {
    "__admin__": [{"value": {"username": "global-admin", "password": "g"}}],
    "t1": [{"value": {"username": "t1-user", "password": "p1"}}],
    "t2": [{"value": {"username": "t2-user", "password": "p2"}}],
}


async def _automation_list_by_type(hub, kind, buckets):
    out = []
    if kind == "console":
        for b in buckets:
            out.extend(_BY_BUCKET.get(b, []))
    return out


async def _automation_get(hub, bucket, name):
    return None


_fake_cv.automation_list_by_type = _automation_list_by_type
_fake_cv.automation_get = _automation_get
_fake_cv._vault_available = lambda hub: True
sys.modules["cred_vault"] = _fake_cv

from routes import console as console_routes  # noqa: E402


class _State:
    def __init__(self):
        self.system_state = {"console_credentials_enc": "", "global_config": {}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self):
        self.state = _State()


def _client(role, tenants, explicit_ok=True):
    app = FastAPI()
    app.state.hub = _Hub()

    def _effective_tenant(req, explicit=None):
        # Mirror access.effective_tenant: non-admin gets explicit only if owned,
        # else their session tenant_id.
        if explicit and explicit in tenants:
            return explicit
        return tenants[0] if tenants else None

    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": {"permissions": {"role": role},
                                            "tenants": list(tenants),
                                            "tenant_id": (tenants[0] if tenants else "")}},
        _is_admin=lambda s: role == "admin",
        _is_tenant_admin=lambda s: role == "tenant_admin",
        _has_console_write_access=lambda s: True,
        _has_console_access=lambda s: True,
        _resolve_tenant=lambda req, explicit=None: (tenants[0] if tenants else None),
        _effective_tenant=_effective_tenant,
    )
    console_routes.register(app, app.state.hub, ctx)
    return TestClient(app)


def test_tenant_admin_sees_own_bucket_only_plus_shared_count():
    c = _client("tenant_admin", ("t1",))
    r = c.get("/api/console/credentials?tenant=t1")
    assert r.status_code == 200
    body = r.json()
    assert body["read_only"] is True
    assert body["creation_disabled"] is True
    assert body["tenant"] == "t1"
    users = sorted(x["username"] for x in body["credentials"])
    # ONLY the tenant's own bucket login is enumerated — never the privileged
    # global __admin__ usernames (surfaced as a count instead).
    assert users == ["t1-user"]
    assert body["shared_global_count"] == 1
    # A tenant admin never sees the global LOCAL legacy passwords.
    assert body["local_credentials"] == []
    assert body["local_passwords_present"] is False


def test_tenant_admin_cannot_reach_other_tenant():
    # Crafted ?tenant=t2 for a t1-only admin is confined back to t1 by
    # effective_tenant — no cross-tenant leak.
    c = _client("tenant_admin", ("t1",))
    r = c.get("/api/console/credentials?tenant=t2")
    assert r.status_code == 200
    body = r.json()
    users = sorted(x["username"] for x in body["credentials"])
    assert users == ["t1-user"]
    assert "t2-user" not in users


def test_tenant_admin_delete_is_forbidden():
    # The delete-only POST stays Global-Admin-only; a tenant admin is 403.
    c = _client("tenant_admin", ("t1",))
    r = c.post("/api/console/credentials", json={"credentials": []})
    assert r.status_code == 403


def test_tenant_admin_without_tenant_denied():
    c = _client("tenant_admin", ())
    r = c.get("/api/console/credentials")
    assert r.status_code == 403
