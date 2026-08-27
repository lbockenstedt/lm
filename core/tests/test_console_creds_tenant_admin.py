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


class _CredVaultError(Exception):
    pass


async def _put_secret(hub, bucket, name, value, mode=None, sec_type=None,
                      description=None, psk="", actor="?"):
    if _PSK_BUCKETS.get(bucket) and psk != _PSK_BUCKETS[bucket]:
        raise _CredVaultError("bad pass-phrase")
    _BY_BUCKET[bucket] = [{"value": dict(value)}]
    return {"status": "ok"}


async def _delete_secret(hub, bucket, name, psk="", actor="?"):
    if _PSK_BUCKETS.get(bucket) and psk != _PSK_BUCKETS[bucket]:
        raise _CredVaultError("bad pass-phrase")
    if bucket in _BY_BUCKET:
        del _BY_BUCKET[bucket]
    else:
        raise _CredVaultError("absent")


def _bucket_has_psk(hub, bucket):
    return bool(_PSK_BUCKETS.get(bucket))


_PSK_BUCKETS = {}
_fake_cv.automation_list_by_type = _automation_list_by_type
_fake_cv.automation_get = _automation_get
_fake_cv._vault_available = lambda hub: True
_fake_cv.put_secret = _put_secret
_fake_cv.delete_secret = _delete_secret
_fake_cv.bucket_has_psk = _bucket_has_psk
_fake_cv.CredVaultError = _CredVaultError
sys.modules["cred_vault"] = _fake_cv

from routes import console as console_routes  # noqa: E402


class _State:
    def __init__(self, spoke_tenants=None):
        self.system_state = {"console_credentials_enc": "", "global_config": {}}
        self._spoke_tenants = spoke_tenants or {}

    def _mark_dirty(self):
        pass

    def get_spoke_tenant(self, sid):
        return self._spoke_tenants.get(sid)


class _Hub:
    def __init__(self, spoke_tenants=None):
        self.state = _State(spoke_tenants)
        self._console_creds_seeded = set()
        self.sent = []

    def get_all_spokes_by_type(self, kind):
        return list(self.state._spoke_tenants.keys())

    async def send_to_spoke_command(self, sid, cmd, payload):
        self.sent.append((sid, cmd, payload))


def _client(role, tenants, explicit_ok=True, spoke_tenants=None):
    app = FastAPI()
    app.state.hub = _Hub(spoke_tenants)

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
    # A tenant admin can now MANAGE their own bucket's console scan logins.
    assert body["read_only"] is False
    assert body["creation_disabled"] is False
    assert body["can_manage"] is True
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


def _reset_vault():
    _BY_BUCKET.clear()
    _BY_BUCKET.update({
        "__admin__": [{"value": {"username": "global-admin", "password": "g"}}],
        "t1": [{"value": {"username": "t1-user", "password": "p1"}}],
        "t2": [{"value": {"username": "t2-user", "password": "p2"}}],
    })
    _PSK_BUCKETS.clear()


def _bucket_creds(bucket):
    """Flatten the fake bucket's stored console secret into (user, pass) pairs."""
    out = []
    for rec in _BY_BUCKET.get(bucket, []):
        v = rec.get("value") or {}
        rows = v.get("credentials") if isinstance(v.get("credentials"), list) else [v]
        for c in rows:
            out.append((c.get("username", ""), c.get("password", "")))
    return sorted(out)


def test_set_tenant_admin_writes_own_bucket_and_reseeds_only_that_tenant():
    _reset_vault()
    c = _client("tenant_admin", ("t1",),
                spoke_tenants={"con-t1": "t1", "con-t2": "t2"})
    r = c.post("/api/console/credentials/set",
               json={"tenant": "t1",
                     "credentials": [{"username": "scan1", "password": "s1"}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    assert body["bucket"] == "t1"
    assert _bucket_creds("t1") == [("scan1", "s1")]
    # Only THIS tenant's console spoke is re-seeded, never t2's.
    hub = c.app.state.hub
    seeded = [sid for sid, _cmd, _pl in hub.sent]
    assert seeded == ["con-t1"]


def test_set_blank_password_keeps_existing():
    _reset_vault()
    c = _client("tenant_admin", ("t1",), spoke_tenants={"con-t1": "t1"})
    # Submit the existing username with a blank password → keep stored p1.
    r = c.post("/api/console/credentials/set",
               json={"tenant": "t1",
                     "credentials": [{"username": "t1-user", "password": ""}]})
    assert r.status_code == 200, r.text
    assert _bucket_creds("t1") == [("t1-user", "p1")]


def test_set_empty_list_clears_bucket():
    _reset_vault()
    c = _client("tenant_admin", ("t1",), spoke_tenants={"con-t1": "t1"})
    r = c.post("/api/console/credentials/set",
               json={"tenant": "t1", "credentials": []})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 0
    assert "t1" not in _BY_BUCKET


def test_set_tenant_admin_cannot_touch_admin_or_sibling_bucket():
    _reset_vault()
    # A t1 admin aiming at __admin__ or t2 is confined to t1 by effective_tenant.
    c = _client("tenant_admin", ("t1",), spoke_tenants={"con-t1": "t1"})
    before_admin = _bucket_creds("__admin__")
    before_t2 = _bucket_creds("t2")
    r = c.post("/api/console/credentials/set",
               json={"tenant": "__admin__",
                     "credentials": [{"username": "x", "password": "y"}]})
    assert r.status_code == 200, r.text
    assert r.json()["bucket"] == "t1"
    # The privileged/sibling buckets are untouched.
    assert _bucket_creds("__admin__") == before_admin
    assert _bucket_creds("t2") == before_t2
    assert _bucket_creds("t1") == [("x", "y")]


def test_set_requires_bucket_psk_when_protected():
    _reset_vault()
    _PSK_BUCKETS["t1"] = "s3cret"
    c = _client("tenant_admin", ("t1",), spoke_tenants={"con-t1": "t1"})
    # Wrong/missing pass-phrase on a PSK-protected bucket → 400 and no write.
    r = c.post("/api/console/credentials/set",
               json={"tenant": "t1",
                     "credentials": [{"username": "scan1", "password": "s1"}]})
    assert r.status_code == 400
    assert _bucket_creds("t1") == [("t1-user", "p1")]
    # Correct pass-phrase → written. GET also advertises the PSK requirement.
    g = c.get("/api/console/credentials?tenant=t1").json()
    assert g["bucket_has_psk"] is True
    r2 = c.post("/api/console/credentials/set",
                json={"tenant": "t1", "psk": "s3cret",
                      "credentials": [{"username": "scan1", "password": "s1"}]})
    assert r2.status_code == 200, r2.text
    assert _bucket_creds("t1") == [("scan1", "s1")]


def test_set_forbidden_for_non_admin():
    _reset_vault()
    c = _client("user", ("t1",), spoke_tenants={"con-t1": "t1"})
    r = c.post("/api/console/credentials/set",
               json={"tenant": "t1", "credentials": []})
    assert r.status_code == 403
