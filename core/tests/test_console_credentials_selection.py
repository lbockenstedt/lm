"""Console auto-identify credential SELECTION — an admin can pick which of a
bucket's automation-readable ``console``/``login`` vault secrets the sweep is
allowed to use, instead of it always trying every one it finds. Exercises the
new ``GET /api/console/credentials/candidates`` and
``POST /api/console/credentials/selection`` routes plus the aggregator-level
filtering with a fake ``cred_vault`` so no real Azure vault is needed.
"""
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

_fake_enc = types.ModuleType("security.encryption")
_fake_enc.hub_encryption = SimpleNamespace(
    encrypt=lambda s: (s.encode() if isinstance(s, str) else s),
    decrypt=lambda b: b,
)

_fake_cv = types.ModuleType("cred_vault")
_fake_cv.ADMIN_BUCKET = "__admin__"

# t1 has two console/login secrets so a selection can meaningfully narrow it.
_BY_BUCKET = {
    "t1": [
        {"bucket": "t1", "name": "primary", "value": {"username": "u1", "password": "p1"}},
        {"bucket": "t1", "name": "backup", "value": {"username": "u2", "password": "p2"}},
    ],
}


async def _automation_list_by_type(hub, kind, buckets):
    want = {kind} if isinstance(kind, str) else set(kind)
    out = []
    if "console" in want or "login" in want:
        for b in (buckets if buckets is not None else list(_BY_BUCKET.keys())):
            out.extend(_BY_BUCKET.get(b, []))
    return out


async def _automation_get(hub, bucket, name):
    return None


class _CredVaultError(Exception):
    pass


_fake_cv.automation_list_by_type = _automation_list_by_type
_fake_cv.automation_get = _automation_get
_fake_cv._vault_available = lambda hub: True
_fake_cv.CredVaultError = _CredVaultError

from routes import console as console_routes  # noqa: E402


@pytest.fixture(autouse=True)
def _fake_modules(monkeypatch):
    monkeypatch.setitem(sys.modules, "security.encryption", _fake_enc)
    monkeypatch.setitem(sys.modules, "cred_vault", _fake_cv)


class _State:
    def __init__(self):
        self.system_state = {"console_credentials_enc": "", "global_config": {}}

    def _mark_dirty(self):
        pass

    def get_spoke_tenant(self, sid):
        return None


class _Hub:
    def __init__(self):
        self.state = _State()
        self._console_creds_seeded = set()
        self.sent = []

    def get_all_spokes_by_type(self, kind):
        return []

    async def send_to_spoke_command(self, sid, cmd, payload):
        self.sent.append((sid, cmd, payload))


def _client(role="admin", tenants=("t1",)):
    app = FastAPI()
    app.state.hub = _Hub()

    def _effective_tenant(req, explicit=None):
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
    return app, TestClient(app)


def test_candidates_default_all_selected():
    _app, c = _client()
    r = c.get("/api/console/credentials/candidates?tenant=t1")
    assert r.status_code == 200
    body = r.json()
    assert body["selection_active"] is False
    names = sorted(x["name"] for x in body["candidates"])
    assert names == ["backup", "primary"]
    assert all(x["selected"] for x in body["candidates"])


def test_set_selection_narrows_candidates_and_sweep():
    app, c = _client()
    r = c.post("/api/console/credentials/selection",
              json={"tenant": "t1", "selected": ["primary"]})
    assert r.status_code == 200
    body = r.json()
    assert body["selection_active"] is True
    assert body["selected"] == ["primary"]

    r2 = c.get("/api/console/credentials/candidates?tenant=t1")
    b2 = r2.json()
    assert b2["selection_active"] is True
    sel_map = {x["name"]: x["selected"] for x in b2["candidates"]}
    assert sel_map == {"primary": True, "backup": False}

    # The tenant-view credential listing is now narrowed to the selection too.
    r3 = c.get("/api/console/credentials?tenant=t1")
    users = sorted(x["username"] for x in r3.json()["credentials"])
    assert users == ["u1"]


def test_invalid_selection_names_rejected():
    _app, c = _client()
    r = c.post("/api/console/credentials/selection",
              json={"tenant": "t1", "selected": ["does-not-exist"]})
    assert r.status_code == 400


def test_null_selection_reverts_to_default():
    _app, c = _client()
    c.post("/api/console/credentials/selection", json={"tenant": "t1", "selected": ["primary"]})
    r = c.post("/api/console/credentials/selection", json={"tenant": "t1", "selected": None})
    assert r.status_code == 200
    assert r.json()["selection_active"] is False
    r2 = c.get("/api/console/credentials/candidates?tenant=t1")
    assert r2.json()["selection_active"] is False
    assert all(x["selected"] for x in r2.json()["candidates"])


def test_tenant_admin_cannot_select_for_other_tenant():
    _app, c = _client(role="tenant_admin", tenants=("t1",))
    r = c.post("/api/console/credentials/selection", json={"tenant": "t2", "selected": ["primary"]})
    # _effective_tenant confines a foreign ?tenant= back to the admin's own t1.
    assert r.status_code == 200
    assert r.json()["bucket"] == "t1"


def test_non_admin_forbidden():
    _app, c = _client(role="user", tenants=("t1",))
    r = c.get("/api/console/credentials/candidates?tenant=t1")
    assert r.status_code == 403
    r2 = c.post("/api/console/credentials/selection", json={"tenant": "t1", "selected": []})
    assert r2.status_code == 403
