"""``POST /api/console/tenant`` — the per-port "Assign Port to Tenant" action.

Regression: the route's ``@app.post`` decorator was accidentally dropped when
``/api/console/capture`` was inserted above it, so the handler was never
registered and assigning a port (e.g. to the shared tenant) returned
405 Method Not Allowed.
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

    def get_spoke_by_type(self, kind):
        return "console-1"

    async def request_response(self, sid, cmd, payload, timeout=None):
        self.sent.append((sid, cmd, payload))
        return {"payload": {"data": {"status": "SUCCESS", **payload}}}


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


def test_admin_assigns_port_to_shared_tenant():
    app, c = _client(role="admin")
    r = c.post("/api/console/tenant",
               json={"spoke_id": "console-1", "port_id": "ttyUSB0", "tenant_id": "shared"})
    assert r.status_code == 200, r.text
    assert r.json()["tenant_id"] == "shared"
    assert app.state.hub.sent[-1] == (
        "console-1", "CONSOLE_SET_TENANT", {"port_id": "ttyUSB0", "tenant_id": "shared"})


def test_empty_tenant_clears_override():
    app, c = _client(role="admin")
    r = c.post("/api/console/tenant", json={"port_id": "ttyUSB0", "tenant_id": ""})
    assert r.status_code == 200, r.text
    assert app.state.hub.sent[-1][2] == {"port_id": "ttyUSB0", "tenant_id": ""}


def test_non_admin_forbidden():
    app, c = _client(role="tenant_admin")
    r = c.post("/api/console/tenant", json={"port_id": "ttyUSB0", "tenant_id": "shared"})
    assert r.status_code == 403
    assert app.state.hub.sent == []


def test_port_id_required():
    _app, c = _client(role="admin")
    r = c.post("/api/console/tenant", json={"tenant_id": "shared"})
    assert r.status_code == 400
