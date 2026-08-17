"""Delete-only ``POST /api/console/credentials`` + ``local_credentials`` in GET.

Creating or changing console passwords in the module is disabled (they live in
the Credential Vault), but an operator MUST still be able to DELETE legacy LOCAL
passwords to clean them up once the vault is in use — the agreed "delete but not
add" rule. This exercises the route end-to-end with fake encryption + cred_vault
modules so no real Fernet key / Azure vault is needed.
"""
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Fake security.encryption: identity JSON codec (encrypt(str)->bytes, decrypt
# passes bytes through) so the local credential blob round-trips as plain JSON.
_fake_enc = types.ModuleType("security.encryption")
_fake_enc.hub_encryption = SimpleNamespace(
    encrypt=lambda s: (s.encode() if isinstance(s, str) else s),
    decrypt=lambda b: b,
)
sys.modules.setdefault("security", types.ModuleType("security"))
sys.modules["security.encryption"] = _fake_enc

# Fake cred_vault: vault "available" (so vault_enabled True) but no console
# secret present (automation_get -> None) → the resolver falls back to local.
_fake_cv = types.ModuleType("cred_vault")
_fake_cv.ADMIN_BUCKET = "__admin__"
async def _automation_get(hub, bucket, name):
    return None
_fake_cv.automation_get = _automation_get
_fake_cv._vault_available = lambda hub: True
sys.modules["cred_vault"] = _fake_cv

from routes import console as console_routes  # noqa: E402


class _State:
    def __init__(self, creds):
        self.system_state = {
            "console_credentials_enc": json.dumps(creds) if creds is not None else "",
            "global_config": {},
        }

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, creds):
        self.state = _State(creds)
        self.pushed = []

    def get_all_spokes_by_type(self, kind):
        return ["c1"] if kind == "console" else []

    async def send_to_spoke_command(self, sid, cmd, payload):
        self.pushed.append((sid, cmd, payload))
        return {}


def _client(creds):
    app = FastAPI()
    hub = _Hub(creds)
    app.state.hub = hub
    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": {"is_admin": True, "username": "root"}},
        _is_admin=lambda s: True,
        _resolve_tenant=lambda req, explicit=None: "default",
    )
    console_routes.register(app, hub, ctx)
    return TestClient(app), hub


def _local(hub):
    return json.loads(hub.state.system_state["console_credentials_enc"] or "[]")


def test_get_reports_local_credentials():
    c, _ = _client([{"username": "admin", "password": "x"},
                    {"username": "root", "password": "y"}])
    r = c.get("/api/console/credentials")
    assert r.status_code == 200
    body = r.json()
    assert body["creation_disabled"] is True
    users = sorted(x["username"] for x in body["local_credentials"])
    assert users == ["admin", "root"]


def test_delete_removes_one_local_credential():
    c, hub = _client([{"username": "admin", "password": "x"},
                      {"username": "root", "password": "y"}])
    # Submit the surviving username only (no password) → delete "admin".
    r = c.post("/api/console/credentials", json={"credentials": [{"username": "root"}]})
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "removed": 1, "remaining": 1}
    assert [x["username"] for x in _local(hub)] == ["root"]
    # Removal is pushed to connected console spokes.
    assert hub.pushed and hub.pushed[0][1] == "CONSOLE_SET_CREDENTIALS"


def test_delete_all_local_credentials():
    c, hub = _client([{"username": "admin", "password": "x"}])
    r = c.post("/api/console/credentials", json={"credentials": []})
    assert r.status_code == 200
    assert r.json()["remaining"] == 0
    assert _local(hub) == []


def test_reject_adding_new_username():
    c, hub = _client([{"username": "admin", "password": "x"}])
    r = c.post("/api/console/credentials",
               json={"credentials": [{"username": "admin"}, {"username": "new"}]})
    assert r.status_code == 409
    assert "only DELETE" in r.json()["detail"]
    # Store unchanged.
    assert [x["username"] for x in _local(hub)] == ["admin"]


def test_reject_password_change():
    c, hub = _client([{"username": "admin", "password": "x"}])
    r = c.post("/api/console/credentials",
               json={"credentials": [{"username": "admin", "password": "newpass"}]})
    assert r.status_code == 409
    assert [x["username"] for x in _local(hub)] == ["admin"]
    assert _local(hub)[0]["password"] == "x"


def test_reject_when_nothing_to_delete():
    c, _ = _client([{"username": "admin", "password": "x"}])
    # Resubmitting the full existing set deletes nothing → 409 (delete-only).
    r = c.post("/api/console/credentials", json={"credentials": [{"username": "admin"}]})
    assert r.status_code == 409
    assert "No local credentials to delete" in r.json()["detail"]
