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

from routes import console as console_routes  # noqa: E402


@pytest.fixture(autouse=True)
def _fake_modules(monkeypatch):
    """Install the fake security.encryption / cred_vault for THIS module only.

    These used to be assigned into sys.modules at module import time and never
    removed, so every test module collected afterwards saw the stubs instead of
    the real ones — test_plaintext_fallback_gate then failed to import
    plaintext_fallback_allowed from a stub that has no such attribute, and the
    whole core suite died with a collection error.

    routes.console imports both lazily (inside the request handlers), so the
    fakes only need to exist while a test RUNS. monkeypatch.setitem restores
    whatever was there before, including the real modules.
    """
    # Identity JSON codec (encrypt(str)->bytes, decrypt passes bytes through)
    # so the local credential blob round-trips as plain JSON.
    fake_enc = types.ModuleType("security.encryption")
    fake_enc.hub_encryption = SimpleNamespace(
        encrypt=lambda s: (s.encode() if isinstance(s, str) else s),
        decrypt=lambda b: b,
    )
    monkeypatch.setitem(sys.modules, "security.encryption", fake_enc)

    # Vault "available" (so vault_enabled True) but no console secret present
    # (automation_get -> None) → the resolver falls back to local.
    fake_cv = types.ModuleType("cred_vault")
    fake_cv.ADMIN_BUCKET = "__admin__"

    async def _automation_get(hub, bucket, name):
        return None

    fake_cv.automation_get = _automation_get
    fake_cv._vault_available = lambda hub: True
    monkeypatch.setitem(sys.modules, "cred_vault", fake_cv)


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
        # register() pulls the console RBAC gates off ctx; a fake without them
        # fails at route-registration time, not in the assertion.
        _has_console_write_access=lambda s: True,
        _has_console_access=lambda s: True,
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


# ── no vault configured: full create/update is the supported path ───────────
#
# Pins the counterpart of the LE DNS-01 bug: the module unconditionally refused
# to create console passwords and steered the operator to the Credential Vault
# — even when NO vault was configured, leaving nowhere at all to put them.
# With no vault, the hub-local store (Fernet-encrypted `console_credentials_enc`)
# is the supported path and the editor must stay open.

def _set_vault(enabled):
    sys.modules["cred_vault"]._vault_available = lambda hub: enabled


def test_get_reports_editable_when_no_vault_configured():
    _set_vault(False)
    c, _ = _client([{"username": "admin", "password": "x"}])
    body = c.get("/api/console/credentials").json()
    assert body["creation_disabled"] is False
    assert body["read_only"] is False
    assert body["vault_enabled"] is False
    assert body["migrate_warning"] == ""  # nothing to migrate to


def test_create_new_credential_allowed_when_no_vault():
    _set_vault(False)
    c, hub = _client([])
    r = c.post("/api/console/credentials",
               json={"credentials": [{"username": "admin", "password": "s3cret"}]})
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "count": 1}
    assert _local(hub) == [{"username": "admin", "password": "s3cret"}]
    # Pushed to connected console spokes so it takes effect immediately.
    assert hub.pushed and hub.pushed[0][1] == "CONSOLE_SET_CREDENTIALS"


def test_blank_password_keeps_the_stored_one_when_no_vault():
    """The GET masks passwords, so the WebUI submits blanks for untouched rows;
    a naive replace would silently wipe them."""
    _set_vault(False)
    c, hub = _client([{"username": "admin", "password": "keepme"}])
    r = c.post("/api/console/credentials",
               json={"credentials": [{"username": "admin", "password": ""},
                                     {"username": "root", "password": "new"}]})
    assert r.status_code == 200
    got = {x["username"]: x["password"] for x in _local(hub)}
    assert got == {"admin": "keepme", "root": "new"}


def test_password_change_allowed_when_no_vault():
    _set_vault(False)
    c, hub = _client([{"username": "admin", "password": "old"}])
    c.post("/api/console/credentials",
           json={"credentials": [{"username": "admin", "password": "rotated"}]})
    assert _local(hub) == [{"username": "admin", "password": "rotated"}]


def test_credentials_are_never_stored_in_plaintext_state_key():
    """The list must round-trip through hub_encryption into
    ``console_credentials_enc`` — never a bare plaintext state key."""
    _set_vault(False)
    c, hub = _client([])
    c.post("/api/console/credentials",
           json={"credentials": [{"username": "admin", "password": "s3cret"}]})
    assert "console_credentials" not in hub.state.system_state
    assert "console_credentials_enc" in hub.state.system_state


def test_delete_still_works_when_no_vault():
    _set_vault(False)
    c, hub = _client([{"username": "admin", "password": "x"},
                      {"username": "root", "password": "y"}])
    r = c.post("/api/console/credentials", json={"credentials": [{"username": "root"}]})
    assert r.status_code == 200
    assert [x["username"] for x in _local(hub)] == ["root"]


def test_empty_list_clears_all_when_no_vault():
    _set_vault(False)
    c, hub = _client([{"username": "admin", "password": "x"}])
    r = c.post("/api/console/credentials", json={"credentials": []})
    assert r.status_code == 200
    assert _local(hub) == []


def test_non_admin_still_rejected_when_no_vault():
    _set_vault(False)
    app = FastAPI()
    hub = _Hub([])
    app.state.hub = hub
    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": {"is_admin": False, "username": "bob"}},
        _is_admin=lambda s: False,
        _has_console_write_access=lambda s: True,
        _has_console_access=lambda s: True,
        _resolve_tenant=lambda req, explicit=None: "default",
    )
    console_routes.register(app, hub, ctx)
    r = TestClient(app).post("/api/console/credentials",
                             json={"credentials": [{"username": "x", "password": "y"}]})
    assert r.status_code == 403
