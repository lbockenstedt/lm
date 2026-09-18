"""The hub-local console password store is retired, end-to-end.

Console logins live in the Credential Vault, which is available on EVERY
deployment — with no cloud vault configured it falls back to its own encrypted
``blobs`` map — so the module-private second store (the Fernet blob
``console_credentials_enc``) had no remaining purpose.

It was also a live failure mode: the blob is encrypted with the hub Fernet key,
so any hub whose key was replaced (re-install, restore, rotation without
``LM_FERNET_KEY_PREVIOUS``) holds an ORPHAN it can never read. Every resolve
logged "could not decrypt stored credentials" and returned [], which read as
the cause of an empty credential list while hiding the real one.

This pins the replacement contract: the GET never offers local credentials and
PURGES the blob on sight, and the write endpoint is retired with a 409 pointing
at the Credential Library — whether or not a cloud vault is configured. Run
end-to-end with fake encryption + cred_vault modules so no real Fernet key /
Azure vault is needed.
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


def _purged(hub):
    return "console_credentials_enc" not in hub.state.system_state


def _set_vault(enabled):
    sys.modules["cred_vault"]._vault_available = lambda hub: enabled


# ── GET: nothing local is offered, and the orphan is dropped ────────────────
def test_get_never_reports_local_credentials():
    c, _ = _client([{"username": "admin", "password": "x"},
                    {"username": "root", "password": "y"}])
    body = c.get("/api/console/credentials").json()
    assert body["local_credentials"] == []
    assert body["local_passwords_present"] is False
    assert body["migrate_warning"] == ""
    assert body["creation_disabled"] is True
    assert body["read_only"] is True


def test_get_purges_the_legacy_blob():
    c, hub = _client([{"username": "admin", "password": "x"}])
    assert not _purged(hub)          # precondition: the orphan is there
    c.get("/api/console/credentials")
    assert _purged(hub)


def test_get_purges_an_unreadable_orphan():
    """The real-world case: the blob cannot be decrypted at all. It must still
    be removed — and must NOT raise or blank the response."""
    c, hub = _client(None)
    hub.state.system_state["console_credentials_enc"] = "gAAAAAB_unreadable=="
    r = c.get("/api/console/credentials")
    assert r.status_code == 200
    assert _purged(hub)


def test_get_is_unchanged_when_no_vault_is_configured():
    """Previously the editor re-opened with no vault, because the local store
    was 'the supported path'. The Credential Vault works without a cloud vault,
    so it no longer is."""
    _set_vault(False)
    body = _client([{"username": "admin", "password": "x"}])[0] \
        .get("/api/console/credentials").json()
    assert body["creation_disabled"] is True
    assert body["read_only"] is True
    assert body["local_credentials"] == []


# ── POST: retired ──────────────────────────────────────────────────────────
def test_post_is_retired():
    c, _ = _client([{"username": "admin", "password": "x"}])
    r = c.post("/api/console/credentials",
               json={"credentials": [{"username": "admin"}]})
    assert r.status_code == 409
    assert "Credential Library" in r.json()["detail"]


def test_post_is_retired_without_a_vault_too():
    _set_vault(False)
    c, _ = _client([])
    r = c.post("/api/console/credentials",
               json={"credentials": [{"username": "admin", "password": "s3cret"}]})
    assert r.status_code == 409


def test_post_never_writes_a_password_anywhere():
    _set_vault(False)
    c, hub = _client([])
    c.post("/api/console/credentials",
           json={"credentials": [{"username": "admin", "password": "s3cret"}]})
    assert "console_credentials" not in hub.state.system_state
    assert _purged(hub)
    assert "s3cret" not in json.dumps(hub.state.system_state)


def test_post_purges_the_legacy_blob():
    c, hub = _client([{"username": "admin", "password": "x"}])
    c.post("/api/console/credentials", json={"credentials": []})
    assert _purged(hub)


def test_post_pushes_nothing_to_spokes():
    """A retired endpoint must not re-seed: the old handler pushed a mutated
    list to every console spoke."""
    c, hub = _client([{"username": "admin", "password": "x"}])
    c.post("/api/console/credentials", json={"credentials": []})
    assert hub.pushed == []
