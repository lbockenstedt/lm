"""Regression tests for the module-level HE.NET DDNS credential assignment.

The External-DNS (HE.NET) module lets a Global Admin assign a DDNS credential
*once* — a non-secret ``{bucket, name}`` reference persisted in hub global
config under ``henet.vault_credential`` — so add/sync writes no longer have to
re-pick the credential on every request. The secret VALUE is resolved
unattended at write-time via ``cred_vault.automation_get`` and is never
returned to the browser. Contract under test:

* ``GET /api/henet/credential`` returns ``null`` until one is assigned, then the
  stored ``{bucket, name}`` (never a secret value);
* ``POST /api/henet/credential`` validates the reference resolves to an
  automation-readable ``henet`` secret carrying a ``ddns_key`` BEFORE
  persisting — a bad reference is rejected up-front (404), a missing
  bucket/name is a 400;
* a successful POST persists to global config under ``henet.vault_credential``;
* ``DELETE /api/henet/credential`` clears the assignment.
"""
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import access
import cred_vault
import routes.net_services as net_services


# ── session builders ────────────────────────────────────────────────────────
def _global_admin():
    return {"user": {"user_id": "root", "tenants": [],
                     "permissions": {"admin": True, "role": "admin"}}}


# ── fake hub/state carrying a real global_config dict ───────────────────────
class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}
        self.saved = 0

    def get_global_config(self):
        return self.system_state.setdefault("global_config", {})

    def update_global_config(self, config):
        gc = self.system_state.setdefault("global_config", {})
        gc.update(config)

    async def save_state_now(self):
        self.saved += 1


class _Hub:
    def __init__(self):
        self.state = _State()


class _Holder:
    def __init__(self):
        self.current = None


class _Ctx:
    def __init__(self, holder):
        self._session_user = lambda req: holder.current
        self._is_admin = access.is_admin
        self._filter_session = lambda req: None
        self._filter_tenant = lambda req: None
        self._effective_tenant = lambda req: None


def _build():
    hub = _Hub()
    holder = _Holder()
    app = FastAPI()
    app.state.hub = hub
    net_services.register(app, hub, _Ctx(holder))
    return TestClient(app), hub, holder


@pytest.fixture
def patch_vault(monkeypatch):
    """Patch cred_vault.automation_get with a scripted resolver."""
    def _install(value):
        async def _fake(hub, bucket, name):
            return value
        monkeypatch.setattr(cred_vault, "automation_get", _fake)
    return _install


# ── GET default ─────────────────────────────────────────────────────────────
def test_get_credential_null_when_unassigned():
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.get("/api/henet/credential")
    assert r.status_code == 200
    assert r.json() == {"status": "SUCCESS", "credential": None}


# ── POST validation ─────────────────────────────────────────────────────────
def test_post_credential_requires_bucket_and_name():
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.post("/api/henet/credential", json={"bucket": "", "name": ""})
    assert r.status_code == 400


def test_post_credential_rejects_reference_without_ddns_key(patch_vault):
    patch_vault({"something_else": "x"})  # resolves but no ddns_key
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.post("/api/henet/credential",
               json={"bucket": "__admin__", "name": "he-key"})
    assert r.status_code == 404
    # nothing persisted on a bad reference
    assert "henet" not in hub.state.get_global_config()


# ── POST happy path + persistence ───────────────────────────────────────────
def test_post_credential_persists_reference(patch_vault):
    patch_vault({"ddns_key": "s3cr3t"})
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.post("/api/henet/credential",
               json={"bucket": "__admin__", "name": "he-key"})
    assert r.status_code == 200
    assert r.json()["credential"] == {"bucket": "__admin__", "name": "he-key"}
    # persisted to global config (secret value NOT stored — only the reference)
    stored = hub.state.get_global_config()["henet"]["vault_credential"]
    assert stored == {"bucket": "__admin__", "name": "he-key"}
    assert hub.state.saved >= 1

    # ...and GET now reflects the assignment.
    r2 = c.get("/api/henet/credential")
    assert r2.json()["credential"] == {"bucket": "__admin__", "name": "he-key"}


# ── DELETE clears ───────────────────────────────────────────────────────────
def test_delete_credential_clears_assignment(patch_vault):
    patch_vault({"ddns_key": "s3cr3t"})
    c, hub, holder = _build()
    holder.current = _global_admin()
    c.post("/api/henet/credential",
           json={"bucket": "__admin__", "name": "he-key"})
    r = c.delete("/api/henet/credential")
    assert r.status_code == 200
    assert r.json()["credential"] is None
    assert c.get("/api/henet/credential").json()["credential"] is None
