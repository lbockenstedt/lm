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


def _tenant_user(tenant_id, reach=None):
    return {"user": {"user_id": f"user-{tenant_id}", "tenant_id": tenant_id,
                     "tenants": list(reach) if reach is not None else [tenant_id],
                     "permissions": {"dns": True}}}


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
    # Global Admin with no ?tenant= gets the merged overview: the global slot
    # under "credential" (null, unassigned) PLUS every tenant's own ("tenants",
    # empty since none has assigned one yet).
    assert r.json() == {"status": "SUCCESS", "credential": None, "tenants": {}}


# ── POST validation ─────────────────────────────────────────────────────────
def test_post_credential_requires_bucket_and_name():
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.post("/api/henet/credential", json={"bucket": "", "name": ""})
    assert r.status_code == 400


def test_post_credential_rejects_reference_without_ddns_key(patch_vault):
    patch_vault({"something_else": "x"})  # resolves but no usable HE key
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.post("/api/henet/credential",
               json={"bucket": "__admin__", "name": "he-key"})
    assert r.status_code == 404
    # nothing persisted on a bad reference
    assert "henet" not in hub.state.get_global_config()


def test_post_credential_accepts_shared_le_hurricane_electric_secret(patch_vault):
    # ONE Hurricane Electric credential serves both modules: a secret stored via
    # the LE DNS-01 "Hurricane Electric (account login)" form has no ddns_key but
    # carries he_password — the module reformats it into the dyndns push
    # password, so it must be accepted here too.
    patch_vault({"provider": "he-login", "he_username": "me@example.com",
                 "he_password": "acct-pass"})
    c, hub, holder = _build()
    holder.current = _global_admin()
    r = c.post("/api/henet/credential",
               json={"bucket": "acme", "name": "he-le-cred"})
    assert r.status_code == 200
    assert r.json()["credential"] == {"bucket": "acme", "name": "he-le-cred"}


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


# ── Per-tenant credential slots ─────────────────────────────────────────────
def test_tenant_sets_own_credential_sees_only_own(patch_vault):
    patch_vault({"ddns_key": "s3cr3t"})
    c, hub, holder = _build()
    holder.current = _tenant_user("lrb")
    r = c.post("/api/henet/credential", json={"bucket": "lrb", "name": "he-key"})
    assert r.status_code == 200
    assert r.json() == {"status": "SUCCESS", "credential": {"bucket": "lrb", "name": "he-key"},
                        "tenant": "lrb"}
    # ...and GET (still as that tenant) reflects it.
    r2 = c.get("/api/henet/credential")
    assert r2.json() == {"status": "SUCCESS", "credential": {"bucket": "lrb", "name": "he-key"}}


def test_tenant_and_global_credential_slots_dont_clobber_each_other(patch_vault):
    """Regression: update_global_config only shallow-replaces the WHOLE 'henet'
    key — setting a tenant's slot must not silently wipe the global slot (or a
    sibling tenant's), and vice versa. See _henet_update_cfg."""
    patch_vault({"ddns_key": "s3cr3t"})
    c, hub, holder = _build()
    holder.current = _global_admin()
    c.post("/api/henet/credential", json={"bucket": "__admin__", "name": "global-key"})
    holder.current = _tenant_user("lrb")
    c.post("/api/henet/credential", json={"bucket": "lrb", "name": "lrb-key"})
    holder.current = _tenant_user("acme")
    c.post("/api/henet/credential", json={"bucket": "acme", "name": "acme-key"})

    holder.current = _global_admin()
    overview = c.get("/api/henet/credential").json()
    assert overview["credential"] == {"bucket": "__admin__", "name": "global-key"}
    assert overview["tenants"] == {
        "lrb": {"bucket": "lrb", "name": "lrb-key"},
        "acme": {"bucket": "acme", "name": "acme-key"},
    }
    # Each tenant still sees only its own slot.
    holder.current = _tenant_user("lrb")
    assert c.get("/api/henet/credential").json()["credential"] == {"bucket": "lrb", "name": "lrb-key"}
    holder.current = _tenant_user("acme")
    assert c.get("/api/henet/credential").json()["credential"] == {"bucket": "acme", "name": "acme-key"}


def test_tenant_credential_reach_enforced(patch_vault):
    """A tenant can only assign a Credential Vault bucket it has reach to —
    same reach check as the existing global-admin path, just scoped."""
    patch_vault({"ddns_key": "s3cr3t"})
    c, hub, holder = _build()
    holder.current = _tenant_user("lrb", reach=["lrb"])
    r = c.post("/api/henet/credential", json={"bucket": "someone-elses-bucket", "name": "x"})
    assert r.status_code == 404


def test_clearing_tenant_credential_leaves_global_and_other_tenants_intact(patch_vault):
    patch_vault({"ddns_key": "s3cr3t"})
    c, hub, holder = _build()
    holder.current = _global_admin()
    c.post("/api/henet/credential", json={"bucket": "__admin__", "name": "global-key"})
    holder.current = _tenant_user("lrb")
    c.post("/api/henet/credential", json={"bucket": "lrb", "name": "lrb-key"})
    r = c.delete("/api/henet/credential")
    assert r.status_code == 200
    assert c.get("/api/henet/credential").json()["credential"] is None

    holder.current = _global_admin()
    overview = c.get("/api/henet/credential").json()
    assert overview["credential"] == {"bucket": "__admin__", "name": "global-key"}
    assert overview["tenants"] == {}
