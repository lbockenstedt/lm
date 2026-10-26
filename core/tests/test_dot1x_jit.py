"""JIT 802.1X broker (dot1x_jit.py): provisioning across Entra / LDAP /
ClearPass, password storage (vault vs encrypted hub state), rotation, release,
spoke sync, the cleanup sweep and the no-reveal My Users listing."""
import asyncio
import json
import time

import pytest

import access
import cloud_nac
import cloud_vault
import dot1x_jit as dj
from security.encryption import hub_encryption

DAY = 86400.0


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}
        self.tenants = {"cs1": "t1", "cs2": "t2"}

    def _mark_dirty(self):
        pass

    async def save_state_now(self):
        pass

    def get_spoke_tenant(self, sid):
        return self.tenants.get(sid)


class _Hub:
    def __init__(self):
        self.state = _State()
        self.calls = []
        self.fail = {}          # cmd -> message
        self.active_connections = {"cs1", "cs2", "ldap1", "nac1"}

    def _primary_key(self, sid):
        return sid

    def get_directory_spoke_for_tenant(self, tid):
        return "ldap1"

    def get_cppm_spoke_for_tenant(self, tid):
        return "nac1"

    def get_cppm_spoke_for_shared(self):
        return "nac1"

    async def request_response(self, sid, cmd, payload, timeout=30.0):
        self.calls.append((sid, cmd, json.loads(json.dumps(payload))))
        if cmd in self.fail:
            return {"payload": {"data": {"status": "ERROR", "message": self.fail[cmd]}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}

    def cmds(self, name=None):
        return [c for c in self.calls if name is None or c[1] == name]


@pytest.fixture
def hub(monkeypatch):
    dj._locks.clear()
    monkeypatch.setattr(access, "ldap_tenant_slug", lambda hub, tid: f"slug-{tid}")
    monkeypatch.setattr(access, "tenant_is_shared", lambda tid: False)
    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: None)
    return _Hub()


@pytest.fixture
def vault(monkeypatch):
    store = {"fail": False, "secrets": {}}

    async def set_secret(hub, name, value, http=None, **kw):
        if store["fail"]:
            raise RuntimeError("vault down")
        store["secrets"][name] = value

    async def get_secret(hub, name, http=None):
        return store["secrets"].get(name)

    async def delete_secret(hub, name, http=None):
        store["secrets"].pop(name, None)
        return True

    monkeypatch.setattr(cloud_vault, "active_provider", lambda hub: "azure")
    monkeypatch.setattr(cloud_vault, "set_secret", set_secret)
    monkeypatch.setattr(cloud_vault, "get_secret", get_secret)
    monkeypatch.setattr(cloud_vault, "delete_secret", delete_secret)
    return store


def run(coro):
    return asyncio.run(coro)


def _creds(hub):
    return [c for c in hub.calls if c[1] == dj.CREDENTIAL_CMD]


def test_ldap_provision_creates_in_tenant_ou_and_delivers(hub):
    rec = run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap", "MIA-1X"))
    assert [c[1] for c in hub.calls] == ["LDAP_PROVISION_TENANT_OU", "LDAP_CREATE_USER", dj.CREDENTIAL_CMD]
    create = hub.cmds("LDAP_CREATE_USER")[0][2]
    assert create["tenant_slug"] == "slug-t1" and create["uid"] == "jsmith"
    assert create["auth_mode"] == "local"
    pw = create["password"]
    assert len(pw) >= 16
    cred = _creds(hub)[0]
    assert cred[0] == "cs1" and cred[2]["password"] == pw and cred[2]["hostnames"] == ["jsmith-1"]
    # stored locally (no vault), encrypted, and never in the public record
    key = dj.account_key("t1", "ldap", "jsmith")
    blob = hub.state.system_state[dj.SECRETS_KEY][key]
    assert pw not in blob and hub_encryption.decrypt(blob.encode()) == pw
    assert "password" not in rec and pw not in json.dumps(rec)
    assert pw not in json.dumps(dj.list_accounts(hub, "t1"))
    assert rec["password_store"] == "local" and rec["cells"] == ["MIA-1X"]


def test_second_hostname_reuses_account_and_password(hub):
    run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    pw = hub.cmds("LDAP_CREATE_USER")[0][2]["password"]
    hub.calls.clear()
    run(dj.provision(hub, "t1", "cs2", "jsmith-2", "jsmith", "ldap"))
    assert [c[1] for c in hub.calls] == [dj.CREDENTIAL_CMD]
    assert hub.calls[0][0] == "cs2" and hub.calls[0][2]["password"] == pw


def test_release_deletes_only_after_last_hostname(hub):
    run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    run(dj.provision(hub, "t1", "cs1", "jsmith-2", "jsmith", "ldap"))
    assert run(dj.release(hub, "t1", "jsmith-1", "jsmith", "ldap")) is False
    assert not hub.cmds("LDAP_DELETE_USER")
    assert run(dj.release(hub, "t1", "jsmith-2", "jsmith", "ldap")) is True
    assert hub.cmds("LDAP_DELETE_USER")[0][2] == {"tenant_slug": "slug-t1", "uid": "jsmith"}
    assert dj.list_accounts(hub) == []
    assert not hub.state.system_state[dj.SECRETS_KEY]


def test_ldap_refuses_to_take_over_existing_user(hub):
    hub.fail["LDAP_CREATE_USER"] = "user jsmith already exists"
    with pytest.raises(dj.Dot1xJitError, match="not created by LM"):
        run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    assert dj.list_accounts(hub) == [] and not _creds(hub)


def test_clearpass_local_user(hub):
    hub.state.system_state["global_config"]["dot1x_jit"] = {"cppm_role": "[Guest]"}
    run(dj.provision(hub, "t1", "cs1", "amy-3", "amy", "clearpass"))
    sid, cmd, p = hub.cmds("CPPM_CREATE_LOCAL_USER")[0]
    assert sid == "nac1" and p["user_id"] == "amy" and p["role_name"] == "[Guest]"
    assert p["tenant_slug"] == "slug-t1"
    run(dj.release(hub, "t1", "amy-3", "amy", "clearpass"))
    assert hub.cmds("CPPM_DELETE_LOCAL_USER")[0][2] == {"user_id": "amy"}


def test_entra_uses_cloud_nac_with_chosen_password(hub, monkeypatch):
    seen = {}

    async def provision_user(oidc, domain, username, http=None, password=None):
        seen.update(domain=domain, username=username, password=password)
        return {"upn": f"{username}@{domain}", "oid": "oid-1"}

    async def delete_user(oidc, ident, http=None):
        seen["deleted"] = ident

    monkeypatch.setattr(cloud_nac, "provision_user", provision_user)
    monkeypatch.setattr(cloud_nac, "delete_user", delete_user)
    monkeypatch.setattr(dj, "_entra_cfg", lambda hub: ({"enabled": True, "domain": "x.com"}, None))
    rec = run(dj.provision(hub, "t1", "cs1", "bob-1", "bob", "entra"))
    assert seen["password"] == _creds(hub)[0][2]["password"]
    assert rec["identity"] == "bob@x.com"
    # Same Entra username for another tenant is refused (one global directory).
    with pytest.raises(dj.Dot1xJitError, match="already JIT-provisioned"):
        run(dj.provision(hub, "t2", "cs2", "bob-9", "bob", "entra"))
    run(dj.release(hub, "t1", "bob-1", "bob", "entra"))
    assert seen["deleted"] == "oid-1"


def test_vault_storage_and_rotation(hub, vault):
    run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    pw1 = hub.cmds("LDAP_CREATE_USER")[0][2]["password"]
    key = dj.account_key("t1", "ldap", "jsmith")
    rec = hub.state.system_state[dj.STATE_KEY][key]
    assert rec["store"] == "kv" and rec["kv_name"].startswith("dot1x-")
    assert key not in hub.state.system_state[dj.SECRETS_KEY]
    token = vault["secrets"][rec["kv_name"]]
    assert pw1 not in token and hub_encryption.decrypt(token.encode()) == pw1
    hub.calls.clear()
    pub = run(dj.rotate(hub, "t1", "ldap", "jsmith"))
    setpw = hub.cmds("LDAP_SET_PASSWORD")[0][2]
    pw2 = setpw["password"]
    assert pw2 != pw1 and hub_encryption.decrypt(vault["secrets"][rec["kv_name"]].encode()) == pw2
    assert _creds(hub)[0][2]["password"] == pw2
    assert pub["password_store"] == "vault"


def test_rotate_reverts_backend_when_vault_write_fails(hub, vault):
    run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    pw1 = hub.cmds("LDAP_CREATE_USER")[0][2]["password"]
    hub.calls.clear()
    vault["fail"] = True
    with pytest.raises(dj.Dot1xJitError, match="vault write failed"):
        run(dj.rotate(hub, "t1", "ldap", "jsmith"))
    sets = [c[2]["password"] for c in hub.cmds("LDAP_SET_PASSWORD")]
    assert len(sets) == 2 and sets[1] == pw1      # reverted to the stored password
    assert not _creds(hub)                         # nothing pushed


def test_new_account_rolled_back_when_vault_write_fails(hub, vault):
    vault["fail"] = True
    with pytest.raises(dj.Dot1xJitError):
        run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    assert hub.cmds("LDAP_DELETE_USER") and dj.list_accounts(hub) == []


def test_operator_delete_revokes_on_spoke(hub):
    run(dj.provision(hub, "t1", "cs1", "jsmith-1", "jsmith", "ldap"))
    hub.calls.clear()
    run(dj.delete(hub, "t1", "ldap", "jsmith"))
    assert [c[1] for c in hub.calls] == ["LDAP_DELETE_USER", dj.CREDENTIAL_CMD]
    cred = hub.calls[1][2]
    assert cred["revoke"] is True and "password" not in cred
    with pytest.raises(dj.Dot1xJitError, match="no such account"):
        run(dj.delete(hub, "t1", "ldap", "jsmith"))


def test_sync_releases_missing_redelivers_and_provisions(hub):
    run(dj.provision(hub, "t1", "cs1", "a-1", "a", "ldap"))
    run(dj.provision(hub, "t1", "cs1", "b-1", "b", "ldap"))
    key_a = dj.account_key("t1", "ldap", "a")
    rotated = hub.state.system_state[dj.STATE_KEY][key_a]["rotated_at"]
    hub.calls.clear()
    stats = run(dj.sync(hub, "t1", "cs1", [
        {"hostname": "a-1", "username": "a", "backend": "ldap", "version": 0},     # stale → redeliver
        {"hostname": "c-1", "username": "c", "backend": "ldap", "cell": "X"},      # unknown → provision
    ]))
    assert stats == {"touched": 1, "provisioned": 1, "redelivered": 1, "released": 1}
    assert hub.cmds("LDAP_DELETE_USER")[0][2]["uid"] == "b"
    users = {u["username"] for u in dj.list_accounts(hub, "t1")}
    assert users == {"a", "c"}
    # an up-to-date version is not re-sent
    hub.calls.clear()
    run(dj.sync(hub, "t1", "cs1", [
        {"hostname": "a-1", "username": "a", "backend": "ldap", "version": rotated},
        {"hostname": "c-1", "username": "c", "backend": "ldap",
         "version": hub.state.system_state[dj.STATE_KEY][dj.account_key("t1", "ldap", "c")]["rotated_at"]},
    ]))
    assert not hub.calls


def test_sync_only_releases_this_spokes_hostnames(hub):
    run(dj.provision(hub, "t1", "cs1", "a-1", "a", "ldap"))
    run(dj.provision(hub, "t1", "cs2", "a-2", "a", "ldap"))
    run(dj.sync(hub, "t1", "cs1", []))
    assert dj.list_accounts(hub, "t1")[0]["hostnames"] == ["a-2"]


def test_sweep_rotates_and_cleans_up(hub):
    run(dj.provision(hub, "t1", "cs1", "a-1", "a", "ldap"))
    run(dj.provision(hub, "t1", "cs1", "b-1", "b", "ldap"))
    idx = hub.state.system_state[dj.STATE_KEY]
    now = time.time()
    ka, kb = dj.account_key("t1", "ldap", "a"), dj.account_key("t1", "ldap", "b")
    idx[ka]["rotated_at"] = now - 31 * DAY
    for m in idx[kb]["hostnames"].values():
        m["last_active"] = now - 31 * DAY
    idx[kb]["last_active_at"] = now - 31 * DAY
    idx[kb]["rotated_at"] = now        # avoid rotating b
    hub.calls.clear()
    out = run(dj.sweep(hub, now=now))
    assert out == {"rotated": 1, "deleted": 1, "errors": 0}
    assert hub.cmds("LDAP_SET_PASSWORD")[0][2]["uid"] == "a"
    assert hub.cmds("LDAP_DELETE_USER")[0][2]["uid"] == "b"
    assert hub.state.system_state[dj.META_KEY]["last_cleanup"] == now
    # cleanup only every cleanup_interval_days
    out = run(dj.sweep(hub, now=now + DAY))
    assert out["deleted"] == 0


def test_failed_delete_is_retried_by_sweep(hub):
    run(dj.provision(hub, "t1", "cs1", "a-1", "a", "ldap"))
    hub.fail["LDAP_DELETE_USER"] = "server down"
    assert run(dj.release(hub, "t1", "a-1", "a", "ldap")) is False
    acc = dj.list_accounts(hub, "t1")[0]
    assert acc["status"] == "pending_delete"
    del hub.fail["LDAP_DELETE_USER"]
    out = run(dj.sweep(hub))
    assert out["deleted"] == 1 and dj.list_accounts(hub) == []


def test_handle_spoke_message_scopes_to_spoke_tenant(hub):
    run(dj.handle_spoke_message(hub, "cs2", "CS_DOT1X_PROVISION",
                                {"hostname": "z-1", "username": "z", "backend": "ldap", "tenant_id": "t1"}))
    assert [u["tenant_id"] for u in dj.list_accounts(hub)] == ["t2"]
    hub.state.tenants.pop("cs2")
    hub.calls.clear()
    run(dj.handle_spoke_message(hub, "cs2", "CS_DOT1X_PROVISION",
                                {"hostname": "y-1", "username": "y", "backend": "ldap"}))
    assert not hub.calls
    # bad input never raises
    run(dj.handle_spoke_message(hub, "cs1", "CS_DOT1X_PROVISION", {"username": "../x"}))


def test_list_accounts_tenant_filter_and_next_rotation(hub):
    run(dj.provision(hub, "t1", "cs1", "a-1", "a", "ldap"))
    run(dj.provision(hub, "t2", "cs2", "a-2", "a", "ldap"))
    assert len(dj.list_accounts(hub)) == 2
    rows = dj.list_accounts(hub, "t1")
    assert len(rows) == 1
    assert rows[0]["next_rotation_at"] == pytest.approx(rows[0]["rotated_at"] + 30 * DAY)


def test_validation(hub):
    with pytest.raises(dj.Dot1xJitError):
        dj.normalize_backend("radius")
    with pytest.raises(dj.Dot1xJitError):
        dj.normalize_username("bad user")
    assert dj.normalize_username(" JSmith ") == "jsmith"


def test_selftest_runs_full_lifecycle_without_delivering(hub):
    out = run(dj.selftest(hub, "t1", ["ldap", "clearpass"]))
    assert [r["ok"] for r in out] == [True, True]
    assert [s["step"] for s in out[0]["steps"]] == ["provision", "rotate", "delete"]
    assert hub.cmds("LDAP_DELETE_USER") and hub.cmds("CPPM_DELETE_LOCAL_USER")
    assert not _creds(hub)                 # nothing pushed to any cs spoke
    assert dj.list_accounts(hub) == []     # nothing left behind


def test_selftest_deletes_even_when_rotate_fails(hub):
    hub.fail["LDAP_SET_PASSWORD"] = "boom"
    out = run(dj.selftest(hub, "t1", ["ldap"]))
    steps = {s["step"]: s["ok"] for s in out[0]["steps"]}
    assert steps == {"provision": True, "rotate": False, "delete": True}
    assert out[0]["ok"] is False
    assert dj.list_accounts(hub) == []


def test_selftest_reports_provision_failure(hub):
    hub.fail["LDAP_CREATE_USER"] = "server down"
    out = run(dj.selftest(hub, "t1", ["ldap"]))
    assert out[0]["ok"] is False
    assert out[0]["steps"] == [{"step": "provision", "ok": False, "error": "server down"}]
