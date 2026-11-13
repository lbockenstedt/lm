"""Directory → Active Directory hub routes (``routes/directory_ad``).

A tenant sees only its own AD connections, the bind password comes from the
vault at send time and only reaches the tenant's own or the shared directory
spoke, and "no accounts" is never confused with "couldn't ask".
"""
import sys
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import log_redaction  # noqa: E402
from routes import directory_ad as routes  # noqa: E402

ACME = {"id": "c1", "name": "Acme AD", "tenant_id": "acme", "domain": "acme.example",
        "primary_server": "dc1.acme.example", "backup_server": "dc2.acme.example:636",
        "dns_servers": "10.0.0.1, 10.0.0.2", "bind_user": "svc-lm", "use_ssl": True,
        "vault_credential": {"bucket": "acme", "name": "ad-bind"}}


class _Hub:
    """Fake hub: AD connections, a spoke per tenant, recorded commands."""

    def __init__(self, conns, spoke_tenant="acme", reply=None):
        self.sent = []
        self.reply = reply or {"status": "SUCCESS", "data": [{"username": "jdoe"}],
                               "truncated": False,
                               "server": {"host": "dc1", "port": 636, "ssl": True,
                                          "source": "configured"}}
        self.state = SimpleNamespace(
            system_state={"global_config": {"ad_connections": conns}},
            get_spoke_tenant=lambda sid: spoke_tenant)

    def get_directory_spoke_for_tenant(self, tid):
        return "dir-spoke"

    async def request_response(self, spoke_id, cmd, payload, timeout=None):
        self.sent.append((spoke_id, cmd, payload))
        reply = self.reply(payload) if callable(self.reply) else self.reply
        return {"header": {}, "payload": {"data": reply}}

    async def cache_read(self, ns, key, fetch, tenants=None, lane=None):
        return await fetch()

    def cache_annotate(self, data, ns, key):
        return data


def _client(monkeypatch, hub, sess=None, password="s3cret"):
    async def overlay(_hub, rec, _key):
        out = {k: v for k, v in rec.items() if k != "vault_credential"}
        if password:
            out["bind_password"] = password
        return out
    monkeypatch.setattr(routes.instance_vault, "overlay", overlay)
    app = FastAPI()
    sess = sess or {"user": {"permissions": {"admin": True}}}
    is_admin = lambda s: bool(s.get("user", {}).get("permissions", {}).get("admin"))  # noqa: E731
    routes.register(app, hub, SimpleNamespace(_session_user=lambda r: sess, _is_admin=is_admin))
    return TestClient(app)


def test_spoke_config_sends_only_the_connection_fields():
    cfg = routes.spoke_config({**ACME, "bind_password": "pw"})
    assert cfg["servers"] == ["dc1.acme.example", "dc2.acme.example:636"]
    assert cfg["dns_servers"] == ["10.0.0.1", "10.0.0.2"]
    assert cfg["bind_password"] == "pw" and cfg["domain"] == "acme.example"
    for leaked in ("tenant_id", "id", "name", "vault_credential", "primary_server"):
        assert leaked not in cfg


def test_tenant_sees_only_its_own_connections_with_the_vault_password(monkeypatch):
    beta = {**ACME, "id": "c2", "name": "Beta AD", "tenant_id": "beta"}
    hub = _Hub([ACME, beta, {**ACME, "id": "c3", "tenant_id": ""}])
    res = _client(monkeypatch, hub).get("/api/ldap/ad?tenant=acme").json()
    assert res == {"configured": True, "connections": [
        {"name": "Acme AD", "domain": "acme.example", "users": [{"username": "jdoe"}],
         "truncated": False, "server": "dc1:636"}]}
    [(spoke, cmd, payload)] = hub.sent
    assert (spoke, cmd, payload["q"], payload["limit"]) == ("dir-spoke", "AD_SEARCH_USERS", "", 1000)
    assert payload["ad"]["bind_password"] == "s3cret"


def test_no_connection_is_not_configured(monkeypatch):
    hub = _Hub([ACME])
    assert _client(monkeypatch, hub).get("/api/ldap/ad?tenant=beta").json() == {
        "configured": False, "connections": []}
    assert hub.sent == []


def test_a_failed_connection_reports_its_error_and_the_others_still_show(monkeypatch):
    other = {**ACME, "id": "c2", "name": "Lab AD", "domain": "lab.example"}

    def reply(payload):
        if payload["ad"]["domain"] == "acme.example":
            return {"status": "ERROR", "message": "no AD server reachable"}
        return {"status": "SUCCESS", "data": [], "truncated": False, "server": "dc9"}
    res = _client(monkeypatch, _Hub([ACME, other], reply=reply)).get(
        "/api/ldap/ad?tenant=acme").json()
    assert res["connections"][0] == {"name": "Acme AD", "domain": "acme.example",
                                     "users": [], "error": "no AD server reachable"}
    assert res["connections"][1]["users"] == [] and "error" not in res["connections"][1]


def test_another_tenants_spoke_never_gets_the_password(monkeypatch):
    for owner, ok in (("beta", False), ("", True), ("shared", True), ("ACME", True)):
        hub = _Hub([ACME], spoke_tenant=owner)
        r = _client(monkeypatch, hub).post("/setup/ad-connections/c1/test")
        assert (r.status_code == 200) is ok, (owner, r.status_code)
        assert bool(hub.sent) is ok
        if ok:
            # The spoke's {host, port, ...} server reads as host:port.
            assert r.json()["server"] == "dc1:636"


def test_vault_miss_and_old_spoke_are_clear_errors(monkeypatch):
    hub = _Hub([ACME])
    r = _client(monkeypatch, hub, password="").post("/setup/ad-connections/c1/discover")
    assert r.status_code == 503 and "Credential Vault" in r.json()["detail"]
    assert hub.sent == []
    hub = _Hub([ACME], reply={"status": "ERROR", "message": "Unknown command: AD_TEST"})
    r = _client(monkeypatch, hub).post("/setup/ad-connections/c1/test")
    assert r.status_code == 501 and "update the directory spoke" in r.json()["detail"]


def test_a_reply_without_success_status_is_an_error_not_empty(monkeypatch):
    for reply in ({"data": []}, {"status": "WEIRD", "data": []}):
        hub = _Hub([ACME], reply=reply)
        r = _client(monkeypatch, hub).post("/setup/ad-connections/c1/test")
        assert r.status_code == 502, reply
        r = _client(monkeypatch, hub).get("/api/ldap/ad", params={"tenant": "acme"})
        block = r.json()["connections"][0]
        assert block["users"] == [] and block.get("error"), reply


def test_connection_without_a_tenant_is_refused(monkeypatch):
    hub = _Hub([{**ACME, "tenant_id": ""}])
    r = _client(monkeypatch, hub).post("/setup/ad-connections/c1/test")
    assert r.status_code == 400 and hub.sent == []


def test_non_admin_cannot_read_another_tenants_ad(monkeypatch):
    sess = {"user": {"permissions": {"ldap": True}, "tenants": ["beta"]}}
    hub = _Hub([ACME])
    r = _client(monkeypatch, hub, sess=sess).get("/api/ldap/ad?tenant=acme")
    assert r.status_code == 403 and hub.sent == []


def test_only_a_global_admin_can_test_or_discover(monkeypatch):
    sess = {"user": {"permissions": {"ldap": True}, "tenants": ["acme"]}}
    hub = _Hub([ACME])
    client = _client(monkeypatch, hub, sess=sess)
    for verb in ("test", "discover"):
        assert client.post(f"/setup/ad-connections/c1/{verb}").status_code == 403
    assert hub.sent == []


def test_ad_commands_are_fully_redacted_in_logs():
    for cmd in ("AD_TEST", "AD_DISCOVER", "AD_SEARCH_USERS"):
        out = log_redaction._redact(cmd, {"ad": {"bind_password": "s3cret"}, "q": ""})
        assert "s3cret" not in repr(out)


def test_ad_password_is_never_stored_inline(monkeypatch):
    # Even with no cloud vault, an inline bind password is refused (the
    # generic /setup CRUD would otherwise store and list it in clear).
    import asyncio

    import cred_vault
    import instance_vault
    from fastapi import HTTPException
    monkeypatch.setattr(cred_vault, "_vault_available", lambda hub: False)
    rec = {"name": "Corp", "tenant_id": "ssplm", "domain": "corp.example", "bind_password": "pw"}
    try:
        asyncio.run(instance_vault.validate_ref(object(), rec, {}, is_admin=True, storage_key="ad_connections"))
    except HTTPException as exc:
        assert exc.status_code == 400 and "Credential Vault" in exc.detail
    else:
        raise AssertionError("inline AD password was accepted")


def _crud_client(monkeypatch, existing=()):
    """The real /setup/ad-connections CRUD (routes/nw.py) as a Global Admin."""
    import routes.nw as nw

    async def no_vault_check(*_a, **_k):
        return None
    monkeypatch.setattr(nw.instance_vault, "validate_ref", no_vault_check)
    hub = _Hub([dict(c) for c in existing])
    hub.state.get_spoke_tenant = lambda sid: None
    hub.state._mark_dirty = lambda: None
    app = FastAPI()
    app.state.hub = hub
    nw.register(app, hub, SimpleNamespace(
        _session_user=lambda r: {"user": {"permissions": {"admin": True}}},
        _is_admin=lambda s: True, _is_tenant_admin=lambda s: False,
        _filter_nw=lambda *a, **k: []))
    return TestClient(app), hub


def test_crud_refuses_a_connection_with_no_tenant(monkeypatch):
    client, hub = _crud_client(monkeypatch, [ACME])
    new = {k: v for k, v in ACME.items() if k not in ("id", "tenant_id")}
    assert client.post("/setup/ad-connections", json={"instance": new}).status_code == 400
    # An edit can't clear the tenant either.
    r = client.put("/setup/ad-connections/c1", json={"config": {"tenant_id": ""}})
    assert r.status_code == 400
    assert hub.state.system_state["global_config"]["ad_connections"] == [ACME]


def test_crud_refuses_another_tenants_or_the_admin_vault_bucket(monkeypatch):
    client, hub = _crud_client(monkeypatch, [ACME])
    for bucket in ("beta", "__admin__"):
        ref = {"bucket": bucket, "name": "ad-bind"}
        new = {**{k: v for k, v in ACME.items() if k != "id"}, "vault_credential": ref}
        assert client.post("/setup/ad-connections", json={"instance": new}).status_code == 400
        r = client.put("/setup/ad-connections/c1", json={"config": {"vault_credential": ref}})
        assert r.status_code == 400
    # The tenant's own bucket is fine.
    new = {k: v for k, v in ACME.items() if k != "id"}
    assert client.post("/setup/ad-connections", json={"instance": new}).status_code == 200


def test_the_global_admin_slot_is_not_a_connection_tenant(monkeypatch):
    ref = {"bucket": "__admin__", "name": "ad-bind"}
    admin_conn = {**ACME, "tenant_id": "__admin__", "vault_credential": ref}
    client, hub = _crud_client(monkeypatch, [ACME])
    new = {k: v for k, v in admin_conn.items() if k != "id"}
    assert client.post("/setup/ad-connections", json={"instance": new}).status_code == 400
    r = client.put("/setup/ad-connections/c1",
                   json={"config": {"tenant_id": "__admin__", "vault_credential": ref}})
    assert r.status_code == 400
    assert hub.state.system_state["global_config"]["ad_connections"] == [ACME]
    # A record stored before this check is never sent either.
    hub = _Hub([admin_conn])
    r = _client(monkeypatch, hub).post("/setup/ad-connections/c1/test")
    assert r.status_code == 400 and hub.sent == []


def test_a_stored_cross_tenant_credential_is_never_sent(monkeypatch):
    # A record saved before the save-time check still can't send another
    # tenant's password to this tenant's spoke.
    bad = {**ACME, "vault_credential": {"bucket": "beta", "name": "ad-bind"}}
    hub = _Hub([bad])
    r = _client(monkeypatch, hub).post("/setup/ad-connections/c1/test")
    assert r.status_code == 400 and hub.sent == []


def test_a_dropped_spoke_shows_on_its_connection_not_a_500(monkeypatch):
    def reply(_payload):
        raise ConnectionError("socket closed")
    hub = _Hub([ACME], reply=reply)
    r = _client(monkeypatch, hub).get("/api/ldap/ad?tenant=acme")
    assert r.status_code == 200
    block = r.json()["connections"][0]
    assert block["users"] == [] and block["error"]


def test_setup_list_and_add_show_the_credential_by_name_only(monkeypatch):
    # The vault bucket (always the connection's own tenant) stays on the hub.
    client, hub = _crud_client(monkeypatch, [ACME])
    listed = client.get("/setup/ad-connections").json()["instances"][0]
    assert listed["vault_credential"] == {"name": "ad-bind"} and listed["bind_password_set"]
    new = {k: v for k, v in ACME.items() if k != "id"}
    added = client.post("/setup/ad-connections", json={"instance": new}).json()["instance"]
    assert added["vault_credential"] == {"name": "ad-bind"}
    # The stored records keep the full reference.
    stored = hub.state.system_state["global_config"]["ad_connections"]
    assert all(c["vault_credential"]["bucket"] == "acme" for c in stored)


def test_connections_are_read_side_by_side(monkeypatch):
    import asyncio
    import time
    conns = [{**ACME, "id": f"c{i}", "name": f"AD {i}"} for i in range(2)]
    hub = _Hub(conns)

    async def slow_read(ns, key, fetch, tenants=None, lane=None):
        await asyncio.sleep(0.5)
        return await fetch()
    hub.cache_read = slow_read
    client = _client(monkeypatch, hub)
    # Two 0.5 s reads: ~0.5 s side by side, 1.0 s one after the other.
    start = time.monotonic()
    r = client.get("/api/ldap/ad?tenant=acme")
    assert time.monotonic() - start < 0.75
    assert [b["name"] for b in r.json()["connections"]] == ["AD 0", "AD 1"]


def test_saving_a_connection_is_ok_not_spoke_not_connected(monkeypatch):
    # AD connections are save-only (nothing is pushed), so a save is "ok".
    client, _hub = _crud_client(monkeypatch, [ACME])
    new = {k: v for k, v in ACME.items() if k != "id"}
    added = client.post("/setup/ad-connections", json={"instance": new}).json()
    assert added["status"] == "ok" and "not connected" not in added["message"]
    updated = client.put("/setup/ad-connections/c1", json={"config": {"name": "Renamed"}}).json()
    assert updated["status"] == "ok" and "not connected" not in updated["message"]
