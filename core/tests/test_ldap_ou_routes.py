"""Directory OU routes (``/api/ldap/ous``, ``/api/ldap/users/move``).

The routes relay LDAP_*_OU / LDAP_MOVE_USER to the tenant's directory spoke
with the session-derived tenant slug, reject a malformed OU path before it
reaches the spoke (it must never read as "the top level"), and tell an older
spoke ("Unknown command") apart from an LDAP failure.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from routes import ldap as ldap_routes  # noqa: E402


class _Hub:
    """Fake hub that records every relayed command."""

    def __init__(self, replies):
        self.replies = replies
        self.sent = []
        self.state = SimpleNamespace(get_tenant=lambda tid: {"netbox_tenant_slug": tid})
        self.warm_cache = {}

    def get_directory_spoke_for_tenant(self, tid):
        return f"dir-{tid}"

    async def request_response(self, spoke_id, cmd, data, timeout=None):
        self.sent.append((spoke_id, cmd, data))
        return {"payload": {"data": self.replies.get(cmd, {"status": "SUCCESS"})}}

    async def cache_read(self, ns, key, fetch, tenants=None, lane=None):
        return await fetch()

    def cache_annotate(self, data, ns, key):
        return data


def _client(replies=None):
    hub = _Hub(replies or {})
    app = FastAPI()
    admin = {"user": {"permissions": {"admin": True}}}
    ldap_routes.register(app, hub, SimpleNamespace(_session_user=lambda r: admin))
    return TestClient(app), hub


def test_ou_writes_relay_to_the_tenants_spoke_with_its_slug():
    c, hub = _client()
    assert c.post("/api/ldap/ous", json={"tenant_id": "acme", "name": "Lab",
                                         "parent_path": "Eng"}).status_code == 200
    assert c.put("/api/ldap/ous", json={"tenant_id": "acme", "path": ["Eng", "Lab"],
                                        "new_name": "Labs"}).status_code == 200
    assert c.request("DELETE", "/api/ldap/ous",
                     json={"tenant_id": "acme", "path": "Eng/Labs"}).status_code == 200
    assert c.post("/api/ldap/users/move", json={"tenant_id": "acme", "uid": "alice",
                                                "target_path": ""}).status_code == 200
    assert hub.sent == [
        ("dir-acme", "LDAP_CREATE_OU", {"name": "Lab", "parent_path": ["Eng"],
                                        "tenant_slug": "acme"}),
        ("dir-acme", "LDAP_RENAME_OU", {"path": ["Eng", "Lab"], "new_name": "Labs",
                                        "tenant_slug": "acme"}),
        ("dir-acme", "LDAP_DELETE_OU", {"path": ["Eng", "Labs"], "tenant_slug": "acme"}),
        ("dir-acme", "LDAP_MOVE_USER", {"uid": "alice", "target_path": [],
                                        "tenant_slug": "acme"}),
    ]


def test_malformed_or_missing_paths_are_400_and_never_relayed():
    c, hub = _client()
    bad = [
        ("post", "/api/ldap/users/move", {"uid": "alice", "target_path": {"x": 1}}),
        ("post", "/api/ldap/users/move", {"uid": "alice", "target_path": ["Eng", 5]}),
        ("post", "/api/ldap/ous", {"name": "Lab", "parent_path": 7}),
        ("post", "/api/ldap/ous", {"parent_path": "Eng"}),
        ("put", "/api/ldap/ous", {"path": "", "new_name": "X"}),
        ("delete", "/api/ldap/ous", {"path": []}),
        ("post", "/api/ldap/users", {"uid": "bob", "ou_path": True}),
        ("post", "/api/ldap/users/move", {"uid": "alice", "target_path": "/"}),
        ("post", "/api/ldap/users/move", {"uid": "alice", "target_path": "Eng//Lab"}),
        ("post", "/api/ldap/ous", {"name": "Lab", "parent_path": ["Eng", " "]}),
    ]
    for method, url, body in bad:
        r = c.request(method.upper(), url, json={"tenant_id": "acme", **body})
        assert r.status_code == 400, (url, body)
    assert hub.sent == []


def test_older_spoke_is_reported_as_needing_an_update():
    c, _ = _client({"LDAP_LIST_OUS": {"status": "ERROR",
                                      "message": "Unknown command: LDAP_LIST_OUS"}})
    r = c.get("/api/ldap/ous?tenant=acme")
    assert r.status_code == 501
    assert "update the directory spoke" in r.json()["detail"]


def test_partial_rollback_message_reaches_the_ui():
    msg = "rewrite failed; the change could not be fully undone: entry is still at uid=a"
    c, _ = _client({"LDAP_MOVE_USER": {"status": "ERROR", "error": "PARTIAL_ROLLBACK",
                                       "message": msg}})
    r = c.post("/api/ldap/users/move", json={"tenant_id": "acme", "uid": "a",
                                             "target_path": "Eng"})
    assert r.status_code == 502 and r.json()["detail"] == msg


def test_create_in_ou_warns_when_an_older_spoke_put_the_user_at_the_top():
    old = {"LDAP_CREATE_USER": {"status": "SUCCESS",
                                "dn": "uid=bob,ou=users,ou=acme,dc=lab"}}
    c, hub = _client(old)
    r = c.post("/api/ldap/users", json={"tenant_id": "acme", "uid": "bob",
                                        "ou_path": "Eng"})
    assert r.status_code == 200 and "Update it, then move the user" in r.json()["warning"]
    assert hub.sent[0][2]["ou_path"] == ["Eng"]
    new = {"LDAP_CREATE_USER": {"status": "SUCCESS",
                                "dn": "uid=bob\\,x,ou=Eng,ou=users,ou=acme,dc=lab"}}
    c, _ = _client(new)
    r = c.post("/api/ldap/users", json={"tenant_id": "acme", "uid": "bob,x",
                                        "ou_path": "Eng"})
    assert "warning" not in r.json()
