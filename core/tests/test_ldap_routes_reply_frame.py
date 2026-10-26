"""``routes/ldap.py`` must read the spoke's result from inside the reply frame.

``hub.request_response`` returns the whole reply frame
(``{"header", "payload": {"type": "COMMAND_RESULT", "data": <spoke result>}}``).
The routes used to check ``status``/``data`` only at the top level, so on the
live hub the Directory list showed "no users" for a tenant that had one (the
frame itself was returned as the list) and a failed write showed "created".
"""
import sys
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from routes import ldap as ldap_routes  # noqa: E402


def _frame(result):
    return {"correlation_id": "c1", "header": {"sender_id": "dir-spoke"},
            "payload": {"type": "COMMAND_RESULT", "data": result}}


class _FakeHub:
    def __init__(self, replies):
        self.replies = replies  # cmd -> spoke result
        self.state = SimpleNamespace(get_tenant=lambda tid: {"netbox_tenant_slug": tid})
        self.warm_cache = {}

    def get_directory_spoke_for_tenant(self, tid):
        return "dir-spoke"

    async def request_response(self, spoke_id, cmd, data, timeout=None):
        return _frame(self.replies[cmd])

    async def cache_read(self, ns, key, fetch, tenants=None, lane=None):
        return await fetch()

    def cache_annotate(self, data, ns, key):
        return data


def _client(replies):
    app = FastAPI()
    admin = {"user": {"permissions": {"admin": True}}}
    ldap_routes.register(app, _FakeHub(replies), SimpleNamespace(_session_user=lambda r: admin))
    return TestClient(app)


def test_user_list_is_unwrapped_from_the_reply_frame():
    users = [{"username": "test-account", "first_name": "Lance"}]
    c = _client({"LDAP_LIST_USERS": {"status": "SUCCESS", "data": users}})
    r = c.get("/api/ldap/users?tenant=lrb")
    assert r.status_code == 200
    assert r.json() == users


def test_create_returns_the_spoke_result():
    c = _client({"LDAP_CREATE_USER": {"status": "SUCCESS", "dn": "uid=a,ou=users,ou=lrb",
                                      "password": "pw"}})
    r = c.post("/api/ldap/users", json={"tenant_id": "lrb", "uid": "a"})
    assert r.status_code == 200
    assert r.json()["password"] == "pw"


def test_spoke_error_inside_the_frame_is_a_502():
    c = _client({"LDAP_CREATE_USER": {"status": "ERROR", "message": "SERVER_DOWN"},
                 "LDAP_LIST_USERS": {"status": "ERROR", "message": "SERVER_DOWN"}})
    r = c.post("/api/ldap/users", json={"tenant_id": "lrb", "uid": "a"})
    assert r.status_code == 502
    assert "SERVER_DOWN" in r.json()["detail"]
    assert c.get("/api/ldap/users?tenant=lrb").status_code == 502
