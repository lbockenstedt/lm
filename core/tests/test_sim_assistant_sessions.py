"""routes.sim_assistant — interactive session relay (/api/sim-assistant/session*).

The hub only gates access and relays SIM_SESSION_* to AppBuilder; these tests
pin the gating (cs access, Global-Admin-only submit), the owner identity the
hub stamps (never taken from the browser), the error mapping, and the
capability probe that keeps older AppBuilders on the legacy /chat flow.
"""
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.sim_assistant import register


class _Hub:
    def __init__(self, replies=None, connected=True):
        self.active_connections = {"ab": object()} if connected else {}
        self.replies = replies or {}
        self.calls = []

    def _primary_key(self, sid):
        return sid

    async def request_response(self, target, cmd, payload, timeout=None):
        self.calls.append((cmd, payload, timeout))
        r = self.replies.get(cmd)
        if callable(r):
            r = r(payload)
        if r is None:
            return {"status": "ERROR", "message": "Timed out waiting for spoke response"}
        return {"payload": {"data": r}}


def _ctx(admin=False, cs=True, user="alice", tenant="t1"):
    sess = {"user_id": user, "user": {"username": user}}
    return SimpleNamespace(
        _session_user=lambda req: sess,
        _is_admin=lambda s: admin,
        _has_cs_access=lambda s: cs,
        _resolve_tenant=lambda req, *a: tenant,
    )


def _client(hub, **kw):
    app = FastAPI()
    app.state.hub = hub
    register(app, hub, _ctx(**kw))
    return TestClient(app)


OK = {"status": "SUCCESS", "session_id": "s1", "state": "preparing", "seq": 1}


def test_available_reports_sessions_and_submit_right():
    hub = _Hub({"SIM_SESSION_PING": {"status": "SUCCESS", "ready": True, "reasons": []}})
    body = _client(hub, admin=True).get("/api/sim-assistant/available").json()
    assert body == {"available": True, "sessions": True, "sessions_reason": "", "can_submit": True}
    # cached: a second call does not re-probe
    _client(hub).get("/api/sim-assistant/available")


def test_available_sessions_false_with_reason_when_ab_not_ready():
    hub = _Hub({"SIM_SESSION_PING": {"status": "SUCCESS", "ready": False,
                                     "reasons": ["GitHub Copilot CLI not installed on AppBuilder"]}})
    body = _client(hub).get("/api/sim-assistant/available").json()
    assert body["sessions"] is False and "Copilot CLI" in body["sessions_reason"]
    assert body["can_submit"] is False


def test_available_older_ab_times_out_to_legacy():
    body = _client(_Hub({})).get("/api/sim-assistant/available").json()
    assert body["available"] is True and body["sessions"] is False


def test_start_stamps_owner_server_side():
    hub = _Hub({"SIM_SESSION_START": OK})
    r = _client(hub, user="bob", tenant="default").post(
        "/api/sim-assistant/session", json={"message": "hi", "owner": {"user": "mallory"}})
    assert r.status_code == 200 and r.json()["session_id"] == "s1" and "status" not in r.json()
    cmd, payload, _ = hub.calls[-1]
    assert cmd == "SIM_SESSION_START"
    assert payload["message"] == "hi"
    o = payload["owner"]
    assert (o["user"], o["tenant"], o["admin"]) == ("bob", "", False)
    assert set(o) == {"user", "tenant", "admin", "auth_type", "ip"}


def test_start_requires_message_and_cs_access():
    hub = _Hub({"SIM_SESSION_START": OK})
    assert _client(hub).post("/api/sim-assistant/session", json={"message": "  "}).status_code == 400
    assert _client(hub, cs=False).post("/api/sim-assistant/session",
                                       json={"message": "x"}).status_code == 403
    assert not hub.calls


def test_poll_reply_cancel_relay():
    hub = _Hub({"SIM_SESSION_POLL": dict(OK, events=[]), "SIM_SESSION_REPLY": OK,
                "SIM_SESSION_CANCEL": OK})
    c = _client(hub)
    assert c.get("/api/sim-assistant/session/s1?since=7").status_code == 200
    assert hub.calls[-1][1]["since"] == 7 and hub.calls[-1][1]["session_id"] == "s1"
    assert c.post("/api/sim-assistant/session/s1/reply", json={"message": "5 qps"}).status_code == 200
    assert hub.calls[-1][1]["message"] == "5 qps"
    assert c.post("/api/sim-assistant/session/s1/cancel").status_code == 200


def test_error_mapping():
    hub = _Hub({"SIM_SESSION_POLL": {"status": "ERROR", "code": "not_found", "message": "session not found"},
                "SIM_SESSION_REPLY": {"status": "ERROR", "message": "the assistant is still working"}})
    c = _client(hub)
    assert c.get("/api/sim-assistant/session/zz").status_code == 404
    r = c.post("/api/sim-assistant/session/zz/reply", json={"message": "x"})
    assert r.status_code == 409 and "still working" in r.json()["detail"]
    assert c.post("/api/sim-assistant/session/zz/cancel").status_code == 504


def test_submit_is_global_admin_only():
    hub = _Hub({"SIM_SESSION_SUBMIT": dict(OK, state="submitted", submitted=[{"url": "u"}])})
    r = _client(hub, admin=False).post("/api/sim-assistant/session/s1/submit")
    assert r.status_code == 403 and not hub.calls
    r = _client(hub, admin=True).post("/api/sim-assistant/session/s1/submit")
    assert r.status_code == 200 and r.json()["state"] == "submitted"
    assert hub.calls[-1][1]["owner"]["admin"] is True


def test_no_ab_connected_is_409():
    r = _client(_Hub(connected=False)).post("/api/sim-assistant/session", json={"message": "x"})
    assert r.status_code == 409
