"""routes.request_assistant — interactive Bug/Feature Request capture.

The hub relays REQ_SESSION_* to AppBuilder and, on submit, stores the
AB-rendered report through the SAME store as /api/bug-report (so ab's
scan_bugs → auto-fix / feature approval pipeline is unchanged). These tests
pin: owner stamped server-side, capability probe fallback, the submit → store
→ FILED sequence, idempotent re-submit, and the hub_bug_store extra fields.
"""
import json
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.request_assistant import register


class _Hub:
    def __init__(self, replies=None, connected=True):
        self.active_connections = {"ab": object()} if connected else {}
        self.replies = replies or {}
        self.calls = []
        self.stored = []

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

    def _store_bug_report(self, data):
        self.stored.append(dict(data))
        return "abc123def456"


def _ctx(user="alice", tenant="t1", logged_in=True, admin=False):
    sess = {"user_id": user, "user": {"username": user, "auth_type": "ldap"}, "client_ip": "10.0.0.5"}
    return SimpleNamespace(
        _session_user=lambda req: sess if logged_in else None,
        _is_admin=lambda s: admin,
        _resolve_tenant=lambda req, *a: tenant,
    )


def _client(hub, **kw):
    app = FastAPI()
    app.state.hub = hub
    register(app, hub, _ctx(**kw))
    return TestClient(app)


OK = {"status": "SUCCESS", "session_id": "s1", "state": "preparing", "seq": 1}
REPORT = {"type": "feature", "severity": "high", "title": "CSV export",
          "explanation": "CSV export\n\n**Request trace**\n- session s1",
          "spec": {"intent": "feature", "title": "CSV export"}, "session_id": "s1"}


def test_available_probe_and_fallbacks():
    hub = _Hub({"REQ_SESSION_PING": {"status": "SUCCESS", "ready": True, "reasons": []}})
    assert _client(hub).get("/api/request-assistant/available").json() == {
        "available": True, "sessions": True, "sessions_reason": ""}
    # older AB never answers → one-shot form
    body = _client(_Hub({})).get("/api/request-assistant/available").json()
    assert body["available"] is True and body["sessions"] is False
    body = _client(_Hub(connected=False)).get("/api/request-assistant/available").json()
    assert body["available"] is False and body["sessions"] is False


def test_start_stamps_owner_and_context_server_side():
    hub = _Hub({"REQ_SESSION_START": OK})
    r = _client(hub, tenant="default").post("/api/request-assistant/session", json={
        "message": "delete is broken", "type": "bug", "owner": {"user": "mallory"},
        "context": {"currentView": "Simulations"}, "console_errors": "ERR 500"})
    assert r.status_code == 200 and r.json()["session_id"] == "s1" and "status" not in r.json()
    cmd, payload, _ = hub.calls[0]
    assert cmd == "REQ_SESSION_START"
    assert payload["owner"] == {"user": "alice", "tenant": "", "admin": False,
                                "auth_type": "ldap", "ip": "10.0.0.5"}
    assert payload["context"] == {"currentView": "Simulations", "type": "bug", "console_errors": "ERR 500"}


def test_requires_login_and_message():
    hub = _Hub({"REQ_SESSION_START": OK})
    assert _client(hub, logged_in=False).post("/api/request-assistant/session",
                                              json={"message": "x"}).status_code == 401
    assert _client(hub).post("/api/request-assistant/session", json={}).status_code == 400
    assert hub.calls == []


def test_error_mapping():
    hub = _Hub({"REQ_SESSION_POLL": {"status": "ERROR", "code": "not_found", "message": "x"},
                "REQ_SESSION_REPLY": {"status": "ERROR", "message": "a reply is already running"}})
    c = _client(hub)
    assert c.get("/api/request-assistant/session/s1").status_code == 404
    assert c.post("/api/request-assistant/session/s1/reply", json={"message": "m"}).status_code == 409
    assert c.post("/api/request-assistant/session/s1/cancel").status_code == 504
    assert _client(_Hub(connected=False)).get("/api/request-assistant/session/s1").status_code == 409


def test_submit_stores_through_bug_store_then_marks_filed():
    hub = _Hub({"REQ_SESSION_SUBMIT": {"status": "SUCCESS", "state": "submitted", "report": REPORT},
                "REQ_SESSION_FILED": {"status": "SUCCESS", "state": "submitted",
                                      "report_id": "abc123def456"}})
    r = _client(hub).post("/api/request-assistant/session/s1/submit", json={
        "console_logs": "log", "html": "<html>", "screenshot": "data:image/png;base64,AA==",
        "context": {"currentView": "Devices", "currentTenant": "zz"}})
    assert r.status_code == 200
    body = r.json()
    assert body["report_id"] == "abc123def456" and body["type"] == "feature" and "report" not in body
    assert [c[0] for c in hub.calls] == ["REQ_SESSION_SUBMIT", "REQ_SESSION_FILED"]
    assert hub.calls[1][1]["report_id"] == "abc123def456"
    st = hub.stored[0]
    assert st["explanation"] == REPORT["explanation"] and st["type"] == "feature"
    assert st["severity"] == "high" and st["title"] == "CSV export"
    assert st["request_spec"] == REPORT["spec"] and st["assistant_session"] == "s1"
    assert st["console_logs"] == "log" and st["html"] == "<html>" and st["screenshot"].startswith("data:")
    assert st["tenant_id"] == "t1"  # server-side tenant beats the browser's currentTenant
    assert st["context"]["source"] == "request-assistant" and st["context"]["currentView"] == "Devices"


def test_submit_already_filed_does_not_store_again():
    hub = _Hub({"REQ_SESSION_SUBMIT": {"status": "SUCCESS", "state": "submitted", "report_id": "x1"}})
    r = _client(hub).post("/api/request-assistant/session/s1/submit", json={})
    assert r.status_code == 200 and r.json()["report_id"] == "x1"
    assert hub.stored == []


def test_submit_gate_error_propagates_without_storing():
    hub = _Hub({"REQ_SESSION_SUBMIT": {"status": "ERROR",
                                       "message": "not ready to file: Still needed: steps to reproduce."}})
    r = _client(hub).post("/api/request-assistant/session/s1/submit", json={})
    assert r.status_code == 409 and "steps to reproduce" in r.json()["detail"]
    assert hub.stored == []


def test_submit_survives_filed_relay_failure():
    hub = _Hub({"REQ_SESSION_SUBMIT": {"status": "SUCCESS", "state": "submitted", "report": REPORT}})
    r = _client(hub).post("/api/request-assistant/session/s1/submit", json={})
    assert r.status_code == 200 and r.json()["report_id"] == "abc123def456"


def test_bug_store_persists_optional_assistant_fields(tmp_path):
    from hub_bug_store import HubBugStoreMixin

    class S(HubBugStoreMixin):
        pass

    s = S()
    s.bug_dir, s.bug_reports, s.bug_report_limit = str(tmp_path), {}, 50
    rid = s._store_bug_report({"explanation": "Title\n\n**Request trace**", "type": "bug",
                               "title": "  Delete   does nothing ", "request_spec": {"intent": "bug"},
                               "assistant_session": "s1"})
    rj = json.load(open(tmp_path / rid / "report.json"))
    assert rj["title"] == "Delete does nothing" and rj["request_spec"] == {"intent": "bug"}
    assert rj["assistant_session"] == "s1"
    assert s.bug_reports[rid]["summary"] == "Delete does nothing"
    # one-shot reports are unchanged (no new keys)
    rid2 = s._store_bug_report({"explanation": "plain", "type": "bug"})
    rj2 = json.load(open(tmp_path / rid2 / "report.json"))
    assert "title" not in rj2 and "request_spec" not in rj2 and s.bug_reports[rid2]["summary"] == "plain"
    s.bug_reports = {}
    s.warm_load_bug_reports()
    assert s.bug_reports[rid]["summary"] == "Delete does nothing"


def test_webui_footer_modal_offers_guided_mode_with_quick_form_fallback():
    import os
    d = os.path.dirname(os.path.abspath(__file__))
    while not os.path.isdir(os.path.join(d, "WebUI")):
        d = os.path.dirname(d)
    src = open(os.path.join(d, "WebUI", "main.js"), encoding="utf-8").read()
    body = src[src.index("async function fileBug(prefill = '')"):src.index("// Shared capture for manual")]
    assert "/api/request-assistant/available" in body and "_reqAsstProbe(" in body
    assert 'onclick="submitBugReport()"' in body and "bugUseQuickForm" in body
    assert "/submit`" in body and "_captureBugContext()" in body
    # all assistant/user text goes through escapeHtml or the escaping markdown renderer
    assert "innerHTML = (!busy" in body and "escapeHtml(String(c))" in body
