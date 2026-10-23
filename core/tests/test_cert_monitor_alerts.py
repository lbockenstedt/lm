"""Cert Monitor alert rules: rule cleaning, edge-triggered breach/recovery
evaluation, persisted state, retry on failed send, email formats, and the
Global-Admin-only /api/certmon/alerts/* routes."""
import asyncio
import datetime as _dt
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import cert_monitor as cm
import cert_monitor_alerts as cma


def _r(host, days, service="Juniper Mist", status=None, trusted=True, error=""):
    return {"host": host, "port": 443, "service": service, "region": "Global 01",
            "role": "API", "days_left": days, "trusted": trusted, "error": error,
            "not_after": "2026-11-01T00:00:00+00:00" if days is not None else None,
            "status": status or (cm.classify(days, error))}


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}

    def _mark_dirty(self):
        pass

    async def save_state_now(self):
        pass


def _hub():
    return SimpleNamespace(state=_State())


def test_clean_rule_defaults_and_validation():
    r = cma.clean_rule({"trigger": "bogus", "threshold_days": "x",
                        "services": ["Juniper Mist", "Nope"], "recipients": "a@x.com; b@x.com",
                        "format": "RAW"})
    assert r["trigger"] == "expiring" and r["threshold_days"] == cma.DEFAULT_THRESHOLD_DAYS
    assert r["services"] == ["Juniper Mist"]
    assert r["recipients"] == ["a@x.com", "b@x.com"]
    assert r["format"] == "raw" and r["enabled"] is True and r["id"]
    assert cma.clean_rule({"threshold_days": 0})["threshold_days"] == 1
    kept = cma.clean_rule({"name": "n"}, {"id": "abc"})
    assert kept["id"] == "abc"


def test_evaluate_edges_breach_then_silent_then_recover():
    rule = cma.clean_rule({"trigger": "expiring", "threshold_days": 30})
    b, rec, bad = cma.evaluate_rule(rule, [_r("a", 10), _r("b", 100)], [])
    assert [x["host"] for x in b] == ["a"] and rec == [] and bad == ["a:443"]
    b, rec, bad = cma.evaluate_rule(rule, [_r("a", 9), _r("b", 99)], bad)
    assert b == [] and rec == [] and bad == ["a:443"]  # still bad → silent
    b, rec, bad = cma.evaluate_rule(rule, [_r("a", 400), _r("b", 99)], bad)
    assert b == [] and [x["host"] for x in rec] == ["a"] and bad == []


def test_expiring_keeps_verdict_when_host_unreachable():
    rule = cma.clean_rule({"trigger": "expiring", "threshold_days": 30})
    _, _, bad = cma.evaluate_rule(rule, [_r("a", 5)], [])
    b, rec, bad2 = cma.evaluate_rule(rule, [_r("a", None, error="timeout")], bad)
    assert b == [] and rec == [] and bad2 == ["a:443"]


def test_error_untrusted_and_service_scope():
    err = cma.clean_rule({"trigger": "error"})
    b, _, _ = cma.evaluate_rule(err, [_r("a", None, error="DNS"), _r("b", 50)], [])
    assert [x["host"] for x in b] == ["a"]
    unt = cma.clean_rule({"trigger": "untrusted"})
    b, _, _ = cma.evaluate_rule(unt, [_r("a", 50, trusted=False), _r("b", 50)], [])
    assert [x["host"] for x in b] == ["a"]
    scoped = cma.clean_rule({"trigger": "expiring", "services": ["Aruba Central"]})
    b, _, _ = cma.evaluate_rule(scoped, [_r("m", 1), _r("c", 1, service="Aruba Central")], [])
    assert [x["host"] for x in b] == ["c"]


def test_build_email_human_and_raw():
    rule = cma.clean_rule({"name": "N", "trigger": "expiring", "threshold_days": 30})
    subj, text, html = cma.build_email(rule, [_r("a<b", 3)], [_r("c", 200)], ts="T")
    assert subj.startswith("[LM ALERT] Cert Monitor") and "1 breached, 1 recovered" in subj
    assert "BREACHED (1)" in text and "RECOVERED (1)" in text and "3 d left" in text
    assert "a&lt;b" in html and "a<b" not in html
    raw = cma.clean_rule({"trigger": "expiring", "format": "raw"})
    subj, body, html = cma.build_email(raw, [_r("a", -2)], [], ts="T")
    p = json.loads(body)
    assert html == "" and p["event"] == "lm_certmon_alert"
    assert p["breached"][0]["host"] == "a" and "EXPIRED" in p["breached"][0]["detail"]
    assert "  " not in subj


def test_run_alerts_persists_and_retries_failed_send(tmp_path, monkeypatch):
    hub = _hub()
    rule = cma.clean_rule({"trigger": "expiring", "recipients": ["n@x.com"]})
    hub.state.system_state["global_config"][cma.CONFIG_KEY] = {"rules": [rule]}
    sent, ok = [], {"v": False}

    async def fake_send(h, r, subj, text, html):
        sent.append(subj)
        return ok["v"]
    monkeypatch.setattr(cma, "_send", fake_send)
    res = [_r("a", 5)]
    d = str(tmp_path)
    asyncio.run(cma.run_alerts(hub, res, state_dir=d))
    assert len(sent) == 1 and cma.load_state(d) == {rule["id"]: []}  # not advanced
    ok["v"] = True
    asyncio.run(cma.run_alerts(hub, res, state_dir=d))
    assert len(sent) == 2 and cma.load_state(d) == {rule["id"]: ["a:443"]}
    asyncio.run(cma.run_alerts(hub, res, state_dir=d))  # still bad, persisted → silent
    assert len(sent) == 2
    asyncio.run(cma.run_alerts(hub, [_r("a", 300)], state_dir=d))
    assert len(sent) == 3 and "1 recovered" in sent[-1]
    # Deleted rule → its state is dropped.
    hub.state.system_state["global_config"][cma.CONFIG_KEY] = {"rules": []}
    asyncio.run(cma.run_alerts(hub, res, state_dir=d))
    assert cma.load_state(d) == {}


def test_disabled_or_recipientless_rule_never_sends(tmp_path, monkeypatch):
    hub = _hub()
    hub.state.system_state["global_config"][cma.CONFIG_KEY] = {"rules": [
        cma.clean_rule({"enabled": False, "recipients": ["n@x.com"]}),
        cma.clean_rule({"recipients": []})]}
    sent = []

    async def fake_send(*a):
        sent.append(a)
        return True
    monkeypatch.setattr(cma, "_send", fake_send)
    asyncio.run(cma.run_alerts(hub, [_r("a", 1)], state_dir=str(tmp_path)))
    assert sent == []


# ── routes ──────────────────────────────────────────────────────────────────

def _client(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(cm, "STATE_DIR", str(tmp_path))
    import routes.cert_monitor as rcm
    hub = _hub()
    sess = {"user": {"is_admin": admin}}
    ctx = SimpleNamespace(_session_user=lambda request: sess,
                          _is_admin=lambda s: bool(s and s["user"]["is_admin"]))
    app = FastAPI()
    rcm.register(app, hub, ctx)
    return TestClient(app), hub


@pytest.mark.parametrize("method,path", [
    ("get", "/api/certmon/alerts/rules"), ("post", "/api/certmon/alerts/rules"),
    ("put", "/api/certmon/alerts/rules/x"), ("delete", "/api/certmon/alerts/rules/x"),
    ("post", "/api/certmon/alerts/rules/x/test")])
def test_alert_routes_admin_only(method, path, tmp_path, monkeypatch):
    client, _ = _client(False, tmp_path, monkeypatch)
    kw = {"json": {}} if method in ("post", "put") else {}
    assert getattr(client, method)(path, **kw).status_code == 403


def test_alert_rule_crud_and_test(tmp_path, monkeypatch):
    client, hub = _client(True, tmp_path, monkeypatch)
    meta = client.get("/api/certmon/alerts/rules").json()
    assert meta["rules"] == [] and "expiring" in meta["triggers"]
    assert "Juniper Mist" in meta["services"] and "Custom" in meta["services"]

    r = client.post("/api/certmon/alerts/rules", json={
        "name": "NOC", "trigger": "expiring", "threshold_days": 14,
        "recipients": ["noc@x.com"]})
    assert r.status_code == 200
    rid = r.json()["rule"]["id"]
    stored = hub.state.system_state["global_config"][cma.CONFIG_KEY]["rules"]
    assert stored[0]["threshold_days"] == 14
    # Cert Monitor's own config normalisation must not touch the alert rules.
    assert client.put("/api/certmon/config", json={"custom_hosts": []}).status_code == 200
    assert hub.state.system_state["global_config"][cma.CONFIG_KEY]["rules"][0]["id"] == rid

    cma.save_state({rid: ["a:443"]})
    r = client.put(f"/api/certmon/alerts/rules/{rid}", json={"name": "NOC", "trigger": "error",
                                                              "recipients": ["noc@x.com"]})
    assert r.status_code == 200 and r.json()["rule"]["trigger"] == "error"
    assert rid not in cma.load_state()  # trigger change resets the edge state
    assert client.put("/api/certmon/alerts/rules/nope", json={}).status_code == 404

    cm.save_results({"last_run": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                     "results": [_r("a", None, error="DNS")]})
    got = []

    async def fake_send(h, subj, text, to_emails=None, html=""):
        got.append((subj, to_emails))
        return True
    import notifications
    monkeypatch.setattr(notifications, "send_email", fake_send)
    r = client.post(f"/api/certmon/alerts/rules/{rid}/test")
    assert r.status_code == 200 and r.json()["to"] == ["noc@x.com"]
    assert got and got[0][0].startswith("[LM TEST]") and "1 breached" in got[0][0]

    assert client.delete(f"/api/certmon/alerts/rules/{rid}").json()["removed"] is True
    assert client.get("/api/certmon/alerts/rules").json()["rules"] == []


def test_ignored_host_never_breaches_and_drops_silently():
    rule = cma.clean_rule({"trigger": "expiring", "threshold_days": 30})
    a = dict(_r("a", 5), ignored=True)
    b, rec, bad = cma.evaluate_rule(rule, [a, _r("b", 5)], [])
    assert [x["host"] for x in b] == ["b"] and bad == ["b:443"]
    # Already breached, then ignored → leaves the state with no recovery email.
    b, rec, bad = cma.evaluate_rule(rule, [dict(_r("b", 5), ignored=True)], ["b:443"])
    assert b == [] and rec == [] and bad == []


def test_rule_test_send_skips_ignored_hosts(tmp_path, monkeypatch):
    client, hub = _client(True, tmp_path, monkeypatch)
    rid = client.post("/api/certmon/alerts/rules", json={
        "trigger": "error", "recipients": ["noc@x.com"], "enabled": False}).json()["rule"]["id"]
    cm.save_results({"last_run": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                     "results": [_r("a.example.com", None, error="DNS"),
                                 _r("b.example.com", None, error="DNS")]})
    assert client.post("/api/certmon/ignore", json={"host": "a.example.com"}).status_code == 200
    got = []

    async def fake_send(h, subj, text, to_emails=None, html=""):
        got.append(text)
        return True
    import notifications
    monkeypatch.setattr(notifications, "send_email", fake_send)
    assert client.post(f"/api/certmon/alerts/rules/{rid}/test").status_code == 200
    assert "b.example.com" in got[-1] and "a.example.com" not in got[-1]
