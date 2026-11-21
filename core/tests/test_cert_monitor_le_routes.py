"""Cert Monitor LE deployment verification through the routes: pushed LE certs
are checked even while the monitor is disabled, re-checked when their push
state changes, and tagged onto the result rows."""
import asyncio
from types import SimpleNamespace

from fastapi import FastAPI

import cert_monitor as cm


class _State:
    """Minimal hub state holding global_config."""

    def __init__(self):
        """Start with an empty global_config."""
        self.system_state = {"global_config": {}}

    def _mark_dirty(self):
        """No-op dirty flag."""

    async def save_state_now(self):
        """No-op save."""


def _setup(tmp_path, monkeypatch, certs, served_not_after, admin=False):
    """Register the routes on a fake hub whose le cache holds ``certs``; probes are faked."""
    monkeypatch.setattr(cm, "STATE_DIR", str(tmp_path))
    probes = []

    def fake_probe(entry, timeout=None, now=None):
        """Record the probe and return a reachable row serving ``served_not_after``."""
        probes.append(entry["host"])
        return {"host": entry["host"], "port": 443, "service": entry.get("service", ""),
                "region": "", "role": entry.get("role", ""), "error": "", "trusted": False,
                "not_after": served_not_after, "days_left": 5, "status": "red",
                "san": [entry["host"]]}

    monkeypatch.setattr(cm, "probe_host", fake_probe)
    # The tick's daily vendor-page refresh would fetch over the network and hang offline.
    monkeypatch.setattr(cm, "refresh_sources", lambda *a, **k: {})
    import routes.cert_monitor as rcm
    cache = {"status": "SUCCESS", "data": {"certs": certs}}
    hub = SimpleNamespace(state=_State(), le_cache_get=lambda k: cache if k == "certs" else None)
    ctx = SimpleNamespace(_session_user=lambda r: {"user": {"username": "a", "permissions": {"admin": admin}}}, _is_admin=lambda s: admin)
    app = FastAPI()
    rcm.register(app, hub, ctx)
    app.state.hub = hub
    return app, probes, certs


def _cert(status="DEFERRED"):
    """One LE cert pushed to an ipam target with the given ledger status."""
    return {"domain": "netbox.example.com", "not_after": "2027-02-14T02:22:00+00:00",
            "tenant_id": "default",
            "targets": [{"module_type": "ipam", "identifier": "nb-agent", "last_status": status,
                         "last_message": "cached but NOT installed"}]}


def test_le_only_check_runs_while_monitor_disabled(tmp_path, monkeypatch, caplog):
    """Disabled monitor + a pushed LE cert → an LE-only check flags the stale served cert."""
    app, probes, _ = _setup(tmp_path, monkeypatch, [_cert()], "2026-11-16T02:22:00+00:00")
    with caplog.at_level("WARNING", logger="Hub"):
        asyncio.run(app.state.certmon_tick())
    data = cm.load_results()
    assert probes == ["netbox.example.com"]
    assert data["scope"] == "le" and data["trigger"] == "scheduled"
    row = data["results"][0]
    assert row["deploy_state"] == "stale" and row["status"] == "red"
    assert "DEFERRED" in row["deploy_detail"]
    assert "[cert-verify] netbox.example.com:443 STALE (tenant default)" in caplog.text
    # Nothing changed → the next tick does not probe again.
    asyncio.run(app.state.certmon_tick())
    assert probes == ["netbox.example.com"]


def test_le_push_state_change_triggers_recheck(tmp_path, monkeypatch):
    """A new push status for an LE cert is re-checked on the next tick."""
    app, probes, certs = _setup(tmp_path, monkeypatch, [_cert()], "2027-02-14T02:22:00+00:00")
    asyncio.run(app.state.certmon_tick())
    certs[0]["targets"][0]["last_status"] = "SUCCESS"
    asyncio.run(app.state.certmon_tick())
    data = cm.load_results()
    assert len(probes) == 2 and data["trigger"] == "le-change"
    assert data["results"][0]["deploy_state"] == "verified"


def test_no_check_while_disabled_without_le_certs(tmp_path, monkeypatch):
    """Disabled monitor and no pushed LE certs → no probes, no results file."""
    app, probes, _ = _setup(tmp_path, monkeypatch, [_cert(status="")], "x")
    asyncio.run(app.state.certmon_tick())
    assert probes == [] and cm.load_results() == {}


def test_enabled_monitor_le_change_probes_only_le_hosts(tmp_path, monkeypatch):
    """With the monitor enabled, an LE push change re-probes only the LE
    endpoints and keeps the full scan's rows and schedule."""
    app, probes, certs = _setup(tmp_path, monkeypatch, [_cert()], "2026-11-16T02:22:00+00:00")
    monkeypatch.setattr(cm, "effective_hosts", lambda cfg: [
        {"host": "mist.example", "port": 443, "service": "Custom", "region": "", "role": "Custom"}])
    app.state.hub.state.system_state["global_config"]["cert_monitor"] = {"enabled": True}
    asyncio.run(app.state.certmon_tick())
    assert sorted(probes) == ["mist.example", "netbox.example.com"]
    full_run = cm.load_results()["last_run"]
    certs[0]["targets"][0]["last_status"] = "SUCCESS"
    asyncio.run(app.state.certmon_tick())
    data = cm.load_results()
    assert probes[2:] == ["netbox.example.com"]
    assert data["last_run"] == full_run and data["scope"] == "all" and data["trigger"] == "le-change"
    assert {r["host"] for r in data["results"]} == {"mist.example", "netbox.example.com"}


def test_last_push_removed_clears_le_rows(tmp_path, monkeypatch):
    """When the last pushed LE cert goes away, the next tick clears its row."""
    app, probes, certs = _setup(tmp_path, monkeypatch, [_cert()], "2026-11-16T02:22:00+00:00")
    asyncio.run(app.state.certmon_tick())
    assert cm.load_results()["results"]
    certs.clear()
    asyncio.run(app.state.certmon_tick())
    data = cm.load_results()
    assert data["results"] == [] and data["trigger"] == "le-change"
    asyncio.run(app.state.certmon_tick())
    assert probes == ["netbox.example.com"]


def test_rule_test_email_sees_only_shared_le_rows(tmp_path, monkeypatch):
    """A rule's test email uses the same tenant scope as the real evaluation:
    another tenant's LE domain never appears in it."""
    from fastapi.testclient import TestClient
    import cert_monitor_alerts as cma
    certs = [dict(_cert(), tenant_id="acme"), dict(_cert(), domain="shared.example.com", tenant_id="shared")]
    app, _, _ = _setup(tmp_path, monkeypatch, certs, "2026-11-16T02:22:00+00:00", admin=True)
    asyncio.run(app.state.certmon_tick())
    assert {r["host"] for r in cm.load_results()["results"]} == {"netbox.example.com", "shared.example.com"}
    monkeypatch.setattr(cma, "get_rules", lambda hub: [{"id": "r1", "trigger": "le_deploy",
                                                        "recipients": ["ops@example.com"]}])
    sent = []

    async def fake_send_test(hub, rule, results):
        """Capture the rows the test email would list."""
        sent.extend(r["host"] for r in results)
        return True
    monkeypatch.setattr(cma, "send_test", fake_send_test)
    assert TestClient(app).post("/api/certmon/alerts/rules/r1/test").status_code == 200
    assert sent == ["shared.example.com"]


def test_overview_scopes_le_rows_to_the_tenant_in_view(tmp_path, monkeypatch):
    """A global admin sees a tenant's LE rows only after switching into it
    (?tenant=, resolved through access); shared rows show either way."""
    from fastapi.testclient import TestClient
    certs = [dict(_cert(), tenant_id="acme"), dict(_cert(), domain="shared.example.com", tenant_id="shared")]
    app, _, _ = _setup(tmp_path, monkeypatch, certs, "2026-11-16T02:22:00+00:00", admin=True)
    asyncio.run(app.state.certmon_tick())
    client = TestClient(app)
    hosts = lambda q: {r["host"] for r in client.get("/api/certmon/overview" + q).json()["results"]}
    assert hosts("") == {"shared.example.com"}
    assert hosts("?tenant=acme") == {"netbox.example.com", "shared.example.com"}


def test_unreadable_le_cache_holds_le_rows(tmp_path, monkeypatch):
    """An unreadable LE cert list is not "no certs pushed": the LE rows and
    their failing verdict stay, and no LE-change run clears them."""
    app, probes, _ = _setup(tmp_path, monkeypatch, [_cert()], "2026-11-16T02:22:00+00:00")
    asyncio.run(app.state.certmon_tick())
    before = cm.load_results()
    assert [r["deploy_state"] for r in before["results"]] == ["stale"]
    for broken in (lambda k: None, lambda k: {"status": "ERROR"}):
        app.state.hub.le_cache_get = broken
        asyncio.run(app.state.certmon_tick())
        assert cm.load_results() == before and len(probes) == 1
