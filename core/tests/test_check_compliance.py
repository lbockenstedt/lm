"""Compliance roll-up for the Simulations Dashboard compliance views: a long-term
daily store (back-filled from the 30-day hourly history), 24h flap counting, and
the week / month / quarter / year scores built from them."""
import json
import os
import time

from simulations.central_hub_poller import CheckHealthHistory, build_compliance

DAY = 86400


def test_daily_store_backfills_from_hourly_once(tmp_path):
    h = CheckHealthHistory(str(tmp_path))
    h.record("t1", "siteA", "chk", "ok")
    h.record("t1", "siteA", "chk", "error")
    h.save()
    # Simulate a hub that only has hourly history (feature just deployed).
    for root, _, files in os.walk(tmp_path):
        for f in files:
            if f.endswith("_daily.json"):
                os.remove(os.path.join(root, f))
    h2 = CheckHealthHistory(str(tmp_path))
    days = h2.compliance_raw("t1")["chk"]["days"]
    assert sum(c[0] for c in days.values()) == 1 and sum(c[2] for c in days.values()) == 1
    h2.save()
    # Reloading must not back-fill a second time.
    h3 = CheckHealthHistory(str(tmp_path))
    days = h3.compliance_raw("t1")["chk"]["days"]
    assert sum(c[0] + c[2] for c in days.values()) == 2


def test_flaps_count_graded_changes_only(tmp_path):
    h = CheckHealthHistory(str(tmp_path))
    for st in ["ok", "error", "no_data", "error", "ok", "warning"]:
        h.record("t1", "s", "chk", st)
    # ok→error, error→ok, ok→warning; no_data is ignored.
    assert h.compliance_raw("t1")["chk"]["flaps"] == 3


def test_build_compliance_windows_months_and_order():
    now = time.time()
    today = int(now // DAY * DAY)
    raw = {
        "good": {"sites": {"a"}, "hours": {}, "flaps": 0,
                 "days": {today: [10, 0, 0, 0]}},
        "bad": {"sites": {"a", "b"}, "hours": {}, "flaps": 0,
                "days": {today: [9, 1, 0, 5], today - 10 * DAY: [0, 0, 10, 0]}},
    }
    r = build_compliance(raw, now)
    bad, good = r["checks"]                      # worst 30-day first
    assert bad["check"] == "bad" and bad["sites"] == 2
    assert bad["d7"] == 90.0                     # only today is inside 7 days
    assert bad["d30"] == 45.0                    # 9 OK of 20 graded; no-data excluded
    assert good["d30"] == 100.0
    assert bad["flaps"] is None and bad["hours"] == []   # daily-only source
    # Overall pools every poll across checks.
    assert r["overall"]["d30"]["pct"] == round(100 * 19 / 30, 1)
    assert r["overall"]["d7"]["prev"] == 0.0     # days -13..-7 hold the 10 errors
    assert len(r["months"]) == 12 and len(r["quarters"]) == 4
    assert r["since"] == today - 10 * DAY
    json.dumps(r)                                 # route returns it as JSON


def test_compliance_route_combines_hub_poller_and_relayed_spokes(tmp_path):
    from types import SimpleNamespace
    from fastapi import FastAPI
    from starlette.testclient import TestClient
    import access as access_mod
    from simulations.routes import register_simulations_routes
    from test_central_on_prem_routes import _OnPremStore, _RouteHub, _cs_user

    hub = _RouteHub(_OnPremStore())
    health = CheckHealthHistory(str(tmp_path))
    health.record("acme", "MIA", "dns_fail", "ok")
    hub.central_hub_poller = SimpleNamespace(_health=health)
    today = int(time.time() // DAY * DAY)
    # A distributed Mist spoke relays daily buckets only.
    hub.simulations_cache = {"s1": {"mist": {"health": {"NYC": {"ap_down": [
        {"d": today, "o": 1, "w": 0, "e": 1, "n": 0}]}}}}}
    hub.active_connections = {"s1"}
    app = FastAPI()
    register_simulations_routes(
        app, hub, session_user_fn=lambda req: _cs_user("acme"),
        resolve_tenant_fn=lambda req: "acme", is_admin_fn=access_mod.is_admin,
        check_tenant_access_fn=access_mod.check_tenant_access, sessions=None,
        has_cs_access_fn=access_mod.has_cs_access, is_tenant_admin_fn=access_mod.is_tenant_admin)
    r = TestClient(app).get("/sim/api/aggregate/compliance?tenant_id=acme")
    assert r.status_code == 200
    rows = {(c["product"], c["check"]): c for c in r.json()["checks"]}
    assert rows[("Central", "dns_fail")]["d7"] == 100.0
    assert rows[("Mist", "ap_down")]["d7"] == 50.0
    assert r.json()["overall"]["d7"]["pct"] == round(100 * 2 / 3, 1)
