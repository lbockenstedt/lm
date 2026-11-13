"""Firewall > Impairment add form in headless Chromium against the real app:
a bandwidth limit above 4 Gbit/s (the most an OPNsense shaper pipe accepts,
compared in bits/s) is refused in the browser and never sent; a valid limit
is sent with its unit. Alias and device targets and a rotating schedule
are sent as the spoke expects, and the list shows the schedule with an
On/Off control."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")


def test_impairment_bandwidth_over_4_gbit_is_refused_in_the_form(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            sent = []

            def impair(route):
                sent.append(json.loads(route.request.post_data or "{}"))
                route.fulfill(content_type="application/json", body=json.dumps({"status": "SUCCESS"}))

            page.route("**/api/firewall/fw-1/impair*", impair)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("_opnFirewalls = [{id: 'fw-1', name: 'fw'}]; showOpnsenseAddModal('Impairment')")
            page.fill("#add-opn-target", "192.0.2.5")
            page.fill("#add-opn-delay", "50")

            # 5000 Mbit/s is over 4 Gbit/s once normalised: refused, nothing sent.
            page.fill("#add-opn-bw", "5000")
            page.select_option("#add-opn-bw-unit", "Mbit")
            page.click("#opn-add-modal button[title^=Submit]")
            page.get_by_text("OPNsense pipes are limited to 4 Gbit/s").first.wait_for()
            assert sent == []

            # 4 Gbit/s is allowed and sent with its unit.
            page.fill("#add-opn-bw", "4")
            page.select_option("#add-opn-bw-unit", "Gbit")
            page.click("#opn-add-modal button[title^=Submit]")
            page.wait_for_function("!document.getElementById('opn-add-modal')")
            assert [(b["targets"], b["bandwidth"], b["bandwidth_unit"]) for b in sent] == [(["192.0.2.5"], "4", "Gbit")]
            # One address, always on: an older spoke can still do it from "target".
            assert sent[0]["target"] == "192.0.2.5"
            assert errors == []
        finally:
            browser.close()


def _page(p, base, token):
    browser = p.chromium.launch()
    context = browser.new_context()
    context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
    return browser, context.new_page()


def test_impairment_alias_device_and_schedule_are_sent(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser, page = _page(p, base, token)
        try:
            errors, sent = [], []
            page.on("pageerror", lambda e: errors.append(str(e)))

            def impair(route):
                sent.append(json.loads(route.request.post_data or "{}"))
                route.fulfill(content_type="application/json", body=json.dumps({"status": "SUCCESS"}))

            page.route("**/api/firewall/fw-1/impair*", impair)
            page.route("**/api/firewall/fw-1/aliases*", lambda r: r.fulfill(
                content_type="application/json",
                body=json.dumps({"data": [{"name": "lab_hosts"}, {"name": "web_servers"}]})))
            page.route("**/api/netbox/devices*", lambda r: r.fulfill(
                content_type="application/json",
                body=json.dumps({"devices": [{"name": "sw1", "primary_ip": "192.0.2.7/24"},
                                             {"name": "noip", "primary_ip": None}]})))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("_opnFirewalls = [{id: 'fw-1', name: 'fw'}]; showOpnsenseAddModal('Impairment')")
            page.fill("#add-opn-delay", "50")

            # Alias, one member at a time, every 3 h for 15 min from a set start.
            page.select_option("#add-opn-ttype", "alias")
            page.wait_for_function("document.querySelectorAll('#add-opn-alias option').length === 2")
            assert page.is_visible("#add-opn-alias") and not page.is_visible("#add-opn-target")
            page.select_option("#add-opn-alias", ["lab_hosts"])
            page.check("#add-opn-alias-members")
            page.select_option("#add-opn-mode", "scheduled")
            page.fill("#add-opn-every", "3")
            page.fill("#add-opn-for", "180")
            page.click("#opn-add-modal button[title^=Submit]")
            page.get_by_text("shorter than the interval").first.wait_for()
            assert sent == []
            page.fill("#add-opn-for", "15")
            page.fill("#add-opn-start", "2030-01-02T03:00")
            page.click("#opn-add-modal button[title^=Submit]")
            page.wait_for_function("!document.getElementById('opn-add-modal')")
            start = page.evaluate("Math.floor(new Date('2030-01-02T03:00').getTime() / 1000)")
            b = sent[-1]
            assert (b["target_type"], b["targets"], b["alias_members"]) == ("alias", ["lab_hosts"], True)
            assert b["schedule"] == {"every_hours": 3, "for_minutes": 15, "start": start}
            assert b["target"] == ""  # an older spoke must refuse, not run it always on

            # Device: only devices with an IP are offered; the name goes in labels.
            page.evaluate("showOpnsenseAddModal('Impairment')")
            page.fill("#add-opn-delay", "50")
            page.select_option("#add-opn-ttype", "device")
            page.wait_for_function("document.querySelectorAll('#add-opn-device option').length === 1")
            page.select_option("#add-opn-device", ["192.0.2.7"])
            page.click("#opn-add-modal button[title^=Submit]")
            page.wait_for_function("!document.getElementById('opn-add-modal')")
            b = sent[-1]
            assert (b["target_type"], b["targets"], b["labels"], b["schedule"]) == ("device", ["192.0.2.7"], ["sw1"], None)
            assert errors == []
        finally:
            browser.close()


def test_impairment_list_shows_schedule_and_toggles(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser, page = _page(p, base, token)
        try:
            errors, puts = [], []
            page.on("pageerror", lambda e: errors.append(str(e)))
            row = {"uuid": "i1", "target": "a, b", "target_type": "ip", "targets": ["192.0.2.5", "192.0.2.6"],
                   "labels": [], "alias_members": False, "interface": "lan", "direction": "both",
                   "delay": 50, "loss": 0.0, "bandwidth": 0, "bandwidth_unit": "", "description": "",
                   "enabled": True, "complete": True, "active": False, "active_target": "",
                   "schedule": {"every_hours": 3, "for_minutes": 15, "start": 1900000000},
                   "next_on": 1900010800, "next_off": 1900011700, "next_target": "192.0.2.6",
                   "error": "", "error_at": None}

            def impair(route):
                if route.request.method == "PUT":
                    puts.append((route.request.url, json.loads(route.request.post_data)))
                    route.fulfill(content_type="application/json", body=json.dumps({"status": "SUCCESS"}))
                else:
                    route.fulfill(content_type="application/json", body=json.dumps({"data": [row]}))

            page.route("**/api/firewall/fw-1/impair**", impair)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            texts = page.evaluate("""() => { const it = %s; _impairRow(it);
                return [it.when, it.next_change, it.state]; }""" % json.dumps(row))
            assert texts[0] == "every 3 h for 15 min"
            assert texts[1].startswith("on ") and texts[1].endswith("(192.0.2.6)")
            assert texts[2] == "waiting"
            failed = page.evaluate("""() => { const it = %s; _impairRow(it); return it.state; }"""
                                   % json.dumps({**row, "error": "toggle failed"}))
            assert failed == "error: toggle failed"
            both = page.evaluate("""() => { const it = %s; _impairRow(it); return it.state; }"""
                                 % json.dumps({**row, "error": "toggle failed", "complete": False}))
            assert both == "error: toggle failed (incomplete)"
            page.evaluate("""() => { const b = document.createElement('button'); document.body.appendChild(b);
                return _impairToggle({...%s, _fwId: 'fw-1'}, b); }""" % json.dumps(row))
            assert len(puts) == 1 and puts[0][0].split("?")[0].endswith("/api/firewall/fw-1/impair/i1")
            body = puts[0][1]
            assert body["enabled"] == "0" and body["targets"] == ["192.0.2.5", "192.0.2.6"]
            assert body["schedule"]["start"] == 1900000000 and body["target"] == ""
            assert errors == []
        finally:
            browser.close()
