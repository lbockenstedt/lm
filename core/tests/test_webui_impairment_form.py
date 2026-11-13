"""Firewall > Impairment add form in headless Chromium against the real app:
a bandwidth limit above 4 Gbit/s (the most an OPNsense shaper pipe accepts,
compared in bits/s) is refused in the browser and never sent; a valid limit
is sent with its unit."""
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
            assert [(b["target"], b["bandwidth"], b["bandwidth_unit"]) for b in sent] == [("192.0.2.5", "4", "Gbit")]
            assert errors == []
        finally:
            browser.close()
