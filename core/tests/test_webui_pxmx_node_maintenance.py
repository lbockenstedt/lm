"""Hypervisors → Nodes "Maintenance" button in headless Chromium against the
real app: a node in HA maintenance shows the wrench icon, the button's tooltip
names the action (Enter/Exit), clicking it asks for confirmation and POSTs
{node, cluster, enable} to /api/pxmx/server/maintenance, and an error from the
hub shows as a toast."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

NODES = [
    {"node": "pve1", "cluster": "lab", "status": "online", "agent_id": "ag-1", "maintenance": True},
    {"node": "pve2", "cluster": "lab", "status": "online", "agent_id": "ag-1", "maintenance": False},
    # No button: state unknown (agent too old) or node offline.
    {"node": "pve3", "cluster": "lab", "status": "online", "agent_id": "ag-1"},
    {"node": "pve4", "cluster": "lab", "status": "offline", "agent_id": "ag-1", "maintenance": False},
]


def test_maintenance_button_and_wrench(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            posted = []

            def maint(route):
                body = json.loads(route.request.post_data or "{}")
                posted.append(body)
                if body.get("node") == "pve1":
                    route.fulfill(status=502, content_type="application/json",
                                  body=json.dumps({"detail": "ha-manager failed: no quorum"}))
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(
                        {"status": "ok", "node": body["node"], "maintenance": True,
                         "message": "pve2: entering maintenance mode"}))

            page.route("**/api/pxmx/server/maintenance*", maint)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            # Render the Nodes table into a host element from a known node list.
            page.evaluate("""nodes => {
                const w = document.createElement('div'); w.id = 'pxmx-nodes-wrap';
                document.body.prepend(w);
                window._pxmxNodes = nodes;
                renderPxmxNodes();
            }""", NODES)

            rows = page.locator("#pxmx-nodes-wrap tbody tr")
            assert rows.nth(0).locator("[data-pxmx-maint-icon] svg").count() == 1
            assert rows.nth(1).locator("[data-pxmx-maint-icon]").count() == 0
            btn1 = rows.nth(0).get_by_role("button", name="Maintenance")
            btn2 = rows.nth(1).get_by_role("button", name="Maintenance")
            assert btn1.get_attribute("title").startswith("Exit maintenance")
            assert btn2.get_attribute("title").startswith("Enter maintenance")
            for i in (2, 3):
                assert rows.nth(i).get_by_role("button", name="Maintenance").count() == 0

            # Enter maintenance on pve2: confirm, POST, then the wrench appears.
            page.evaluate("document.getElementById('lm-toast-region').replaceChildren()")
            btn2.click()
            page.get_by_role("button", name="Confirm").click()
            page.wait_for_function(
                "document.querySelectorAll('#pxmx-nodes-wrap tbody tr')[1]"
                ".querySelector('[data-pxmx-maint-icon]') !== null")
            assert posted[-1] == {"node": "pve2", "cluster": "lab", "enable": True}

            # Exit on pve1 fails on the hub: the error shows as a toast.
            # Clear earlier toasts first; they sit over the table in a small viewport.
            page.evaluate("document.getElementById('lm-toast-region').replaceChildren()")
            rows.nth(0).get_by_role("button", name="Maintenance").click()
            page.get_by_role("button", name="Confirm").click()
            page.get_by_text("ha-manager failed: no quorum").wait_for()
            assert posted[-1] == {"node": "pve1", "cluster": "lab", "enable": False}
            assert errors == []
        finally:
            browser.close()
