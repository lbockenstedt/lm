"""Hypervisors → Nodes "Maintenance" switch and "Reboot" button in headless
Chromium against the real app. The switch (role=switch) shows the reported
state ON/OFF; clicking asks a plain confirm (no command text) and POSTs
{node, cluster, enable}; until telemetry confirms, the switch keeps the old
state, disabled, reading "Entering…". Reboot shows only while the node is
reported in maintenance; after a confirmed reboot request the row reads
"Rebooting…" until the node is back online with a reset uptime. Errors from the hub
show as a toast."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

NODES = [
    {"node": "pve1", "cluster": "lab", "status": "online", "agent_id": "ag-1", "maintenance": True,
     "uptime": 900000},
    {"node": "pve2", "cluster": "lab", "status": "online", "agent_id": "ag-1", "maintenance": False},
    # No switch: state unknown (agent too old) or node offline.
    {"node": "pve3", "cluster": "lab", "status": "online", "agent_id": "ag-1"},
    {"node": "pve4", "cluster": "lab", "status": "offline", "agent_id": "ag-1", "maintenance": False},
]

# Apply a telemetry update to the cached node list, settle pending ops, redraw.
TELEMETRY = """([name, patch]) => {
    const n = window._pxmxNodes.find(x => x.node === name);
    Object.assign(n, patch);
    pxmxReconcileNodeOps(window._pxmxNodes);
    renderPxmxNodes();
}"""


def test_maintenance_switch_and_reboot(hub_url_and_session):  # noqa: F811
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
                posted.append(("maintenance", body))
                if body.get("enable") is False:
                    route.fulfill(status=502, content_type="application/json",
                                  body=json.dumps({"detail": "maintenance failed: no quorum"}))
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(
                        {"status": "ok", "node": body["node"], "maintenance": True,
                         "message": "entering maintenance mode"}))

            def reboot(route):
                posted.append(("reboot", json.loads(route.request.post_data or "{}")))
                route.fulfill(content_type="application/json", body=json.dumps(
                    {"status": "ok", "message": "pve1: reboot requested"}))

            page.route("**/api/pxmx/server/maintenance*", maint)
            page.route("**/api/pxmx/server/reboot*", reboot)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            # Render the Nodes table into a host element from a known node list.
            page.evaluate("""nodes => {
                const w = document.createElement('div'); w.id = 'pxmx-nodes-wrap';
                document.body.prepend(w);
                window._pxmxNodes = nodes;
                renderPxmxNodes();
            }""", NODES)
            toasts = page.locator("#lm-toast-region")

            def clear_toasts():
                # Toasts sit over the table in a small viewport.
                page.evaluate("document.getElementById('lm-toast-region').replaceChildren()")

            def row(i):
                return page.locator("#pxmx-nodes-wrap tbody tr").nth(i)

            # The switch reflects the reported state; Reboot only when in maintenance.
            sw1 = row(0).get_by_role("switch", name="Maintenance")
            sw2 = row(1).get_by_role("switch", name="Maintenance")
            assert sw1.get_attribute("aria-checked") == "true"
            assert sw2.get_attribute("aria-checked") == "false"
            assert row(0).locator("[data-pxmx-maint-state]").inner_text() == "ON"
            assert row(1).locator("[data-pxmx-maint-state]").inner_text() == "OFF"
            assert "ha-manager" not in (sw1.get_attribute("title") + sw2.get_attribute("title"))
            assert row(0).locator("[data-pxmx-maint-icon] svg").count() == 1
            assert row(1).locator("[data-pxmx-maint-icon]").count() == 0
            assert row(0).get_by_role("button", name="Reboot").count() == 1
            for i in (1, 2, 3):
                assert row(i).get_by_role("button", name="Reboot").count() == 0
            for i in (2, 3):
                assert row(i).get_by_role("switch").count() == 0

            # Enable on pve2: plain confirm, POST, then "Entering…" without flipping.
            clear_toasts()
            sw2.click()
            assert "Enable maintenance mode on pve2?" in toasts.inner_text()
            assert "ha-manager" not in toasts.inner_text()
            page.get_by_role("button", name="Confirm").click()
            row(1).locator("[data-pxmx-maint-state]").get_by_text("Entering…").wait_for()
            assert posted[-1] == ("maintenance", {"node": "pve2", "cluster": "lab", "enable": True})
            assert sw2.get_attribute("aria-checked") == "false" and sw2.is_disabled()
            assert row(1).get_by_role("button", name="Reboot").count() == 0
            # Telemetry confirms it: ON, enabled, wrench and Reboot appear.
            page.evaluate(TELEMETRY, ["pve2", {"maintenance": True}])
            assert sw2.get_attribute("aria-checked") == "true" and not sw2.is_disabled()
            assert row(1).locator("[data-pxmx-maint-icon]").count() == 1
            assert row(1).get_by_role("button", name="Reboot").count() == 1

            # Reboot pve1: plain confirm, POST, "Rebooting…" until it goes down and back up.
            clear_toasts()
            row(0).get_by_role("button", name="Reboot").click()
            assert "Reboot pve1? It is in maintenance mode." in toasts.inner_text()
            page.get_by_role("button", name="Confirm").click()
            row(0).get_by_text("Rebooting…").wait_for()
            assert posted[-1] == ("reboot", {"node": "pve1", "cluster": "lab"})
            assert row(0).get_by_role("switch").count() == 0
            # A failed, stale or disconnected node read never counts as "went down".
            assert page.evaluate("""() => [null, {nodes: []}, {nodes: [], stale: true},
                {nodes: [], spoke_connected: false}].map(pxmxNodeListIsLive)""") == [
                False, True, False, False]
            # While down, the hub may rebuild the row from the offline roster without
            # its cluster; it still reads "Rebooting…".
            page.evaluate("""() => {
                const i = window._pxmxNodes.findIndex(x => x.node === 'pve1');
                window._pxmxNodes.splice(i, 1, {node: 'pve1', cluster: '', status: 'offline',
                                                offline: true, agent_id: 'ag-1'});
                pxmxReconcileNodeOps(window._pxmxNodes);
                renderPxmxNodes();
            }""")
            assert page.locator("#pxmx-nodes-wrap").get_by_text("Rebooting…").count() == 1
            page.evaluate("""() => {
                const i = window._pxmxNodes.findIndex(x => x.node === 'pve1');
                window._pxmxNodes.splice(i, 1, {node: 'pve1', cluster: 'lab', status: 'online',
                                                agent_id: 'ag-1', maintenance: true, uptime: 900030});
            }""")
            # Back online but with the old uptime (a read that missed the node, or
            # the reboot not started yet): still rebooting.
            page.evaluate(TELEMETRY, ["pve1", {}])
            assert row(0).get_by_text("Rebooting…").count() == 1
            # Uptime reset: it booted again.
            page.evaluate(TELEMETRY, ["pve1", {"uptime": 95}])
            assert row(0).get_by_text("Rebooting…").count() == 0
            assert row(0).get_by_role("switch").get_attribute("aria-checked") == "true"
            assert row(0).get_by_role("button", name="Reboot").count() == 1

            # Disable on pve1 fails on the hub: the error shows as a toast.
            clear_toasts()
            row(0).get_by_role("switch").click()
            assert "Disable maintenance mode on pve1?" in toasts.inner_text()
            page.get_by_role("button", name="Confirm").click()
            page.get_by_text("maintenance failed: no quorum").wait_for()
            assert posted[-1] == ("maintenance", {"node": "pve1", "cluster": "lab", "enable": False})
            assert row(0).get_by_role("switch").get_attribute("aria-checked") == "true"

            # A pending change that never confirms times out, even with no node reads.
            clear_toasts()
            row(0).get_by_role("button", name="Reboot").click()
            page.get_by_role("button", name="Confirm").click()
            row(0).get_by_text("Rebooting…").wait_for()
            page.evaluate("""() => {
                for (const e of _pxmxNodeOps.values()) e.ts -= 3600000;
                pxmxExpireNodeOps();
                renderPxmxNodes();
            }""")
            assert row(0).get_by_text("Rebooting…").count() == 0
            assert "no confirmation from the node yet" in toasts.inner_text()
            assert errors == []
        finally:
            browser.close()
