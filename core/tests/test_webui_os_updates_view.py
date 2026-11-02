"""OS Updates page in headless Chromium against the real app, with
/api/os-updates mocked: the node list survives its 5-second poll (open package
list stays open, picked package stays picked) and the CVE lookup renders
hostile data as text. Guards the React-lite migration of this pilot view
(docs/webui-react-lite-plan.md)."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

EVIL = "<img src=x onerror=window.__pwned=1>"

NODES = {
    "totals": {"with_updates": 1, "packages": 2},
    "checked_at": 1700000000,
    "nodes": [{
        "kind": "agent", "id": "a1", "label": "web-01", "eligible": True, "count": 2,
        "features": ["packages", "reboot"], "checked": True,
        "packages": [
            {"package": "php8.2", "current": "1", "candidate": "2", "security": True},
            {"package": "curl", "current": "1", "candidate": "2"},
        ],
    }],
}

CVES = {
    "feeds": {"bookworm": {"fetched_at": 1700000000}}, "query": "php", "kind": "package",
    "affected_nodes": 1, "checked_nodes": 1,
    "results": [{"cve": "CVE-2026-1", "description": EVIL, "affected": [
        {"node": "agent:a1", "label": "web-01", "release": "bookworm", "package": "php8.2",
         "version": "1", "binaries": ["php8.2"], "update_pending": True}], "patched": []}],
}


def test_os_updates_list_survives_polling(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            polls = []

            data = dict(NODES)

            def nodes(route):
                polls.append(1)
                route.fulfill(content_type="application/json", body=json.dumps(data))

            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/cves?*", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(CVES)))
            page.goto(base + "/")
            # Login init ends with installClickFeedback(); setView('dashboard');
            # open OS Updates only after that.
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            details = page.locator("#osu-body details")
            details.locator("summary").click()

            # Each pick re-renders the list; the open package list stays open.
            page.get_by_label("curl").check()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
            assert details.evaluate("d => d.open")

            page.fill("#osu-cve-q", "php")
            page.click("text=Look up")
            page.wait_for_selector("#osu-cve-body >> text=CVE-2026-1")
            assert EVIL in page.locator("#osu-cve-body").inner_text()
            page.click("text=Select fixes (1)")
            assert page.get_by_label("php8.2").is_checked()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
            assert not page.evaluate("window.__pwned")

            # A running roll polls every 5 s; the open list survives each poll.
            data["run"] = {"status": "running", "done": 0, "total": 1, "current": "web-01", "items": []}
            page.evaluate("osuLoad()")
            first = len(polls)
            page.wait_for_timeout(5600)
            assert len(polls) > first, "page did not poll"
            assert "deploying 0/1" in page.locator("#osu-run").inner_text()
            assert details.evaluate("d => d.open")
            assert not errors, errors
        finally:
            browser.close()
