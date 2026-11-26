"""Browser smoke test: the real WebUI, served by the real create_app, walked in
headless Chromium (Playwright) as an admin. Fails on any uncaught JS error.

Static checks can't see rendering. This catches a refactor that leaves a view
throwing -- a missing function, a load-order mistake, a bad template -- before
it ships (docs/webui-react-lite-plan.md, Phase 0b).

The hub is a thin fake, so many API calls return 500; that is expected and
not a failure. The UI must survive a failing API without an uncaught error.

Needs `pip install playwright && python -m playwright install chromium`.
Skipped locally when that is missing; in CI (CI=true) it must run.
"""
import os
import socket
import tempfile
import threading
import time

import pytest

from webui_walk import walk_ui

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

import api as api_mod  # noqa: E402
from test_auth_session_security import _FakeHub  # noqa: E402


SPOKE_UUID = "3f2b8c1e-9d4a-4e6b-8a71-2c5d9e0f1a22"

# What a browser test waits for before it acts on the app: main.js has wired
# its click handlers, and the tenant switch _initApp starts at sign-in
# (setTenant) has unlocked and redrawn the page. That redraw drops the page
# reads still in flight, so a dialog a test opened before it kept empty lists.
APP_READY = ("window._lmClickFeedbackInstalled === true && _setTenantSeq > 0"
             " && !document.getElementById('page-content').hasAttribute('inert')")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def hub_url_and_session():
    """Serve the real app on a free local port; yield (base_url, admin token)."""
    import uvicorn

    hub = _FakeHub(tempfile.mkdtemp(), {"users": {}})
    hub.state.tenant_state = {"tenants": {}}
    app = api_mod.create_app(hub)
    token = api_mod._record_session(hub, {
        "user_id": "admin", "auth_type": "local",
        "permissions": {"role": "admin", "admin": True},
        "tenants": [], "tenant_id": None, "protected": False})
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="critical"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "hub app did not start"
    yield f"http://127.0.0.1:{port}", token
    server.should_exit = True
    thread.join(timeout=10)
    api_mod._sessions.pop(token, None)


def test_every_view_renders_without_js_errors(hub_url_and_session):
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            if os.environ.get("CI"):
                raise
            pytest.skip(f"Chromium not installed (python -m playwright install chromium): {e}")
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            failures = walk_ui(context.new_page(), base + "/")
        finally:
            browser.close()
    assert not failures, "WebUI errors:\n" + "\n".join(failures)


def test_uuid_check_sees_visible_text_only():
    """visible_uuids flags ids a user can read, not ones kept in attributes or hidden nodes."""
    from webui_walk import visible_uuids
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # noqa: BLE001
            if os.environ.get("CI"):
                raise
            pytest.skip(f"Chromium not installed: {e}")
        try:
            page = browser.new_page()
            page.set_content(f'<div data-id="{SPOKE_UUID}">Acme Labs</div>'
                             f'<div style="display:none">{SPOKE_UUID}</div>')
            assert visible_uuids(page) == []
            page.set_content(f"<td>{SPOKE_UUID}</td>")
            assert visible_uuids(page) == [SPOKE_UUID]
        finally:
            browser.close()


def test_llm_dashboard_shows_worker_status_badges_and_tooltips(hub_url_and_session):
    """Exercise the actual LLM page: worker status mapping, tooltips, and no Settings/Qualify controls."""
    base, token = hub_url_and_session
    digest = "a" * 64
    workers = [
        {"name": "W Ready", "state": "ready", "capabilities": {"vcpus": 16}, "models": [{"name": "trial:cpu", "digest": digest}],
         "catalog": [{"key": "a", "model": "trial:cpu", "state": "serving"},
                     {"key": "b", "model": "deep:70b", "state": "failed", "code": "fixture_mismatch"}]},
        {"name": "W Busy", "state": "busy"},
        {"name": "W Prov", "state": "provisioning", "detail": "gemma"},
        {"name": "W Off", "state": "no_fresh_report"},
        {"name": "W Attn", "state": "unavailable", "issues": [{"code": "runtime_unit_missing"}]},
        {"name": "W Odd", "state": "weird"},
    ]
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            page.route("**/api/llm/admin/dashboard", lambda route: route.fulfill(json={
                "workers": workers,
                "jobs": [{"kind": "inference", "state": "queued", "model": "trial:cpu", "tier": "shared"}],
            }))
            page.goto(base + "/")
            page.wait_for_function("window.lmCoreLoaded && typeof currentUser !== 'undefined' && !!currentUser")
            # The nav entry is a button: it must carry its icon and span the nav like its div siblings.
            # The fake hub cannot serve the status poll, so build the dynamic nav directly.
            page.evaluate("_rebuildMainNav([], [])")
            nav = page.locator("#nav-llm")
            nav.wait_for()
            assert nav.locator("svg").count() == 1
            assert nav.bounding_box()["width"] == page.locator("#nav-security").bounding_box()["width"]
            nav.click()
            page.get_by_text("W Ready", exact=True).wait_for()
            # Each raw API state maps to its badge label; unknown states show their raw text.
            # Each worker is a table row; its tooltip (title) carries the details.
            cards = {name: page.locator(f"xpath=//td[text()='{name}']/ancestor::tr[1]") for name in
                     ("W Ready", "W Busy", "W Prov", "W Off", "W Attn", "W Odd")}
            badges = {name: row.locator("td").nth(2).locator("span") for name, row in cards.items()}
            assert badges["W Ready"].inner_text() == "Ready"
            assert badges["W Busy"].inner_text() == "Busy"
            assert badges["W Prov"].inner_text() == "Provisioning: gemma"
            assert badges["W Off"].inner_text() == "Offline"
            assert badges["W Attn"].inner_text() == "Needs attention"
            assert badges["W Odd"].inner_text() == "weird"
            # Details live in the card tooltip.
            ready_tip = cards["W Ready"].get_attribute("title")
            assert "16 vCPUs" in ready_tip and "trial:cpu" in ready_tip
            assert "runtime_unit_missing" in cards["W Attn"].get_attribute("title")
            page.get_by_text("Queued", exact=True).wait_for()
            # Model chips come from the catalog states, not job history.
            assert cards["W Ready"].get_by_text("deep:70b · failed").get_attribute("title") == "Failed: fixture_mismatch"
            # The Settings panel and Qualify controls are gone.
            assert page.get_by_role("button", name="Settings", exact=True).count() == 0
            assert page.get_by_role("button", name="Qualify", exact=True).count() == 0
        finally:
            browser.close()


def test_llm_dashboard_saves_appbuilder_work_rule(hub_url_and_session):
    """The AppBuilder work card loads the saved rule, offers the shared tenant, has no certificate box and saves only llm_ab_work."""
    base, token = hub_url_and_session
    saved = []

    def settings(route):
        """Serve the stored rule on GET and record what a POST saves."""
        if route.request.method == "POST":
            saved.append(route.request.post_data_json)
            return route.fulfill(json={"status": "ok"})
        route.fulfill(json={"llm_ab_work": {"tenant": "acme", "tasks": ["scout", "custom"]}})

    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            page.route("**/api/llm/admin/dashboard", lambda route: route.fulfill(json={"workers": [], "jobs": []}))
            page.route("**/api/llm/admin/settings", settings)
            page.route("**/setup/tenants", lambda route: route.fulfill(json={"tenants": [
                {"id": "acme", "name": "Acme"}, {"id": "shared", "name": "Shared", "shared": True}]}))
            page.goto(base + "/")
            page.wait_for_function("window.lmCoreLoaded && typeof currentUser !== 'undefined' && !!currentUser")
            page.evaluate("_rebuildMainNav([], [])")
            page.locator("#nav-llm").click()
            page.get_by_text("AppBuilder work", exact=True).wait_for()
            tenant = page.locator("select[data-action=abTenant]")
            page.wait_for_function("document.querySelector('select[data-action=abTenant]').value === 'acme'")
            assert tenant.locator("option").all_inner_texts() == ["Select a tenant", "Acme", "Shared"]
            assert page.locator("input[data-input=abCertificate]").count() == 0
            # Tick one more task; a saved task outside the known list stays listed and ticked.
            page.locator("input[data-action=abTask][value=review]").check()
            assert page.locator("input[data-action=abTask][value=custom]").is_checked()
            page.get_by_role("button", name="Save", exact=True).click()
            for _ in range(50):
                if saved:
                    break
                page.wait_for_timeout(100)
            assert saved == [{"llm_ab_work": {"tenant": "acme",
                                              "tasks": ["scout", "custom", "review"]}}]
        finally:
            browser.close()
