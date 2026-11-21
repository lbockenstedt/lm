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


def test_llm_dashboard_uses_reported_model_and_launches_qualification(hub_url_and_session):
    """Exercise the actual LLM page and its delegated settings/qualification actions."""
    from routes.llm import ROUTING_FORM_SCHEMA

    base, token = hub_url_and_session
    digest = "a" * 64
    config = {"llm_task_models": {}, "llm_ab_pr_repos": {}, "routing_form_schema": ROUTING_FORM_SCHEMA,
              "llm_qualification_candidates": {}, "llm_cloud_profiles": [], "test_workers": [],
              "public_candidates": [{"key": "trial", "label": "Trial", "model": "trial:cpu",
                                     "digest": digest, "options": {"num_ctx": 65536, "temperature": 0.6,
                                                                   "top_p": 0.95, "top_k": 20}}]}
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            page.route("**/api/llm/admin/dashboard", lambda route: route.fulfill(json={
                "workers": [{"name": "CPU Worker", "state": "ready", "capabilities": {"vcpus": 16},
                             "models": [{"name": "trial:cpu", "digest": digest}]}],
                "candidates": [{"key": "trial", "label": "Candidate", "worker": "Test VM"}],
            }))
            page.route("**/api/llm/admin/settings", lambda route: route.fulfill(
                json=config if route.request.method == "GET" else {"status": "ok"}))
            page.route("**/api/llm/admin/qualify",
                       lambda route: route.fulfill(status=202, json={"status": "accepted"}))
            page.route("**/setup/tenants", lambda route: route.fulfill(json={"tenants": [
                {"id": "test-tenant", "name": "Test Tenant"},
                {"id": "shared", "name": "Shared", "shared": True},
            ]}))
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
            page.get_by_text("CPU Worker", exact=True).wait_for()
            with page.expect_request(lambda req: req.url.endswith("/admin/qualify")) as qualification:
                page.get_by_role("button", name="Qualify", exact=True).click()
            assert qualification.value.post_data_json == {"candidate": "trial"}
            page.get_by_role("button", name="Settings", exact=True).click()
            page.get_by_label("Task", exact=True).fill("pr_summary")
            page.get_by_label("Approved model").select_option("0")
            assert page.get_by_label("Context tokens", exact=False).input_value() == "65536"
            assert page.get_by_label("Temperature", exact=False).input_value() == "0.6"
            page.get_by_label("Minimum vCPUs").fill("16")
            page.get_by_label("Temperature", exact=False).fill("0.7")
            with page.expect_request(lambda req: req.url.endswith("/admin/settings")
                                     and req.method == "POST") as save:
                page.get_by_role("button", name="Add model", exact=True).click()
            assert save.value.post_data_json == {"llm_task_models": {"pr_summary": [
                {"model": "trial:cpu", "digest": digest, "min_vcpus": 16, "min_ram_bytes": 0,
                 "temperature": 0.7, "top_p": 0.95, "top_k": 20, "num_ctx": 65536},
            ]}}
            page.get_by_text("16 vCPUs, 0 RAM bytes minimum", exact=False).wait_for()
            page.get_by_text("temperature 0.7, top-p 0.95", exact=False).wait_for()
            page.get_by_label("Repository", exact=True).fill("not-a-repository")
            repository = page.get_by_label("Repository", exact=True)
            assert repository.evaluate("(input) => input.validity.patternMismatch")
            repository.fill("test-org/test-repo")
            tenant = page.get_by_label("Tenant", exact=True)
            assert tenant.get_by_role("option", name="Shared").count() == 0
            tenant.select_option(label="Test Tenant")
            page.get_by_label("AppBuilder certificate SAN").fill("ab.test")
            with page.expect_request(lambda req: req.url.endswith("/admin/settings")
                                     and req.method == "POST") as binding:
                page.get_by_role("button", name="Save repository", exact=True).click()
            assert binding.value.post_data_json == {"llm_ab_pr_repos": {
                "test-org/test-repo": {"tenant": "test-tenant", "certificate": "ab.test",
                                       "allow_public_cloud": False},
            }}
        finally:
            browser.close()
