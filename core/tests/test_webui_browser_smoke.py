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
