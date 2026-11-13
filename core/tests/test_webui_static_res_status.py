"""The static-reservation status line (staticResStatusView in
WebUI/js/sync-sources.js) in headless Chromium: every state the card can be
in says what it is, including the ones that used to show nothing."""
import json
import os
from urllib.parse import urlparse

import pytest

from webui_src import WEBUI

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

ON = {"enabled": True}
ROWS = {"reserved": [{"ip": "10.20.0.50"}], "conflicts": [], "errors": []}

# (config fetch, status fetch) → (tone, text fragment). undefined = loading.
CASES = [
    ("undefined", "undefined", "muted", "Loading…"),
    ("'failed'", "undefined", "error", "Could not load the settings"),
    ("{}", "undefined", "muted", "Off."),
    (ON, "undefined", "muted", "Loading the last pass"),
    (ON, "'failed'", "error", "Could not load the last pass"),
    (ON, {"status": "x"}, "error", "Unexpected status reply"),
    (ON, {"status": {"static_reservations": "x"}}, "error", "Unexpected status reply"),
    (ON, {"status": {}}, "warn", "reports no pass status"),
    (ON, {"status": {"static_reservations": {"visibility_reason": "no_permission"}}},
     "muted", "need the DHCP right"),
    (ON, {"status": {"static_reservations": {"visibility_reason": "tenant"}}},
     "muted", "No pass has run yet"),
    (ON, {"status": {"static_reservations": {"status": "ok", "visibility_reason": "no_tenant"}}},
     "ok", "Switch into a tenant"),
    (ON, {"status": {"static_reservations": {"status": "error", "visibility_reason": "no_tenant"}}},
     "error", "Last pass: error"),
    (ON, {"status": {"static_reservations": {"status": "disabled", "visibility_reason": "no_tenant"}}},
     "muted", "Last pass: disabled"),
    (ON, {"status": {"static_reservations": {"status": "disabled", "reason": "dns/dhcp sync is off"}}},
     "muted", "Off (dns/dhcp sync is off)"),
    (ON, {"status": {"static_reservations": {"status": "unsupported"}}}, "warn", "too old"),
    (ON, {"status": {"static_reservations": dict(ROWS, status="conflicts")}}, "warn", "conflicts"),
    (ON, {"status": {"static_reservations": dict(
        ROWS, status="error", errors=[{"error": "no strict kea read"}])}}, "error", "no strict kea read"),
    (ON, {"status": {"static_reservations": dict(ROWS, status="ok")}}, "ok", "reserved 1"),
    (ON, {"status": {"static_reservations": {"status": "skipped"}}}, "muted", "nothing to check"),
    (ON, {"status": {"static_reservations": {"status": "degraded"}}}, "error", "Unexpected status reply"),
]


def _js(value):
    """A case argument as JavaScript: strings are already JS, dicts become JSON."""
    return value if isinstance(value, str) else json.dumps(value)


def test_every_status_card_state_has_its_own_text_and_tone():
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        def serve(route):
            path = urlparse(route.request.url).path.lstrip("/")
            if path:
                route.fulfill(path=str(WEBUI / path))
            else:
                route.fulfill(content_type="text/html", body="<meta charset=\"utf-8\"><div></div>")

        page.route("http://lm.test/**", serve)
        page.goto("http://lm.test/")
        page.add_script_tag(url="/js/sync-sources.js")
        got = [page.evaluate(f"staticResStatusView({_js(c)}, {_js(s)})")
               for c, s, _tone, _text in CASES]
        browser.close()
    for (c, s, tone, text), view in zip(CASES, got):
        assert view["tone"] == tone and text in view["text"], (c, s, view)
