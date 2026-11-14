"""Syslog page (js/views/syslog.js) in headless Chromium against the real app,
with /api/syslog/* mocked: Search shows the source badge and renders hostile
messages as text, a Sources row opens Live Tail filtered to that host, an
invalid drop rule disables Save, the external archive form sends tls_name,
and Diagnostics renders, all without a page error or a visible UUID."""
import json
import os
import re
import time

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

EVIL = "<img src=x onerror=window.__pwned=1>"
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
NOW = time.time()

OVERVIEW = {
    "collectors": [{"name": "syslog-a", "online": True, "active": True, "address": "10.0.0.50",
                    "msgs_5m": 12, "size_mb": 10, "max_mb": 2048}],
    "sources": [{"host": "sw-core-1", "src_ip": "10.0.0.9", "collector": "syslog-a",
                 "last_ts": NOW - 30, "count": 4, "by_severity": {"4": 3, "6": 1}},
                {"host": "sw-old", "src_ip": "10.0.0.10", "collector": "syslog-a",
                 "last_ts": NOW - 7200, "count": 1, "by_severity": {"6": 1}}],
    "archive": None,
}
QUERY = {"messages": [{"ts": NOW - 5, "collector": "syslog-a", "host": "sw-core-1",
                       "src_ip": "10.0.0.9", "program": "lldp", "severity": 4, "msg": EVIL}],
         "sources": {"local": 1}, "errors": []}
SETTINGS = {"retention_hours": 24, "max_mb": 2048, "drop_rules": []}
DIAG = {"collector": "syslog-a", "rsyslog": {"active": True}, "listeners": ["udp/514"]}


def test_syslog_view_tabs(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors, queries, archive_puts = [], [], []
            page.on("pageerror", lambda e: errors.append(str(e)))

            def json_route(body):
                return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

            def query(route):
                queries.append(json.loads(route.request.post_data))
                route.fulfill(content_type="application/json", body=json.dumps(QUERY))

            def archive(route):
                archive_puts.append(json.loads(route.request.post_data or "{}"))
                route.fulfill(content_type="application/json", body='{"ok": true}')

            page.route("**/api/syslog/overview*", json_route(OVERVIEW))
            page.route("**/api/syslog/query*", query)
            page.route("**/api/syslog/settings*", json_route(SETTINGS))
            page.route("**/api/syslog/archive*", archive)
            page.route("**/api/syslog/diagnostics*", json_route(DIAG))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")

            # Search: the Local badge and the hostile message as plain text.
            page.evaluate("setView('syslog')")
            page.locator("#syslog-search-collector option", has_text="syslog-a").wait_for(state="attached")
            page.locator("#syslog-content button[type='submit']", has_text="Search").click()
            results = page.locator("#syslog-results")
            results.locator("text=Local · 1").wait_for()
            assert EVIL in results.inner_text()

            # Sources: the silent host is flagged; clicking a row tails that host.
            page.evaluate("setSubView('Sources')")
            page.locator("#syslog-sources tr[data-host='sw-old']", has_text="silent").wait_for()
            queries.clear()
            page.locator("#syslog-sources tr[data-host='sw-core-1']").click()
            page.wait_for_function("currentSubView === 'Live Tail'")
            page.wait_for_function("document.querySelector('#syslog-tail-body table') !== null")
            assert any(q.get("host") == "sw-core-1" for q in queries)

            # Drop Rules: an invalid regex disables Save.
            page.evaluate("setSubView('Drop Rules')")
            page.locator("#syslog-rules button[data-action='addRule']").click()
            page.select_option("#syslog-rule-0-op", "regex")
            page.fill("#syslog-rule-0-value", "([unclosed")
            assert page.locator("#syslog-rules button[data-action='save']").is_disabled()

            # Settings → Archive: the external form sends tls_name.
            page.evaluate("setSubView('Settings')")
            page.locator("input[name='archmode'][value='external']").check()
            page.fill("#syslog-arch-host", "10.0.0.60")
            page.fill("#syslog-arch-api", "https://10.0.0.60:9000/api")
            page.fill("#syslog-arch-tlsname", "archive.lab.example")
            page.locator("#syslog-arch-save").click()
            for _ in range(20):
                if archive_puts:
                    break
                page.wait_for_timeout(100)
            assert archive_puts and archive_puts[0]["tls_name"] == "archive.lab.example"

            # Diagnostics renders for the collector by name.
            page.evaluate("setSubView('Diagnostics')")
            page.locator("#syslog-diag-collector option", has_text="syslog-a").wait_for(state="attached")

            assert not UUID_RE.search(page.inner_text("#syslog-content"))
            assert page.evaluate("window.__pwned") is None
            assert errors == []
        finally:
            browser.close()
