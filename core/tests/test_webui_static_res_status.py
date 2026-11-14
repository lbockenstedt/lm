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
ROWS = {"reserved": [{"ip": "192.0.2.50"}], "conflicts": [], "errors": []}

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
    (ON, {"status": {"static_reservations": {"status": "ok", "visibility_reason": "tenant",
                                             "skipped_reasons": {"outside any dhcp scope": 12,
                                                                 "no netbox ip": 30}}}},
     "ok", "Skipped: no netbox ip × 30, outside any dhcp scope × 12"),
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


# ── the rows below the status line and the "Use new MAC" button ─────────────

OLD, NEW = "02:00:00:00:00:0a", "02:00:00:00:00:0b"
CONFLICT = {"ip": "192.0.2.50", "mac": NEW, "old_mac": OLD, "reason": "reserved for another mac",
            "replace": "waiting before replacing"}


def _page(p, routes=None, tenant_qs=""):
    """A blank page with sync-sources.js loaded; ``routes`` maps a path to a
    JSON reply (status, body), recording each request it answers as (path,
    method, body, query). ``tenant_qs`` is what the tenant picker's
    _tenantQS() returns."""
    seen = []

    def serve(route):
        path = urlparse(route.request.url).path
        if routes and path in routes:
            seen.append((path, route.request.method, route.request.post_data,
                         urlparse(route.request.url).query))
            status, body = routes[path]
            route.fulfill(status=status, content_type="application/json", body=json.dumps(body))
        elif path.lstrip("/"):
            route.fulfill(path=str(WEBUI / path.lstrip("/")))
        else:
            route.fulfill(content_type="text/html", body=(
                "<meta charset=\"utf-8\"><input type=\"checkbox\" id=\"static-res-enabled\">"
                "<input id=\"static-res-interval\"><input type=\"checkbox\" id=\"static-res-auto-replace\">"
                "<div id=\"static-res-status\"></div><div id=\"static-res-action-msg\"></div>"
                "<div id=\"static-res-rows\"></div>"))

    browser = p.chromium.launch()
    page = browser.new_page()
    page.route("http://lm.test/**", serve)
    page.goto("http://lm.test/")
    page.add_script_tag(content=(
        "window.setupFetch = (u, o) => fetch(u, o);"
        "window._spokeFetch = async (u) => { const r = await fetch(u);"
        " return { ok: r.ok, data: await r.json() }; };"
        "window.showToast = () => {};"
        + (f"window._tenantQS = () => {json.dumps(tenant_qs)};" if tenant_qs else "")))
    page.add_script_tag(url="/js/sync-sources.js")
    return browser, page, seen


def _sync(**p):
    """A sync-status body whose static_reservations is ``p`` for a tenant view."""
    return {"status": {"static_reservations": dict(p, visibility_reason="tenant")}}


def test_rows_offer_the_button_only_for_a_different_mac_conflict():
    cases = [
        (_sync(conflicts=[CONFLICT, {"ip": "192.0.2.51", "mac": NEW, "reason": "leased to another mac"},
                          {"ip": "192.0.2.54", "mac": NEW, "old_mac": OLD, "reason": "netbox mac differs"}],
               pending_replace=[{"ip": "192.0.2.52", "old_mac": OLD, "new_mac": NEW, "first_seen_age": 900},
                                {"ip": "192.0.2.55", "old_mac": OLD, "new_mac": NEW, "first_seen_age": 900,
                                 "old_mac_unconfirmed": True}],
               replaced=[{"ip": "192.0.2.53", "old_mac": OLD, "new_mac": NEW, "interface": {"id": 1, "after": {"mac_address": NEW}}}]),
         [("conflict", True, ""), ("conflict", False, None), ("conflict", False, None),
          ("pending", False, None), ("pending", False, None), ("replaced", False, None)]),
        # An older netbox spoke: the button is there but disabled, with the reason.
        (_sync(replace_supported=False, conflicts=[{"ip": "192.0.2.50", "mac": NEW,
                                                     "reason": "reserved for another mac"}]),
         [("conflict", True, "The netbox spoke is too old for this; update it.")]),
        # No tenant view, or no reply: no rows at all.
        ({"status": {"static_reservations": {"status": "conflicts", "visibility_reason": "no_tenant"}}}, []),
        (None, []),
    ]
    with sync_api.sync_playwright() as p:
        browser, page, _ = _page(p)
        got = [page.evaluate(f"staticResRowsView({json.dumps(s)})") for s, _ in cases]
        browser.close()
    for (s, want), rows in zip(cases, got):
        assert [(r["kind"], bool(r["action"]), (r["action"] or {}).get("disabled"))
                for r in rows] == want, s
    assert "first seen 15 min ago" in got[0][3]["text"]
    assert "no sweep or agent can confirm the old MAC is gone" in got[0][4]["text"]
    assert "with its interface" in got[0][5]["text"]


def test_use_new_mac_confirms_posts_shows_the_result_and_refreshes():
    routes = {
        "/setup/config": (200, {"global_config": {"static_ip_reservations": {"enabled": True}}}),
        "/api/dns-dhcp/sync-status": (200, _sync(status="conflicts", conflicts=[CONFLICT])),
        "/setup/static-reservations/use-new-mac": (409, {"detail": "cannot replace: old mac holds a lease"}),
    }
    with sync_api.sync_playwright() as p:
        browser, page, seen = _page(p, routes, tenant_qs="?tenant=t-a")
        page.evaluate("loadStaticResConfig()")
        page.wait_for_selector("#static-res-rows button")
        assert page.is_checked("#static-res-auto-replace")
        # Cancelled: nothing is sent.
        page.once("dialog", lambda d: d.dismiss())
        page.click("#static-res-rows button")
        assert not [s for s in seen if s[1] == "POST"]
        # Confirmed: the hub's refusal is shown and the card reloads.
        page.once("dialog", lambda d: d.accept())
        before = len([s for s in seen if s[0] == "/api/dns-dhcp/sync-status"])
        page.click("#static-res-rows button")
        page.wait_for_function(
            "document.getElementById('static-res-action-msg').textContent.includes('old mac holds')")
        posts = [s for s in seen if s[1] == "POST"]
        page.wait_for_timeout(200)
        reloads = len([s for s in seen if s[0] == "/api/dns-dhcp/sync-status"]) - before
        msg_class = page.get_attribute("#static-res-action-msg", "class")
        browser.close()
    assert json.loads(posts[0][2]) == {"ip": "192.0.2.50", "old_mac": OLD, "new_mac": NEW}
    assert "text-red-600" in msg_class and reloads >= 1
    # The rows and the button act in the tenant the admin switched into.
    assert {q for path, _m, _b, q in seen if path != "/setup/config"} == {"tenant=t-a"}


def test_the_auto_replace_box_follows_the_setting_and_is_saved():
    # null is off, as the hub reads it (only a missing value means on).
    routes = {"/setup/config": (200, {"global_config": {"static_ip_reservations": {
        "enabled": False, "auto_replace": None}}})}
    with sync_api.sync_playwright() as p:
        browser, page, seen = _page(p, routes)
        page.evaluate("loadStaticResConfig()")
        page.evaluate("document.getElementById('static-res-auto-replace').checked = true")
        page.evaluate("loadStaticResConfig()")
        page.wait_for_function("!document.getElementById('static-res-auto-replace').checked")
        page.check("#static-res-auto-replace")
        page.evaluate("saveStaticResConfig()")
        page.wait_for_timeout(200)
        posts = [s for s in seen if s[1] == "POST"]
        browser.close()
    assert json.loads(posts[0][2])["config"]["static_ip_reservations"]["auto_replace"] is True
