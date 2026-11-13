"""Directory → Users with OUs (js/views/directory-users.js) in headless
Chromium against the real app, with /api/ldap/* mocked: the OU tree lists the
tenant's OUs with counts, picking one filters the table, the Move form posts
the chosen OU path, and hostile directory values render as text."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

EVIL = "<img src=x onerror=window.__pwned=1>"

USERS = [
    {"username": "alice", "first_name": "Alice", "auth_mode": "local", "ou_path": []},
    {"username": "bob", "first_name": EVIL, "auth_mode": "entra", "upn": "bob@x.org",
     "ou_path": ["Eng"]},
    {"username": "carol", "auth_mode": "local", "ou_path": ["Eng", "Lab"]},
]
OUS = {"ous": [{"path": ["Eng"], "name": "Eng", "user_count": 1},
               {"path": ["Eng", "Lab"], "name": "Lab", "user_count": 1}],
       "root_user_count": 1}


def test_directory_ou_tree_filters_and_moves(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors, moves = [], []
            page.on("pageerror", lambda e: errors.append(str(e)))

            def json_route(body):
                return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

            def move(route):
                moves.append(json.loads(route.request.post_data))
                route.fulfill(content_type="application/json", body='{"status": "SUCCESS"}')

            page.route("**/api/ldap/tenants", json_route(
                {"tenants": [{"id": "acme", "name": "Acme", "ou": "acme"}]}))
            page.route("**/api/ldap/health", json_route({}))
            page.route("**/api/ldap/users?*", json_route(USERS))
            page.route("**/api/ldap/ous?*", json_route(OUS))
            page.route("**/api/ldap/users/move", move)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('ldap')")

            # The tree: All users (3), Top level (1), Eng (1), Lab (1).
            panel = page.locator("#ldap-ou-panel")
            panel.locator("text=Lab").wait_for()
            assert page.locator("#ldap-table-body tr").count() == 3

            # Picking Eng shows only bob; his hostile name is text, not markup.
            panel.locator("button[title='Eng']").click()
            rows = page.locator("#ldap-table-body tr")
            assert rows.count() == 1 and "bob" in rows.inner_text()
            assert EVIL in rows.inner_text()

            # Move bob to Eng/Lab: the hub gets the path as a list.
            rows.locator("button[data-action='move']").click()
            page.select_option("#dir-move-target", label="Eng/Lab")
            panel.locator("button[data-action='submit']").click()
            page.wait_for_selector("#dir-move-target", state="detached")
            assert moves == [{"tenant_id": "acme", "uid": "bob", "target_path": ["Eng", "Lab"]}]

            assert page.evaluate("window.__pwned") is None
            assert errors == []
        finally:
            browser.close()


def test_late_reply_from_previous_tenant_is_dropped(hub_url_and_session):  # noqa: F811
    """Switching tenant while tenant A's user list is in flight must not draw
    A's users under B (row actions would then act on B with A's uids)."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors, held = [], []
            page.on("pageerror", lambda e: errors.append(str(e)))

            def json_route(body):
                return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

            def users(route):
                # Hold tenant a's reply; answer tenant b at once.
                if "tenant=a" in route.request.url:
                    held.append(route)
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(
                        [{"username": "bee", "auth_mode": "local", "ou_path": []}]))

            page.route("**/api/ldap/tenants", json_route(
                {"tenants": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]}))
            page.route("**/api/ldap/health", json_route({}))
            page.route("**/api/ldap/ous?*", json_route({"ous": [], "root_user_count": 1}))
            page.route("**/api/ldap/users?*", users)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('ldap')")
            page.wait_for_function("document.getElementById('ldap-tenant-select')?.value === 'a'")
            while not held:
                page.wait_for_timeout(50)

            # Switch to b, then let a's reply land late.
            page.select_option("#ldap-tenant-select", "b")
            page.locator("#ldap-table-body >> text=bee").wait_for()
            for r in held:
                r.fulfill(content_type="application/json", body=json.dumps(
                    [{"username": "ant", "auth_mode": "local", "ou_path": []}]))
            page.wait_for_timeout(500)
            body = page.locator("#ldap-table-body").inner_text()
            assert "bee" in body and "ant" not in body
            assert errors == []
        finally:
            browser.close()


def test_late_ou_reply_from_previous_tenant_is_dropped(hub_url_and_session):  # noqa: F811
    """Tenant A's OU list landing after the picker moved to B (while B's users
    are still loading) must not redraw A's rows."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors, held_ous, held_b = [], [], []
            page.on("pageerror", lambda e: errors.append(str(e)))

            def json_route(body):
                return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

            def users(route):
                # Answer tenant a at once; hold tenant b's users.
                if "tenant=b" in route.request.url:
                    held_b.append(route)
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(
                        [{"username": "ant", "auth_mode": "local", "ou_path": []}]))

            def ous(route):
                # Hold tenant a's OU list.
                if "tenant=a" in route.request.url:
                    held_ous.append(route)
                else:
                    route.fulfill(content_type="application/json",
                                  body='{"ous": [], "root_user_count": 1}')

            page.route("**/api/ldap/tenants", json_route(
                {"tenants": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]}))
            page.route("**/api/ldap/health", json_route({}))
            page.route("**/api/ldap/users?*", users)
            page.route("**/api/ldap/ous?*", ous)
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('ldap')")
            while not held_ous:
                page.wait_for_timeout(50)

            # Pick b (its users are held), then release a's OU list.
            page.select_option("#ldap-tenant-select", "b")
            while not held_b:
                page.wait_for_timeout(50)
            for r in held_ous:
                r.fulfill(content_type="application/json", body='{"ous": [], "root_user_count": 1}')
            page.wait_for_timeout(500)
            assert "ant" not in page.locator("#ldap-table-body").inner_text()

            # b's users then land normally.
            for r in held_b:
                r.fulfill(content_type="application/json", body=json.dumps(
                    [{"username": "bee", "auth_mode": "local", "ou_path": []}]))
            page.locator("#ldap-table-body >> text=bee").wait_for()
            assert "ant" not in page.locator("#ldap-table-body").inner_text()
            assert errors == []
        finally:
            browser.close()


def test_returning_to_the_page_resets_the_picked_ou(hub_url_and_session):  # noqa: F811
    """Leaving Directory and coming back starts at All users again."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()

            def json_route(body):
                return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

            page.route("**/api/ldap/tenants", json_route(
                {"tenants": [{"id": "acme", "name": "Acme"}]}))
            page.route("**/api/ldap/health", json_route({}))
            page.route("**/api/ldap/users?*", json_route(USERS))
            page.route("**/api/ldap/ous?*", json_route(OUS))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('ldap')")
            panel = page.locator("#ldap-ou-panel")
            panel.locator("button[title='Eng']").click()
            assert page.locator("#ldap-table-body tr").count() == 1

            page.evaluate("setView('dashboard')")
            page.evaluate("setView('ldap')")
            page.locator("#ldap-ou-panel >> text=Lab").wait_for()
            page.wait_for_function(
                "document.querySelectorAll('#ldap-table-body tr').length === 3")
        finally:
            browser.close()


def test_tenant_switch_hides_the_old_tenants_ous(hub_url_and_session):  # noqa: F811
    """While tenant B's users load, tenant A's OU panel is hidden and its
    picked OU is not used for a new user (it would land in B under A's path)."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            held_b = []

            def json_route(body):
                return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

            def users(route):
                # Answer tenant a at once; hold tenant b's users.
                if "tenant=b" in route.request.url:
                    held_b.append(route)
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(USERS))

            page.route("**/api/ldap/tenants", json_route(
                {"tenants": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]}))
            page.route("**/api/ldap/health", json_route({}))
            page.route("**/api/ldap/users?*", users)
            page.route("**/api/ldap/ous?*", json_route(OUS))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('ldap')")
            page.locator("#ldap-ou-panel button[title='Eng']").click()
            assert page.evaluate("lmViews.directoryOuPath()") == ["Eng"]

            page.select_option("#ldap-tenant-select", "b")
            while not held_b:
                page.wait_for_timeout(50)
            assert page.locator("#ldap-ou-panel").is_hidden()
            assert page.evaluate("lmViews.directoryOuPath()") == []
            for r in held_b:
                r.fulfill(content_type="application/json", body="[]")
            page.locator("#ldap-ou-panel").wait_for(state="visible")
        finally:
            browser.close()
