"""Directory → Entra (js/views/directory-entra.js) in headless Chromium
against the real app, with /api/ldap/* mocked: the group panel filters the
accounts, a new account posts the typed fields and shows a generated password
once, hostile Entra values render as text, no object id is shown, and the
"cached" badge shows only for stale or old data."""
import json
import os
import time

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

EVIL = "<img src=x onerror=window.__pwned=1>"
U1 = "00000000-0000-0000-0000-000000000001"
U2 = "00000000-0000-0000-0000-000000000002"
G = "00000000-0000-0000-0000-0000000000aa"
ENTRA = {
    "configured": True,
    "users": [{"id": U1, "upn": "al@x.com", "name": "Al", "enabled": True},
              {"id": U2, "upn": "bo@x.com", "name": EVIL, "enabled": False}],
    "groups": [{"id": "00000000-0000-0000-0000-0000000000ff", "name": "LM-Acme-Users",
                "base": True, "member_count": 2},
               {"id": G, "name": "LM-Acme-Ops", "base": False,
                "members": [{"id": U1, "upn": "al@x.com", "name": "Al", "enabled": True}]}],
}


def _open(p, base, token, entra, posts):
    """A page on Directory → Entra for tenant acme, with the hub mocked."""
    context = p.chromium.launch().new_context()
    context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def json_route(body):
        return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

    def create(route):
        posts.append(json.loads(route.request.post_data))
        route.fulfill(content_type="application/json", body=json.dumps(
            {"id": U2, "upn": "cy@x.com", "name": "Cy", "password": "Gen-3rated!"}))

    page.route("**/api/ldap/tenants", json_route({"tenants": [{"id": "acme", "name": "Acme"}]}))
    page.route("**/api/ldap/health", json_route({}))
    page.route("**/api/ldap/users?*", json_route([]))
    page.route("**/api/ldap/ous?*", json_route({"ous": [], "root_user_count": 0}))
    page.route("**/api/ldap/entra?*", json_route(entra))
    page.route("**/api/ldap/entra/users", create)
    page.goto(base + "/")
    page.wait_for_function("window._lmClickFeedbackInstalled === true")
    page.evaluate("setView('ldap')")
    page.wait_for_function("document.getElementById('ldap-tenant-select')?.value === 'acme'")
    page.evaluate("setSubView('Entra')")
    return page, errors


def test_entra_accounts_groups_and_create(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        posts = []
        # A failed refresh (stale) on a list under 5 minutes old: no badge.
        page, errors = _open(p, base, token, dict(ENTRA, stale=True, cached_at=time.time()), posts)
        panel = page.locator("#ldap-ou-panel")
        rows = page.locator("#ldap-table-body tr")
        page.locator("#ldap-table-body >> text=bo@x.com").wait_for()

        # All accounts: both, the hostile name as text; no object id shown.
        assert rows.count() == 2 and EVIL in page.inner_text("#ldap-table-body")
        assert U1 not in page.inner_text("body") and G not in page.inner_text("body")
        assert "LM-Acme-Ops" in rows.first.inner_text()
        assert page.locator("#entra-cached").count() == 0  # under 5 minutes: no badge
        # Al is already in every tenant group, so his "+ Group" is disabled.
        assert page.locator(f"button[data-action='addMember'][data-id='{U1}']").is_disabled()
        assert page.locator(f"button[data-action='addMember'][data-id='{U2}']").is_enabled()
        assert "Entra" in page.get_attribute("#ldap-ou-panel", "title")

        # Picking the group shows only its member.
        panel.locator("button[title='LM-Acme-Ops']").click()
        assert rows.count() == 1 and "al@x.com" in rows.inner_text()

        # Remove from the group asks first; Cancel sends nothing.
        removed = []
        page.route("**/api/ldap/entra/groups/members", lambda r: (
            removed.append(json.loads(r.request.post_data)),
            r.fulfill(content_type="application/json", body="{}")))
        confirm = page.locator(".lm-toast", has_text="Remove al@x.com from the Entra group LM-Acme-Ops?")
        rows.locator("button[data-action='removeMember']").click()
        confirm.get_by_role("button", name="Cancel").click()
        page.wait_for_timeout(300)
        assert removed == []
        rows.locator("button[data-action='removeMember']").click()
        confirm.last.get_by_role("button", name="Confirm").click()
        page.locator("text=al@x.com removed from LM-Acme-Ops.").wait_for()
        assert removed == [{"tenant_id": "acme", "group_id": G, "user_id": U1}]

        # A new account in that group with a generated password, shown once,
        # even when the reload after the write never answers (a page GET
        # cancelled by navigation never settles in lmFetch).
        page.unroute("**/api/ldap/entra?*")
        page.route("**/api/ldap/entra?*", lambda r: None)
        panel.locator("button[data-action='newAccount']").click()
        page.fill("#entra-upn", "cy@x.com")
        page.fill("#entra-name", "Cy")
        panel.locator("button[data-action='submit']").click()
        page.locator("#entra-secret").wait_for()
        assert page.inner_text("#entra-secret") == "Gen-3rated!"
        assert posts == [{"tenant_id": "acme", "upn": "cy@x.com", "name": "Cy",
                          "password": "", "group_ids": [G]}]
        # Nothing but Done (or leaving) can drop the shown password.
        assert panel.locator("button[data-action='newAccount']").is_disabled()
        assert panel.locator("button[data-action='newGroup']").is_disabled()
        page.evaluate("lmViews.directoryEntraAdd()")
        assert page.inner_text("#entra-secret") == "Gen-3rated!"
        panel.locator("button[data-action='dismiss']").click()
        page.wait_for_selector("#entra-secret", state="detached")

        # A Delete confirmed after leaving the module sends nothing.
        page.locator(f"button[data-action='deleteAccount'][data-id='{U1}']").click()
        page.evaluate("setView('dashboard')")
        page.locator(".lm-toast", has_text="Delete the Entra account al@x.com?").last \
            .get_by_role("button", name="Confirm").click()
        page.wait_for_timeout(300)
        assert len(posts) == 1

        assert page.evaluate("window.__pwned") is None
        assert errors == []


def test_entra_not_configured_and_secret_kept_until_done(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, {"configured": False, "users": [], "groups": []}, [])
        page.locator("#ldap-table-body >> text=Entra is not set up").wait_for()
        assert page.locator("#ldap-ou-panel").is_hidden()
        # A later failed request is an error, not "not set up".
        page.unroute("**/api/ldap/entra?*")
        page.route("**/api/ldap/entra?*", lambda r: r.fulfill(status=500, body="boom"))
        page.evaluate("refreshCurrentView()")
        page.locator("#ldap-table-body >> text=Entra unavailable").wait_for()

        # The one-time password survives leaving and reloading until Done.
        page.unroute("**/api/ldap/entra?*")
        page.route("**/api/ldap/entra?*", lambda r: r.fulfill(
            content_type="application/json",
            body=json.dumps(dict(ENTRA, stale=True, cached_at=time.time() - 3600))))
        page.evaluate("setSubView('Users')")
        page.evaluate("setSubView('Entra')")
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        assert page.locator("#entra-cached").count() == 1  # stale list is badged
        page.locator("#ldap-ou-panel button[data-action='newAccount']").click()
        page.fill("#entra-upn", "cy@x.com")
        page.locator("#ldap-ou-panel button[data-action='submit']").click()
        page.locator("#entra-secret").wait_for()
        # Leaving clears it from the screen at once, even if the Users fetch fails.
        page.unroute("**/api/ldap/users?*")
        page.route("**/api/ldap/users?*", lambda r: r.abort())
        page.evaluate("setSubView('Users')")
        assert page.locator("#entra-secret").count() == 0
        assert "OUs" in page.get_attribute("#ldap-ou-panel", "title")
        page.evaluate("setSubView('Entra')")
        page.locator("#entra-secret").wait_for()  # back again on return
        page.evaluate("refreshCurrentView()")      # and after Refresh
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        assert page.inner_text("#entra-secret") == "Gen-3rated!"
        # Signing out (no page reload) takes it off the screen; the next user
        # on this browser never gets it, the user who made it does.
        page.evaluate("window.__me = currentUser; handleSessionExpired()")
        assert page.locator("#entra-secret").count() == 0
        page.evaluate("currentUser = {...window.__me, user_id: 'someone-else'}")
        page.evaluate("setSubView('Entra')")
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        assert page.locator("#entra-secret").count() == 0
        # An impersonated user is not the person who made it either.
        page.evaluate("currentUser = {...window.__me, user_id: 'someone-else',"
                      " impersonator: {user_id: 'other-admin'}}")
        page.evaluate("setSubView('Entra')")
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        assert page.locator("#entra-secret").count() == 0
        # The person who made it gets it back, also while impersonating.
        page.evaluate("currentUser = {...window.__me, user_id: 'someone-else',"
                      " impersonator: {user_id: window.__me.user_id}};"
                      " document.getElementById('login-overlay').classList.add('hidden')")
        page.evaluate("setSubView('Entra')")
        page.locator("#entra-secret").wait_for()
        assert page.inner_text("#entra-secret") == "Gen-3rated!"
        page.locator("#ldap-ou-panel button[data-action='dismiss']").click()
        page.evaluate("setSubView('Users')")
        page.evaluate("setSubView('Entra')")
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        assert page.locator("#entra-secret").count() == 0  # Done dropped it
        assert errors == []


def test_entra_generated_password_survives_leaving_and_failed_reload(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, ENTRA, [])
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        reply = json.dumps({"id": U2, "upn": "cy@x.com", "password": "Gen-3rated!"})

        # Two creates answer only after the admin left for Users: neither
        # password is on screen, and both are shown, one at a time, on the
        # return to Entra (neither overwrites the other).
        held = []
        page.unroute("**/api/ldap/entra/users")
        page.route("**/api/ldap/entra/users", lambda r: held.append(r))
        for n, upn in enumerate(["cy@x.com", "di@x.com"]):
            page.evaluate("setSubView('Entra')")
            page.locator("#ldap-table-body >> text=al@x.com").wait_for()
            page.locator("#ldap-ou-panel button[data-action='newAccount']").click()
            page.fill("#entra-upn", upn)
            page.locator("#ldap-ou-panel button[data-action='submit']").click()
            while len(held) <= n:
                page.wait_for_timeout(50)
            page.evaluate("setSubView('Users')")
        for r, upn, pw in zip(held, ["cy@x.com", "di@x.com"], ["Gen-1!", "Gen-2!"]):
            r.fulfill(content_type="application/json", body=json.dumps({"upn": upn, "password": pw}))
            page.locator(f"text=Open Directory → Entra to copy the password for {upn}.").wait_for()
        assert page.locator("#entra-secret").count() == 0
        page.evaluate("setSubView('Entra')")
        page.locator("#entra-secret").wait_for()
        assert page.inner_text("#entra-secret") == "Gen-1!"
        page.locator("#ldap-ou-panel button[data-action='dismiss']").click()
        assert page.inner_text("#entra-secret") == "Gen-2!"
        page.locator("#ldap-ou-panel button[data-action='dismiss']").click()
        page.evaluate("setSubView('Users')")
        page.evaluate("setSubView('Entra')")
        page.locator("#ldap-table-body >> text=al@x.com").wait_for()
        assert page.locator("#entra-secret").count() == 0  # Done dropped both

        # The same when the admin leaves the Directory module altogether.
        held.clear()
        page.locator("#ldap-ou-panel button[data-action='newAccount']").click()
        page.fill("#entra-upn", "ed@x.com")
        page.locator("#ldap-ou-panel button[data-action='submit']").click()
        while not held:
            page.wait_for_timeout(50)
        page.evaluate("setView('dashboard')")
        held[0].fulfill(content_type="application/json", body=json.dumps({"upn": "ed@x.com", "password": "Gen-3!"}))
        page.locator("text=Open Directory → Entra to copy the password for ed@x.com.").wait_for()
        page.evaluate("setView('ldap')")
        page.wait_for_function("document.getElementById('ldap-tenant-select')?.value === 'acme'")
        page.evaluate("setSubView('Entra')")
        page.locator("#entra-secret").wait_for()
        assert page.inner_text("#entra-secret") == "Gen-3!"
        page.locator("#ldap-ou-panel button[data-action='dismiss']").click()

        # A reload that fails after the create still leaves the password shown.
        page.unroute("**/api/ldap/entra/users")
        page.route("**/api/ldap/entra/users", lambda r: r.fulfill(content_type="application/json", body=reply))
        page.unroute("**/api/ldap/entra?*")
        page.route("**/api/ldap/entra?*", lambda r: r.fulfill(status=502, body="{}"))
        page.locator("#ldap-ou-panel button[data-action='newAccount']").click()
        page.fill("#entra-upn", "cy@x.com")
        page.locator("#ldap-ou-panel button[data-action='submit']").click()
        page.locator("#ldap-table-body >> text=Entra unavailable").wait_for()
        assert page.inner_text("#entra-secret") == "Gen-3rated!"
        page.locator("#ldap-ou-panel button[data-action='dismiss']").click()
        assert page.locator("#ldap-ou-panel").is_hidden()  # no empty card by the error
        assert errors == []
