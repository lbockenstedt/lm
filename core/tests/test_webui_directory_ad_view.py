"""Directory → AD (js/views/directory-ad.js) in headless Chromium against the
real app, with /api/ldap/* mocked: accounts are listed per AD connection, a
connection that could not be read shows its error next to one that worked,
hostile AD values render as text, an unreadable account state shows as
Unknown, and a tenant with no AD connection gets the setup hint."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

EVIL = "<img src=x onerror=window.__pwned=1>"
AD = {
    "configured": True,
    "connections": [
        {"name": "Corp", "domain": "corp.example", "truncated": False, "users": [
            {"username": "al", "display_name": "Al", "upn": "al@corp.example", "enabled": True},
            {"username": "bo", "display_name": EVIL, "upn": "bo@corp.example", "enabled": False},
            {"username": "cy", "display_name": "Cy", "upn": "cy@corp.example", "enabled": None}]},
        {"name": "Lab", "domain": "lab.example", "users": [], "error": "no AD server found"},
    ],
}


def _open(p, base, token, ad):
    """A page on Directory → AD for tenant acme, with the hub mocked."""
    context = p.chromium.launch().new_context()
    context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def json_route(body):
        return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

    page.route("**/api/ldap/tenants", json_route({"tenants": [{"id": "acme", "name": "Acme"}]}))
    page.route("**/api/ldap/health", json_route({}))
    page.route("**/api/ldap/users?*", json_route([]))
    page.route("**/api/ldap/ous?*", json_route({"ous": [], "root_user_count": 0}))
    page.route("**/api/ldap/ad?*", json_route(ad))
    page.goto(base + "/")
    page.wait_for_function("window._lmClickFeedbackInstalled === true")
    page.evaluate("setView('ldap')")
    page.wait_for_function("document.getElementById('ldap-tenant-select')?.value === 'acme'")
    page.evaluate("setSubView('AD')")
    return page, errors


def test_ad_accounts_per_connection_with_errors(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, AD)
        page.locator("#ldap-table-body >> text=no AD server found").wait_for()
        body = page.inner_text("#ldap-table-body")
        # Both connections are shown; the failed one says why, the other lists accounts.
        assert "Corp" in body and "Lab" in body and "al@corp.example" in body
        assert "Could not read this AD: no AD server found" in body
        # Hostile values are text; states are Enabled / Disabled / Unknown.
        assert EVIL in body and page.evaluate("window.__pwned") is None
        rows = page.locator("#ldap-table-body tr")
        assert "Enabled" in rows.nth(1).inner_text()
        assert "Disabled" in rows.nth(2).inner_text()
        assert "Unknown" in rows.nth(3).inner_text()
        # AD has no OU panel and is read-only.
        assert page.locator("#ldap-ou-panel").is_hidden()
        assert not errors

        # A tenant with no AD connection gets the setup hint, not an empty table.
        page.unroute("**/api/ldap/ad?*")
        page.route("**/api/ldap/ad?*", lambda r: r.fulfill(
            content_type="application/json", body=json.dumps({"configured": False, "connections": []})))
        page.evaluate("setSubView('AD')")
        page.locator("#ldap-table-body >> text=No Active Directory connection").wait_for()
        assert not errors


def test_setup_ad_connection_form_is_vault_only_and_tenant_bound(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        context = p.chromium.launch().new_context()
        context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
        page = context.new_page()
        errors, posts = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.route("**/setup/tenants", lambda r: r.fulfill(content_type="application/json", body=json.dumps(
            {"tenants": [{"id": "ssplm", "name": "SSPLM"}, {"id": "grp", "name": "Group", "is_group": True}]})))
        page.route("**/tenant/cred-vault/automation-secrets*", lambda r: r.fulfill(
            content_type="application/json", body=json.dumps({"vault_available": False, "secrets": [
                {"bucket": "ssplm", "name": "ad-bind", "type": "login"}]})))

        def save(route):
            posts.append(json.loads(route.request.post_data))
            route.fulfill(content_type="application/json", body="{}")
        page.route("**/setup/ad-connections", save)
        page.goto(base + "/")
        page.wait_for_function("window._lmClickFeedbackInstalled === true")
        page.evaluate("showAddDeviceModal('ad')")
        page.wait_for_function("document.querySelectorAll('#dev-tenant_id option').length === 2")

        # The tenant picker lists tenants (not groups); no spoke and no password box.
        assert page.locator("#dev-tenant_id option").all_inner_texts() == ["— select tenant —", "SSPLM"]
        assert page.locator("#dev-spoke-row").is_hidden()
        assert page.locator("#device-modal input[type=password]").count() == 0

        page.fill("#dev-name", "Corp AD")
        page.select_option("#dev-tenant_id", "ssplm")
        page.fill("#dev-domain", "corp.example")
        page.wait_for_function("document.querySelectorAll('#dev-vaultcred option').length === 2")
        # Even with no cloud vault the picker reads as required, never "enter inline".
        box = page.locator("#dev-vaultcred").locator("xpath=..")
        assert box.locator("label").inner_text() == "Credential Vault (required)"
        assert page.locator("#dev-vaultcred option[value='']").inner_text() == "— select a vault credential —"
        # Without a vault credential nothing is sent.
        page.evaluate("saveDevice()")
        page.wait_for_timeout(300)
        assert posts == []
        page.select_option("#dev-vaultcred", "0")
        page.evaluate("saveDevice()")
        page.wait_for_function("!document.getElementById('device-modal')")
        inst = posts[0]["instance"]
        assert inst["tenant_id"] == "ssplm" and inst["domain"] == "corp.example"
        assert inst["vault_credential"] == {"bucket": "ssplm", "name": "ad-bind"}
        assert "bind_password" not in inst and inst["spoke_id"] == ""
        assert not errors


def test_ad_connection_row_shows_its_own_tenant(hub_url_and_session):  # noqa: F811
    # An AD connection has no spoke, so its Managed Devices row takes the
    # tenant from the record itself rather than showing none.
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        context = p.chromium.launch().new_context()
        context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
        page = context.new_page()
        page.route("**/setup/tenants", lambda r: r.fulfill(content_type="application/json", body=json.dumps(
            {"tenants": [{"id": "ssplm", "name": "SSPLM"}]})))
        page.route("**/setup/ad-connections", lambda r: r.fulfill(
            content_type="application/json", body=json.dumps({"instances": [
                {"id": "c1", "name": "Corp AD", "tenant_id": "ssplm", "spoke_id": "",
                 "domain": "corp.example"}]})))
        page.goto(base + "/")
        page.wait_for_function("window._lmClickFeedbackInstalled === true")
        page.evaluate("""async () => {
            const el = document.createElement('div'); el.id = 'all-devices-list';
            document.body.appendChild(el); await loadAllDevices(); }""")
        row = page.evaluate("(window._allDevices || []).find(d => d._typeKey === 'ad')")
        assert row["_tenant"] == "ssplm" and row["_tenantLabel"] == "SSPLM"


def test_editing_an_ad_connection_keeps_its_named_credential(hub_url_and_session):  # noqa: F811
    # The list returns the credential by name only; the edit form rebuilds the
    # reference in the connection's own tenant bucket and preselects it.
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        context = p.chromium.launch().new_context()
        context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
        page = context.new_page()
        page.route("**/setup/tenants", lambda r: r.fulfill(content_type="application/json", body=json.dumps(
            {"tenants": [{"id": "ssplm", "name": "SSPLM"}]})))
        page.route("**/tenant/cred-vault/automation-secrets*", lambda r: r.fulfill(
            content_type="application/json", body=json.dumps({"vault_available": False, "secrets": [
                {"bucket": "ssplm", "name": "other"}, {"bucket": "ssplm", "name": "ad-bind"}]})))
        page.goto(base + "/")
        page.wait_for_function("window._lmClickFeedbackInstalled === true")
        page.evaluate("""showAddDeviceModal('ad', {id: 'c1', name: 'Corp AD', tenant_id: 'ssplm',
            spoke_id: '', domain: 'corp.example', vault_credential: {name: 'ad-bind'}})""")
        page.wait_for_function("document.querySelectorAll('#dev-vaultcred option').length === 3")
        assert page.evaluate("JSON.stringify(_collectVaultCred('dev-vaultcred'))") == \
            json.dumps({"bucket": "ssplm", "name": "ad-bind"}, separators=(",", ":"))
