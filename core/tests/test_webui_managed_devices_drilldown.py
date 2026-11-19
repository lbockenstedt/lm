"""Setup → Module Management → Managed Devices in headless Chromium against the
real app, with the device and spoke lists mocked.

The list is select-first: a visit lists nothing until the user picks a tenant
or a device type, clicking the picked chip again clears it, devices with no
tenant get an Unassigned chip, a refresh after an edit keeps the picks, a new
visit clears them, and a tenant switch moves a tenant pick to the new tenant
(lm#486: the old tenant's devices must never stay listed). Tenants are grouped
by the tenant_key the hub sends, so the mocks carry it as the hub does."""
import json
import os

import pytest

from access import _norm_tenant_id
from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

SPOKES = [
    {"spoke_id": "s-dxp", "display_name": "dxp-nw", "approved": True, "tenant_id": "dxp"},
    {"spoke_id": "s-lrb", "display_name": "lrb-nw", "approved": True, "tenant_id": "lrb"},
]
FIREWALLS = [
    {"id": "f1", "name": "fw-dxp", "spoke_id": "s-dxp", "host": "10.0.0.1"},
    {"id": "f2", "name": "fw-lrb", "spoke_id": "s-lrb", "host": "10.0.0.2"},
]
NW_DEVICES = [
    {"id": "n1", "name": "sw-dxp", "spoke_id": "s-dxp", "address": "10.0.1.1"},
    {"id": "n2", "name": "sw-orphan", "spoke_id": "", "address": "10.0.1.2"},
]
# A tenant-admin's view: /tenant/devices/* lists only records whose own
# tenant_id is one of theirs. fw-role's spoke is missing from their bindable
# spokes (/tenant/devices/spokes), as a freshly auto-loaded role sub-spoke with
# no tenant of its own is.
TA_FIREWALLS = [
    {"id": "f1", "name": "fw-dxp", "spoke_id": "s-dxp", "host": "10.0.0.1", "tenant_id": "dxp"},
    {"id": "f2", "name": "fw-lrb", "spoke_id": "s-lrb", "host": "10.0.0.2", "tenant_id": "lrb"},
    {"id": "f3", "name": "fw-role", "spoke_id": "s-lrb-dns", "host": "10.0.0.3", "tenant_id": "lrb"},
]
NAMES = ("acme-fw1", "acme-fw2", "fw-dxp", "fw-lrb", "fw-role", "fw-shared",
         "strasse-fw1", "strasse-fw2", "strasse-fw3", "sw-dxp", "sw-orphan")
TENANTS = [{"id": "dxp", "name": "DXP"}, {"id": "lrb", "name": "LRB"}]


def _keyed(rows, field="tenant_id"):
    """The rows as the hub lists them: each with the tenant_key it computes
    (access._norm_tenant_id) from the row's tenant id."""
    return [dict(r, tenant_key=_norm_tenant_id(r.get(field))) for r in rows]


def _open(p, base, token, firewalls=FIREWALLS, nw_devices=NW_DEVICES, tenant_admin=False,
          spokes=SPOKES, tenants=TENANTS, keyed=True):
    """A page on Setup → Module Management, with the device lists mocked. With
    tenant_admin, the browser is a tenant-admin of dxp and lrb on My Devices.
    Without keyed, the lists carry no tenant_key, as an older hub's do."""
    key = _keyed if keyed else (lambda rows, field="tenant_id": rows)
    context = p.chromium.launch().new_context()
    context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def json_route(body):
        return lambda r: r.fulfill(content_type="application/json", body=json.dumps(body))

    # setTenant() records the hub-wide active tenant; keep the test tenants out
    # of the shared test hub's state.
    page.route("**/setup/tenant", json_route({}))
    if tenant_admin:
        # The WebUI takes the role from /auth/me. /setup/* is admin-only, so
        # /setup/tenants answers 403 and no tenant display names are known.
        page.route("**/auth/me", json_route({
            "user_id": "ta", "permissions": {"role": "tenant_admin"},
            "tenants": ["dxp", "lrb"], "tenant_id": "dxp"}))
        page.route("**/setup/tenants", lambda r: r.fulfill(
            status=403, content_type="application/json", body='{"detail": "Admin access required"}'))
        page.route("**/tenant/devices/spokes", json_route({"spokes": key(spokes)}))
        page.route("**/tenant/devices/firewalls", json_route({"firewalls": key(firewalls)}))
        page.route("**/tenant/devices/nw-devices", json_route({"nw_devices": key(nw_devices)}))
        view = "setView('mydevices')"
    else:
        # The device lists carry tenant_key as the hub's do. A device takes
        # its tenant from its own record, and from its spoke's row only when
        # the record names none.
        page.route("**/setup/pending_spokes", json_route({"spokes": key(spokes)}))
        page.route("**/setup/tenants", json_route({"tenants": key(tenants, "id")}))
        page.route("**/setup/firewalls", json_route({"firewalls": key(firewalls)}))
        page.route("**/setup/nw-devices", json_route({"nw_devices": key(nw_devices)}))
        view = "setView('setup'); setSubView('Module Management')"
    page.goto(base + "/")
    page.wait_for_function("window._lmClickFeedbackInstalled === true")
    page.evaluate(view)
    page.wait_for_function("!document.querySelector('#all-devices-list .animate-pulse')")
    return page, errors


def _listed(page):
    """Names of the devices the list shows, in NAMES order."""
    text = page.inner_text("#all-devices-list")
    return [n for n in NAMES if n in text]


def _chips(page, row):
    """Chip labels (count stripped) of the Tenant or Type row."""
    return page.evaluate("""row => [...document.querySelectorAll('#all-devices-tabs > div')]
        .filter(r => r.firstElementChild.textContent === row)
        .flatMap(r => [...r.querySelectorAll('.sub-nav-item')])
        .map(c => c.firstChild.textContent)""", row)


def _click(page, label):
    page.locator("#all-devices-tabs .sub-nav-item", has_text=label).first.click()


def test_nothing_is_listed_until_a_tenant_or_type_is_picked(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        assert _listed(page) == []
        assert "Pick a tenant or a device type above" in page.inner_text("#all-devices-list")
        # No "All" chip; the device with no tenant gets its own chip, listed last.
        assert _chips(page, "Tenant") == ["DXP", "LRB", "Unassigned"]
        assert _chips(page, "Type") == ["Firewall", "Network"]

        _click(page, "DXP")
        assert _listed(page) == ["fw-dxp", "sw-dxp"]
        _click(page, "DXP")  # clicking the picked chip again clears it
        assert _listed(page) == []

        _click(page, "Unassigned")
        assert _listed(page) == ["sw-orphan"]
        # Under a tenant pick the Type row offers only what that tenant owns.
        assert _chips(page, "Type") == ["Network"]
        _click(page, "Unassigned")

        _click(page, "Firewall")
        assert _listed(page) == ["fw-dxp", "fw-lrb"]
        _click(page, "LRB")
        assert _listed(page) == ["fw-lrb"]
        assert not errors


def test_a_refresh_keeps_the_picks_and_a_new_visit_clears_them(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        _click(page, "Firewall")
        _click(page, "LRB")
        # What an add, edit or delete calls afterwards.
        page.evaluate("loadAllDevices()")
        page.wait_for_function("!document.querySelector('#all-devices-list .animate-pulse')")
        assert _listed(page) == ["fw-lrb"]

        page.evaluate("setView('dashboard'); setView('setup'); setSubView('Module Management')")
        page.wait_for_function("!document.querySelector('#all-devices-list .animate-pulse')")
        assert _listed(page) == []
        assert not errors


def test_a_refresh_that_leaves_no_device_drops_the_picks(hub_url_and_session):  # noqa: F811
    """Deleting the last device removes every chip, so the picks go with them:
    devices added later are not listed under picks the page no longer shows."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        empty = {"on": False}

        def device_list(name, rows):
            return lambda r: r.fulfill(content_type="application/json", body=json.dumps(
                {name: [] if empty["on"] else _keyed(rows)}))

        # Registered last, so these answer instead of _open's mocks.
        page.route("**/setup/firewalls", device_list("firewalls", FIREWALLS))
        page.route("**/setup/nw-devices", device_list("nw_devices", NW_DEVICES))
        _click(page, "Firewall")
        _click(page, "LRB")
        assert _listed(page) == ["fw-lrb"]

        empty["on"] = True
        page.evaluate("loadAllDevices()")
        assert "No managed devices yet" in page.inner_text("#all-devices-list")

        empty["on"] = False
        page.evaluate("loadAllDevices()")
        page.wait_for_function("!document.querySelector('#all-devices-list .animate-pulse')")
        assert _listed(page) == []
        assert "Pick a tenant or a device type above" in page.inner_text("#all-devices-list")
        assert not errors


def test_a_list_that_fails_to_load_keeps_the_picks(hub_url_and_session):  # noqa: F811
    """A device or spoke list that fails to load (an HTTP error, bad JSON, a
    reply with no list) is unknown, not empty: the page says what failed and
    keeps the picks, which
    apply again once the lists load. Only a load in which every list answered
    drops a pick that has no device left."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        how = {"firewalls": "", "nw_devices": "", "spokes": ""}

        def answer(name, rows):
            """Answer list ``name`` with ``rows``, or as ``how[name]`` says:
            "502", "json" (a body that is not JSON), "nolist" (a reply with
            no list in it) or "empty"."""
            def handler(route):
                if how[name] == "502":
                    route.fulfill(status=502, content_type="application/json", body='{"detail": "Bad Gateway"}')
                elif how[name] == "json":
                    route.fulfill(content_type="application/json", body="{")
                elif how[name] == "nolist":
                    route.fulfill(content_type="application/json", body="{}")
                else:
                    route.fulfill(content_type="application/json", body=json.dumps(
                        {name: [] if how[name] == "empty" else _keyed(rows)}))
            return handler

        def reload():
            """What an add, edit or delete calls afterwards; the list's text."""
            page.evaluate("loadAllDevices()")
            return page.inner_text("#all-devices-list")

        def picked():
            """Labels of the picked chips, Tenant row first."""
            return page.evaluate("""() => [...document.querySelectorAll('#all-devices-tabs .sub-nav-item.active')]
                .map(c => c.firstChild.textContent)""")

        # Registered last, so these answer instead of _open's mocks.
        page.route("**/setup/firewalls", answer("firewalls", FIREWALLS))
        page.route("**/setup/nw-devices", answer("nw_devices", NW_DEVICES))
        page.route("**/setup/pending_spokes", answer("spokes", SPOKES))
        _click(page, "Firewall")
        _click(page, "LRB")
        assert _listed(page) == ["fw-lrb"]

        # The firewall list fails while the network list still has devices.
        how["firewalls"] = "502"
        text = reload()
        assert "Could not load: Firewall." in text
        assert "No devices match" not in text
        assert picked() == ["LRB", "Firewall"]

        # Every list fails: that is not "no devices".
        how["nw_devices"] = "json"
        text = reload()
        assert "Could not load: Firewall, Network." in text
        assert "No managed devices yet" not in text

        # A reply with no list in it is not an empty list either.
        how.update(firewalls="nolist", nw_devices="")
        text = reload()
        assert "Could not load: Firewall." in text
        assert picked() == ["LRB", "Firewall"]

        # Once the lists load again, the picks apply again.
        how.update(firewalls="", nw_devices="")
        text = reload()
        assert _listed(page) == ["fw-lrb"]
        assert "Could not load" not in text

        # Without the spoke list, the tenants the spokes give are unknown, and
        # the devices that take theirs from a spoke are not Unassigned ones.
        _click(page, "LRB")
        _click(page, "Firewall")
        _click(page, "DXP")
        how["spokes"] = "502"
        text = reload()
        assert "Could not load: Spokes." in text
        assert picked() == ["DXP"]
        how["spokes"] = "nolist"
        text = reload()
        assert "Could not load: Spokes." in text
        assert picked() == ["DXP"]
        how["spokes"] = ""
        reload()
        assert _listed(page) == ["fw-dxp", "sw-dxp"]

        # Unassigned is kept while a list that could hold its device failed.
        _click(page, "DXP")
        _click(page, "Unassigned")
        how["nw_devices"] = "502"
        reload()
        assert picked() == ["Unassigned"]
        how["nw_devices"] = ""
        reload()
        assert _listed(page) == ["sw-orphan"]

        # A load in which every list answered still drops a pick that has no
        # device left: here the firewall list answers that it is empty.
        _click(page, "Unassigned")
        _click(page, "Firewall")
        how["firewalls"] = "empty"
        text = reload()
        assert picked() == []
        assert "Pick a tenant above to list them." in text
        assert not errors


def test_a_tenant_switch_moves_the_tenant_pick_to_the_new_tenant(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        _click(page, "DXP")
        page.evaluate("setTenant('lrb')")
        page.wait_for_function("document.getElementById('all-devices-list')?.innerText.includes('fw-lrb')")
        assert _listed(page) == ["fw-lrb"]

        # The type pick survives the switch too: only the tenant moved.
        _click(page, "Firewall")
        page.evaluate("setTenant('dxp')")
        page.wait_for_function("document.getElementById('all-devices-list')?.innerText.includes('fw-dxp')")
        assert _listed(page) == ["fw-dxp"]

        # With no tenant picked, a switch does not pick one.
        _click(page, "DXP")
        _click(page, "Firewall")
        page.evaluate("setTenant('lrb')")
        page.wait_for_timeout(500)
        page.wait_for_function("!document.querySelector('#all-devices-list .animate-pulse')")
        assert _listed(page) == []
        assert not errors


def test_a_tenant_written_in_another_case_is_still_one_tenant(hub_url_and_session):  # noqa: F811
    """Tenant ids are compared by the hub's tenant_key (access._norm_tenant_id):
    spokes bound as "ACME" and "acme" belong to the tenant record "Acme". They
    get one chip under its name, and a header switch to "Acme" keeps the pick."""
    base, token = hub_url_and_session
    spokes = [
        {"spoke_id": "s-a1", "display_name": "a1-spoke", "approved": True, "tenant_id": "ACME"},
        {"spoke_id": "s-a2", "display_name": "a2-spoke", "approved": True, "tenant_id": "acme"},
        SPOKES[1],
    ]
    firewalls = [
        {"id": "f1", "name": "acme-fw1", "spoke_id": "s-a1", "host": "10.0.0.1"},
        {"id": "f2", "name": "acme-fw2", "spoke_id": "s-a2", "host": "10.0.0.2"},
        FIREWALLS[1],
    ]
    tenants = [{"id": "Acme", "name": "Acme Labs"}, {"id": "lrb", "name": "LRB"}]
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=firewalls, nw_devices=[],
                             spokes=spokes, tenants=tenants)
        assert _chips(page, "Tenant") == ["Acme Labs", "LRB"]
        _click(page, "Acme Labs")
        assert _listed(page) == ["acme-fw1", "acme-fw2"]

        page.evaluate("setTenant('lrb')")
        page.wait_for_function("document.getElementById('all-devices-list')?.innerText.includes('fw-lrb')")
        assert _listed(page) == ["fw-lrb"]
        page.evaluate("setTenant('Acme')")
        page.wait_for_function("document.getElementById('all-devices-list')?.innerText.includes('acme-fw1')")
        assert _listed(page) == ["acme-fw1", "acme-fw2"]
        assert not errors


def test_tenants_group_by_the_hub_key_not_a_browser_case_fold(hub_url_and_session):  # noqa: F811
    """JS toLowerCase() keeps "ß" while the hub's casefold() makes it "ss", so
    the page groups by the hub's tenant_key, never a fold of its own: spokes
    bound as "Straße", "STRASSE" and "strasse" are one tenant, listed once
    under the record's name, and a header switch to "Straße" keeps the pick."""
    base, token = hub_url_and_session
    spokes = [{"spoke_id": f"s-ss{i}", "display_name": f"ss{i}-spoke", "approved": True,
               "tenant_id": tid} for i, tid in enumerate(("Straße", "STRASSE", "strasse"), 1)]
    firewalls = [{"id": f"ss{i}", "name": f"strasse-fw{i}", "spoke_id": f"s-ss{i}",
                  "host": f"10.0.2.{i}"} for i in (1, 2, 3)]
    tenants = [{"id": "Straße", "name": "Straße GmbH"}, {"id": "lrb", "name": "LRB"}]
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=firewalls + FIREWALLS[1:],
                             nw_devices=[], spokes=spokes + SPOKES[1:], tenants=tenants)
        assert _chips(page, "Tenant") == ["LRB", "Straße GmbH"]
        _click(page, "Straße GmbH")
        assert _listed(page) == ["strasse-fw1", "strasse-fw2", "strasse-fw3"]
        # Each badge's tooltip shows its binding's tenant id as stored.
        assert page.locator("#all-devices-list span[title='Tenant: STRASSE']").count() == 1

        page.evaluate("setTenant('lrb')")
        page.wait_for_function("document.getElementById('all-devices-list')?.innerText.includes('fw-lrb')")
        assert _listed(page) == ["fw-lrb"]
        page.evaluate("setTenant('Straße')")
        page.wait_for_function("document.getElementById('all-devices-list')?.innerText.includes('strasse-fw1')")
        assert _listed(page) == ["strasse-fw1", "strasse-fw2", "strasse-fw3"]
        assert not errors


def test_an_older_hub_without_tenant_keys_still_groups_by_tenant(hub_url_and_session):  # noqa: F811
    """WebUI files go live the moment a pull lands, the hub process only at its
    next (gated) restart, so the page can meet routes that send no tenant_key
    yet. Devices still group under their tenant, folded as the hub folds an
    ASCII id (a spoke bound as "DXP" is tenant "dxp"), not all under Unassigned."""
    base, token = hub_url_and_session
    spokes = [dict(SPOKES[0], tenant_id="DXP"), SPOKES[1]]
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, spokes=spokes, keyed=False)
        assert _chips(page, "Tenant") == ["DXP", "LRB", "Unassigned"]
        _click(page, "DXP")
        assert _listed(page) == ["fw-dxp", "sw-dxp"]
        assert not errors


def test_with_nothing_to_choose_the_list_shows_straight_away(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=FIREWALLS[:1], nw_devices=[])
        assert _listed(page) == ["fw-dxp"]
        assert page.inner_text("#all-devices-tabs").strip() == ""
        assert not errors


def test_a_tenant_admin_in_two_tenants_picks_a_tenant_first(hub_url_and_session):  # noqa: F811
    """My Devices lists every assigned tenant's devices, so a tenant-admin in
    two tenants picks one first, as on OS Updates, even when every device is
    the same type. Each record goes under its own tenant_id."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=TA_FIREWALLS, nw_devices=[], tenant_admin=True)
        assert _listed(page) == []
        assert "3 devices. Pick a tenant above to list them." in page.inner_text("#all-devices-list")
        # No Unassigned chip, and with no tenant names the chips show the ids.
        assert _chips(page, "Tenant") == ["dxp", "lrb"]
        assert _chips(page, "Type") == []

        _click(page, "lrb")
        assert _listed(page) == ["fw-lrb", "fw-role"]
        assert page.locator("#all-devices-list span[title='Tenant: lrb']").count() == 2
        assert not errors


def test_a_global_admin_files_a_device_under_the_tenant_its_record_names(hub_url_and_session):  # noqa: F811
    """The Global Admin counterpart of the test above: a device goes under the
    tenant its record names, as it does for the tenant-admin, whatever its
    spoke is bound to. fw-role's spoke is a role sub-spoke with no tenant of
    its own and fw-shared's is bound to the shared tenant; under the spoke's
    tenant they would sit under Unassigned and shared, and a pick of LRB would
    hide them. Records that name no tenant still follow their spoke (fw-dxp,
    sw-dxp)."""
    base, token = hub_url_and_session
    spokes = SPOKES + [
        {"spoke_id": "s-lrb-dns", "display_name": "lrb-agent-firewall", "approved": True, "tenant_id": ""},
        {"spoke_id": "s-shared", "display_name": "shared-fw", "approved": True, "tenant_id": "shared"},
    ]
    firewalls = TA_FIREWALLS + [
        {"id": "f4", "name": "fw-shared", "spoke_id": "s-shared", "host": "10.0.0.4", "tenant_id": "lrb"}]
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=firewalls, spokes=spokes)
        assert _chips(page, "Tenant") == ["DXP", "LRB", "Unassigned"]
        _click(page, "LRB")
        assert _listed(page) == ["fw-lrb", "fw-role", "fw-shared"]
        _click(page, "LRB")
        _click(page, "DXP")
        assert _listed(page) == ["fw-dxp", "sw-dxp"]
        _click(page, "DXP")
        _click(page, "Unassigned")
        assert _listed(page) == ["sw-orphan"]
        assert not errors
