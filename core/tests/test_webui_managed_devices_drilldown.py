"""Setup → Module Management → Managed Devices in headless Chromium against the
real app, with the device and spoke lists mocked.

The list is select-first: a visit lists nothing until the user picks a tenant
or a device type, clicking the picked chip again clears it, devices with no
tenant get an Unassigned chip, a refresh after an edit keeps the picks, a new
visit clears them, and a tenant switch moves a tenant pick to the new tenant
(lm#486: the old tenant's devices must never stay listed). Tenants are grouped
by the tenant_key the hub sends, so the mocks carry it as the hub does.

The setTenant tests at the end (lm#2028 items 24 and 30) hold POST
/setup/tenant to check that the page (its content and its action buttons) takes
no clicks until the switch lands while the tenant picker stays usable, that a
Global Admin's switches reach the hub one at a time and in order, each with
the switch ticket (POST /setup/tenant/switch-ticket) the hub issued just
before it and no POST without one, that only the
latest of two quick switches unlocks, redraws, keeps a tenant-admin's subnet
filter and names the header, that a failing step still redraws, that a switch
the hub refuses or does not answer gets one fresh ticket (unless a newer pick
waits) and goes back to the tenant the hub names with it, never reading GET
/api/tenant/scoping, compared and taken by its exact id (legacy twins such as
"ACME" and "acme" are two tenants), that a failed switch after which the hub
does not name its tenant with a fresh ticket keeps the page locked, at sign-in
or later, whatever tenant the page saw the hub on before, that a confirm or
prompt open when a switch starts
answers Cancel and goes away and one asked during it answers Cancel at once,
that a switch closes the old page's dialogs and menus and locks what it keeps
open on <body>, that the console docks it keeps drop the old tenant's
consoles before the page unlocks, that it drops the VM table's cache and no
late answer of the old tenant's fills it again, that it drops the node list
and the node poll's late answer for the old tenant does not fill it again,
that a VNC console opens the
VM of the agent it was picked for when another tenant's VM shares its
unique_id, that an edit started before a switch never opens its dialog,
that only a writable Global Admin's switch is sent to the hub, and that the
redraw never leaves the old tenant's rows or ClearPass tiles on screen."""
import json
import os
from urllib.parse import parse_qs, urlparse

import pytest

from access import _norm_tenant_id
from test_webui_browser_smoke import APP_READY, hub_url_and_session  # noqa: F401 (fixture)

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
    page.wait_for_function(APP_READY)
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


# ── setTenant itself (#2028 items 24 and 30) ──────────────────────────────────

def _hold_tenant_posts(page):
    """Hold every POST /setup/tenant until the test answers it; returns the
    held routes in the order the page sent them."""
    held = []
    page.route("**/setup/tenant", lambda r: held.append(r))
    return held


def _held_for(page, held, tenant):
    """The held POST that switches to `tenant`, once the page has sent it."""
    for _ in range(100):
        for r in held:
            if json.loads(r.request.post_data or "{}").get("tenant_id") == tenant:
                return r
        page.wait_for_timeout(50)
    raise AssertionError(f"setTenant never sent POST /setup/tenant for {tenant!r}")


def _spy_redraws(page):
    """Record setTenant's redraws (setSubView, setView and the Managed Devices
    follow) instead of running them. renderView still rebuilds the page from
    its template."""
    page.evaluate("""() => {
        window.__redraws = [];
        window.__follows = [];
        window.setSubView = (...a) => { window.__redraws.push(['sub', ...a]); };
        window.setView = (...a) => { window.__redraws.push(['view', ...a]); };
        window._mdFollowTenant = t => { window.__follows.push(t); };
    }""")


def _inert(page):
    return page.evaluate("document.getElementById('page-content').hasAttribute('inert')")


def _mouse_click(page, selector):
    """A real mouse click in the middle of `selector`: `inert` ignores it,
    while a synthetic dispatchEvent would get through. Toasts let the click
    through: the test hub never reports ready, so /status answers 503 and the
    "Hub busy" toast can land over the header at any moment of the boot."""
    page.evaluate("_lmToastRegion().style.pointerEvents = 'none'")
    box = page.locator(selector).first.bounding_box()
    page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)


def test_the_page_takes_no_clicks_until_a_tenant_switch_lands(hub_url_and_session):  # noqa: F811
    """Until the switch lands the page still shows the old tenant, so a click
    on it must do nothing (item 24): here a tenant chip, which would otherwise
    list that tenant's devices. Real mouse input: `inert` ignores it, while a
    synthetic dispatchEvent would get through."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        held = _hold_tenant_posts(page)
        page.evaluate("() => { setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")
        assert _inert(page)

        _mouse_click(page, "#all-devices-tabs .sub-nav-item:has-text('DXP')")
        assert _listed(page) == [], "a click reached the page during the tenant switch"

        post.fulfill(content_type="application/json", body="{}")
        page.wait_for_function("!document.getElementById('page-content').hasAttribute('inert')")
        page.wait_for_function("!document.querySelector('#all-devices-list .animate-pulse')")
        _click(page, "DXP")
        assert _listed(page) == ["fw-dxp", "sw-dxp"]
        assert not errors


def _posted(held):
    """The tenants of the held POSTs /setup/tenant, in the order they were sent."""
    return [json.loads(r.request.post_data)["tenant_id"] for r in held]


def test_only_the_latest_tenant_switch_unlocks_and_redraws(hub_url_and_session):  # noqa: F811
    """A Global Admin's switches reach the hub one at a time, in order: the hub
    records the active tenant in the order the POSTs arrive, so two in flight
    at once could leave it on the older pick. A newer pick waits for the older
    POST's answer, which must not unlock or redraw the page; the newer switch
    then does both, once. A pick overtaken before its turn is never sent."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        held = _hold_tenant_posts(page)
        _spy_redraws(page)

        page.evaluate("() => { window.__a = setTenant('dxp'); }")
        older = _held_for(page, held, "dxp")
        page.evaluate("() => { window.__b = setTenant('lrb'); }")
        page.wait_for_timeout(300)
        assert _posted(held) == ["dxp"], "the newer POST went out before the older one was answered"
        older.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__a") is False
        newer = _held_for(page, held, "lrb")
        assert _inert(page), "the older switch unlocked the page the newer one still owns"
        assert page.evaluate("window.__redraws") == []
        newer.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__b") is True
        assert not _inert(page)
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert page.evaluate("window.__follows") == ["lrb"]

        # Three quick picks: the middle one is overtaken while it waits for its
        # turn, so the hub gets only the first and the last.
        held.clear()
        page.evaluate("() => { window.__redraws = []; window.__follows = []; window.__a = setTenant('dxp'); }")
        first = _held_for(page, held, "dxp")
        page.evaluate("() => { window.__b = setTenant('lrb'); window.__c = setTenant('default'); }")
        first.fulfill(content_type="application/json", body="{}")
        _held_for(page, held, "default").fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => Promise.all([window.__a, window.__b, window.__c])") == [False, False, True]
        assert _posted(held) == ["dxp", "default"]
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert page.evaluate("window.__follows") == ["default"]
        assert page.evaluate("currentTenant") == "default"
        assert not errors


@pytest.mark.parametrize("failing", ["storage", "follow"])
def test_a_tenant_switch_redraws_the_page_when_a_step_fails(hub_url_and_session, failing):  # noqa: F811
    """A step that throws after currentTenant moved (storage full or blocked,
    the Managed Devices follow) must not leave the old tenant's page on screen
    or the page locked: the switch still records the tenant and redraws
    (item 30)."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        posted = []
        page.route("**/setup/tenant", lambda r: (posted.append(r.request.post_data),
                                                 r.fulfill(content_type="application/json", body="{}")))
        _spy_redraws(page)
        if failing == "storage":
            page.evaluate("() => { Storage.prototype.setItem = () => { "
                          "throw new DOMException('full', 'QuotaExceededError'); }; }")
        else:
            page.evaluate("() => { window._mdFollowTenant = () => { throw new Error('boom'); }; }")

        outcome = page.evaluate("setTenant('lrb').then(() => 'done', e => 'threw: ' + e)")
        assert outcome == "done"
        assert len(posted) == 1 and json.loads(posted[0])["tenant_id"] == "lrb"
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert not _inert(page)
        assert not errors


def test_an_older_prefix_reply_landing_last_does_not_win(hub_url_and_session):  # noqa: F811
    """A tenant-admin's client-side subnet filter follows the tenant picked
    last, even when the reply for the tenant picked before it lands later."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=TA_FIREWALLS, nw_devices=[], tenant_admin=True)
        held = {}
        page.route("**/auth/prefixes*", lambda r: held.__setitem__(r.request.url.rsplit("=", 1)[-1], r))
        page.evaluate("() => { currentTenant = 'dxp'; window.__a = loadTenantPrefixes(); "
                      "currentTenant = 'lrb'; window.__b = loadTenantPrefixes(); }")
        for _ in range(100):
            if {"dxp", "lrb"} <= held.keys():
                break
            page.wait_for_timeout(50)
        held["lrb"].fulfill(content_type="application/json", body=json.dumps({"prefixes": ["10.2.0.0/16"]}))
        page.evaluate("() => window.__b")
        held["dxp"].fulfill(content_type="application/json", body=json.dumps({"prefixes": ["10.1.0.0/16"]}))
        page.evaluate("() => window.__a")
        assert page.evaluate("_tenantPrefixes") == ["10.2.0.0/16"]
        assert not errors


def test_a_tenant_admins_switch_stays_in_the_page(hub_url_and_session):  # noqa: F811
    """The hub takes POST /setup/tenant only from a Global Admin, so a
    tenant-admin's switch sends none and waits only for the subnet filter. Of
    two quick switches the latest keeps its filter and redraws the page, once,
    even when the older switch's filter answers last."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, firewalls=TA_FIREWALLS, nw_devices=[], tenant_admin=True)
        posts = []
        page.route("**/setup/tenant", lambda r: (posts.append(r.request.post_data), r.fulfill(
            status=403, content_type="application/json", body='{"detail": "Admin access required"}')))
        held = {}
        page.route("**/auth/prefixes*", lambda r: held.__setitem__(r.request.url.rsplit("=", 1)[-1], r))
        _spy_redraws(page)
        page.evaluate("() => { window.__a = setTenant('dxp'); window.__b = setTenant('lrb'); }")
        for _ in range(100):
            if {"dxp", "lrb"} <= held.keys():
                break
            page.wait_for_timeout(50)
        assert _inert(page)

        held["lrb"].fulfill(content_type="application/json", body=json.dumps({"prefixes": ["10.2.0.0/16"]}))
        assert page.evaluate("() => window.__b") is True
        held["dxp"].fulfill(content_type="application/json", body=json.dumps({"prefixes": ["10.1.0.0/16"]}))
        assert page.evaluate("() => window.__a") is False
        assert page.evaluate("_tenantPrefixes") == ["10.2.0.0/16"]
        assert page.evaluate("window.__redraws") == [["view", "mydevices"]]
        assert not _inert(page)
        assert posts == []
        assert not errors


def _header(page):
    """The tenant the header shows: the chip's label, and the tenants the
    picker marks in bold."""
    return page.evaluate("""() => [
        document.getElementById('user-chip-tenant').textContent,
        [...document.querySelectorAll('#tenant-picker-menu button[data-tid].font-bold')]
            .map(b => b.dataset.tid)]""")


def test_the_header_names_the_latest_tenant_pick(hub_url_and_session):  # noqa: F811
    """Two quick picks in the header's tenant picker: the header (the chip's
    label and the bold item) names the latest pick from the moment it is
    made, and still does after the older pick's switch lands."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__a = viewAsTenant('dxp'); }")
        older = _held_for(page, held, "dxp")
        page.evaluate("() => { window.__b = viewAsTenant('lrb'); }")
        assert _header(page) == ["LRB", ["lrb"]]

        older.fulfill(content_type="application/json", body="{}")
        page.evaluate("() => window.__a")
        assert _header(page) == ["LRB", ["lrb"]]
        _held_for(page, held, "lrb").fulfill(content_type="application/json", body="{}")
        page.evaluate("() => window.__b")
        assert page.evaluate("currentTenant") == "lrb"
        assert _header(page) == ["LRB", ["lrb"]]
        assert not errors


def test_the_views_action_buttons_take_no_clicks_during_a_switch(hub_url_and_session):  # noqa: F811
    """A view's action buttons sit above #viewport, in #top-nav-actions (DNS
    "+ Add Record" opens a form that writes). They take no clicks during a
    switch either, also once a navigation has rebuilt that strip. The header's
    tenant picker stays usable, so the user can pick again."""
    base, token = hub_url_and_session
    add_button = ("() => { document.getElementById('top-nav-actions').innerHTML = "
                  "'<button id=\"t-add\" onclick=\"window.__adds = (window.__adds || 0) + 1\">+ Add</button>'; }")
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-wrap > button")
        held = _hold_tenant_posts(page)
        page.evaluate("() => { setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")

        page.evaluate(add_button)
        _mouse_click(page, "#t-add")
        page.evaluate("renderTopNav(currentView)")  # as navigating does
        page.evaluate(add_button)
        _mouse_click(page, "#t-add")
        assert page.evaluate("window.__adds || 0") == 0, "an action button took a click during the switch"
        _mouse_click(page, "#tenant-picker-wrap > button")
        assert page.is_visible("#tenant-picker-menu"), "the tenant picker did not open during the switch"

        page.evaluate("closeTenantPicker()")
        post.fulfill(content_type="application/json", body="{}")
        page.wait_for_function("!document.getElementById('page-content').hasAttribute('inert')")
        page.evaluate(add_button)
        _mouse_click(page, "#t-add")
        assert page.evaluate("window.__adds || 0") == 1
        assert not errors


def _toasts(page):
    """The texts of the toasts on screen."""
    return page.evaluate("[...document.querySelectorAll('.lm-toast')].map(t => t.textContent)")


def _answer(status, body):
    """A route handler answering `status` with the JSON `body`."""
    return lambda r: r.fulfill(status=status, content_type="application/json", body=json.dumps(body))


def _fake_tickets(page, *answers):
    """Answer the switch's POST /setup/tenant/switch-ticket calls in turn: the
    n-th call gets the n-th of `answers`, and the last one stands for every
    call after. A tenant id answers as the hub does, {"ticket": "t<n>",
    "active_tenant": <id>}; "abort" gives no answer; a number refuses with
    that HTTP status. Returns the answers the calls got, in order."""
    calls = []

    def handle(route):
        """Give this call the next answer, and record it."""
        answer = answers[min(len(calls), len(answers) - 1)]
        calls.append(answer)
        if answer == "abort":
            route.abort()
        elif isinstance(answer, int):
            _answer(answer, {"detail": f"refused with {answer}"})(route)
        else:
            _answer(200, {"ticket": f"t{len(calls)}", "active_tenant": answer})(route)
    page.route("**/setup/tenant/switch-ticket", handle)
    return calls


def _scoping_reads(page, tenant):
    """Answer GET /api/tenant/scoping as naming `tenant`; returns the reads
    made. A switch must not use it: a failed POST could still move the hub
    after that read."""
    reads = []
    page.route("**/api/tenant/scoping*", lambda r: (reads.append(r.request.url),
                                                    _answer(200, {"tenant_id": tenant})(r)))
    return reads


@pytest.mark.parametrize("failure", ["refused", "network", "timeout"])
def test_a_switch_the_hub_does_not_take_goes_back_to_the_hubs_tenant(  # noqa: F811
        hub_url_and_session, failure):
    """A Global Admin's switch that the hub refuses, or does not answer in time,
    must not leave the page on the pick: the hub would scope the page's reads
    by its own tenant while the page named another. After the failed POST the
    page gets exactly one more switch ticket, which voids the POST's ticket so
    the POST cannot move the hub later, and goes back to the tenant the hub
    names with it ("dxp", as stored). It never takes the tenant named with the
    ticket before the POST (here the pick: another admin may have moved the hub
    since), nor reads GET /api/tenant/scoping. The page says so, unlocks and
    redraws, and the next switch still goes through."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        assert page.evaluate("setTenant('dxp')") is True
        tickets = _fake_tickets(page, "lrb", "dxp")
        reads = _scoping_reads(page, "lrb")
        if failure == "refused":
            page.route("**/setup/tenant", _answer(500, {"detail": "could not save the state"}))
            reason = "(could not save the state)"
        elif failure == "network":
            page.route("**/setup/tenant", lambda r: r.abort())
            reason = "(Failed to fetch)"
        else:
            _hold_tenant_posts(page)
            page.evaluate("_lmTenantSwitchMs = 500")
            reason = "(no answer from the hub within"
        _spy_redraws(page)

        assert page.evaluate("setTenant('lrb')") is False
        assert tickets == ["lrb", "dxp"], "the failed switch did not get exactly one more ticket"
        assert reads == [], "the switch read GET /api/tenant/scoping"
        assert any("Could not switch to LRB; the page is back on DXP " + reason in t for t in _toasts(page))
        assert page.evaluate("currentTenant") == "dxp"
        assert _header(page) == ["DXP", ["dxp"]]
        assert page.evaluate("localStorage.getItem('lm_tenant')") == "dxp"
        assert not _inert(page)
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert page.evaluate("window.__follows") == ["dxp"]

        page.route("**/setup/tenant", _answer(200, {}))
        assert page.evaluate("setTenant('lrb')") is True
        assert page.evaluate("currentTenant") == "lrb"
        assert not errors


def test_a_switch_the_hub_took_despite_an_error_lands(hub_url_and_session):  # noqa: F811
    """A POST whose answer is lost (a proxy's 502) may still have been applied.
    When the fresh ticket after it names the pick (the hub makes active the
    stored id a switch names, the id the picker lists), the switch landed: no
    error, and the page stays on the pick."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        page.route("**/setup/tenant", lambda r: r.fulfill(status=502, content_type="text/html", body="Bad Gateway"))
        _fake_tickets(page, "dxp", "lrb")
        _spy_redraws(page)
        assert page.evaluate("setTenant('lrb')") is True
        assert not any("Could not switch" in t for t in _toasts(page))
        assert page.evaluate("[currentTenant, localStorage.getItem('lm_tenant')]") == ["lrb", "lrb"]
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert not errors


def test_a_switch_sends_the_ticket_it_got_just_before_its_post(hub_url_and_session):  # noqa: F811
    """A Global Admin's switch first gets a ticket from the hub (POST
    /setup/tenant/switch-ticket) and sends it with its POST /setup/tenant: the
    hub applies the switch only while that ticket is the latest one issued.
    Each switch gets its own, and one that lands asks for no other."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        tickets = _fake_tickets(page, "dxp")
        posts = []

        def post(route):
            """Record the pick, the ticket it carries and how many tickets
            were issued by then; the hub takes the switch."""
            body = json.loads(route.request.post_data)
            posts.append((body["tenant_id"], body.get("switch_ticket"), len(tickets)))
            route.fulfill(content_type="application/json", body="{}")
        page.route("**/setup/tenant", post)
        assert page.evaluate("setTenant('lrb')") is True
        assert page.evaluate("setTenant('dxp')") is True
        assert posts == [("lrb", "t1", 1), ("dxp", "t2", 2)]
        assert len(tickets) == 2
        assert not errors


@pytest.mark.parametrize("failure", ["refused", "network"])
def test_a_switch_the_hub_gives_no_ticket_sends_no_post(hub_url_and_session, failure):  # noqa: F811
    """When the hub gives no ticket before the POST (it refuses, or the call
    fails), the switch sends no POST /setup/tenant: one without a ticket would
    be applied whenever it reached the hub. The page then gets one more ticket
    and goes to the tenant the hub names with it, as after any failed switch."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        assert page.evaluate("setTenant('dxp')") is True
        first = 500 if failure == "refused" else "abort"
        tickets = _fake_tickets(page, first, "dxp")
        posts = []
        page.route("**/setup/tenant", lambda r: (posts.append(r.request.post_data), _answer(200, {})(r)))
        _spy_redraws(page)

        assert page.evaluate("setTenant('lrb')") is False
        assert posts == [], "a switch with no ticket sent its POST"
        assert tickets == [first, "dxp"]
        reason = "(refused with 500)" if failure == "refused" else "(Failed to fetch)"
        assert any("Could not switch to LRB; the page is back on DXP " + reason in t for t in _toasts(page))
        assert page.evaluate("[currentTenant, localStorage.getItem('lm_tenant')]") == ["dxp", "dxp"]
        assert not _inert(page)
        assert not errors


def test_a_failed_switch_a_newer_pick_waits_on_asks_for_no_more_tickets(hub_url_and_session):  # noqa: F811
    """A newer pick waits behind a switch whose POST then fails. The failed
    switch asks for no ticket after its POST: the newer pick's own ticket voids
    the failed POST's, and the newer POST decides the hub's tenant. So the hub
    issues exactly two tickets, one for each pick, and the newer POST carries
    the second."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        tickets = _fake_tickets(page, "dxp")
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__a = setTenant('lrb'); }")
        older = _held_for(page, held, "lrb")
        page.evaluate("() => { window.__b = setTenant('dxp'); }")
        older.fulfill(status=500, content_type="application/json", body='{"detail": "could not save the state"}')
        newer = _held_for(page, held, "dxp")
        assert tickets == ["dxp", "dxp"], f"want one ticket per pick and none after the failed POST, got {tickets}"
        assert json.loads(newer.request.post_data).get("switch_ticket") == "t2"
        newer.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__a") is False
        assert page.evaluate("() => window.__b") is True
        assert len(tickets) == 2
        assert page.evaluate("currentTenant") == "dxp"
        assert not errors


def test_a_sign_in_switch_nothing_confirms_keeps_the_page_locked(hub_url_and_session):  # noqa: F811
    """At sign-in no switch has landed yet, so the page does not know which
    tenant the hub is on. When that first switch fails and the fresh ticket
    after it gets no answer either, nothing confirms any tenant, and showing
    the pick would let the hub scope the page's reads by another tenant under
    its name. The page stays locked, says so, and does not remember the pick
    for the next visit. Picking a tenant again retries, and the page unlocks
    once a switch lands."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        context = p.chromium.launch().new_context()
        context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.route("**/setup/tenants", _answer(200, {"tenants": _keyed(TENANTS, "id")}))
        page.route("**/setup/tenant", _answer(500, {"detail": "could not save the state"}))
        # The ticket before the POST is answered, so the POST is sent and
        # fails; the one after it gets no answer; the retry's is answered.
        tickets = _fake_tickets(page, "dxp", "abort", "dxp")
        page.goto(base + "/")
        page.wait_for_function("[...document.querySelectorAll('.lm-toast')]"
                               ".some(t => t.textContent.includes('did not say which tenant'))")
        assert any("(could not save the state), and the hub did not say which tenant it is on,"
                   " so the page stays dimmed. Pick a tenant again" in t for t in _toasts(page))
        assert tickets == ["dxp", "abort"]
        assert _inert(page)
        assert page.evaluate("localStorage.getItem('lm_tenant')") is None

        page.route("**/setup/tenant", _answer(200, {}))
        assert page.evaluate("setTenant('lrb')") is True
        assert not _inert(page)
        assert page.evaluate("[currentTenant, localStorage.getItem('lm_tenant')]") == ["lrb", "lrb"]
        assert not errors


def _asked(page, call):
    """What the confirm or prompt `call` answers, or "asked" when it is still
    waiting for the user a second later."""
    return page.evaluate(f"Promise.race([{call}, new Promise(r => setTimeout(() => r('asked'), 1000))])")


@pytest.mark.parametrize("failure", ["refused", "timeout"])
@pytest.mark.parametrize("pick", ["lrb", "dxp"])
def test_a_failed_switch_the_hub_cannot_confirm_keeps_the_page_locked(  # noqa: F811
        hub_url_and_session, failure, pick):
    """The page landed on "lrb" earlier. A later switch that the hub refuses,
    or does not answer in time, while the fresh ticket asked for after it
    gets no answer, leaves nothing that says which tenant the hub is on now.
    The tenant the page landed on, and the one the hub named with the ticket
    before the POST ("lrb" both), prove nothing: the POST may have moved the
    hub all the same, and another admin may have moved it since. GET
    /api/tenant/scoping would name the pick, but a failed POST could still
    move the hub after that read, so the switch does not ask it. The page
    stays locked, says so, is not redrawn, and a confirm asked meanwhile
    answers Cancel, whether the pick is the tenant the page landed on ("lrb")
    or another ("dxp"). Picking a tenant again retries, and the page unlocks
    once a switch lands."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        assert page.evaluate("setTenant('lrb')") is True
        tickets = _fake_tickets(page, "lrb", "abort", "lrb")
        reads = _scoping_reads(page, pick)
        if failure == "refused":
            page.route("**/setup/tenant", _answer(500, {"detail": "could not save the state"}))
            reason = "(could not save the state)"
        else:
            _hold_tenant_posts(page)
            page.evaluate("_lmTenantSwitchMs = 500")
            reason = "(no answer from the hub within"
        _spy_redraws(page)

        assert page.evaluate(f"setTenant('{pick}')") is False
        assert any(f"Could not switch to {pick.upper()} {reason}" in t
                   and "did not say which tenant it is on, so the page stays dimmed. Pick a tenant again" in t
                   for t in _toasts(page)), _toasts(page)
        assert _inert(page), "the page unlocked for a tenant the hub did not confirm"
        assert tickets == ["lrb", "abort"] and reads == []
        assert page.evaluate("[window.__redraws, window.__follows]") == [[], []]
        assert page.evaluate("localStorage.getItem('lm_tenant')") == "lrb"
        assert _asked(page, "showConfirmToast('Delete?')") is False

        page.route("**/setup/tenant", _answer(200, {}))
        assert page.evaluate("setTenant('dxp')") is True
        assert not _inert(page)
        assert page.evaluate("[currentTenant, localStorage.getItem('lm_tenant')]") == ["dxp", "dxp"]
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert not errors


@pytest.mark.parametrize("kind", ["confirm", "prompt"])
def test_a_prompt_open_when_a_switch_starts_answers_cancel(hub_url_and_session, kind):  # noqa: F811
    """A confirm or prompt toast sits on <body>, outside the page a switch
    locks, and its button runs the action the old tenant's page asked about:
    delete a rack (a DELETE), reset a NetBox admin password (a command). A
    switch does not drop writes, so pressing it during the switch would act
    while the header names the new tenant. The switch answers Cancel for every
    open confirm and prompt and takes it away, so the action never runs."""
    base, token = hub_url_and_session
    if kind == "confirm":
        action, url, button = "deleteNetboxRack(7)", "**/api/netbox/racks/7", "Confirm"
    else:
        action, url, button = "resetNetboxAdmin('s-lrb')", "**/api/agent/*/command", "Reset"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        writes = []

        def write(route):
            writes.append(route.request.method)
            route.fulfill(content_type="application/json", body='{"status": "SUCCESS"}')
        page.route(url, write)
        page.evaluate(f"() => {{ window.__done = {action}.then(() => 'done'); }}")
        ok = page.locator(".lm-toast button", has_text=button)
        ok.wait_for()
        if kind == "prompt":
            page.fill(".lm-toast input", "abcd")
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__sw = setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")

        # The operator presses the button once the switch has started.
        pressed = ok.count() > 0
        if pressed:
            ok.click()
        assert page.evaluate("() => window.__done") == "done"
        assert writes == [], "the old page's action ran during the tenant switch"
        assert not pressed, "the old page's prompt stayed on screen during the switch"

        post.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__sw") is True
        assert not errors


DRY_RUN = {"groups": [{"primary": {"name": "sw1"}, "merged": [{"name": "sw1"}], "unconfirmed": []}],
           "removed": 1}


def test_a_confirm_asked_during_a_switch_answers_cancel(hub_url_and_session):  # noqa: F811
    """An action the old page started before the switch can ask its confirm
    during it: merging duplicate devices sends its dry run (a POST, which a
    switch does not drop), then asks whether to merge. Asked while the page is
    locked, a confirm or prompt answers Cancel at once and says so, as nothing
    may confirm the old page's action while the header names another tenant.
    Once the switch lands, the merge asks as before."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        dedupe = []

        def on_dedupe(route):
            dedupe.append(route)
            if len(dedupe) > 1:
                route.fulfill(content_type="application/json", body=json.dumps(DRY_RUN))
        page.route("**/setup/nw-devices/dedupe", on_dedupe)
        page.evaluate("() => { window.__merge = mergeDuplicateDevices().then(() => 'done'); }")
        for _ in range(100):
            if dedupe:
                break
            page.wait_for_timeout(50)
        assert dedupe, "the merge never sent its dry run"
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__sw = setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")

        dedupe[0].fulfill(content_type="application/json", body=json.dumps(DRY_RUN))
        assert _asked(page, "window.__merge") == "done", "the merge's confirm waited for the user mid-switch"
        assert page.locator(".lm-toast button", has_text="Confirm").count() == 0
        assert any("Cancelled: the page is switching tenant" in t for t in _toasts(page))
        assert _asked(page, "showPromptToast('Password?')") is None
        assert [json.loads(r.request.post_data)["apply"] for r in dedupe] == [False]

        post.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__sw") is True
        page.evaluate("() => { mergeDuplicateDevices(); }")
        page.locator(".lm-toast button", has_text="Confirm").wait_for()
        assert [json.loads(r.request.post_data)["apply"] for r in dedupe] == [False, False]
        assert not errors


def test_a_switch_closes_the_old_pages_dialogs_and_menus(hub_url_and_session):  # noqa: F811
    """A dialog or menu the old page opened on <body> sits outside the page a
    switch locks, and its Save or its items act on what it was opened for. A
    switch closes each one, as its own Close does: the rack editor, an
    openModal dialog, a VM action menu, a dialog mounted by hand. It keeps the
    page frame, the sign-in screen, the cache bar, the toasts and error
    banners. After the switch the rack editor opens as before."""
    base, token = hub_url_and_session
    rack = "{id: 7, name: 'R1', site: 'Lab A', u_height: 42}"
    closed = ["nb-rack-modal", "t-modal", "pxmx-vm-action-menu", "t-dialog"]
    kept = ["page-content", "login-overlay", "cache-status-bar", "lm-toast-region", "t-alert"]
    present = "ids => ids.filter(id => document.getElementById(id))"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.route("**/api/netbox/sites", _answer(200, {"sites": [{"id": 1, "name": "Lab A", "slug": "lab-a"}]}))
        page.evaluate(f"showNetboxRackModal({rack})")
        page.evaluate("""() => {
            openModal('t-modal', '<button>Save</button>');
            _pxmxVmActionMenuEl().classList.remove('hidden');
            const dialog = document.createElement('div');
            dialog.id = 't-dialog';
            dialog.innerHTML = '<button>Save</button>';
            document.body.appendChild(dialog);
            const banner = document.createElement('div');
            banner.id = 't-alert';
            banner.setAttribute('role', 'alert');
            document.body.appendChild(banner);
            _lmToastRegion();
        }""")
        assert page.evaluate(present, closed + kept) == closed + kept
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__sw = setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")
        assert page.evaluate(present, closed + kept) == kept, "a dialog or menu stayed open during the switch"
        assert page.evaluate("document.querySelectorAll('body > header, body > footer').length") == 2

        post.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__sw") is True
        page.evaluate(f"showNetboxRackModal({rack})")
        assert page.evaluate("document.getElementById('nb-rack-modal').dataset.rackId") == "7"
        assert not errors


# What a switch keeps open on <body> (main.js _LM_KEPT_ON_SWITCH).
KEPT_ON_SWITCH = ["pxmx-vnc-modal", "pxmx-vnc-dock-pill", "serial-console-modal", "serial-console-dock-pill",
                  "cs-dongle-watch", "lm-help-backdrop", "lm-help-drawer", "file-bug-modal",
                  "impersonation-banner"]


def test_what_a_switch_keeps_open_takes_no_input_until_it_lands(hub_url_and_session):  # noqa: F811
    """What a switch keeps open on <body> (the console docks and their pills,
    the dongle watch, Help, the bug report, the impersonation banner) is not
    the header tenant's data, apart from the docks' lists of consoles to open,
    which the switch drops (the dock tests below), so the switch does not
    close it. Like the page, it takes no input until the switch lands. Help's
    backdrop and drawer are the real ones (help.js builds them, closed, when
    the page loads); each other element is a stand-in with a button, and a
    real click on each of those does nothing during the switch and counts
    once after it."""
    base, token = hub_url_and_session
    inert = "ids => ids.filter(id => document.getElementById(id).hasAttribute('inert'))"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        # A small panel side by side over the page for each element the page
        # has not built yet.
        built = page.evaluate("""ids => ids.filter(id => !document.getElementById(id)).map((id, i) => {
            const el = document.createElement('div');
            el.id = id;
            el.style.cssText = `position:fixed;z-index:60;left:${400 + (i % 3) * 140}px;`
                + `top:${250 + Math.floor(i / 3) * 60}px`;
            el.innerHTML = '<button style="width:120px;height:40px">Open</button>';
            el.firstChild.addEventListener('click', () => { window.__clicks = (window.__clicks || 0) + 1; });
            document.body.appendChild(el);
            return id;
        })""", KEPT_ON_SWITCH)
        assert "pxmx-vnc-modal" in built and "file-bug-modal" in built
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__sw = setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")
        assert page.evaluate(inert, KEPT_ON_SWITCH) == KEPT_ON_SWITCH
        for element in built:
            _mouse_click(page, f"#{element} button")
        assert page.evaluate("window.__clicks || 0") == 0, "a kept element took a click during the switch"

        post.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__sw") is True
        assert page.evaluate(inert, KEPT_ON_SWITCH) == []
        for element in built:
            _mouse_click(page, f"#{element} button")
        assert page.evaluate("window.__clicks || 0") == len(built)
        assert not errors


def _by_tenant(page, pattern, answers):
    """Answer each read of `pattern` by the tenant its ?tenant= names, from
    `answers`: a JSON body, a status to fail with, or a list to hold the read
    in until the test answers it. A tenant not in `answers` gets an empty
    body."""
    def handle(route):
        """Answer, fail or hold one read."""
        answer = answers.get(parse_qs(urlparse(route.request.url).query).get("tenant", [""])[0], {})
        if isinstance(answer, list):
            answer.append(route)
        elif isinstance(answer, int):
            _answer(answer, {"detail": "failed"})(route)
        else:
            _answer(200, answer)(route)
    page.route(pattern, handle)


def _first_held(page, held):
    """The first read held in `held`, once the page has sent it."""
    for _ in range(100):
        if held:
            return held[0]
        page.wait_for_timeout(50)
    raise AssertionError("the page never sent the read")


def _rows(page, rows):
    """[key, open] of each row of a console dock's list."""
    return page.evaluate("s => [...document.querySelectorAll(s)].map(r => [r.dataset.key, r.dataset.open])", rows)


def _switch_to_lrb(page, dock, rows):
    """Switch to lrb. Read the moment setTenant is done, while the switch's
    own reads may still be on their way: whether the page or `dock` still
    takes no input, and the dock's rows."""
    return page.evaluate("""async ([dock, rows]) => {
        const ok = await setTenant('lrb');
        const locked = ['page-content', dock].some(id => document.getElementById(id).hasAttribute('inert'));
        return {ok, locked, rows: [...document.querySelectorAll(rows)].map(r => [r.dataset.key, r.dataset.open])};
    }""", [dock, rows])


def _port(spoke, port, alias):
    """A console port as /api/console/ports lists it."""
    return {"spoke_id": spoke, "port_id": port, "alias": alias, "present": True}


def _fail_a_switch_step(page):
    """Make a step of the next switch fail: _mdFollowTenant, the last step
    before the page is unlocked, throws. The switch still lands and unlocks
    the page."""
    page.evaluate("() => { window._mdFollowTenant = () => { throw new Error('a failed step'); }; }")


@pytest.mark.parametrize("read", ["failed", "held", "after-a-failed-step"])
def test_a_switch_drops_the_old_tenants_serial_consoles_before_it_unlocks(  # noqa: F811
        hub_url_and_session, read):
    """The serial console dock floats over every view, and a switch keeps it
    and its open sessions. Besides those it lists the tenant's consoles that
    can be opened, each opened by a click, and they are the old tenant's. So
    they must be gone once the switch unlocks the page, while the new
    tenant's list is still being read (held) and after that read fails; the
    open session stays. The same holds when a step of the switch failed, as
    the page is unlocked then too (after-a-failed-step, with the read held).
    The new tenant's consoles are listed once their read answers. The open
    session is a stand-in, as a real one needs a console server."""
    base, token = hub_url_and_session
    held = []
    answers = {"dxp": {"ports": [_port("c1", "a1", "DXP-1"), _port("c1", "a2", "DXP-2")]},
               "lrb": 500 if read == "failed" else held}
    rows = "#serial-console-list .serial-console-row"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        _by_tenant(page, "**/api/console/ports*", answers)
        page.evaluate("setTenant('dxp')")
        page.evaluate("serialEnsureConsoleDock()")
        page.wait_for_function("s => document.querySelectorAll(s).length === 2", arg=rows)
        page.evaluate("""() => {
            window._serialConsoles = window._serialConsoles || new Map();
            window._serialConsoles.set('c1::a2', {key: 'c1::a2', spokeId: 'c1', portId: 'a2',
                                                  label: 'DXP-2', statusCls: 'text-green-400'});
            serialRenderConsoleList();
        }""")
        assert _rows(page, rows) == [["c1::a2", "1"], ["c1::a1", "0"]]

        if read == "after-a-failed-step":
            _fail_a_switch_step(page)
        after = _switch_to_lrb(page, "serial-console-modal", rows)
        assert after["ok"] is True and after["locked"] is False
        assert after["rows"] == [["c1::a2", "1"]], "the old tenant's consoles stayed in the dock after the switch"
        if read == "failed":
            page.wait_for_timeout(300)
            assert _rows(page, rows) == [["c1::a2", "1"]]
        else:
            _first_held(page, held).fulfill(content_type="application/json",
                                            body=json.dumps({"ports": [_port("c2", "b1", "LRB-1")]}))
            page.wait_for_function("s => document.querySelectorAll(s).length === 2", arg=rows)
            assert _rows(page, rows) == [["c1::a2", "1"], ["c2::b1", "0"]]
        assert not errors


def _vm(uid, name, agent):
    """A VM as /api/pxmx/vms lists it: on the agent `agent`, with the vmid and
    node its unique_id names."""
    parts = uid.split("/")
    return {"unique_id": uid, "vmid": int(parts[-1]), "node": parts[-2], "name": name, "type": "qemu",
            "status": "running", "agent_id": agent}


@pytest.mark.parametrize("read", ["failed", "held", "overtaken", "after-a-failed-step"])
def test_a_switch_drops_the_old_tenants_vms_from_the_vnc_search(hub_url_and_session, read):  # noqa: F811
    """The VNC console dock lists its open sessions and, while a search is
    typed, the tenant's VMs that match it, each opened by a click. A switch
    keeps the dock, its open sessions and the search, but the old tenant's
    VMs must be gone once it unlocks the page: while the new tenant's
    directory is still being read (held), after that read fails, when the
    old tenant's read was still on its way at the switch and answers after
    it (overtaken), and when a step of the switch failed (after-a-failed-
    step, with the read held). The open session stays, and the new tenant's
    VMs are listed once their read answers. The open session is a stand-in,
    as a real one needs a VM. Rows are keyed by agent and VM
    (pxmxConsoleKey)."""
    base, token = hub_url_and_session
    held_dxp, held_lrb = [], []
    dxp = {"vms": [_vm("pve/101", "dxp-vm-1", "ag-dxp")], "template_pools": []}
    lrb = {"vms": [_vm("pve/201", "lrb-vm-1", "ag-lrb")], "template_pools": []}
    answers = {"dxp": held_dxp if read == "overtaken" else dxp,
               "lrb": {"failed": 500, "overtaken": lrb}.get(read, held_lrb)}
    rows = "#pxmx-vnc-list .pxmx-vnc-row"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        _by_tenant(page, "**/api/pxmx/vms*", answers)
        page.evaluate("setTenant('dxp')")
        page.evaluate("""() => {
            pxmxEnsureConsoleDock();
            window._pxmxConsoles = window._pxmxConsoles || new Map();
            window._pxmxConsoles.set('ag-dxp|pve/102', {statusCls: 'text-green-400', vm: {
                unique_id: 'pve/102', vmid: 102, name: 'dxp-vm-2', agent_id: 'ag-dxp'}});
            const search = document.getElementById('pxmx-vnc-search');
            search.value = 'vm';
            search.dispatchEvent(new Event('input'));
        }""")
        if read == "overtaken":
            old = _first_held(page, held_dxp)
            assert _rows(page, rows) == [["ag-dxp|pve/102", "1"]]
        else:
            page.wait_for_function("s => document.querySelectorAll(s).length === 2", arg=rows)
            assert _rows(page, rows) == [["ag-dxp|pve/102", "1"], ["ag-dxp|pve/101", "0"]]

        if read == "after-a-failed-step":
            _fail_a_switch_step(page)
        after = _switch_to_lrb(page, "pxmx-vnc-modal", rows)
        assert after["ok"] is True and after["locked"] is False
        assert after["rows"] == [["ag-dxp|pve/102", "1"]], "the old tenant's VMs stayed in the dock after the switch"
        if read == "failed":
            page.wait_for_timeout(300)
            assert _rows(page, rows) == [["ag-dxp|pve/102", "1"]]
        else:
            if read == "overtaken":
                old.fulfill(content_type="application/json", body=json.dumps(dxp))
            else:
                _first_held(page, held_lrb).fulfill(content_type="application/json", body=json.dumps(lrb))
            page.wait_for_function("s => document.querySelectorAll(s).length === 2", arg=rows)
            assert _rows(page, rows) == [["ag-dxp|pve/102", "1"], ["ag-lrb|pve/201", "0"]]
        assert not errors


# Two tenants' VMs on independent clusters that share a unique_id
# ("<cluster>/<node>/<vmid>" names no agent): dxp's on agent-a, lrb's on agent-b.
A_VM = _vm("pve/pve/100", "dxp-vm-100", "agent-a")
B_VM = _vm("pve/pve/100", "lrb-vm-100", "agent-b")


def _mock_vnc(page):
    """Let the page open VNC consoles with no VM behind them: POST
    /api/pxmx/console answers a new session, the viewer roster is empty and
    noVNC is a stand-in. Returns the agent_id each console POST named, in
    order."""
    posted = []

    def start(route):
        """Answer one console POST with a new session."""
        posted.append(route.request.post_data_json.get("agent_id"))
        _answer(200, {"session_id": f"s-{len(posted)}", "ws_token": "t", "ticket": "", "read_only": False})(route)
    page.route("**/api/pxmx/console", start)
    page.route("**/api/pxmx/console/viewers*", _answer(200, {"viewers": []}))
    page.evaluate("""() => { window.__noVNCRFB = class extends EventTarget {
        constructor() { super(); }
        sendCredentials() {}
        disconnect() {}
        focus() {}
    }; }""")
    return posted


@pytest.mark.parametrize("via", ["search", "dashboard"])
def test_a_console_opens_the_vm_of_the_agent_it_was_picked_for(hub_url_and_session, via):  # noqa: F811
    """A VM's unique_id names no agent, so two tenants' clusters can share
    one. dxp's VM is open as a console, and is in the VM table's cache: it is
    put back there after the switch to lrb, which drops that cache, as a
    stand-in for any cache that still holds it, so this checks the console's
    identity itself. lrb's VM has the same unique_id. Picked in the console
    search (a real click on its row, which must be listed beside dxp's open
    console) or on the device dashboard, lrb's VM must get a console of its
    own on lrb's agent, not bring up dxp's. Opening dxp's VM again still
    brings up its open console, with no new session."""
    base, token = hub_url_and_session
    rows = "#pxmx-vnc-list .pxmx-vnc-row"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        posted = _mock_vnc(page)
        _by_tenant(page, "**/api/pxmx/vms*", {"lrb": {"vms": [B_VM], "template_pools": []}})
        page.evaluate("setTenant('dxp')")
        page.evaluate("vm => { window._pxmxVms = [vm]; return pxmxOpenConsole(vm.unique_id); }", A_VM)
        assert posted == ["agent-a"]
        assert page.evaluate("setTenant('lrb')") is True
        page.evaluate("vm => { window._pxmxVms = [vm]; }", A_VM)

        if via == "search":
            page.evaluate("""() => {
                const search = document.getElementById('pxmx-vnc-search');
                search.value = 'vm';
                search.dispatchEvent(new Event('input'));
            }""")
            page.wait_for_function("s => document.querySelectorAll(s).length === 2", arg=rows, timeout=5000)
            assert _rows(page, rows) == [["agent-a|pve/pve/100", "1"], ["agent-b|pve/pve/100", "0"]]
            page.click(f"{rows}[data-open='0']")
        else:
            page.evaluate("vm => ddOpenVnc(vm)", B_VM)
        page.wait_for_function("() => window._pxmxConsoles.size === 2", timeout=5000)
        assert posted == ["agent-a", "agent-b"]
        assert page.evaluate("pxmxActiveConsole().vm.agent_id") == "agent-b"

        page.evaluate("pxmxOpenConsole('pve/pve/100')")
        assert page.evaluate("pxmxActiveConsole().vm.agent_id") == "agent-a"
        assert posted == ["agent-a", "agent-b"]
        assert not errors


@pytest.mark.parametrize("read", ["held", "old-answer-late"])
def test_a_switch_drops_the_vm_table_cache(hub_url_and_session, read):  # noqa: F811
    """The Hypervisors page caches the tenant's VMs (window._pxmxVms), and
    the VM table's console and VM actions look a VM up there by unique_id,
    which names no agent. A switch drops that cache before it unlocks the
    page, and the redraw reads the new tenant's VMs into it (held until the
    test answers). The old tenant's read, when its answer is still arriving
    as the switch starts (old-answer-late: its body is read only after the
    switch), must not put the old tenant's VMs back."""
    base, token = hub_url_and_session
    held = []
    answers = {"dxp": {"vms": [A_VM]}, "lrb": held if read == "held" else {"vms": [B_VM]}}
    agents = "() => window._pxmxVms && window._pxmxVms.map(v => v.agent_id)"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        _by_tenant(page, "**/api/pxmx/vms*", answers)
        page.route("**/api/pxmx/nodes*", _answer(200, {"nodes": []}))
        page.evaluate("setTenant('dxp')")
        if read == "old-answer-late":
            page.evaluate("""() => {
                const json = Response.prototype.json;
                const gate = new Promise(r => { window.__endOldAnswer = r; });
                Response.prototype.json = async function () {
                    if (this.url.includes('/api/pxmx/vms?tenant=dxp')) {
                        window.__oldAnswerArriving = true;
                        await gate;
                    }
                    return json.call(this);
                };
            }""")
        page.evaluate("() => { setView('pxmx'); }")
        if read == "held":
            page.wait_for_function(f"() => JSON.stringify(({agents})()) === '[\"agent-a\"]'", timeout=5000)
        else:
            page.wait_for_function("() => window.__oldAnswerArriving === true", timeout=5000)

        after = page.evaluate(f"async () => ({{ok: await setTenant('lrb'), agents: ({agents})()}})")
        assert after["ok"] is True
        if read == "held":
            assert after["agents"] is None, "the old tenant's VMs stayed in the VM table cache after the switch"
            _first_held(page, held).fulfill(content_type="application/json", body=json.dumps({"vms": [B_VM]}))
        page.wait_for_function(f"() => JSON.stringify(({agents})()) === '[\"agent-b\"]'", timeout=5000)
        if read == "old-answer-late":
            page.evaluate("window.__endOldAnswer()")
            page.wait_for_timeout(300)
        assert page.evaluate(agents) == ["agent-b"], "the old tenant's late answer refilled the VM table cache"
        assert not errors


# A node as /api/pxmx/nodes lists it, on each tenant's own cluster.
A_NODE = {"node": "dxp-node-1", "cluster": "dxp-cl", "status": "online", "maintenance": False,
          "uptime": 1000, "agent_id": "agent-a"}
B_NODE = {"node": "lrb-node-1", "cluster": "lrb-cl", "status": "online", "maintenance": False,
          "uptime": 1000, "agent_id": "agent-b"}


def test_a_switch_drops_the_node_list_and_a_late_node_poll(hub_url_and_session):  # noqa: F811
    """The Hypervisors page caches the tenant's nodes (window._pxmxNodes) for
    the node table and the create-VM node picker, and while a node operation
    waits, a poll reads the list again every 10 s. dxp starts an operation
    (pxmxStartNodeOp, as the Maintenance switch does once its POST answers),
    and the poll's read is still arriving when the switch to lrb starts: its
    answer is read only after the switch, so lmFetch cannot drop it. The
    switch drops the node list before it unlocks the page (lrb's read is
    held, so nothing has refilled it), the redraw reads lrb's nodes into
    it, and dxp's late answer must not put dxp's nodes back."""
    base, token = hub_url_and_session
    held = []
    nodes = "() => window._pxmxNodes && window._pxmxNodes.map(n => n.node)"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.route("**/api/pxmx/vms*", _answer(200, {"vms": []}))
        _by_tenant(page, "**/api/pxmx/nodes*", {"dxp": {"nodes": [A_NODE]}, "lrb": held})
        page.evaluate("setTenant('dxp')")
        page.evaluate("() => { setView('pxmx'); }")
        page.wait_for_function(f"""() => JSON.stringify(({nodes})()) === '["dxp-node-1"]'
            && !!document.getElementById('pxmx-nodes-wrap')""", timeout=5000)
        # From here on, dxp's node list answers only when the test lets it.
        page.evaluate("""() => {
            const json = Response.prototype.json;
            const gate = new Promise(r => { window.__endOldAnswer = r; });
            Response.prototype.json = async function () {
                if (this.url.includes('/api/pxmx/nodes?tenant=dxp')) {
                    window.__oldAnswerArriving = true;
                    await gate;
                }
                return json.call(this);
            };
        }""")
        # Start an operation on dxp's node; its poll runs at once, not in 10 s.
        page.evaluate("""() => {
            const later = window.setTimeout;
            window.setTimeout = (fn, ms, ...args) => later(fn, ms === 10000 ? 0 : ms, ...args);
            try { pxmxStartNodeOp('dxp-node-1', 'dxp-cl', 'enter'); } finally { window.setTimeout = later; }
        }""")
        page.wait_for_function("() => window.__oldAnswerArriving === true", timeout=5000)

        after = page.evaluate(f"async () => ({{ok: await setTenant('lrb'), nodes: ({nodes})()}})")
        assert after["ok"] is True
        assert after["nodes"] is None, "the old tenant's nodes stayed in the node list after the switch"
        _first_held(page, held).fulfill(content_type="application/json", body=json.dumps({"nodes": [B_NODE]}))
        page.wait_for_function(f"() => JSON.stringify(({nodes})()) === '[\"lrb-node-1\"]'", timeout=5000)
        page.evaluate("window.__endOldAnswer()")
        page.wait_for_timeout(300)
        assert page.evaluate(nodes) == ["lrb-node-1"], "the old tenant's late poll answer refilled the node list"
        assert "dxp-node-1" not in page.inner_text("#pxmx-nodes-wrap")
        assert not errors


def test_an_edit_started_before_a_switch_never_opens_its_dialog(hub_url_and_session):  # noqa: F811
    """Editing a rack reads the sites list, then opens its dialog on <body>,
    outside the locked page, and its Save writes the rack it was opened on. An
    edit started on the old tenant's page must not open while the switch is
    under way: the switch drops the old page's reads, as a navigation does, so
    the edit never goes on. An edit started after the switch opens as before."""
    base, token = hub_url_and_session
    sites = {"sites": [{"id": 1, "name": "Lab A", "slug": "lab-a"}]}
    rack = "{id: 7, name: 'R1', site: 'Lab A', u_height: 42}"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        held_sites = []
        page.route("**/api/netbox/sites", lambda r: held_sites.append(r))
        page.evaluate(f"() => {{ showNetboxRackModal({rack}); }}")
        for _ in range(100):
            if held_sites:
                break
            page.wait_for_timeout(50)
        assert held_sites, "the rack edit never read the sites list"
        held = _hold_tenant_posts(page)
        page.evaluate("() => { window.__sw = setTenant('lrb'); }")
        post = _held_for(page, held, "lrb")

        # The sites list arrives while the switch is still under way. The page
        # may already have cancelled the read, so the answer can be refused.
        try:
            held_sites[0].fulfill(content_type="application/json", body=json.dumps(sites))
        except sync_api.Error:
            pass
        page.wait_for_timeout(500)
        assert not page.evaluate("!!document.getElementById('nb-rack-modal')"), \
            "an edit started before the switch opened its dialog during it"

        post.fulfill(content_type="application/json", body="{}")
        assert page.evaluate("() => window.__sw") is True
        page.route("**/api/netbox/sites", _answer(200, sites))
        page.evaluate(f"showNetboxRackModal({rack})")
        assert page.evaluate("document.getElementById('nb-rack-modal').dataset.rackId") == "7"
        assert not errors


# Legacy twins: two tenants whose ids differ only by case, saved before the
# hub kept tenant ids unique. Named so the picker (sorted by name) lists the
# "acme" entry first, where a case fold of "ACME" would find it.
TWINS = TENANTS + [{"id": "ACME", "name": "Acme West"}, {"id": "acme", "name": "Acme East"}]


@pytest.fixture
def twins(monkeypatch):
    """The picker's tenants with the twins "ACME" and "acme". The hub tells
    them apart by exact spelling (access._AMBIGUOUS_TENANT_IDS), so the mocked
    /setup/tenants carries the tenant_key it then sends for each."""
    monkeypatch.setattr("access._AMBIGUOUS_TENANT_IDS", frozenset({"acme"}))
    return TWINS


@pytest.mark.parametrize("failure", ["refused", "timeout"])
def test_a_failed_switch_to_a_twin_goes_back_to_the_hubs_twin(  # noqa: F811
        hub_url_and_session, twins, failure):
    """With the hub on "acme", a switch to its twin "ACME" that the hub refuses,
    or does not answer in time, has not landed, although the fresh ticket
    after it names "acme": that is the other tenant. The page says so and
    goes back to "acme", under acme's own entry in the header."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, tenants=twins)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        assert page.evaluate("setTenant('acme')") is True
        _fake_tickets(page, "acme")
        if failure == "refused":
            page.route("**/setup/tenant", _answer(500, {"detail": "could not save the state"}))
            reason = "(could not save the state)"
        else:
            _hold_tenant_posts(page)
            page.evaluate("_lmTenantSwitchMs = 500")
            reason = "(no answer from the hub within"
        _spy_redraws(page)

        assert page.evaluate("setTenant('ACME')") is False
        assert any("Could not switch to Acme West; the page is back on Acme East " + reason in t
                   for t in _toasts(page))
        assert page.evaluate("currentTenant") == "acme"
        assert _header(page) == ["Acme East", ["acme"]]
        assert page.evaluate("localStorage.getItem('lm_tenant')") == "acme"
        assert page.evaluate("window.__follows") == ["acme"]
        assert not errors


def test_a_switch_to_a_twin_the_hub_took_despite_an_error_lands(hub_url_and_session, twins):  # noqa: F811
    """With the hub on "acme", a switch to its twin "ACME" whose answer is lost
    (a proxy's 502) lands when the fresh ticket after it names "ACME". The
    page stays on "ACME" under its own entry, and takes "ACME", not its twin,
    as the tenant the hub is on."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, tenants=twins)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        assert page.evaluate("setTenant('acme')") is True
        page.route("**/setup/tenant", lambda r: r.fulfill(status=502, content_type="text/html", body="Bad Gateway"))
        _fake_tickets(page, "acme", "ACME")
        _spy_redraws(page)
        assert page.evaluate("setTenant('ACME')") is True
        assert not any("Could not switch" in t for t in _toasts(page))
        assert page.evaluate("[currentTenant, localStorage.getItem('lm_tenant')]") == ["ACME", "ACME"]
        assert _header(page) == ["Acme West", ["ACME"]]
        assert not errors


def test_a_failed_switch_takes_the_hubs_spelling_of_its_tenant(hub_url_and_session):  # noqa: F811
    """The picker lists "dxp" but not "DXP". After a refused switch to "dxp",
    the fresh ticket names "DXP": a tenant id the picker does not list, such
    as one another admin moved the hub to since the page loaded. The page
    cannot tell whether that is "dxp" or a twin of it, so the switch has not
    landed, and the page goes to "DXP" as the hub spells it, named by its id."""
    base, token = hub_url_and_session
    tenants = [{"id": "dxp", "name": "Dexter"}, {"id": "lrb", "name": "LRB"}]
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token, tenants=tenants)
        page.wait_for_selector("#tenant-picker-menu button[data-tid]", state="attached")
        assert page.evaluate("setTenant('lrb')") is True
        page.route("**/setup/tenant", _answer(500, {"detail": "could not save the state"}))
        _fake_tickets(page, "lrb", "DXP")
        _spy_redraws(page)

        assert page.evaluate("setTenant('dxp')") is False
        assert any("Could not switch to Dexter; the page is back on DXP (could not save the state)" in t
                   for t in _toasts(page))
        assert page.evaluate("[currentTenant, localStorage.getItem('lm_tenant')]") == ["DXP", "DXP"]
        assert _header(page) == ["DXP", []]
        assert page.evaluate("window.__follows") == ["DXP"]
        assert not errors


def test_a_switch_that_ends_the_session_adds_no_error(hub_url_and_session):  # noqa: F811
    """A 401 ends the session and the sign-in screen says why, so the switch
    shows no error of its own on top of it."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.route("**/setup/tenant", _answer(401, {"detail": "Not authenticated"}))
        _fake_tickets(page, "dxp", 401)
        assert page.evaluate("setTenant('lrb')") is False
        assert page.is_visible("#login-overlay")
        assert not any("Could not switch" in t for t in _toasts(page))
        assert not errors


def test_a_read_only_admins_switch_stays_in_the_page(hub_url_and_session):  # noqa: F811
    """The hub refuses every write from a read-only account, POST /setup/tenant
    included, so a read-only Global Admin's switch sends none: it shows no
    error and redraws the page for the pick."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        posts = []
        page.route("**/setup/tenant", lambda r: (posts.append(r.request.post_data),
                                                 _answer(403, {"detail": "Read-only account"})(r)))
        _spy_redraws(page)
        page.evaluate("currentUser.permissions.read_only = true")
        assert page.evaluate("setTenant('lrb')") is True
        assert posts == []
        assert page.evaluate("currentTenant") == "lrb"
        assert page.evaluate("window.__redraws") == [["sub", "Module Management"]]
        assert not any("Could not switch" in t for t in _toasts(page))
        assert not errors


def test_a_tenant_switch_takes_the_old_tenants_rows_off_the_page(hub_url_and_session):  # noqa: F811
    """Monitoring keeps what it last drew until its new read answers. A switch
    redraws the page from its template first, so once the page takes clicks
    again the old tenant's hosts are gone, while the new tenant's read is
    still on its way."""
    base, token = hub_url_and_session
    host = {"name": "dxp-mon-1", "tenant": "dxp", "ip": "192.0.2.10", "method": "agent",
            "availability": "available", "enabled": True, "problems": []}
    shown = "document.getElementById('page-content').innerText.includes('DXP-MON-1')"
    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.route("**/api/monitoring/status", _answer(200, {}))
        page.route("**/api/monitoring/hosts*", _answer(200, {"hosts": [host]}))
        page.evaluate("setView('zabbix')")
        page.evaluate("setTenant('dxp')")
        page.wait_for_function(shown)

        held = []
        page.route("**/api/monitoring/hosts*", lambda r: held.append(r))
        page.evaluate("setTenant('lrb')")
        assert not _inert(page)
        assert not page.evaluate(shown), "the old tenant's hosts stayed on the page"
        for _ in range(100):
            if held:
                break
            page.wait_for_timeout(50)
        held[0].fulfill(content_type="application/json", body=json.dumps({"hosts": []}))
        page.wait_for_function("document.getElementById('page-content').innerText"
                               ".includes('No monitored devices for tenant \"lrb\"')")
        assert not errors


def test_a_tenant_switch_refills_the_clearpass_tiles(hub_url_and_session):  # noqa: F811
    """The NAC tiles sit above every ClearPass tab and only the page's loader
    fills them. A switch redraws the page from its template, which puts them
    back to "—", so the loader must fill them again, for the tenant picked:
    the hub picks the ClearPass by the request's ?tenant= (a Global Admin's
    request naming none reads the global one). The fake answers by the tenant
    the request names, and a request naming none gets numbers neither tenant
    has."""
    base, token = hub_url_and_session
    keys = ("active_sessions", "total_devices", "known_devices", "unknown_devices")
    tiles = {"dxp": [7, 9, 5, 4], "lrb": [3, 4, 2, 2], "": [1, 1, 1, 1]}
    asked = []

    def nac_status(route):
        """Answer with the tiles of the tenant the request names."""
        tenant = parse_qs(urlparse(route.request.url).query).get("tenant", [""])[0]
        asked.append(tenant)
        _answer(200, dict(zip(keys, tiles.get(tenant, tiles[""]))))(route)

    with sync_api.sync_playwright() as p:
        page, errors = _open(p, base, token)
        page.route("**/api/cppm/nac-status*", nac_status)
        page.evaluate("setTenant('dxp')")
        page.evaluate("setView('cppm')")
        page.wait_for_function("document.getElementById('nac-sessions')?.textContent === '7'")

        page.evaluate("setTenant('lrb')")
        page.wait_for_function("document.getElementById('nac-sessions')?.textContent === '3'")
        assert [page.inner_text(f"#nac-{k}") for k in ("sessions", "total", "known", "unknown")] == ["3", "4", "2", "2"]
        assert asked[-1] == "lrb" and set(asked) == {"dxp", "lrb"}
        assert not errors
