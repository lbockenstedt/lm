"""OS Updates page in headless Chromium against the real app, with
/api/os-updates mocked: the node list survives its 5-second poll (open package
list stays open, picked package stays picked), the CVE lookup renders hostile
data as text, and the list is a drill-down: nothing is listed until a tenant or
a state is picked. Guards the React-lite migration of this pilot view
(docs/webui-react-lite-plan.md)."""
import json
import os

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

EVIL = "<img src=x onerror=window.__pwned=1>"

NODES = {
    "totals": {"with_updates": 1, "packages": 2},
    "checked_at": 1700000000,
    "nodes": [{
        "kind": "agent", "id": "a1", "label": "web-01", "eligible": True, "count": 2,
        "features": ["packages", "reboot"], "checked": True,
        "packages": [
            {"package": "php8.2", "current": "1", "candidate": "2", "security": True},
            {"package": "curl", "current": "1", "candidate": "2"},
        ],
    }],
}

# Hostile text in every field the CVE panel shows.
CVES = {
    "feeds": {"bookworm": {"fetched_at": 1700000000, "error": EVIL}}, "query": "php", "kind": "package",
    "affected_nodes": 1, "checked_nodes": 1,
    "results": [{"cve": "CVE-2026-1", "urgency": EVIL, "description": EVIL, "affected": [
        {"node": "agent:a1", "label": "web-01", "release": EVIL, "package": EVIL,
         "version": EVIL, "binaries": ["php8.2"], "update_pending": True}],
        "patched": [{"node": "agent:b", "label": EVIL, "release": "bookworm", "package": "php8.2",
                     "version": "2", "binaries": ["php8.2"]}]}],
    "unknown": [{"label": EVIL, "reason": EVIL}],
}
FLEET = [{"cve": "CVE-2026-1", "nodes": 1, "urgency": "high", "description": EVIL}]


def test_os_updates_list_survives_polling(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            polls = []

            data = dict(NODES)

            def nodes(route):
                polls.append(1)
                route.fulfill(content_type="application/json", body=json.dumps(data))

            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/check", nodes)
            page.route("**/api/os-updates/cves?*", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(CVES)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(FLEET)))
            page.goto(base + "/")
            # Login init ends with installClickFeedback(); setView('dashboard');
            # open OS Updates only after that.
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            details = page.locator("#osu-body details.osu-pkgs")
            details.locator("summary").click()

            # Each pick re-renders the list; the open package list stays open.
            page.get_by_label("curl").check()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
            assert details.evaluate("d => d.open")

            # CVE lookup (a Preact component): suggestions come from the
            # fleet list; hostile data renders as text, never as markup.
            page.wait_for_selector("#osu-cve-list option[value='CVE-2026-1']", state="attached")
            page.fill("#osu-cve-q", "php")
            page.click("text=Look up")
            page.wait_for_selector("#osu-cve-body >> text=CVE-2026-1")
            body = page.locator("#osu-cve-body")
            assert body.inner_text().count(EVIL) >= 6
            assert body.locator("img").count() == 0
            assert "web-01 debian " in body.inner_text()
            # Picking a suggestion looks it up straight away.
            page.fill("#osu-cve-q", "CVE-2026-1")
            page.wait_for_selector("#osu-cve-body >> text=1 of 1 checked node(s) affected")
            page.click("text=Select fixes (1)")
            assert page.get_by_label("php8.2").is_checked()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
            assert not page.evaluate("window.__pwned")

            # Declining the approval prompt leaves the node unapproved.
            prompts = []
            page.once("dialog", lambda d: (prompts.append(d.message), d.dismiss()))
            page.get_by_label("Auto-patch").click()
            assert prompts and prompts[0].startswith("Approve web-01 for auto-patching?")
            assert not page.get_by_label("Auto-patch").is_checked()

            # A running roll polls every 5 s; the open list survives each poll.
            data["run"] = {"status": "running", "done": 0, "total": 1, "current": "web-01", "items": []}
            page.click("text=Check for updates")
            first = len(polls)
            page.wait_for_timeout(5600)
            assert len(polls) > first, "page did not poll"
            assert "deploying 0/1" in page.locator("#osu-run").inner_text()
            assert details.evaluate("d => d.open")
            assert not errors, errors
        finally:
            browser.close()


def _node(label, tenant, count=0, **extra):
    """One mocked node: ``count`` pending packages, in ``tenant`` (key: lower-case name
    unless ``tenant_key`` is given)."""
    return {"kind": "agent", "id": label, "label": label, "tenant": tenant,
            "tenant_key": tenant.lower(), "eligible": True,
            "count": count, "features": ["packages"], "checked": True,
            "packages": [{"package": f"pkg{i}", "current": "1", "candidate": "2"} for i in range(count)],
            **extra}


def _pick(page, row, value):
    """Click a drill-down chip: ``row`` is "Tenant" or "State", ``value`` the
    chip's tenant group key or state id. Clicking a picked chip clears it."""
    page.click(f'#osu-body [data-action="pick{row}"][data-pick="{value}"]')


def _chips(page, row):
    """``(label, count)`` of each chip in the Tenant or State row."""
    return [tuple(c) for c in page.locator(f'#osu-body [data-action="pick{row}"]').evaluate_all(
        "els => els.map(e => [e.firstChild.textContent, e.lastChild.textContent])")]


def _failures(page):
    """``(headline, node labels)`` of each failure summary above the list."""
    return [tuple(f) for f in page.locator("#osu-body div.bg-red-50").evaluate_all(
        "els => els.map(e => [e.children[0].textContent, e.children[1].textContent])")]


# Two different tenants are both named "Zulu": they must stay separate groups.
GROUPED = {
    "totals": {"with_updates": 3, "packages": 6},
    "checked_at": 1700000000,
    "nodes": [_node("app-01", "Acme", 1, reboot_required=True), _node("fw-01", "Acme", unreachable=True),
              _node("db-02", "Acme"), _node("web-01", "Zulu", 3), _node("db-01", "Zulu"),
              _node("web-02", "Zulu", 2, tenant_key="zulu-2"), _node("db-03", "Zulu", tenant_key="zulu-2")],
}


def test_os_updates_groups_nodes_by_tenant_then_state(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            nodes = lambda r: r.fulfill(content_type="application/json", body=json.dumps(GROUPED))  # noqa: E731
            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")

            # Needs-attention groups are open. app-01 has pending updates AND a reboot
            # nobody scheduled, so it needs attention (not "Updates pending") alongside
            # the unreachable fw-01.
            _pick(page, "Tenant", "tenant-acme")
            assert page.locator("#osu-s-tenant-acme-attention").evaluate("d => d.open")
            assert "app-01" in page.locator("#osu-s-tenant-acme-attention").inner_text()
            assert page.locator("#osu-s-tenant-acme-pending").count() == 0
            # Picking another tenant replaces the pick. Zulu's pending group is open, its
            # up-to-date group collapsed because the tenant has other states to look at.
            _pick(page, "Tenant", "tenant-zulu")
            assert page.locator("#osu-t-tenant-acme").count() == 0
            assert page.locator("#osu-s-tenant-zulu-pending").evaluate("d => d.open")
            assert not page.locator("#osu-s-tenant-zulu-current").evaluate("d => d.open")

            # A group's select-all ticks only the deployable nodes of that group, and
            # not those of another tenant that has the same name.
            page.locator('input[data-action="toggleGroup"][data-tenant="tenant-zulu"][data-state="pending"]').check()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
            _pick(page, "Tenant", "tenant-zulu")

            # Every tenant has an up-to-date node. Worst first: Acme has an unreachable
            # node, the Zulus only pending updates.
            _pick(page, "State", "current")
            tenants = page.locator("#osu-body > details > summary > span:first-child")
            assert tenants.all_inner_texts() == ["Acme", "Zulu", "Zulu"]
            # Most updates first puts the Zulus (3 and 2 packages) ahead of Acme (1).
            page.select_option("#osu-sort", "updates")
            assert tenants.all_inner_texts() == ["Zulu", "Zulu", "Acme"]
            page.select_option("#osu-sort", "name")
            assert tenants.all_inner_texts() == ["Acme", "Zulu", "Zulu"]

            # A tenant the user closed stays closed when the list is redrawn in a new order.
            page.locator("#osu-t-tenant-zulu > summary").click()
            page.select_option("#osu-sort", "updates")
            assert tenants.all_inner_texts() == ["Zulu", "Zulu", "Acme"]
            assert not page.locator("#osu-t-tenant-zulu").evaluate("d => d.open")
            assert page.locator("#osu-t-tenant-zulu-2").evaluate("d => d.open")
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_lists_nothing_until_a_tenant_or_state_is_picked(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    data = json.loads(json.dumps(GROUPED))
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            nodes = lambda r: r.fulfill(content_type="application/json", body=json.dumps(data))  # noqa: E731
            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/check", nodes)
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            body = page.locator("#osu-body")
            page.locator('#osu-body [data-action="pickTenant"]').first.wait_for()

            # Nothing is listed: the bar asks for a pick. Same-name tenants are two chips.
            assert "7 nodes. Pick a tenant or a state above to list them." in body.inner_text()
            assert body.locator("details").count() == 0
            assert _chips(page, "Tenant") == [("Acme", "3"), ("Zulu", "2"), ("Zulu", "2")]
            assert _chips(page, "State") == [("Needs attention", "2"), ("Updates pending", "2"), ("Up to date", "3")]

            # Each row counts under the other row's pick; Acme has no pending node.
            _pick(page, "State", "pending")
            assert _chips(page, "Tenant") == [("Zulu", "1"), ("Zulu", "1")]
            _pick(page, "Tenant", "tenant-zulu")
            assert _chips(page, "State") == [("Updates pending", "1"), ("Up to date", "1")]
            assert body.locator("details").first.get_attribute("id") == "osu-t-tenant-zulu"
            assert page.locator("#osu-body > details").count() == 1
            assert "1 of 2 node(s)" in page.locator("#osu-t-tenant-zulu > summary").inner_text()

            # Changing the pick unticks every node, so none is left on a node it hides.
            page.locator('#osu-body input[data-action="toggleNode"][data-node="agent:web-01"]').check()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
            _pick(page, "State", "pending")
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (0)"

            # A new pick is drawn afresh: the up-to-date group collapsed under the tenant
            # pick opens when up to date is picked.
            assert not page.locator("#osu-s-tenant-zulu-current").evaluate("d => d.open")
            _pick(page, "State", "current")
            assert page.locator("#osu-s-tenant-zulu-current").evaluate("d => d.open")

            # Clicking the picked chips again brings the prompt back.
            _pick(page, "State", "current")
            _pick(page, "Tenant", "tenant-zulu")
            assert body.locator("details").count() == 0

            # A new visit starts with nothing picked.
            _pick(page, "State", "pending")
            assert page.locator("#osu-body > details").count() == 2
            page.evaluate("setView('dashboard'); setView('osupdates')")
            page.wait_for_function("document.getElementById('osu-body')?.innerText.includes('7 nodes. Pick')")
            assert body.locator("details").count() == 0

            # A picked tenant whose nodes went away falls back to the prompt.
            _pick(page, "Tenant", "tenant-acme")
            data["nodes"] = [n for n in data["nodes"] if n["tenant"] != "Acme"]
            page.click('button:has-text("Check for updates")')
            page.wait_for_function("document.getElementById('osu-body').innerText.includes('4 nodes. Pick')")
            assert _chips(page, "Tenant") == [("Zulu", "2"), ("Zulu", "2")]

            # A picked state is kept when its nodes move on: its chip stays (count 0) to
            # clear it, and the Tenant row goes, as no tenant has a node to list.
            _pick(page, "State", "pending")
            for n in data["nodes"]:
                n.update(count=0, packages=[])
            page.click('button:has-text("Check for updates")')
            page.wait_for_function("document.getElementById('osu-body').innerText.includes('No nodes are in this state right now.')")
            assert _chips(page, "State") == [("Updates pending", "0"), ("Up to date", "4")]
            assert page.locator('#osu-body [data-action="pickTenant"]').count() == 0
            assert "Tenant" not in body.inner_text()

            # With no node reported there is no bar to clear a pick from, so the
            # state pick goes too: nodes that report again ask for a pick.
            reporting = data["nodes"]
            data["nodes"] = []
            page.click('button:has-text("Check for updates")')
            page.wait_for_function("document.getElementById('osu-body').innerText.includes('No nodes reporting.')")
            data["nodes"] = reporting
            page.click('button:has-text("Check for updates")')
            page.wait_for_function("document.getElementById('osu-body').innerText.includes('4 nodes. Pick')")
            assert body.locator("details").count() == 0
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_failure_summary_names_only_nodes_the_pick_covers(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    data = {
        "totals": {"with_updates": 1, "packages": 5}, "checked_at": 1700000000,
        "nodes": [_node("a-01", "Acme", 1), _node("a-02", "Acme", 1), _node("z-01", "Zulu", 1), _node("z-02", "Zulu", 2)],
        "run": {"status": "finished", "done": 5, "total": 5, "items": [
            {"key": "agent:a-01", "label": "a-01", "status": "failed", "message": "boom", "cause": "boom"},
            {"key": "agent:a-02", "label": "a-02", "status": "failed", "message": "boom", "cause": "boom"},
            {"key": "agent:z-01", "label": "z-01", "status": "failed", "message": "boom", "cause": "boom"},
            # Spoke s-01 went offline: the hub no longer lists it or its agent, so
            # this summary is the only place their failure shows.
            {"key": "spoke:s-01", "label": "s-01", "status": "failed", "cause": "spoke s-01 is offline"},
            {"key": "agent:s-02", "label": "s-02", "status": "failed", "cause": "spoke s-01 is offline"},
            # One node alone behind another offline spoke: no row shows it either.
            {"key": "agent:t-01", "label": "t-01", "status": "failed", "cause": "spoke s-03 is offline"}]},
    }
    offline = ("2 nodes not patched — spoke s-01 is offline", "s-01, s-02")
    lone = ("1 node not patched — spoke s-03 is offline", "t-01")
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            nodes = lambda r: r.fulfill(content_type="application/json", body=json.dumps(data))  # noqa: E731
            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/check", nodes)
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            page.locator('#osu-body [data-action="pickTenant"]').first.wait_for()

            # Before a pick no listed node is named, only the nodes no pick can list,
            # even a cause that took down a single one of them.
            assert _failures(page) == [offline, lone]
            # A tenant pick names only its own nodes; the unlisted ones have no tenant.
            _pick(page, "Tenant", "tenant-acme")
            assert _failures(page) == [("2 nodes not patched — boom", "a-01, a-02")]
            # A cause only one listed node has shows in that node's row instead.
            _pick(page, "Tenant", "tenant-zulu")
            assert _failures(page) == []
            _pick(page, "Tenant", "tenant-zulu")
            # Failed nodes need attention, in every tenant.
            _pick(page, "State", "attention")
            assert _failures(page) == [("3 nodes not patched — boom", "a-01, a-02, z-01"), offline, lone]
            _pick(page, "State", "pending")
            assert _failures(page) == []

            # No node reports at all: there is no bar to clear the pick, so every failure shows.
            data["nodes"] = []
            page.click('button:has-text("Check for updates")')
            page.wait_for_function("document.getElementById('osu-body').innerText.includes('No nodes reporting.')")
            assert _failures(page) == [("3 nodes not patched — boom", "a-01, a-02, z-01"), offline, lone]
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_ticks_and_cve_fixes_stay_on_listed_nodes(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    php = [{"package": "php8.2", "current": "1", "candidate": "2", "security": True}]
    data = {
        "totals": {"with_updates": 4, "packages": 4}, "checked_at": 1700000000,
        # z-03 runs an LM that cannot pick packages: no package box, so no fix is ticked on it.
        "nodes": [_node("a-01", "Acme", 1, packages=php), _node("z-01", "Zulu", 1, packages=php),
                  _node("z-02", "Zulu", 1), _node("z-03", "Zulu", 1, packages=php, features=[])],
    }
    # Two CVEs in the same package: each node's fix is one package update, not two.
    cves = {
        "feeds": {"bookworm": {"fetched_at": 1700000000}}, "query": "php", "kind": "package",
        "affected_nodes": 3, "checked_nodes": 4,
        "results": [{"cve": cve, "affected": [
            {"node": f"agent:{n}", "label": n, "release": "bookworm", "package": "php8.2",
             "version": "1", "binaries": ["php8.2"], "update_pending": True} for n in ("a-01", "z-01", "z-03")]}
            for cve in ("CVE-2026-1", "CVE-2026-2")],
    }
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            nodes = lambda r: r.fulfill(content_type="application/json", body=json.dumps(data))  # noqa: E731
            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/check", nodes)
            page.route("**/api/os-updates/cves?*", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(cves)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            page.locator('#osu-body [data-action="pickTenant"]').first.wait_for()
            cve = page.locator("#osu-cve-body")
            selected = page.locator("#osu-apply-selected")

            # Nothing is listed yet, so no fix can be ticked: the card says where they are.
            page.fill("#osu-cve-q", "php")
            page.click("text=Look up")
            page.wait_for_selector("#osu-cve-body >> text=3 of 4 checked node(s) affected")
            assert cve.locator("button").count() == 0
            assert "2 fix(es) on nodes not listed above" in cve.inner_text()

            # The count follows the pick without a new lookup, and only listed nodes are ticked.
            _pick(page, "Tenant", "tenant-zulu")
            assert cve.locator("button").inner_text() == "Select fixes (1)"
            assert "1 fix(es) on nodes not listed above" in cve.inner_text()
            cve.locator("button").click()
            assert page.locator('#osu-body input[data-action="togglePkg"][data-node="agent:z-01"][data-pkg="php8.2"]').is_checked()
            assert selected.inner_text() == "Deploy selected (1)"

            # A re-check that moves a ticked node to another tenant drops its tick.
            page.locator('#osu-body input[data-action="toggleNode"][data-node="agent:z-02"]').check()
            assert selected.inner_text() == "Deploy selected (2)"
            data["nodes"][2].update(tenant="Acme", tenant_key="acme")
            page.click('button:has-text("Check for updates")')
            page.wait_for_function("!document.getElementById('osu-node-agent:z-02')")
            assert selected.inner_text() == "Deploy selected (1)"
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_run_results_are_not_mistaken_for_up_to_date(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    data = {
        "totals": {"with_updates": 5, "packages": 12}, "checked_at": 1700000000,
        "nodes": [_node("a-01", "Acme", 1), _node("b-01", "Acme", 3), _node("c-01", "Acme", 2),
                  _node("d-01", "Acme", 1), _node("e-01", "Beta", 5),
                  _node("f-01", "Beta", 4), _node("g-01", "Beta", 3), _node("h-01", "Beta", 6)],
        "run": {"status": "running", "done": 6, "total": 7, "current": "", "items": [
            {"key": "agent:a-01", "status": "done", "remaining": 0},
            {"key": "agent:b-01", "status": "done", "remaining": 2, "mode": "packages"},
            {"key": "agent:c-01", "status": "skipped"},
            # The cached node is stale mid-run: the item alone says d-01 now needs a reboot.
            {"key": "agent:d-01", "status": "done", "remaining": 0, "reboot_required": True},
            # apt exited part-way: it installed some and re-listed what is left, so the item is the truth.
            {"key": "agent:f-01", "status": "failed", "remaining": 1, "reboot_required": True, "message": "dist-upgrade exited 100"},
            # The apply never reached apt: no count, so the cached 3 packages still stand.
            {"key": "agent:g-01", "status": "failed", "message": "no privilege"},
            # Patched and now rebooting through maintenance mode: patching, nothing left, no reboot still due.
            {"key": "agent:h-01", "status": "rebooting", "remaining": 0, "reboot_required": True}]},
    }
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.route("**/api/os-updates", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(data)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            _pick(page, "Tenant", "tenant-acme")

            # Fully updated is up to date; a deploy that left packages pending is not; a skipped node was never patched.
            assert "a-01" in page.locator("#osu-s-tenant-acme-current").text_content()
            pending = page.locator("#osu-s-tenant-acme-pending").text_content()
            assert "b-01" in pending and "updated, 2 left" in pending
            attention = page.locator("#osu-s-tenant-acme-attention").text_content()
            assert "c-01" in attention and "skipped" in attention
            # d-01 finished but the run item says it needs a reboot: attention, badge and tenant count.
            assert "d-01" in attention and "reboot required" in attention
            assert "d-01" not in page.locator("#osu-s-tenant-acme-current").text_content()
            assert "1 need reboot" in page.locator("#osu-t-tenant-acme > summary").text_content()
            assert "b-01" not in page.locator("#osu-s-tenant-acme-current").text_content()

            # The finished nodes' pre-deploy packages are gone from the rows, the tenant total
            # (b-01's 2 + c-01's 2 left, not the cached 7) and the "most updates" order.
            assert "package(s)" not in page.locator("#osu-s-tenant-acme-current").text_content()
            assert "3 package(s)" not in pending
            assert "4 package(s) pending" in page.locator("#osu-t-tenant-acme > summary").text_content()
            # Both tenants have nodes that need attention. The header counts the whole tenant,
            # so the tie on attention goes to the tenant with more packages left.
            _pick(page, "Tenant", "tenant-acme")
            _pick(page, "State", "attention")
            tenants = page.locator("#osu-body > details > summary > span:first-child")
            assert tenants.all_inner_texts() == ["Beta", "Acme"]
            page.select_option("#osu-sort", "name")
            assert tenants.all_inner_texts() == ["Acme", "Beta"]
            page.select_option("#osu-sort", "updates")
            assert tenants.all_inner_texts() == ["Beta", "Acme"]

            # A failed apply that re-listed shows what is left and its reboot need; one that never
            # reached apt keeps its cached count. Both stay failed, under Needs attention.
            _pick(page, "State", "attention")
            _pick(page, "Tenant", "tenant-beta")
            beta = page.locator("#osu-t-tenant-beta > summary").text_content()
            assert "9 package(s) pending" in beta and "1 need reboot" in beta
            failed = page.locator("#osu-s-tenant-beta-attention").text_content()
            assert "f-01" in failed and "g-01" in failed and failed.count("failed") >= 2
            assert "1 package(s)" in page.locator("#osu-node-agent\\:f-01").text_content()
            assert "4 package(s)" not in failed and "3 package(s)" in failed
            patching = page.locator("#osu-s-tenant-beta-patching").text_content()
            assert "h-01" in patching and "rebooting…" in patching
            assert "package(s)" not in patching and "reboot required" not in patching
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_a_run_that_is_over_leaves_no_node_patching(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    # The hub restarted mid-run: the saved run is interrupted but its items kept in-flight statuses.
    data = {
        "totals": {"with_updates": 4, "packages": 4}, "checked_at": 1700000000,
        "nodes": [_node("a-01", "Acme", 1), _node("b-01", "Acme", 1), _node("c-01", "Acme", 1),
                  _node("d-01", "Acme", 1)],
        "run": {"status": "interrupted", "done": 0, "total": 4, "current": "", "items": [
            {"key": "agent:a-01", "status": "applying"}, {"key": "agent:b-01", "status": "rebooting"},
            {"key": "agent:c-01", "status": "queued"}, {"key": "agent:d-01", "status": "snapshotting"}]},
    }
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.route("**/api/os-updates", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(data)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            page.locator("#osu-s-tenant-acme-attention").wait_for()

            # Cut-off applies are interrupted and never-started nodes skipped, all under Needs attention.
            assert page.locator("#osu-s-tenant-acme-patching").count() == 0
            attention = page.locator("#osu-s-tenant-acme-attention").text_content()
            assert all(f"{x}-01" in attention for x in "abcd")
            assert attention.count("interrupted") == 2 and attention.count("skipped") == 2
            assert "…" not in attention
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_a_node_whose_reboot_did_not_finish_cleanly_needs_attention(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    # The patch worked on the first four, which need different follow-up: m-01 rebooted but was
    # left drained in HA maintenance mode, n-01's reboot failed, q-01's reboot command got no
    # answer, p-01 was never rebooted at all (a manual Reboot item that failed). Only the clean one
    # is up to date.
    data = {
        "totals": {"with_updates": 0, "packages": 0}, "checked_at": 1700000000,
        "nodes": [_node("m-01", "Acme"), _node("n-01", "Acme"), _node("o-01", "Acme"),
                  _node("p-01", "Acme"), _node("q-01", "Acme")],
        "run": {"status": "finished", "done": 5, "total": 5, "current": "", "items": [
            {"key": "agent:m-01", "status": "done", "remaining": 0, "reboot_state": "drained",
             "auto_reboot": "rebooted, but maintenance mode NOT cleared: pmxcfs busy"},
            {"key": "agent:n-01", "status": "done", "remaining": 0, "reboot_state": "failed",
             "auto_reboot": "failed: unexpected error: boom — check whether n-01 is still in maintenance mode"},
            {"key": "agent:q-01", "status": "done", "remaining": 0, "reboot_state": "unconfirmed",
             "auto_reboot": "failed: Timed out waiting for spoke response — maintenance mode cleared"},
            {"key": "agent:o-01", "status": "done", "remaining": 0, "reboot_state": "ok",
             "auto_reboot": "rebooted (cluster maintenance mode)"},
            {"key": "agent:p-01", "status": "failed", "mode": "reboot", "reboot_state": "not_started",
             "auto_reboot": "failed: maintenance mode: pmxcfs not quorate"}]},
    }
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.route("**/api/os-updates", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(data)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            _pick(page, "State", "attention")

            attention = page.locator("#osu-s-tenant-acme-attention").text_content()
            assert "o-01" not in attention
            # Each outcome has its own badge, on its own node.
            for node, badge in (("m-01", "left in maintenance"), ("n-01", "reboot failed"),
                                ("q-01", "reboot not confirmed"), ("p-01", "not rebooted")):
                row = page.locator(f"#osu-node-agent\\:{node}").text_content()
                assert badge in row, (node, row)
            assert attention.count("left in maintenance") == 1
            assert attention.count("reboot failed") == 1 and attention.count("not rebooted") == 1
            assert attention.count("reboot not confirmed") == 1
            assert "maintenance mode NOT cleared: pmxcfs busy" in attention
            # The clean node is still simply up to date.
            _pick(page, "State", "current")
            assert "o-01" in page.locator("#osu-s-tenant-acme-current").text_content()
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_a_node_rebooted_by_hand_stops_counting_as_needing_a_reboot(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    # The one-node Reboot button runs an item with no package count: while it reboots, the node is
    # patching, keeps its cached package count and is no longer "need reboot"; another node still is.
    data = {
        "totals": {"with_updates": 2, "packages": 3}, "checked_at": 1700000000,
        "nodes": [_node("r-01", "Acme", 2, reboot_required=True),
                  _node("s-01", "Acme", 1, reboot_required=True)],
        "run": {"status": "running", "done": 0, "total": 1, "current": "", "items": [
            {"key": "agent:r-01", "status": "rebooting", "mode": "reboot"}]},
    }
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.route("**/api/os-updates", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(data)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            _pick(page, "State", "patching")

            patching = page.locator("#osu-s-tenant-acme-patching").text_content()
            assert "r-01" in patching and "rebooting…" in patching
            assert "reboot required" not in patching
            # The header counts the whole tenant, not only the nodes listed.
            assert "1 need reboot" in page.locator("#osu-t-tenant-acme > summary").text_content()
            _pick(page, "State", "attention")
            assert "s-01" in page.locator("#osu-s-tenant-acme-attention").text_content()
            assert not errors, errors
        finally:
            browser.close()


# Tenant ids are free text: real tenants whose ids equal the old Hub / "no tenant"
# sentinel keys, or end in a state name, must stay separate groups with unique DOM ids.
COLLIDING = {
    "totals": {"with_updates": 4, "packages": 4},
    "checked_at": 1700000000,
    "nodes": [_node("hub", "", kind="hub", tenant_key=""), _node("loose-01", "", tenant_key=""),
              _node("hub-01", "Hubco", 1, tenant_key="__hub"), _node("none-01", "Nonesuch", 1, tenant_key="__none"),
              _node("alpha-01", "Alpha", 1), _node("alpha-02", "Alpha Pending", 1, tenant_key="alpha-pending")],
}


def test_os_updates_tenant_ids_never_merge_into_hub_unassigned_or_each_other(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.route("**/api/os-updates", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps(COLLIDING)))
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            page.locator('#osu-body [data-action="pickTenant"]').first.wait_for()
            chips = page.locator('#osu-body [data-action="pickTenant"]')
            # Real tenants A–Z, then the hub, then nodes with no tenant: six chips, six keys.
            assert [c[0] for c in _chips(page, "Tenant")] == [
                "Alpha", "Alpha Pending", "Hubco", "Nonesuch", "Hub", "Unassigned"]
            assert chips.evaluate_all("els => els.map(e => e.dataset.pick)") == [
                "tenant-alpha", "tenant-alpha-pending", "tenant-__hub", "tenant-__none", "hub", "none"]
            tenants = page.locator("#osu-body > details > summary > span:first-child")
            text = lambda sel: page.locator(sel).inner_text()  # noqa: E731
            unique_ids = """() => {
                const ids = [...document.querySelectorAll('[id]')].map(e => e.id);
                return ids.length === new Set(ids).size;
            }"""

            _pick(page, "State", "pending")
            assert sorted(tenants.all_inner_texts()) == ["Alpha", "Alpha Pending", "Hubco", "Nonesuch"]
            assert "hub-01" in text("#osu-t-tenant-__hub") and "none-01" in text("#osu-t-tenant-__none")
            # Tenant "alpha-pending" must not take the id of tenant "alpha"'s pending group.
            assert "alpha-01" in text("#osu-s-tenant-alpha-pending")
            assert "alpha-02" in text("#osu-s-tenant-alpha-pending-pending")
            assert page.evaluate(unique_ids)

            _pick(page, "State", "current")
            assert sorted(tenants.all_inner_texts()) == ["Hub", "Unassigned"]
            assert "hub-01" not in text("#osu-t-hub")
            assert "none-01" not in text("#osu-t-none") and "loose-01" in text("#osu-t-none")
            assert page.evaluate(unique_ids)

            # The Hub chip and tenant "__hub"'s chip each list only their own nodes.
            _pick(page, "State", "current")
            _pick(page, "Tenant", "hub")
            assert tenants.all_inner_texts() == ["Hub"]
            _pick(page, "Tenant", "tenant-__hub")
            assert tenants.all_inner_texts() == ["Hubco"]
            assert "hub-01" in text("#osu-t-tenant-__hub")
            assert not errors, errors
        finally:
            browser.close()


def test_os_updates_deploy_listed_covers_only_the_listed_nodes(hub_url_and_session):  # noqa: F811
    """Fleet rule 7.5: "Approve & deploy listed" deploys only the listed nodes
    that have pending updates and can be deployed. It is disabled until a pick
    lists one, and posts exactly their keys, never an empty body (the hub reads
    that as every node in scope, the nodes the list hides included)."""
    base, token = hub_url_and_session
    data = {
        "totals": {"with_updates": 3, "packages": 4}, "checked_at": 1700000000,
        # z-02 has nothing pending and z-03 is blocked: neither can be deployed.
        "nodes": [_node("a-01", "Acme", 1), _node("z-01", "Zulu", 2), _node("z-02", "Zulu"),
                  _node("z-03", "Zulu", 1, apply_blocker="disk full")],
    }
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            context = browser.new_context()
            context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("dialog", lambda d: d.accept())
            nodes = lambda r: r.fulfill(content_type="application/json", body=json.dumps(data))  # noqa: E731
            page.route("**/api/os-updates", nodes)
            page.route("**/api/os-updates/check", nodes)
            page.route("**/api/os-updates/cves/fleet", lambda r: r.fulfill(
                content_type="application/json", body="[]"))
            page.route("**/api/os-updates/apply", lambda r: r.fulfill(
                content_type="application/json", body=json.dumps({"queued": 1})))
            page.goto(base + "/")
            page.wait_for_function("window._lmClickFeedbackInstalled === true")
            page.evaluate("setView('osupdates')")
            page.locator('#osu-body [data-action="pickTenant"]').first.wait_for()
            deploy = page.locator("#osu-apply")

            # Nothing is listed yet, so there is nothing to deploy.
            assert deploy.is_disabled()
            assert deploy.inner_text() == "Approve & deploy listed (0)"

            def posted():
                """Click the button and return the JSON body it posts."""
                with page.expect_request(lambda req: req.url.endswith("/api/os-updates/apply")) as req:
                    deploy.click()
                return json.loads(req.value.post_data)

            # One tenant picked: only its node with updates and no blocker is sent.
            _pick(page, "Tenant", "tenant-zulu")
            assert deploy.inner_text() == "Approve & deploy listed (1)"
            assert posted() == {"nodes": ["agent:z-01"], "security_only": False}

            # A state picked on its own lists, and sends, every tenant's nodes in it.
            _pick(page, "Tenant", "tenant-zulu")
            _pick(page, "State", "pending")
            assert deploy.inner_text() == "Approve & deploy listed (2)"
            assert posted() == {"nodes": ["agent:a-01", "agent:z-01"], "security_only": False}
            assert not errors, errors
        finally:
            browser.close()
