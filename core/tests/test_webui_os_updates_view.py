"""OS Updates page in headless Chromium against the real app, with
/api/os-updates mocked: the node list survives its 5-second poll (open package
list stays open, picked package stays picked) and the CVE lookup renders
hostile data as text. Guards the React-lite migration of this pilot view
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


# Two different tenants are both named "Zulu": they must stay separate groups.
GROUPED = {
    "totals": {"with_updates": 3, "packages": 6},
    "checked_at": 1700000000,
    "nodes": [_node("app-01", "Acme", 1, reboot_required=True), _node("fw-01", "Acme", unreachable=True),
              _node("web-01", "Zulu", 3), _node("db-01", "Zulu"),
              _node("web-02", "Zulu", 2, tenant_key="zulu-2")],
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
            tenants = page.locator("#osu-body > details > summary > span:first-child")
            tenants.first.wait_for()

            # Worst first: Acme has an unreachable node, the Zulus only pending updates.
            assert tenants.all_inner_texts() == ["Acme", "Zulu", "Zulu"]
            # Needs-attention and pending groups are open; Zulu's up-to-date group is
            # collapsed because the tenant has other states to look at.
            assert page.locator("#osu-s-tenant-acme-attention").evaluate("d => d.open")
            # app-01 has pending updates AND a reboot nobody scheduled, so it needs attention
            # (not "Updates pending") alongside the unreachable fw-01.
            assert "app-01" in page.locator("#osu-s-tenant-acme-attention").inner_text()
            assert page.locator("#osu-s-tenant-acme-pending").count() == 0
            assert page.locator("#osu-s-tenant-zulu-pending").evaluate("d => d.open")
            assert not page.locator("#osu-s-tenant-zulu-current").evaluate("d => d.open")

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
            page.locator("#osu-t-tenant-zulu > summary").click()

            # A group's select-all ticks only the deployable nodes of that group, and
            # not those of another tenant that has the same name.
            page.locator('input[data-action="toggleGroup"][data-tenant="tenant-zulu"][data-state="pending"]').check()
            assert page.locator("#osu-apply-selected").inner_text() == "Deploy selected (1)"
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
            page.locator("#osu-s-tenant-acme-current").wait_for()

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
            tenants = page.locator("#osu-body > details > summary > span:first-child")
            # Tied on attention, so the tenant with more packages left comes first.
            assert tenants.all_inner_texts() == ["Beta", "Acme"]
            page.select_option("#osu-sort", "name")
            assert tenants.all_inner_texts() == ["Acme", "Beta"]
            page.select_option("#osu-sort", "updates")
            assert tenants.all_inner_texts() == ["Beta", "Acme"]

            # A failed apply that re-listed shows what is left and its reboot need; one that never
            # reached apt keeps its cached count. Both stay failed, under Needs attention.
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
            page.locator("#osu-s-tenant-acme-attention").wait_for()

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
            page.locator("#osu-s-tenant-acme-patching").wait_for()

            patching = page.locator("#osu-s-tenant-acme-patching").text_content()
            assert "r-01" in patching and "rebooting…" in patching
            assert "reboot required" not in patching
            assert "s-01" in page.locator("#osu-s-tenant-acme-attention").text_content()
            assert "1 need reboot" in page.locator("#osu-t-tenant-acme > summary").text_content()
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
            tenants = page.locator("#osu-body > details > summary > span:first-child")
            tenants.first.wait_for()

            assert sorted(tenants.all_inner_texts()) == [
                "Alpha", "Alpha Pending", "Hub", "Hubco", "Nonesuch", "Unassigned"]
            text = lambda sel: page.locator(sel).inner_text()  # noqa: E731
            assert "hub-01" in text("#osu-t-tenant-__hub") and "hub-01" not in text("#osu-t-hub")
            assert "none-01" in text("#osu-t-tenant-__none") and "none-01" not in text("#osu-t-none")
            assert "loose-01" in text("#osu-t-none")
            # Tenant "alpha-pending" must not take the id of tenant "alpha"'s pending group.
            assert "alpha-01" in text("#osu-s-tenant-alpha-pending")
            assert "alpha-02" in text("#osu-s-tenant-alpha-pending-pending")
            assert page.evaluate("""() => {
                const ids = [...document.querySelectorAll('[id]')].map(e => e.id);
                return ids.length === new Set(ids).size;
            }""")
            assert not errors, errors
        finally:
            browser.close()
