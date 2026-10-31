"""Walk every WebUI view in a logged-in Playwright page and collect JS errors.

Used by test_webui_browser_smoke.py (CI, fake hub). Written to be reusable by
an AB walker against a live hub (docs/webui-react-lite-plan.md, Phase 0b), so
it only drives the UI's own navigation functions and never clicks buttons:
nothing here can change state on the hub.

The walk visits every view in VIEW_SUBMENUS plus the standalone views, every
sub-view of each, and every child / grandchild tab (Simulations, Settings ->
Cloud). An uncaught exception or unhandled promise rejection anywhere along
the way is a failure, tagged with where it happened.
"""
import json

# Views reached from the sidebar / header that have no VIEW_SUBMENUS entry.
STANDALONE_VIEWS = ["reports", "credvault", "templates", "security", "osupdates",
                    "mydevices", "bugs", "features", "certmon"]


def walk_ui(page, url, pause_ms=250):
    """Open ``url`` (the page's context must hold a logged-in session), then
    visit every view, sub-view and child tab. Returns a list of failures,
    each ``"<where>: <message>"``."""
    failures = []
    where = ["startup"]
    page.on("pageerror", lambda e: failures.append(f"{where[0]}: {e}"))
    page.on("dialog", lambda d: d.dismiss())
    page.goto(url)
    page.wait_for_function(
        "window.lmCoreLoaded && typeof currentUser !== 'undefined' && !!currentUser",
        timeout=20000)

    def step(label, js):
        where[0] = label
        try:
            page.evaluate(js)
        except Exception as e:  # noqa: BLE001 - a throw in the navigation call itself
            failures.append(f"{label}: {str(e).splitlines()[0]}")
        page.wait_for_timeout(pause_ms)

    # Cert Expiry Monitor only opens while enabled; the walk should still see it.
    page.evaluate("window.__lmCertMonEnabled = true")
    views = page.evaluate("Object.keys(VIEW_SUBMENUS)") + STANDALONE_VIEWS
    for view in views:
        step(view, f"setView({json.dumps(view)})")
        if page.evaluate("currentView") != view:
            failures.append(f"{view}: setView did not open the view")
            continue
        for sub in page.evaluate(f"VIEW_SUBMENUS[{json.dumps(view)}] || []"):
            step(f"{view} > {sub}", f"setSubView({json.dumps(sub)})")
            children = page.evaluate(
                f"(VIEW_CHILDREN[{json.dumps(view)}] || {{}})[{json.dumps(sub)}] || []")
            for child in children:
                step(f"{view} > {sub} > {child}", f"setSubChild({json.dumps(child)})")
                grandchildren = page.evaluate(
                    f"((VIEW_GRANDCHILDREN[{json.dumps(view)}] || {{}})[{json.dumps(sub)}] || {{}})"
                    f"[{json.dumps(child)}] || []")
                for gchild in grandchildren:
                    step(f"{view} > {sub} > {child} > {gchild}",
                         f"setSubGrandchild({json.dumps(gchild)})")
    if page.evaluate("!!document.querySelector('[role=alert]')"):
        failures.append("the error banner is showing")
    return failures
