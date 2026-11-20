"""System → General → Common VRFs (WebUI/js/views/common-vrfs.js; lm#1992).

The card is rendered under node for each state GET /admin/common-vrfs can
reply with, then driven in headless Chromium against the real app with the
route mocked: ticking a VRF enables Save, Save sends exactly the ticked VRF
ids and redraws from the hub's reply, and System reopened while a save is
still pending waits for the hub's answer instead of offering a second save."""
import json
import os
import re
import shutil
import subprocess

import pytest

from test_webui_browser_smoke import hub_url_and_session  # noqa: F401 (fixture)
from webui_src import WEBUI

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")

NODE = shutil.which("node")
MODULE = (WEBUI / "js" / "views" / "common-vrfs.js").as_uri()
VRFS = [{"id": "2", "name": "dxp"}, {"id": "3", "name": "Shared"}]
AUTO = {"vrf_ids": [], "mode": "automatic", "common": ["3"], "vrfs": VRFS}


def _render(data, picked=(), **opts):
    """commonVrfsHtml(data, picked, opts) as an HTML string."""
    js = (f"globalThis.lmViews = {{}};\n"
          f"const m = await import({json.dumps(MODULE)});\n"
          f"console.log(JSON.stringify(String(m.commonVrfsHtml("
          f"{json.dumps(data)}, {json.dumps(list(picked))}, {json.dumps(opts)}))));")
    out = subprocess.run([NODE, "--input-type=module", "-e", js], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _save_disabled(html):
    """True when the card's Save button carries the disabled attribute."""
    tag = re.search(r'<button[^>]*data-action="save"[^>]*>', html).group(0)
    return re.search(r'\sdisabled[\s>]', tag) is not None


def _rows(html):
    """Each VRF checkbox row's markup, in order."""
    return html.split("<label")[1:]


def _inputs_disabled(html):
    """For each VRF checkbox, in order: True when it carries the disabled attribute."""
    return [re.search(r'\sdisabled[\s>]', re.search(r'<input[^>]*>', row).group(0)) is not None
            for row in _rows(html)]


def _reply(ids):
    """GET /admin/common-vrfs's reply while the hub stores ``ids``."""
    return dict(AUTO, vrf_ids=ids, mode="configured", common=ids) if ids else AUTO


@pytest.mark.skipif(not NODE, reason="node not installed")
class TestCard:
    def test_automatic_mode_lists_names_and_marks_the_common_ones(self):
        html = _render(AUTO)
        assert "Automatic:" in html and "Set by a Global Admin" not in html
        dxp, shared = _rows(html)
        assert 'value="2"' in dxp and "dxp" in dxp and "common now" not in dxp
        assert 'value="3"' in shared and "Shared" in shared and "common now" in shared
        assert "NetBox id" not in html and "checked" not in html
        assert _save_disabled(html)

    def test_ticking_a_vrf_enables_save(self):
        html = _render(AUTO, ["2"])
        dxp, shared = _rows(html)
        assert "checked" in dxp and "checked" not in shared
        assert not _save_disabled(html)

    def test_named_mode_enables_save_only_on_a_change(self):
        named = dict(AUTO, vrf_ids=["2"], mode="configured", common=["2"])
        html = _render(named, ["2"])
        assert "Set by a Global Admin:" in html and "Automatic:" not in html
        assert "common now" in _rows(html)[0] and _save_disabled(html)
        assert not _save_disabled(_render(named, []))

    def test_an_unnamed_or_duplicate_name_shows_the_netbox_id(self):
        html = _render(dict(AUTO, common=[], vrfs=[
            {"id": "4", "name": "Lab"}, {"id": "5", "name": "lab"}, {"id": "9", "name": ""}]))
        assert "Lab (NetBox id 4)" in html and "lab (NetBox id 5)" in html
        assert "Unknown VRF (NetBox id 9)" in html
        assert "The hub's NetBox cache has no name for this VRF" in _rows(html)[2]

    def test_vrf_names_render_as_text(self):
        html = _render(dict(AUTO, vrfs=[{"id": "2", "name": "<img src=x onerror=alert(1)>"}]))
        assert "&lt;img src=x onerror=alert(1)&gt;" in html and "<img" not in html

    def test_loading_error_empty_and_saving_states(self):
        assert "Loading…" in _render(None) and 'data-action="save"' not in _render(None)
        html = _render(None, error="Could not load the common VRFs: 500 boom")
        assert "Could not load the common VRFs: 500 boom" in html and "Loading…" not in html
        assert "No VRFs in the hub's NetBox cache" in _render(dict(AUTO, common=[], vrfs=[]))
        html = _render(AUTO, ["2"], saving=True)
        assert "Saving…" in html and _save_disabled(html)

    def test_the_checkboxes_are_disabled_only_while_saving(self):
        assert _inputs_disabled(_render(AUTO, ["2"])) == [False, False]
        assert _inputs_disabled(_render(AUTO, ["2"], saving=True)) == [True, True]


def test_system_general_saves_the_ticked_vrfs(hub_url_and_session):  # noqa: F811
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        context = p.chromium.launch().new_context()
        context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
        page = context.new_page()
        errors, puts = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))

        def common_vrfs(route):
            # GET answers automatic mode; PUT stores the body, as the hub does.
            reply = AUTO
            if route.request.method == "PUT":
                ids = json.loads(route.request.post_data)["vrf_ids"]
                puts.append(ids)
                reply = dict(AUTO, status="ok", vrf_ids=ids, mode="configured", common=ids)
            route.fulfill(content_type="application/json", body=json.dumps(reply))
        page.route("**/admin/common-vrfs", common_vrfs)
        page.goto(base + "/")
        page.wait_for_function("window._lmClickFeedbackInstalled === true")
        page.evaluate("setView('settings')")
        card = page.locator("#common-vrfs-card")
        card.locator("text=Automatic:").wait_for()
        save = card.locator("button[data-action=save]")
        assert save.is_disabled()
        card.locator("input[value='2']").check()
        assert save.is_enabled()
        save.click()
        card.locator("text=Set by a Global Admin:").wait_for()
        assert puts == [["2"]]
        assert card.locator("input[value='2']").is_checked() and save.is_disabled()
        assert not errors


def test_reopening_system_during_a_save_waits_for_the_hub(hub_url_and_session):  # noqa: F811
    """System reopened while a save is still in flight: the checkboxes are
    disabled during the save, the new card offers no Save until the hub
    answers the PUT (so no second save can land before it), and it then
    draws what the hub stored."""
    base, token = hub_url_and_session
    with sync_api.sync_playwright() as p:
        context = p.chromium.launch().new_context()
        context.add_cookies([{"name": "lm_session", "value": token, "url": base}])
        page = context.new_page()
        errors, held, stored = [], [], []
        page.on("pageerror", lambda e: errors.append(str(e)))

        def common_vrfs(route):
            # GET answers what the hub stores; a PUT waits until the test answers it.
            if route.request.method == "PUT":
                held.append(route)
            else:
                route.fulfill(content_type="application/json", body=json.dumps(_reply(stored)))
        page.route("**/admin/common-vrfs", common_vrfs)
        page.goto(base + "/")
        page.wait_for_function("window._lmClickFeedbackInstalled === true")
        page.evaluate("setView('settings')")
        card = page.locator("#common-vrfs-card")
        card.locator("text=Automatic:").wait_for()
        card.locator("input[value='2']").check()
        card.locator("button[data-action=save]").click()
        card.locator("text=Saving…").wait_for()
        assert card.locator("input[value='3']").is_disabled()
        page.evaluate("setView('settings')")
        with pytest.raises(sync_api.TimeoutError):
            card.locator("button[data-action=save]").wait_for(timeout=1000)
        assert card.locator("text=Loading…").is_visible() and len(held) == 1
        # The hub stores the PUT's VRFs and answers it.
        stored[:] = json.loads(held[0].request.post_data)["vrf_ids"]
        held[0].fulfill(content_type="application/json", body=json.dumps(dict(_reply(stored), status="ok")))
        card.locator("text=Set by a Global Admin:").wait_for()
        assert stored == ["2"] and len(held) == 1
        assert card.locator("input[value='2']").is_checked()
        assert not card.locator("input[value='3']").is_checked()
        assert card.locator("button[data-action=save]").is_disabled()
        assert not errors
