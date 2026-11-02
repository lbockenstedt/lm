"""createView (WebUI/js/core/view.js) in headless Chromium: a refresh morphs
the DOM instead of replacing it, so what the user did to the page survives the
5-second OS Updates poll (docs/webui-react-lite-plan.md, Phase 3)."""
import os

import pytest

from webui_src import WEBUI

if os.environ.get("CI"):
    from playwright import sync_api
else:
    sync_api = pytest.importorskip("playwright.sync_api")


def test_refresh_keeps_dom_nodes_and_open_details():
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_content('<div id="box"></div>')
        for f in ("assets/idiomorph.min.js", "js/core/safe-html.js", "js/core/view.js"):
            page.add_script_tag(content=(WEBUI / f).read_text(encoding="utf-8"))
        out = page.evaluate("""() => {
            const v = createView({ el: 'box', state: { n: 1, name: '<b>x</b>' }, render: s => safeHtml`
                <details id="d"><summary>${s.n} item(s)</summary><input id="i"></details>
                <p id="p">${s.name}</p>` });
            v.refresh();
            const input = document.getElementById('i');
            document.getElementById('d').open = true;
            v.setState({ n: 2 });
            return {
                sameInput: input === document.getElementById('i'),
                open: document.getElementById('d').open,
                summary: document.querySelector('#d summary').textContent,
                p: document.getElementById('p').innerHTML,
            };
        }""")
        browser.close()
    assert out == {"sameInput": True, "open": True, "summary": "2 item(s)", "p": "&lt;b&gt;x&lt;/b&gt;"}
