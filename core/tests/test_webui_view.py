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


def test_delegate_dispatches_data_actions():
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_content("""<div id="root">
            <button data-action="press" data-id="7"><b>Go</b></button>
            <label><input type="checkbox" data-action="tick" data-id="8"> tick</label>
            <form data-submit="search"><input id="q" data-input="typed"></form>
        </div><button id="outside" data-action="press" data-id="9">x</button>""")
        page.add_script_tag(content=(WEBUI / "js/core/view.js").read_text(encoding="utf-8"))
        page.evaluate("""() => {
            window.calls = [];
            const actions = {
                press: el => calls.push('press ' + el.dataset.id),
                tick: el => calls.push('tick ' + el.dataset.id + ' ' + el.checked),
                typed: el => calls.push('typed ' + el.value),
                search: () => calls.push('search'),
            };
            delegate(document.getElementById('root'), {});
            delegate(document.getElementById('root'), actions);  // re-render swaps actions
        }""")
        page.click("text=Go")
        page.click("text=tick")
        page.fill("#q", "php")
        page.press("#q", "Enter")
        page.click("#outside")
        calls = page.evaluate("calls")
        url = page.url
        browser.close()
    assert calls == ["press 7", "tick 8 true", "typed php", "search"]
    assert url == "about:blank"  # submit was prevented
