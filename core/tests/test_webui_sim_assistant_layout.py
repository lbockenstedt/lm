"""Simulations -> Assistant (WebUI/sim-views.js): the compact spec panel and the
chat bubbles, rendered under node from the functions' own source.

The cs twin (cs/lm-spoke/static/sim-views.js) shares these functions; point
SIM_VIEWS_JS at it to run the same checks there.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from webui_src import WEBUI

NODE = shutil.which("node")
SIM_VIEWS = Path(os.environ.get("SIM_VIEWS_JS") or WEBUI / "sim-views.js")

# The pieces of sim-views.js the assistant renderers need, by declaration name.
_PIECES = ("csEscape", "_CS_ASST_MD_CLASSES", "_csAsstStyleMarkdown", "_csAssistantBubble",
           "_csAsstSpecRow", "_csAsstSpecLong", "_csAsstMissingLine", "_csAsstClientIpLabel",
           "_csAsstRenderSpec")


def _extract(src, name):
    """Source of one top-level `function name(...) {...}` or `const name = {...};`."""
    m = re.search(r"^(?:function %s\(|const %s = )" % (name, name), src, re.M)
    assert m, "%s not found in sim-views.js" % name
    end = src.index("\n}", m.start()) + 2
    return src[m.start():end] + (";" if name.isupper() or name.startswith("_CS") else "")


def _run(expr, setup=""):
    """Evaluate `expr` with the assistant renderers loaded; returns its JSON value."""
    src = SIM_VIEWS.read_text(encoding="utf-8")
    js = "\n".join(_extract(src, n) for n in _PIECES) + (
        "\nconst _el = {innerHTML: ''};\nfunction csEl() { return _el; }\n"
        "globalThis.window = globalThis;\n" + setup +
        "\nconsole.log(JSON.stringify(" + expr + "));")
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _spec(intent, spec, **extra):
    """_csAsstRenderSpec() output for one session state."""
    state = dict({"intent": intent, "spec": spec, "ready": False, "problems": [], "builds": []}, **extra)
    return _run("(_csAsstRenderSpec(), _el.innerHTML)", "window._csAsst = %s;" % json.dumps(state))


def _missing(html):
    """The field names on the panel's "Still needed" line ([] when there is none)."""
    m = re.search(r"Still needed:</span> ([^<]*)</div>", html)
    return m.group(1).split(" · ") if m else []


@pytest.mark.skipif(not NODE, reason="node not installed")
class TestSpecPanel:
    def test_empty_fields_share_one_still_needed_line(self):
        html = _spec("create", {"name": "dns_burst", "platforms": ["linux"], "client_ip": ""})
        # Alert and Config knobs are optional, so they are never "needed".
        assert _missing(html) == ["Summary", "Behavior", "Clients keep an IP", "Touch-points"]
        assert html.count("<dt") == 3  # Request, Name, Platforms
        assert ">Summary<" not in html and ">Alert<" not in html

    def test_missing_line_follows_intent_and_peer(self):
        # A removal only needs its name; an older AB that never sends
        # client_ip is not asked for it.
        assert _missing(_spec("remove", {})) == ["Removal confirmed", "Reason", "Name", "Touch-points"]
        assert "Clients keep an IP" not in _missing(_spec("create", {}))
        html = _spec("create", {"client_ip": ""}, ready=True)
        assert not _missing(html) and "Not set:</span>" in html

    def test_client_ip_labels(self):
        for value, label in (("keeps", "Yes"), ("loses", "No (by design)")):
            html = _spec("create", {"client_ip": value})
            assert '<dt class="text-slate-500 whitespace-nowrap">Clients keep an IP</dt>' in html
            assert ">%s</dd>" % label in html
            assert "Clients keep an IP" not in _missing(html)

    def test_client_ip_hidden_for_ui_and_explain(self):
        for intent in ("ui", "explain"):
            assert "Clients keep an IP" not in _spec(intent, {"client_ip": "keeps"})
            assert "Clients keep an IP" not in _spec(intent, {})

    def test_long_text_is_clamped_and_expandable(self):
        html = _spec("modify", {"diagnosis": "x" * 600, "touchpoints": [
            {"repo": "cs", "path": "clients/linux/a.sh"}, {"repo": "lm", "path": "WebUI/sim-views.js"}]})
        diag = html.split(">Diagnosis<")[1].split("</details>")[0]
        assert "line-clamp-3" in diag and "x" * 600 in diag
        assert "<summary" in html.split(">Diagnosis<")[0].rsplit("<details", 1)[1]
        assert "Touch-points (2)</summary>" in html and "Touch-points" not in _missing(html)


@pytest.mark.skipif(not NODE, reason="node not installed")
class TestBubbles:
    def test_user_and_assistant_turns_look_different(self):
        user, asst = _run("[_csAssistantBubble('user', 'line 1\\n<b>x</b>'),"
                                " _csAssistantBubble('assistant', 'hi')]")
        assert 'data-role="user"' in user and "items-end" in user and ">You</div>" in user
        assert "text-white" in user and "line 1\n&lt;b&gt;x&lt;/b&gt;" in user
        assert 'data-role="assistant"' in asst and "items-start" in asst and "Assistant</div>" in asst
        assert "bg-white border" in asst

    def test_assistant_markdown_is_styled(self):
        # The stub returns what help.js renderMarkdown emits for a heading, a
        # list, a fenced block and inline code.
        html = _run("_csAssistantBubble('assistant', 'unused')",
                    "window.renderHelpMarkdown = () => " + json.dumps(
                        "<h1 id=\"sec-plan\">Plan</h1><ul><li>one</li><li>two</li></ul>"
                        "<pre><code>code line</code></pre><p>Use <code>x</code>.</p>") + ";")
        assert '<h1 class="text-base font-bold' in html and '<ul class="list-disc' in html
        assert '<pre class="bg-slate-800' in html and "overflow-x-auto" in html and "font-mono" in html
        assert '<code class="whitespace-pre">code line' in html
        assert '<code class="font-mono text-xs' in html
