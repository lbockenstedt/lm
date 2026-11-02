"""safeHtml / rawHtml (WebUI/js/core/safe-html.js), run under node.

safeHtml is the WebUI's escaping template tag (docs/webui.md, "How to write
markup"). OS Updates is the first view written with it; a hostile CVE record
must render as text, never as markup.
"""
import json
import shutil
import subprocess

import pytest

from webui_src import WEBUI

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")

SAFE_HTML = WEBUI / "js" / "core" / "safe-html.js"
SETTINGS = WEBUI / "js" / "settings.js"


def _run(js):
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _with_helper(body):
    return SAFE_HTML.read_text(encoding="utf-8") + "\n" + body


def test_values_are_escaped_and_nesting_is_not_reescaped():
    out = _run(_with_helper(r"""
        const inner = safeHtml`<i>${'a&b'}</i>`;
        console.log(JSON.stringify({
            esc: String(safeHtml`<b>${`<img src=x onerror="a('1')">`}</b>`),
            nested: String(safeHtml`<p>${inner}</p>`),
            list: String(safeHtml`<ul>${['<x>', 'y'].map(v => safeHtml`<li>${v}</li>`)}</ul>`),
            empty: String(safeHtml`[${null}${undefined}${false}${0}]`),
            raw: String(safeHtml`${rawHtml('<hr>')}`),
            inString: `x${safeHtml`<b>${'<'}</b>`}y`,
        }));
    """))
    assert out["esc"] == "<b>&lt;img src=x onerror=&quot;a(&#39;1&#39;)&quot;&gt;</b>"
    assert out["nested"] == "<p><i>a&amp;b</i></p>"
    assert out["list"] == "<ul><li>&lt;x&gt;</li><li>y</li></ul>"
    assert out["empty"] == "[0]"
    assert out["raw"] == "<hr>"
    assert out["inString"] == "x<b>&lt;</b>y"


def _top_level(src, start):
    """The source of the top-level statement starting at ``start``, up to the
    next line that is a lone closing brace (or the end of a one-line const)."""
    i = src.index(start)
    if start.startswith("const "):
        return src[i:src.index(";\n", i) + 2]
    return src[i:src.index("\n}\n", i) + 3]


def test_os_updates_cve_panel_escapes_hostile_data():
    src = SETTINGS.read_text(encoding="utf-8")
    parts = [_top_level(src, s) for s in (
        "const _OSU_BADGE_CLS", "const _osuBadge", "function _osuCveFixes", "function _osuCveHtml")]
    evil = '<img src=x onerror=alert(1)>'
    data = {
        "feeds": {"trixie": {"fetched_at": 0, "error": evil}}, "query": evil, "kind": "package",
        "affected_nodes": 1, "checked_nodes": 2,
        "results": [{"cve": "CVE-1", "urgency": evil, "description": evil, "affected": [
            {"node": "agent:a", "label": evil, "release": "trixie", "package": evil,
             "version": evil, "binaries": [evil], "update_pending": True}], "patched": []}],
        "unknown": [{"label": evil, "reason": evil}],
    }
    out = _run(_with_helper(
        "const window = {}; const _osuView = { state: { data: {} } };\n" + "\n".join(parts)
        + f"\nconsole.log(JSON.stringify(String(_osuCveHtml({json.dumps(data)}))));"))
    assert "<img" not in out
    assert out.count("&lt;img src=x onerror=alert(1)&gt;") >= 7
    assert "1 of 2 checked node(s) affected" in out
    assert "update pending" in out

