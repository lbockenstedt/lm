"""safeHtml / rawHtml (WebUI/js/core/safe-html.js), run under node.

safeHtml is the WebUI's escaping template tag (docs/webui.md, "How to write
markup"). Hostile data on the OS Updates page itself is covered in the browser
by test_webui_os_updates_view.py.
"""
import json
import shutil
import subprocess

import pytest

from webui_src import WEBUI

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(not NODE, reason="node not installed")

SAFE_HTML = (WEBUI / "js" / "core" / "safe-html.js").as_uri()


def _run(js):
    """Run an ES-module snippet under node; it prints one JSON value."""
    out = subprocess.run([NODE, "--input-type=module", "-e", js],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _with_helper(body):
    return f"import {{ safeHtml, rawHtml }} from {json.dumps(SAFE_HTML)};\n" + body


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
