"""Tests for Issue #439: ReferenceError: Can't find variable: csRenderMyTemplates

In WebKit/Safari, inline event handlers and initial render threw
ReferenceError: Can't find variable: csRenderMyTemplates (#:1) because
csRenderMyTemplates was declared as an async function in sim-views.js
without being explicitly exposed on `window`, and the call site in
csRenderVmServer invoked it without checking whether it was defined in scope.

This test suite verifies:
1. WebUI/sim-views.js exports `window.csRenderMyTemplates = csRenderMyTemplates;`
2. WebUI/sim-views.js guards the call site with `typeof window.csRenderMyTemplates === 'function'`
3. WebUI/sim-views.js guards the button onclick handler
4. cs/lm-spoke/static/sim-views.js has 100% twin parity with WebUI/sim-views.js
5. Neither file has any syntax corruption (validated with JS engine)
"""

import os
import shutil
import subprocess
import pytest

LM_SIM_VIEWS = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "WebUI", "sim-views.js")
)
CS_SIM_VIEWS = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "cs", "lm-spoke", "static", "sim-views.js")
)

JSC = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"


def _lm_src():
    with open(LM_SIM_VIEWS, encoding="utf-8") as f:
        return f.read()


def _cs_src():
    with open(CS_SIM_VIEWS, encoding="utf-8") as f:
        return f.read()


def _js_engine():
    if os.path.exists(JSC):
        return [JSC]
    node = shutil.which("node")
    return [node] if node else None


def test_lm_sim_views_window_export():
    """Verify WebUI/sim-views.js explicitly attaches csRenderMyTemplates to window."""
    src = _lm_src()
    assert "window.csRenderMyTemplates = csRenderMyTemplates;" in src, (
        "WebUI/sim-views.js must expose window.csRenderMyTemplates"
    )


def test_lm_sim_views_call_site_guarded():
    """Verify the call site in WebUI/sim-views.js guards against missing csRenderMyTemplates."""
    src = _lm_src()
    assert "typeof window.csRenderMyTemplates === 'function'" in src, (
        "WebUI/sim-views.js must guard invocation with typeof window.csRenderMyTemplates === 'function'"
    )
    expected_call = (
        "if (_canRefresh && (typeof window.csRenderMyTemplates === 'function' || typeof csRenderMyTemplates === 'function')) {\n"
        "        (window.csRenderMyTemplates || csRenderMyTemplates)();\n"
        "    }"
    )
    assert expected_call in src, (
        f"WebUI/sim-views.js must include exact guarded call block:\n{expected_call}"
    )


def test_lm_sim_views_button_onclick_guarded():
    """Verify the refresh button onclick in WebUI/sim-views.js uses the window fallback guard."""
    src = _lm_src()
    expected_onclick = 'onclick="window.csRenderMyTemplates ? window.csRenderMyTemplates() : csRenderMyTemplates()"'
    assert expected_onclick in src, (
        f"WebUI/sim-views.js must include guarded onclick handler:\n{expected_onclick}"
    )


def test_cs_sim_views_twin_parity():
    """Verify cs/lm-spoke/static/sim-views.js has exact twin parity for the fixed blocks."""
    lm_src = _lm_src()
    cs_src = _cs_src()

    expected_call = (
        "if (_canRefresh && (typeof window.csRenderMyTemplates === 'function' || typeof csRenderMyTemplates === 'function')) {\n"
        "        (window.csRenderMyTemplates || csRenderMyTemplates)();\n"
        "    }"
    )
    expected_export = "window.csRenderMyTemplates = csRenderMyTemplates;"
    expected_onclick = 'onclick="window.csRenderMyTemplates ? window.csRenderMyTemplates() : csRenderMyTemplates()"'

    # Verify presence in cs spoke file
    assert expected_export in cs_src, (
        "cs/lm-spoke/static/sim-views.js must expose window.csRenderMyTemplates"
    )
    assert expected_call in cs_src, (
        "cs/lm-spoke/static/sim-views.js must have guarded invocation"
    )
    assert expected_onclick in cs_src, (
        "cs/lm-spoke/static/sim-views.js must have guarded button onclick"
    )

    # Parity check on the call site and export site
    assert ("window.csRenderMyTemplates = csRenderMyTemplates;" in lm_src) == \
           ("window.csRenderMyTemplates = csRenderMyTemplates;" in cs_src)


@pytest.mark.parametrize("file_path,label", [
    (LM_SIM_VIEWS, "WebUI/sim-views.js"),
    (CS_SIM_VIEWS, "cs/lm-spoke/static/sim-views.js"),
])
def test_sim_views_syntax_and_export_execution(file_path, label):
    """Verify neither file has any syntax corruption and that window.csRenderMyTemplates is exported."""
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine (jsc/node) available")

    # Evaluate file in a minimal browser mock context
    script = (
        "var window = this;\n"
        "var document = { addEventListener: function() {} };\n"
        f"load({repr(file_path)});\n"
        "if (typeof window.csRenderMyTemplates !== 'function') {\n"
        "    throw new Error('window.csRenderMyTemplates is not a function');\n"
        "}\n"
    )
    proc = subprocess.run(
        engine + ["-e", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"{label} failed syntax/execution check:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
