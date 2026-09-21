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
    
    # Assert condition and guarded call are present
    assert "typeof window.csRenderMyTemplates === 'function' || typeof csRenderMyTemplates === 'function'" in src, (
        "WebUI/sim-views.js must include the condition guarding csRenderMyTemplates"
    )
    assert "(window.csRenderMyTemplates || csRenderMyTemplates)()" in src, (
        "WebUI/sim-views.js must invoke the guarded function"
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
    if not os.path.exists(CS_SIM_VIEWS):
        pytest.skip("cs sibling checkout not present")
    lm_src = _lm_src()
    cs_src = _cs_src()

    expected_export = "window.csRenderMyTemplates = csRenderMyTemplates;"
    expected_onclick = 'onclick="window.csRenderMyTemplates ? window.csRenderMyTemplates() : csRenderMyTemplates()"'

    # Verify presence in cs spoke file
    assert expected_export in cs_src, (
        "cs/lm-spoke/static/sim-views.js must expose window.csRenderMyTemplates"
    )
    assert "typeof window.csRenderMyTemplates === 'function' || typeof csRenderMyTemplates === 'function'" in cs_src, (
        "cs/lm-spoke/static/sim-views.js must include the condition guarding csRenderMyTemplates"
    )
    assert "(window.csRenderMyTemplates || csRenderMyTemplates)()" in cs_src, (
        "cs/lm-spoke/static/sim-views.js must invoke the guarded function"
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
    if file_path == CS_SIM_VIEWS and not os.path.exists(CS_SIM_VIEWS):
        pytest.skip("cs sibling checkout not present")

    # Static export validation
    with open(file_path, encoding="utf-8") as f:
        src = f.read()
    assert "window.csRenderMyTemplates = csRenderMyTemplates;" in src, f"{label} missing export"

    # Syntax validation
    if shutil.which("node"):
        proc = subprocess.run(
            ["node", "-c", file_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"{label} failed syntax check with node:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    elif os.path.exists(JSC):
        proc = subprocess.run(
            [JSC, "-e", f"checkSyntax({repr(file_path)})"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"{label} failed syntax check with jsc:\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    else:
        pytest.skip("No JS syntax checker (node/jsc) available")
