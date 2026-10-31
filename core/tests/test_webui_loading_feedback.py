from pathlib import Path
import os
import shutil
import subprocess
import pytest
from webui_src import main_js_paths, main_js_source

WEBUI_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"
JSC = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"


def test_webui_js_exists():
    assert WEBUI_JS.exists(), f"WebUI/main.js not found at {WEBUI_JS}"


def test_has_fetch_tracker():
    content = main_js_source()
    assert "_lmActiveFetchCount" in content
    assert "_lmOnFetchCountChange" in content


def test_fetch_intercepts_and_updates_count():
    content = main_js_source()
    assert "_lmActiveFetchCount++" in content
    assert "_lmActiveFetchCount = Math.max(0, _lmActiveFetchCount - 1);" in content


def test_show_loading_toast_dynamic_dismissal():
    content = main_js_source()
    assert "safetyTimer = setTimeout(_dismissLoadingToast, window.LOADING_TOAST_MS || 15000);" in content
    assert "fallbackTimer = setTimeout(attemptDismiss, 800);" in content
    assert "listenerUnsub = _lmOnFetchCountChange(attemptDismiss);" in content


def test_exports_window_methods():
    content = main_js_source()
    assert "window.dismissLoadingToast = _dismissLoadingToast;" in content
    assert "window.showLoadingToast = showLoadingToast;" in content


def test_js_syntax_valid():
    if not shutil.which("node") and not os.path.exists(JSC):
        pytest.skip("No JS syntax checker available")
    for path in main_js_paths():
        if shutil.which("node"):
            res = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
            assert res.returncode == 0, f"Node syntax error in {path.name}: {res.stderr}"
        else:
            res = subprocess.run([JSC, "-e", f"checkSyntax({repr(str(path))})"], capture_output=True, text=True)
            assert res.returncode == 0, f"JSC syntax error in {path.name}: {res.stderr}"

