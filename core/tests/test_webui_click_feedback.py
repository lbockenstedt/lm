"""Global click feedback: clicking any actionable control pops a short
"Loading …" toast immediately, so a user on a slow load sees the click landed
instead of assuming nothing happened and clicking again.

These are source assertions against WebUI/main.js (the WebUI has no build step
and the suite doesn't execute the browser bundle), pinning the contract:
  * the handler is installed once, in the capture phase, from _initApp;
  * it targets buttons / role=button / nav items;
  * it announces a derived label as "Loading <label>…";
  * it opts out dismiss/copy/toggle affordances and [data-no-loading];
  * repeat clicks on the same thing refresh one toast, never stack.
"""
from pathlib import Path

_MAIN = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"
_SRC = _MAIN.read_text(encoding="utf-8")


def _fn(name):
    i = _SRC.index(f"function {name}(")
    depth, j, started = 0, i, False
    while j < len(_SRC):
        if _SRC[j] == "{":
            depth += 1
            started = True
        elif _SRC[j] == "}":
            depth -= 1
            if started and depth == 0:
                return _SRC[i:j + 1]
        j += 1
    raise AssertionError(f"unterminated {name}")


def test_installer_exists_and_is_wired_into_initapp():
    assert "function installClickFeedback(" in _SRC
    assert "installClickFeedback();" in _SRC
    # Called during app init, near the first view render.
    init = _SRC[_SRC.index("async function _initApp("):]
    assert "installClickFeedback();" in init[:init.index("console.log(\"Lab Manager UI: Initialization complete.\")")]


def test_listener_is_capture_phase_and_installed_once():
    body = _fn("installClickFeedback")
    # Capture phase so it beats handlers that call stopPropagation.
    assert "addEventListener('click'" in body
    assert ", true)" in body
    # Idempotent guard so a session-restore + login don't double-install.
    assert "_lmClickFeedbackInstalled" in body


def test_targets_buttons_and_nav_items():
    body = _fn("installClickFeedback")
    for needle in ("button", '[role="button"]', ".nav-item"):
        assert needle in body


def test_message_is_loading_label():
    body = _fn("showLoadingToast")
    assert "`Loading ${label}…`" in body


def test_repeat_clicks_do_not_stack():
    body = _fn("showLoadingToast")
    # Same label re-uses the one toast (restart its timer) instead of appending.
    assert "_lmLoadingToast.label === label" in body
    assert "clearTimeout(_lmLoadingToast.timer)" in body


def test_skips_dismiss_copy_and_toggle_controls():
    body = _fn("_skipLoadingFeedback")
    assert "data-no-loading" in body
    assert "lm-toast-region" in body           # never on the toast's own buttons
    assert "aria-disabled" in body             # disabled controls run no handler
    assert "role') === 'switch'" in body       # toggles aren't "loading"
    assert "checkbox" in body and "radio" in body


def test_runtime_kill_switch_and_label_override():
    inst = _fn("installClickFeedback")
    assert "LM_CLICK_FEEDBACK === false" in inst
    label = _fn("_loadingLabelFor")
    assert "data-loading-label" in label
    assert "aria-label" in label
    assert "title" in label
