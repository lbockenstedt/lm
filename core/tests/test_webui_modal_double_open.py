"""WebUI guard: clicking a modal button twice must not stack two dialogs.

Reported as "a button is allowed to be clicked many times — example Credentials
in the console page it will load multiple windows".

Thirteen openers build their element, `await` their data, and only THEN append
it. Nothing bars a second click while that fetch is outstanding, so every click
appended another live copy. Because the copies shared one DOM id, the close
buttons — `document.getElementById('console-creds-modal').remove()` — only ever
removed the first, so the user had to dismiss the stack one layer at a time.

`openModal()` has always dropped a same-id node before appending; these tests
hold the hand-built openers to that same rule (`_mountModal`) and lock in the
in-flight suppression (`_singleFlight`) that stops the duplicate fetch from
replacing a dialog the user is already typing into.
"""

import os
import re
import shutil
import subprocess

import pytest

WEBUI = os.path.join(os.path.dirname(__file__), "..", "..", "WebUI")
MAIN_JS = os.path.abspath(os.path.join(WEBUI, "main.js"))

JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/"
       "Helpers/jsc")

# Every opener that appends only AFTER an await, i.e. every one with a window in
# which a second click can land. Kept explicit so a NEW racy opener has to be
# added here consciously rather than silently inheriting the old behaviour.
AWAITING_OPENERS = [
    "editReport", "openAgentConfigModal", "openAgentAssignModal",
    "openSpokeAssignModal", "openSpokeMetadataModal", "showGroupModal",
    "openConsoleCaptureModal", "openConsoleCredentialsModal",
    "openConsolePortTenantModal", "showPxmxInstallModal",
    "showDnsCredentialsModal", "showAddUserModal", "editUser",
]


def _src():
    with open(MAIN_JS, encoding="utf-8") as fh:
        return fh.read()


def _extract(name, src):
    """Source of a top-level `[async] function <name>(...) {...}`, brace-matched
    so the test exercises the real implementation (see the sibling harness in
    test_webui_null_body_guard.py for why the param list is balanced first)."""
    start = src.index("function %s(" % name)
    prefix = "async "
    if src[max(0, start - len(prefix)):start] == prefix:
        start -= len(prefix)
    i = src.index("(", src.index("function %s(" % name))
    depth = 0
    for k in range(i, len(src)):
        if src[k] == "(":
            depth += 1
        elif src[k] == ")":
            depth -= 1
            if depth == 0:
                i = k
                break
    depth = 0
    for k in range(src.index("{", i), len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[start:k + 1]
    raise AssertionError("unbalanced braces in " + name)


def _js_engine():
    if os.path.exists(JSC):
        return [JSC]
    node = shutil.which("node")
    return [node] if node else None


def _run(js, tmp_path):
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine (jsc/node) available")
    harness = "var out = (typeof print === 'function') ? print : console.log;\n"
    path = tmp_path / "t.js"
    path.write_text(harness + js, encoding="utf-8")
    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip().splitlines()


# ── static wiring ────────────────────────────────────────────────────────────

def test_every_awaiting_opener_mounts_through_the_guard():
    """A raw `document.body.appendChild(modal)` after an await is the bug."""
    src = _src()
    for name in AWAITING_OPENERS:
        fn = _extract(name, src)
        assert "document.body.appendChild(modal)" not in fn, (
            "%s appends its modal directly; it must use _mountModal so a second "
            "click replaces the dialog instead of stacking another copy" % name)
        assert "_mountModal(modal)" in fn, "%s must mount via _mountModal" % name


def _wrap_list(src):
    """The names actually passed through _singleFlight at load time."""
    tail = src.index("].forEach(name =>")
    head = src.rindex("[", 0, tail)
    return set(re.findall(r"'([\w]+)'", src[head:tail]))


def test_every_awaiting_opener_is_wrapped_in_single_flight():
    listed = _wrap_list(_src())
    assert set(AWAITING_OPENERS) == listed, (
        "wrap list drifted from the racy openers; missing=%s extra=%s"
        % (sorted(set(AWAITING_OPENERS) - listed),
           sorted(listed - set(AWAITING_OPENERS))))


def test_mount_modal_drops_the_previous_copy():
    fn = _extract("_mountModal", _src())
    assert "getElementById(modal.id)?.remove()" in fn


# ── behavioural ──────────────────────────────────────────────────────────────

_DOM_STUB = """
// Minimal DOM: only what _mountModal touches.
var _nodes = [];
var document = {
    getElementById: function (id) {
        for (var i = 0; i < _nodes.length; i++) {
            if (_nodes[i].id === id) return _nodes[i];
        }
        return null;
    },
    body: { appendChild: function (n) { _nodes.push(n); } }
};
function _mk(id) {
    var n = { id: id };
    n.remove = function () {
        var i = _nodes.indexOf(n);
        if (i >= 0) _nodes.splice(i, 1);
    };
    return n;
}
"""


def test_two_mounts_of_the_same_id_leave_one_dialog(tmp_path):
    js = _DOM_STUB + _extract("_mountModal", _src()) + """
    _mountModal(_mk('console-creds-modal'));
    _mountModal(_mk('console-creds-modal'));
    out('count=' + _nodes.length);
    """
    assert _run(js, tmp_path) == ["count=1"]


def test_a_different_modal_id_is_not_evicted(tmp_path):
    """The guard is per-id: it must not close an unrelated open dialog."""
    js = _DOM_STUB + _extract("_mountModal", _src()) + """
    _mountModal(_mk('console-creds-modal'));
    _mountModal(_mk('add-user-modal'));
    out('count=' + _nodes.length);
    """
    assert _run(js, tmp_path) == ["count=2"]


def test_an_idless_modal_still_mounts(tmp_path):
    js = _DOM_STUB + _extract("_mountModal", _src()) + """
    _mountModal({ id: '' });
    out('count=' + _nodes.length);
    """
    assert _run(js, tmp_path) == ["count=1"]


def test_single_flight_suppresses_the_second_click(tmp_path):
    """Two clicks while the fetch is outstanding must do the work ONCE — the
    late response otherwise replaces a dialog the user is typing into."""
    js = _extract("_singleFlight", _src()) + """
    var calls = 0, release;
    var open = _singleFlight(function () {
        calls++;
        return new Promise(function (res) { release = res; });
    });
    open(); open(); open();
    out('during=' + calls);
    release();
    Promise.resolve().then(function () {
        return Promise.resolve();
    }).then(function () {
        open();
        out('after=' + calls);
    });
    """
    assert _run(js, tmp_path) == ["during=1", "after=2"]


def test_single_flight_is_keyed_on_arguments(tmp_path):
    """editUser(7) right after editUser(3) is a different dialog, not a
    double-click — it must still open."""
    js = _extract("_singleFlight", _src()) + """
    var seen = [];
    var open = _singleFlight(function (id) {
        seen.push(id);
        return new Promise(function () {});
    });
    open(3); open(3); open(7);
    out('seen=' + seen.join(','));
    """
    assert _run(js, tmp_path) == ["seen=3,7"]


def test_single_flight_reopens_after_a_failure(tmp_path):
    """A rejected load must not wedge the button permanently."""
    js = _extract("_singleFlight", _src()) + """
    var calls = 0;
    var open = _singleFlight(function () {
        calls++;
        return Promise.reject(new Error('boom'));
    });
    open().catch(function () {});
    Promise.resolve().then(function () {
        return Promise.resolve();
    }).then(function () {
        open().catch(function () {});
        out('calls=' + calls);
    });
    """
    assert _run(js, tmp_path) == ["calls=2"]


def test_single_flight_passes_a_synchronous_opener_through(tmp_path):
    """No await means no window for a second click, so nothing is retained."""
    js = _extract("_singleFlight", _src()) + """
    var calls = 0;
    var open = _singleFlight(function () { calls++; return 'done'; });
    var a = open(), b = open();
    out('calls=' + calls + ' ret=' + a + ',' + b);
    """
    assert _run(js, tmp_path) == ["calls=2 ret=done,done"]
