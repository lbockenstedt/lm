"""The DNS/DHCP spoke-error paths referenced a variable that does not exist.

Both loaders had, on their "spoke not connected" branch::

    if (addBtn) addBtn.classList.add('hidden');

``addBtn`` is not declared anywhere in main.js -- it is a leftover from when the
per-tab "+ Add ..." buttons lived in a page-body row, before they moved into the
trailing ``#top-nav-actions`` strip (see renderTopNav). ``if (addBtn)`` does NOT
guard against that: reading an undeclared identifier throws a ReferenceError
("Can't find variable: addBtn" in Safari) instead of evaluating falsey.

So the moment either loader took its error branch it threw, aborting the rest of
the function -- including the ``container.innerHTML`` assignment it was in the
middle of -- and the operator got a raw JS error where the spoke-error banner
was supposed to be. It reproduced for a non-admin clicking DNS in the left menu,
because that fetch comes back not-ok for them and takes exactly that branch.

Replaced with ``_clearTopNavActions()``, which withdraws the action button from
the strip it actually renders into now.
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


def _src():
    with open(MAIN_JS, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _fn(name, src=None):
    src = src if src is not None else _src()
    start = src.index("function %s(" % name)
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError("unbalanced braces in " + name)


def _js_engine():
    if os.path.exists(JSC):
        return [JSC]
    node = shutil.which("node")
    return [node] if node else None


# ── the bug itself ──────────────────────────────────────────────────────────

def test_no_reference_to_the_undeclared_addbtn():
    """The whole failure was one undeclared identifier. Nothing may read it."""
    code = _strip_comments(_src())
    # `addResBtn` / `dhcp-add-btn` are unrelated real names -- match `addBtn`
    # only as a standalone identifier.
    hits = re.findall(r"(?<![\w$])addBtn(?![\w$])", code)
    assert not hits, "%d live reference(s) to the undeclared addBtn" % len(hits)


def test_the_replacement_helper_exists():
    assert "function _clearTopNavActions(" in _src()


@pytest.mark.parametrize("fn,banner", [
    ("loadDNSData", "DNS spoke not connected"),
    ("loadDHCPData", "DHCP spoke not connected"),
])
def test_spoke_error_paths_withdraw_the_add_button(fn, banner):
    """Each loader's not-ok branch must still withdraw the action -- leaving a
    live '+ Add' button sitting above a 'spoke not connected' banner is the
    behaviour these lines existed to prevent. (The banner text appears on
    several branches; only the tab that owns an add button withdraws it, so
    assert on the loader as a whole rather than one occurrence.)"""
    body = _fn(fn)
    assert banner in body
    assert "_clearTopNavActions()" in body, (
        "%s must withdraw the add button on its spoke-error path" % fn)


def test_helper_targets_the_strip_the_buttons_render_into():
    body = _fn("_clearTopNavActions")
    assert "top-nav-actions" in body, (
        "the '+ Add ...' buttons render into #top-nav-actions (renderTopNav)")


def test_helper_tolerates_a_missing_strip():
    """The loaders run on views whose nav may not be mounted yet; the helper
    must not become a second source of the very error it replaced."""
    body = _fn("_clearTopNavActions")
    assert re.search(r"if\s*\(\s*el\s*\)|\?\.", body), (
        "guard the lookup -- getElementById returns null when absent")


# ── executed ────────────────────────────────────────────────────────────────

_HARNESS = """
%(fn)s

var el = { innerHTML: '<button>+ Add Reservation</button>' };
var present = %(present)s;
var document = { getElementById: function (id) {
    return (present && id === 'top-nav-actions') ? el : null;
} };

var threw = false;
try { _clearTopNavActions(); } catch (e) { threw = true; }

var out = JSON.stringify({ threw: threw, html: el.innerHTML });
if (typeof console !== 'undefined' && console.log) console.log(out); else print(out);
"""


def _run(present, tmp_path):
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine available to execute main.js")
    script = _HARNESS % {"fn": _fn("_clearTopNavActions"),
                         "present": "true" if present else "false"}
    path = tmp_path / "case.js"
    path.write_text(script, encoding="utf-8")
    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, "JS failed: %s" % (proc.stderr or proc.stdout)
    import json
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_clearing_removes_the_button(tmp_path):
    got = _run(True, tmp_path)
    assert got["threw"] is False
    assert got["html"] == ""


def test_missing_strip_does_not_throw(tmp_path):
    """This is the regression: the old code threw when its target was absent,
    and the throw -- not the missing button -- is what broke the page."""
    assert _run(False, tmp_path)["threw"] is False
