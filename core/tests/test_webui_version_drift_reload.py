"""Stale-bundle guard: reload the SPA when the hub's version moves under it.

The WebUI is a single-page app whose assets are served
``Cache-Control: public, max-age=31536000, immutable`` (see ``serve_ui`` in
core/src/api.py). That is deliberate and correct -- the ``?v=<version>.<hash>``
token makes every build a new URL -- but it has a sharp edge: **only
index.html is no-store, and a SPA never re-fetches index.html.** So the only
moment a tab can learn about a new bundle is a full page load.

There WAS a reload for this, but it hangs off the reconnect path: it fires only
if the status poller actually observed the hub go down (``_statusDownToast``).
A self-update that restarts between two 10s polls -- or a WebUI-only asset
change with no restart at all -- never sets that toast. The tab then runs the
JS it loaded hours ago against a newer API, indefinitely.

The symptom is not a crash, it is a control that silently does nothing: the
handler the button calls only exists in the new bundle, or the button was moved
to a container the old bundle does not render. ("The Add Reservation button is
not triggering anything" -- the deployed bundle was fine; the tab was not.)

``_checkWebuiVersionDrift`` closes that: every poll compares against the version
the page loaded with, and any change reloads -- no outage required.
"""

import json
import os
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


# ── wiring (static, always runs) ────────────────────────────────────────────

def test_guard_exists():
    assert "function _checkWebuiVersionDrift(" in _src()


def test_guard_runs_on_every_status_poll():
    """It has to sit on the normal 200 path, not the reconnect path -- the whole
    point is the case where no outage was ever observed."""
    src = _src()
    i = src.index("window.__lmHubVersion = m.version;")
    after = src[i:i + 400]
    assert "_checkWebuiVersionDrift(m.version)" in after, (
        "the drift check must run where the polled version is recorded")


def test_guard_does_not_depend_on_an_observed_outage():
    body = _fn("_checkWebuiVersionDrift")
    assert "_statusDownToast" not in body and "_statusDownFromVersion" not in body, (
        "keying off the outage state would reintroduce the exact gap this closes")


def test_existing_reconnect_reload_is_left_intact():
    """Regression guard: the outage path still handles its own case. This must
    pass both before and after the change."""
    src = _src()
    assert "_statusDownFromVersion && newVer !== _statusDownFromVersion" in src
    assert "window.location.reload()" in src


# ── behaviour (executed) ────────────────────────────────────────────────────

_HARNESS = """
%(fn)s

var reloaded = false, toasts = [], modalOpen = %(modal)s;
var window = { location: { reload: function () { reloaded = true; } } };
var document = { querySelector: function () { return modalOpen ? {} : null; } };
function showToast(msg) { toasts.push(msg); }
function setTimeout(fn) { fn(); }

var versions = %(versions)s;
for (var i = 0; i < versions.length; i++) _checkWebuiVersionDrift(versions[i]);

var out = JSON.stringify({ reloaded: reloaded, toasts: toasts });
if (typeof console !== 'undefined' && console.log) console.log(out); else print(out);
"""


def _run(versions, tmp_path, modal=False):
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine available to execute main.js")
    # The guard reads module-scope state; hoist it into the harness.
    src = ("let _pageLoadHubVersion = null;\nlet _versionDriftReloading = false;\n"
           + _fn("_checkWebuiVersionDrift"))
    script = _HARNESS % {
        "fn": src,
        "versions": json.dumps(versions),
        "modal": "true" if modal else "false",
    }
    path = tmp_path / "case.js"
    path.write_text(script, encoding="utf-8")
    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, "JS failed: %s" % (proc.stderr or proc.stdout)
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_first_poll_only_records_a_baseline(tmp_path):
    """A fresh tab must not reload itself the instant it starts polling."""
    assert _run(["1.72"], tmp_path)["reloaded"] is False


def test_steady_state_never_reloads(tmp_path):
    assert _run(["1.72"] * 25, tmp_path)["reloaded"] is False


def test_version_change_reloads(tmp_path):
    got = _run(["1.72", "1.72", "1.73"], tmp_path)
    assert got["reloaded"] is True
    assert any("1.72" in t and "1.73" in t for t in got["toasts"]), (
        "tell the operator why the page is about to reload")


def test_reload_is_scheduled_only_once(tmp_path):
    """Polling keeps running while the 1.5s timer is pending -- without the
    latch every subsequent tick would queue another reload and another toast."""
    got = _run(["1.72", "1.73", "1.74", "1.75"], tmp_path)
    assert len(got["toasts"]) == 1, got["toasts"]


def test_an_open_modal_defers_the_reload(tmp_path):
    """Reloading mid-edit would throw away whatever the operator had typed.
    Polling continues, so it reloads on a later tick once the dialog closes."""
    got = _run(["1.72", "1.73"], tmp_path, modal=True)
    assert got["reloaded"] is False
    assert got["toasts"] == []


def test_a_downgrade_also_reloads(tmp_path):
    """VERSION is NOT monotonic in this fleet -- it has been reset backwards
    deliberately (see _webui_version). Any change means a different bundle."""
    assert _run(["1.72", "0.99"], tmp_path)["reloaded"] is True


def test_missing_version_is_ignored(tmp_path):
    """/status can answer without metrics; that must not set a bogus baseline
    that then 'drifts' on the next real poll."""
    got = _run([None, None, "1.72", "1.72"], tmp_path)
    assert got["reloaded"] is False
