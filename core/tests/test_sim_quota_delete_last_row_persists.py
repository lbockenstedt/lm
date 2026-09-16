"""Regression: removing the LAST sim-quota row of a source must actually persist.

CS → Config → Engine renders the tenant's own ``sim_quotas`` rows and offers a
per-row Remove. Removing a row only edits the in-memory working set; the change
reaches the hub on Save. ``csSimQuotaSave`` split-saves by source, but it only
issued the POST ``if (centralRows.length)`` / ``if (mistRows.length)`` -- so
when the operator removed a source's only row the editor had nothing left to
send for that source and **no request was made at all**. The deletion was never
persisted and the row came back on the next load, which is why the row could be
disabled but never removed.

Two things are needed for the delete to stick:

1. POST the source's config whenever it has *stored* rows, even when the editor
   now holds none for that source, and
2. set ``force_sim_quotas_clear`` on that POST, because emptying the table is
   exactly the N>0 -> 0 transition ``guard_sim_quota_wipe`` refuses by default.
   Clearing the editor is a deliberate operator edit, not the stale
   ``simulation.conf`` blast the guard defends against.

The behaviour tests execute the real ``csSimQuotaSave`` under JavaScriptCore
(or node) against stubs, so they check behaviour rather than source text. They
skip where no JS engine is available; the wiring test is static and always runs.

``WebUI/sim-views.js`` has a twin at ``cs/lm-spoke/static/sim-views.js`` -- both
copies carry this fix and must stay in lockstep.
"""

import json
import os
import shutil
import subprocess

import pytest

SIM_VIEWS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "sim-views.js"))

JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/"
       "Helpers/jsc")


def _src():
    with open(SIM_VIEWS, encoding="utf-8") as fh:
        return fh.read()


def _extract_assigned(name, src):
    """Return the source of a top-level ``window.<name> = async function ...``
    by brace-matching, so the test runs the real implementation."""
    start = src.index("window.%s = async function" % name)
    depth, i = 0, src.index("{", start)
    for k in range(i, len(src)):
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


HARNESS = r"""
if (typeof print !== 'function') { var print = console.log; }
var window = {};

var STORE = __STORE__;
var EDITOR = __EDITOR__;
var CALLS = [];

function csTenant() { return 't1'; }
function csSimQuotaSyncFromDom() { return EDITOR; }
function _csQuotaSource(id) {
    return String(id || '').indexOf('Mist:') === 0 ? 'mist' : 'central';
}
function csSimQuotaRowFromServer(r) { return r; }
function csRenderSimQuotaEditor() {}
function showToast() {}

function csFetch(url, opts) {
    var key = url.indexOf('mist-sites-config') >= 0 ? 'mist' : 'central';
    if (opts && opts.method === 'POST') {
        var body = JSON.parse(opts.body);
        CALLS.push({
            source: key,
            rows: (body.sim_quotas || []).map(function (r) { return r.alert_id; }),
            force: !!body.force_sim_quotas_clear,
            kept_monitored: (body.monitored_checks || []).length
        });
        STORE[key].sim_quotas = body.sim_quotas;
        return Promise.resolve({ sim_quotas: body.sim_quotas, sim_quota_errors: [] });
    }
    return Promise.resolve(STORE[key]);
}

__FN__

window.csSimQuotaSave().then(function () {
    print(JSON.stringify({ posts: CALLS, store: STORE }));
}, function (e) { print(JSON.stringify({ error: String(e) })); });
if (typeof drainMicrotasks === 'function') { drainMicrotasks(); }
"""


def _run(store, editor):
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScriptCore or node available")
    script = (HARNESS
              .replace("__STORE__", json.dumps(store))
              .replace("__EDITOR__", json.dumps(editor))
              .replace("__FN__", _extract_assigned("csSimQuotaSave", _src())))
    proc = subprocess.run(engine + ["-e", script] if engine[0] == JSC
                          else engine + ["--input-type=module", "-e", script],
                          capture_output=True, text=True, timeout=60)
    out = (proc.stdout or "").strip().splitlines()
    assert out, "no output from JS engine: %s" % (proc.stderr or "")
    result = json.loads(out[-1])
    assert "error" not in result, result
    return result


def _store(central_rows, mist_rows):
    return {
        "central": {"sim_quotas": central_rows, "site_mappings": {"s": "w"},
                    "monitored_checks": [{"type": "alert", "id": "a"}],
                    "hardware_checks": [], "ignore_global_quotas": False},
        "mist": {"sim_quotas": mist_rows, "site_mappings": {},
                 "monitored_checks": [], "hardware_checks": []},
    }


# ── behaviour ───────────────────────────────────────────────────────────────

def test_removing_the_only_central_row_posts_an_empty_forced_clear():
    stored = [{"alert_id": "Central:AP down", "sim_id": "ping_test", "count": 5}]
    res = _run(_store(stored, []), [])

    posts = [c for c in res["posts"] if c["source"] == "central"]
    assert posts, ("removing the last row sent NO central POST -- the delete "
                   "never reaches the hub and the row returns on reload")
    assert posts[0]["rows"] == [], posts
    assert posts[0]["force"] is True, (
        "an emptied editor must set force_sim_quotas_clear or "
        "guard_sim_quota_wipe silently refuses the delete")
    assert res["store"]["central"]["sim_quotas"] == []


def test_forced_clear_still_preserves_the_other_config_fields():
    stored = [{"alert_id": "Central:AP down", "sim_id": "ping_test", "count": 5}]
    res = _run(_store(stored, []), [])
    posts = [c for c in res["posts"] if c["source"] == "central"]
    assert posts[0]["kept_monitored"] == 1, (
        "clearing quotas must not drop monitored_checks")


def test_removing_the_last_mist_row_does_not_disturb_central_rows():
    central = [{"alert_id": "Central:AP down", "sim_id": "ping_test", "count": 5}]
    mist = [{"alert_id": "Mist:AP down", "sim_id": "ping_test", "count": 3}]
    res = _run(_store(central, mist), central)

    mist_posts = [c for c in res["posts"] if c["source"] == "mist"]
    assert mist_posts and mist_posts[0]["force"] is True, mist_posts
    assert res["store"]["mist"]["sim_quotas"] == []
    assert res["store"]["central"]["sim_quotas"] == central


def test_a_normal_partial_delete_does_not_set_force():
    a = {"alert_id": "Central:AP down", "sim_id": "ping_test", "count": 5}
    b = {"alert_id": "Central:Gateway down", "sim_id": "download", "count": 2}
    res = _run(_store([a, b], []), [a])

    posts = [c for c in res["posts"] if c["source"] == "central"]
    assert posts[0]["rows"] == ["Central:AP down"], posts
    assert posts[0]["force"] is False, (
        "a partial delete is not a wipe -- the guard allows it, so the "
        "force opt-in must stay off")


def test_no_rows_stored_and_none_in_the_editor_posts_nothing():
    res = _run(_store([], []), [])
    assert res["posts"] == [], (
        "with nothing stored and nothing to save there is no change to push")


# ── wiring (static, always runs) ────────────────────────────────────────────

def test_save_consults_stored_rows_so_an_empty_editor_still_saves():
    fn = _extract_assigned("csSimQuotaSave", _src())
    assert "centralStored" in fn and "mistStored" in fn, (
        "csSimQuotaSave must look at the stored row count; gating the POST on "
        "the editor's row count alone makes deleting a source's last row a "
        "no-op")
    assert "force_sim_quotas_clear" in fn, (
        "csSimQuotaSave must opt past guard_sim_quota_wipe when the operator "
        "deliberately empties a source's rows")
