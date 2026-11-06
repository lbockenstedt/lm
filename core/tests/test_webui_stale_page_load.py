"""WebUI guard: a page that is still loading must not paint over the next one.

Reported as "if I click a link off the page too quickly it starts to load but
then the original page is loaded in the frame" (Hypervisors: Overview -> click
Diagnostics -> the VM list replaced the Diagnostics page).

Page loaders `await` their data and then write into the module's content pane.
Sub-tabs share that pane, so the slow Overview response landed after the
Diagnostics render and overwrote it. The fix is central: every navigation bumps
`_lmNavSeq`, and lmFetch never settles a page read (GET) that started before the
latest navigation, so the abandoned loader simply stops.
"""

import os
import shutil
import subprocess

import pytest
from webui_src import main_js_source

WEBUI = os.path.join(os.path.dirname(__file__), "..", "..", "WebUI")
MAIN_JS = os.path.abspath(os.path.join(WEBUI, "main.js"))

JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/"
       "Helpers/jsc")


def _src():
    return main_js_source()


def _extract(name, src):
    """Source of a `[async] function <name>(...) {...}`, brace-matched."""
    start = src.index("function %s(" % name)
    prefix = "async "
    if src[max(0, start - len(prefix)):start] == prefix:
        start -= len(prefix)
    depth = 0
    for k in range(src.index("{", src.index(")", start)), len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[start:k + 1]
    raise AssertionError("unbalanced braces in " + name)


def _run(js, tmp_path):
    engine = [JSC] if os.path.exists(JSC) else (
        [shutil.which("node")] if shutil.which("node") else None)
    if not engine:
        pytest.skip("no JavaScript engine (jsc/node) available")
    harness = "var out = (typeof print === 'function') ? print : console.log;\n"
    path = tmp_path / "t.js"
    path.write_text(harness + js, encoding="utf-8")
    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip().splitlines()


# lmFetch with a controllable network: every request parks until release().
_FETCH_HARNESS = """
var _lmNavSeq = 0, _lmActiveFetchCount = 0, currentUser = null;
function _lmNotifyFetchState() {}
function _lmIsAuthSubmitEndpoint() { return false; }
function handleSessionExpired() {}
if (typeof AbortController === 'undefined') {           // jsc has no DOM APIs
    globalThis.AbortController = function () {
        var sig = { aborted: false, _fns: [], addEventListener: function (_, f) { this._fns.push(f); } };
        this.signal = sig;
        this.abort = function () { if (!sig.aborted) { sig.aborted = true; sig._fns.forEach(function (f) { f(); }); } };
    };
    globalThis.AbortSignal = {};
}
var _parked = [], aborted = 0;
function _lmOrigFetch(input, init) {
    return new Promise(function (res, rej) {
        _parked.push({ res: res, rej: rej });
        if (init && init.signal) init.signal.addEventListener('abort', function () {
            aborted++; rej(new Error('AbortError'));
        });
    });
}
function release() { _parked.forEach(function (p) { p.res({ status: 200 }); }); }
function fail() { _parked.forEach(function (p) { p.rej(new Error('net down')); }); }
async function drain() { for (var i = 0; i < 20; i++) await null; }
function track(p) {
    var r = { state: 'pending' };
    p.then(function () { r.state = 'resolved'; }, function () { r.state = 'rejected'; });
    return r;
}
"""


def _fetch_js(body):
    src = _src()
    return (_FETCH_HARNESS + "var _lmPageReads = new Set();\n"
            + _extract("_lmNavigated", src) + "\n"
            + _extract("_lmLeftPageSince", src) + "\n"
            + _extract("lmFetch", src) + "\n(async function () {\n" + body
            + "\n})();")


def test_tab_switch_drops_the_old_tabs_response(tmp_path):
    """The reported race: Overview's GET returns after Diagnostics opened."""
    js = _fetch_js("""
        _lmNavSeq = 1;                                   // on Overview
        var overview = track(lmFetch('/api/pxmx/vms'));
        _lmNavSeq++;                                     // clicked Diagnostics
        var diag = track(lmFetch('/api/pxmx/diagnostics'));
        release(); await drain();
        out('overview=' + overview.state + ' diag=' + diag.state
            + ' active=' + _lmActiveFetchCount);
    """)
    assert _run(js, tmp_path) == [
        "overview=pending diag=resolved active=0"]


def test_navigation_cancels_the_old_pages_reads(tmp_path):
    """A read from a page the user left must free its browser connection (the
    hub is HTTP/1.1: ~6 per host) instead of holding it until the spoke answers;
    pages stalled until a refresh once a few such reads piled up."""
    js = _fetch_js("""
        _lmNavSeq = 1;
        var old = track(lmFetch('/api/pxmx/vms'));
        var write = track(lmFetch('/api/x', { method: 'POST' }));
        _lmNavigated();
        var cur = track(lmFetch('/api/pxmx/diagnostics'));
        await drain();
        out('aborted=' + aborted + ' old=' + old.state + ' write=' + write.state
            + ' tracked=' + _lmPageReads.size);
        release(); await drain();
        out('cur=' + cur.state + ' write=' + write.state + ' tracked=' + _lmPageReads.size);
    """)
    assert _run(js, tmp_path) == [
        "aborted=1 old=pending write=pending tracked=1",
        "cur=resolved write=resolved tracked=0"]


def test_failed_old_request_does_not_paint_an_error_either(tmp_path):
    js = _fetch_js("""
        _lmNavSeq = 1;
        var old = track(lmFetch('/api/pxmx/vms'));
        _lmNavSeq++;
        fail(); await drain();
        out('old=' + old.state);
    """)
    assert _run(js, tmp_path) == ["old=pending"]


def test_requests_that_must_outlive_the_page_still_complete(tmp_path):
    """Writes, boot-time loads, background polls and opted-out reads."""
    js = _fetch_js("""
        var boot = track(lmFetch('/api/appearance'));    // before first render
        _lmNavSeq = 1;
        var post = track(lmFetch('/setup/x', { method: 'POST' }));
        var bg = track(lmFetch('/status', { _background: true }));
        var keep = track(lmFetch('/setup/backup/download', { _keepOnNavigate: true }));
        _lmNavSeq++;
        release(); await drain();
        out([boot.state, post.state, bg.state, keep.state].join(' '));
    """)
    assert _run(js, tmp_path) == ["resolved resolved resolved resolved"]


def test_single_flight_reopens_after_navigation(tmp_path):
    """An opener whose fetch was dropped must not block that button for good."""
    js = ("var _lmNavSeq = 1;\n" + _extract("_singleFlight", _src()) + """
    var calls = 0;
    var open = _singleFlight(function () {
        calls++;
        return new Promise(function () {});            // dropped: never settles
    });
    open(); open();
    _lmNavSeq++;
    open();
    out('calls=' + calls);
    """)
    assert _run(js, tmp_path) == ["calls=2"]


def test_every_navigation_entry_point_bumps_the_counter():
    src = _src()
    for name in ("setView", "setSubView", "setSubChild", "setSubGrandchild",
                 "refreshCurrentView"):
        assert "_lmNavigated()" in _extract(name, src), (
            "%s must call _lmNavigated() so the page it leaves can't paint over "
            "the new one" % name)
