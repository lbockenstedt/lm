"""WebUI guard: a JSON body of the literal token `null` must not reach callers.

Reported as "DHCP / Overview on the shared instance → Error: null is not an
object (evaluating 'd.status')".

`response.json()` RESOLVES a body of `null` to null rather than throwing, so the
ubiquitous `.catch(() => ({}))` guard never fired and `{ok: true, data: null}`
was handed to consumers whose very next statement dereferenced it. The hub side
now refuses to emit a null body (`_spoke_payload_or_raise`, see
test_relay_contract.py); these tests lock in the browser-side half so a future
route that serializes None degrades to an empty envelope instead of a hard
TypeError that blanks the whole tab.
"""

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


def _extract(name, src):
    """Source of a top-level `[async] function <name>(...) {...}` by brace
    matching, so the test exercises the real implementation.

    Two refinements over the helper in the sibling WebUI tests: an `async`
    prefix is kept (dropping it makes the body a syntax error at its first
    `await`), and the body brace is located by first balancing the PARAMETER
    list — otherwise a default argument like `options = {}` is mistaken for the
    body and the extraction stops at its closing brace."""
    start = src.index("function %s(" % name)
    prefix = "async "
    if src[max(0, start - len(prefix)):start] == prefix:
        start -= len(prefix)
    # Balance the parameter list to find where the body actually begins.
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
    # jsc exposes print(); node exposes console.log. Support both so this runs
    # on CI (node) and on developer machines here (JavaScriptCore).
    harness = "var out = (typeof print === 'function') ? print : console.log;\n"
    path = tmp_path / "t.js"
    path.write_text(harness + js, encoding="utf-8")
    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip().splitlines()


# ── static wiring ────────────────────────────────────────────────────────────

def test_spokefetch_does_not_use_the_bare_catch_only_guard():
    """`.catch(() => ({}))` alone is insufficient — it only fires on a PARSE
    error, and `null` parses fine."""
    src = _src()
    fn = _extract("_spokeFetch", src)
    assert "typeof body === 'object'" in fn, (
        "_spokeFetch must coerce a non-object success body to {}")


def test_apijson_normalizes_a_null_body():
    fn = _extract("apiJson", _src())
    assert "body === null" in fn, "apiJson must normalize a null body to {}"


# ── behavioural ──────────────────────────────────────────────────────────────

def _fetch_stub(json_expr, ok="true", status="200"):
    return """
    function fetch(url, opts) {
        return Promise.resolve({
            ok: %s, status: %s,
            statusText: 'OK',
            headers: { get: function () { return 'application/json'; } },
            json: function () { return Promise.resolve(%s); }
        });
    }
    var setupFetch = fetch;
    """ % (ok, status, json_expr)


def test_spokefetch_null_body_becomes_empty_object(tmp_path):
    """The exact reported failure: the consumer's `d.status` must not throw."""
    js = _fetch_stub("null") + _extract("_spokeFetch", _src()) + """
    _spokeFetch('/api/dhcp/stats').then(function (r) {
        out('ok=' + r.ok);
        out('isNull=' + (r.data === null));
        // Reproduces the crashing line from the DHCP Overview renderer.
        try { var s = r.data.status; out('deref=ok'); }
        catch (e) { out('deref=threw:' + e.message); }
    });
    """
    lines = _run(js, tmp_path)
    assert "ok=true" in lines
    assert "isNull=false" in lines
    assert "deref=ok" in lines


def test_spokefetch_real_body_is_untouched(tmp_path):
    """The guard must not disturb a normal SUCCESS envelope."""
    js = _fetch_stub("{ status: 'SUCCESS', global: { utilization_pct: 42 } }") \
        + _extract("_spokeFetch", _src()) + """
    _spokeFetch('/api/dhcp/stats').then(function (r) {
        out('status=' + r.data.status);
        out('util=' + r.data.global.utilization_pct);
    });
    """
    lines = _run(js, tmp_path)
    assert "status=SUCCESS" in lines
    assert "util=42" in lines


def test_apijson_null_body_becomes_empty_object(tmp_path):
    js = _fetch_stub("null") + _extract("apiJson", _src()) + """
    apiJson('/api/whatever').then(function (d) {
        out('isNull=' + (d === null));
        try { var s = d.status; out('deref=ok'); }
        catch (e) { out('deref=threw:' + e.message); }
    });
    """
    lines = _run(js, tmp_path)
    assert "isNull=false" in lines
    assert "deref=ok" in lines


def test_apijson_array_body_passes_through(tmp_path):
    """A list endpoint must still get its array, not {}."""
    js = _fetch_stub("[1, 2, 3]") + _extract("apiJson", _src()) + """
    apiJson('/api/list').then(function (d) {
        out('isArray=' + Array.isArray(d));
        out('len=' + d.length);
    });
    """
    lines = _run(js, tmp_path)
    assert "isArray=true" in lines
    assert "len=3" in lines
