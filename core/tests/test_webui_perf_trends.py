"""Shared performance charts and History range selector (WebUI/js/perf-trends.js),
used by Storage → Performance and Firewalls → Overview. Runs the real helper
under jsc/node."""

import json
import os
import shutil
import subprocess
import tempfile

import pytest
from webui_src import WEBUI

_JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A"
        "/Helpers/jsc")
_LIB = (WEBUI / "js" / "perf-trends.js").read_text(encoding="utf-8")


def _run(expr):
    """Evaluate ``expr`` with perf-trends.js loaded and a stub document."""
    script = "\n".join([
        "var OUT = typeof print === 'function' ? print : console.log;",
        "var document = {querySelectorAll: () => []};",
        "Date.now = () => 1800000000000;",
        _LIB,
        "OUT(JSON.stringify(%s));" % expr,
    ])
    if os.path.exists(_JSC):
        runtime = [_JSC]
    elif shutil.which("node"):
        runtime = [shutil.which("node")]
    else:  # pragma: no cover
        pytest.skip("no JavaScript runtime (jsc/node) available")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(script)
        path = fh.name
    try:
        proc = subprocess.run(runtime + [path], capture_output=True,
                              text=True, timeout=60)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout.strip().splitlines()[-1])
    finally:
        os.unlink(path)


def test_default_range_needs_no_query_and_others_do():
    # Storage defaults to 1h (hub warm cache), firewalls to 7d (hub copy).
    assert _run("[perfRangeWindow('tn', {preset: 3600}, 3600).qs, "
                "perfRangeWindow('fw', {preset: 604800}, 604800).qs, "
                "perfRangeWindow('fw', {preset: 3600}, 604800).qs, "
                "perfRangeWindow('fw', {start: 100, end: 200}, 604800).qs]") == [
        "", "", "?start=1799996400&end=1800000000", "?start=100&end=200"]


def test_chart_escapes_labels_and_breaks_the_line_at_gaps():
    html = _run("perfTrendChart('c', 'eth<0>', ["
                "{ts: 0, metrics: {a: 1}}, {ts: 300, metrics: {a: 2}}, {ts: 1500, metrics: {a: 3}}],"
                " [{key: 'a', label: '<b>', color: '#000'}], String, 0, 1800)")
    assert "eth&lt;0&gt;" in html and "&lt;b&gt;" in html and "<b>" not in html
    path = html.split('<path d="')[1].split('"')[0]
    assert path.count("M") == 2 and path.count("L") == 1
    assert "No data for this range" in _run("perfTrendChart('c', 't', [], [], String, 0, 1)")

