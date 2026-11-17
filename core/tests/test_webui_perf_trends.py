"""Shared performance charts and History range selector (WebUI/js/perf-trends.js),
used by Storage → Overview and Firewalls → Overview. Runs the real helper
under jsc/node."""

import json
import os
import re
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
    # Storage's hub-served preset is 1h (warm cache), firewalls' is 7d (hub copy).
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



_NW = (WEBUI / "js" / "nw.js").read_text(encoding="utf-8")
_FW = (WEBUI / "js" / "views" / "firewall-overview.js").read_text(encoding="utf-8")


def test_both_pages_open_on_24h_read_as_a_24h_window():
    # Owner's choice: Storage and Firewalls both open on 24 hours. That range
    # is not either page's hub-served preset, so it must be asked for with
    # start/end covering exactly 24h (not the hub's 1h or 7d copy).
    tn = re.search(r"let _tnRange = \{ preset: (\d+) \}", _NW).group(1)
    fw = re.search(r"let perfRange = \{ preset: (\d+) \}", _FW).group(1)
    hub = re.search(r"const HUB_PRESET = (\d+);", _FW).group(1)
    assert tn == fw == "86400"
    assert "perfRangeWindow('tn', _tnRange, 3600)" in _NW
    assert "perfRangeWindow('fw', perfRange, HUB_PRESET)" in _FW
    assert _run("[perfRangeWindow('tn', {preset: %s}, 3600).qs, "
                "perfRangeWindow('fw', {preset: %s}, %s).qs]" % (tn, fw, hub)) == [
        "?start=1799913600&end=1800000000"] * 2


def test_storage_selector_sits_between_tiles_and_charts():
    # Same layout as Firewalls → Overview: tiles, then History, then charts.
    tiles = _NW.index("tile('Read IOPS'")
    bar = _NW.index("perfRangeBar('tn', _tnRange)")
    charts = _NW.index('id="tn-trends-${i}"')
    assert tiles < bar < charts


def test_header_search_yields_to_help_on_a_narrow_window():
    # The search box is centred absolutely; below 1280px it must join the flex
    # row (so it cannot cover Help) and below 1024px the labels drop to icons.
    html = (WEBUI / "index.html").read_text(encoding="utf-8")
    assert 'class="topbar-search absolute' in html
    css = re.search(r"@media \(max-width: 1279px\) \{\s*\.hpe-topbar \.topbar-search \{([^}]*)\}", html)
    assert css and "position: static" in css.group(1) and "transform: none" in css.group(1)
    assert re.search(r"@media \(max-width: 1023px\) \{\s*\.hpe-topbar \.topbar-label \{ display: none; \}", html)
    assert '<span class="topbar-label">Help</span>' in html
    assert '<span class="topbar-label">Updates</span>' in html
