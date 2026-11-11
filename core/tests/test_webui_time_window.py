"""Shared Overview "Time window" picker (WebUI/js/time-window.js), used by
DNS and DHCP Overview. Runs the real helper under jsc/node."""

import json
import os
import shutil
import subprocess
import tempfile

import pytest
from webui_src import WEBUI, main_js_parts, main_js_source

_JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A"
        "/Helpers/jsc")
_LIB = (WEBUI / "js" / "time-window.js").read_text(encoding="utf-8")


def _run(expr, stored=None):
    """Evaluate ``expr`` with time-window.js loaded and a fake localStorage."""
    script = "\n".join([
        "var OUT = typeof print === 'function' ? print : console.log;",
        "var STORE = %s;" % json.dumps(stored or {}),
        "var localStorage = {getItem: k => STORE[k] || null, setItem: (k, v) => { STORE[k] = v; }};",
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


def test_choice_is_remembered_per_page_and_keeps_the_dns_key():
    stored = {"lm_dns_stats_range": "week", "lm_dhcp_stats_range": "hour"}
    assert _run("[timeWindowChoice('dns_stats'), timeWindowChoice('dhcp_stats')]",
                stored) == ["week", "hour"]


def test_missing_or_bad_choice_defaults_to_day():
    assert _run("[timeWindowChoice('dhcp_stats'), timeWindowChoice('dns_stats')]",
                {"lm_dns_stats_range": "decade"}) == ["day", "day"]


def test_range_is_appended_to_urls_with_and_without_a_query():
    assert _run("[timeWindowQS('/api/dhcp/stats', 'hour'), "
                "timeWindowQS('/api/dhcp/stats?tenant=t', 'week')]") == [
        "/api/dhcp/stats?range=hour", "/api/dhcp/stats?tenant=t&range=week"]


def test_note_explains_missing_and_partial_windows_only():
    full, partial, missing = _run(
        "[timeWindowNote({partial: false}, 'day', 'DHCP server', 'Kea'),"
        " timeWindowNote({partial: true, covered_seconds: 7200, unsupported_members: 1}, 'day', 'DHCP server', 'Kea'),"
        " timeWindowNote(null, 'day', 'DHCP server', 'Kea')]")
    assert full == ""
    assert "last 2 hours" in partial and "1 DHCP server(s)" in partial
    assert "last day view" in partial
    assert "since Kea last started" in missing


def test_loaded_before_the_dns_and_dhcp_pages_that_use_it():
    parts = main_js_parts()
    lib = parts.index("js/time-window.js")
    assert lib < parts.index("js/dns-dhcp-cluster.js")
    assert lib < parts.index("js/external-dns-dhcp.js")


def test_dns_and_dhcp_overviews_both_use_the_shared_picker():
    src = main_js_source()
    for page, picker in (("dns_stats", "dns-stats-range"), ("dhcp_stats", "dhcp-stats-range")):
        assert f"timeWindowChoice('{page}')" in src
        assert f"timeWindowPicker('{picker}'" in src
        assert f"timeWindowBind('{picker}', '{page}'" in src
    assert "timeWindowQS('/api/dhcp/stats'" in src
