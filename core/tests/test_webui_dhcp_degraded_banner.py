"""The DHCP list views must render the partial-list warning.

Backend half: ``_dhcp_merge_fanout`` reports unreachable clusters in
``_degraded`` (test_dhcp_merge_degraded_visibility.py). These pin the WebUI
half — a helper that names the missing cluster, wired into ALL THREE merged
DHCP views (Subnets / Leases / Reservations). Wiring only two of them would
leave the exact symptom that was reported ("DHCP shows no reservations") still
unexplained on the third.
"""
import re
from pathlib import Path

_MAIN = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"
_SRC = _MAIN.read_text(encoding="utf-8")


def _fn(name):
    """The source text of a top-level ``function <name>(`` declaration."""
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
    raise AssertionError(f"unterminated function {name}")


def test_banner_helper_exists():
    assert "function _dhcpDegradedBanner(" in _SRC


def test_banner_is_empty_when_nothing_is_degraded():
    body = _fn("_dhcpDegradedBanner")
    assert "if (!bad.length) return '';" in body


def test_banner_reads_the_api_field_and_names_the_cluster():
    body = _fn("_dhcpDegradedBanner")
    assert "_degraded" in body
    assert "b.tenant" in body and "b.spoke" in body
    assert "b.error" in body


def test_banner_escapes_every_interpolated_value():
    # tenant/spoke/error come from spoke-supplied state — never inline them raw.
    body = _fn("_dhcpDegradedBanner")
    for expr in ("b.tenant || b.spoke", "b.error"):
        assert f"escapeHtml({expr}" in body, expr


def test_banner_says_the_rows_are_missing_not_deleted():
    # The whole point: stop an empty table reading as data loss.
    body = _fn("_dhcpDegradedBanner")
    assert "not deleted" in body


def test_all_three_merged_dhcp_views_render_the_banner():
    # Subnets / Leases / Reservations each fall back to their own empty-state
    # string; every one must be prefixed with the banner. (The DHCP Overview
    # panel reuses "No subnets configured." but is a single-spoke view, so it
    # is matched by class here to avoid colliding with it.)
    empties = ['<p class="p-4 text-slate-400 italic text-sm">No subnets configured.</p>',
               '<p class="p-4 text-slate-400 italic text-sm">No active leases.</p>',
               '<p class="p-4 text-slate-400 italic text-sm">No static reservations configured.</p>']
    for empty in empties:
        assert _SRC.count(empty) == 1, empty
        window = _SRC[max(0, _SRC.index(empty) - 400):_SRC.index(empty)]
        assert "_dhcpDegradedBanner(d)" in window, f"no banner before {empty!r}"


def test_banner_wired_into_exactly_the_three_merged_views():
    # One definition + three call sites. A fourth call site (or a missing one)
    # means a merged DHCP view drifted out of sync with the others.
    assert _SRC.count("function _dhcpDegradedBanner(d)") == 1
    assert len(re.findall(r"_dhcpDegradedBanner\(d\)", _SRC)) == 4
