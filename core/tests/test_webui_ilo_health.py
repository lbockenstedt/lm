"""Proxmox → Diagnostics "Hardware (iLO/BMC)" section (WebUI/js/views/ilo-health.js),
rendered under node for each state the hub can send in ``node.hw_health``."""
import json
import shutil
import subprocess

import pytest

from webui_src import WEBUI

NODE = shutil.which("node")
MODULE = (WEBUI / "js" / "views" / "ilo-health.js").as_uri()
NOW = 1_000_000.0
CTL = {"id": "c1", "name": "ilo-pve1", "address": "192.0.2.10"}


def _render(hw):
    """iloHealthHtml(hw) as an HTML string."""
    js = (f"globalThis.lmViews = {{}};\n"
          f"const m = await import({json.dumps(MODULE)});\n"
          f"console.log(JSON.stringify(String(m.iloHealthHtml({json.dumps(hw)}, {NOW}))));")
    out = subprocess.run([NODE, "--input-type=module", "-e", js], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _health(**groups):
    return {"overall": "ok", "source": "snmp", "polled_at": NOW - 300, "components": groups}


@pytest.mark.skipif(not NODE, reason="node not installed")
class TestStates:
    def test_no_linked_ilo(self):
        assert "no controller linked" in _render(None)

    def test_linked_but_not_reported(self):
        html = _render({"controller": CTL, "health": None})
        assert "not reported yet" in html and 'data-action="openIlo" data-id="c1"' in html
        assert "ilo-pve1 · 192.0.2.10" in html

    def test_error_without_a_previous_reading(self):
        html = _render({"controller": CTL, "health": None, "error": "SNMP <timeout>", "error_at": NOW - 60})
        assert "Last read failed" in html and "SNMP &lt;timeout&gt;" in html and "not reported" not in html

    def test_all_ok_summary_and_last_polled(self):
        html = _render({"controller": CTL, "health": _health(
            power=[{"name": "Power supply 1", "condition": "ok"}, {"name": "Power supply 2", "condition": "ok"}],
            fans=[{"name": "Fan 1", "condition": "ok"}])})
        assert "All 3 components OK: Power supply ×2 · Fan ×1." in html
        assert "polled" in html and "5m ago" in html and "<table" not in html

    def test_failed_listed_before_degraded_with_location(self):
        h = _health(fans=[{"name": "Fan 2", "condition": "degraded", "location": "System"}],
                    memory=[{"name": "DIMM 3", "condition": "failed", "location": "PROC 1 DIMM 3",
                             "detail": "degraded"}, {"name": "DIMM 4", "condition": "ok"}])
        h["overall"] = "failed"
        html = _render({"controller": CTL, "health": h})
        assert html.index("DIMM 3") < html.index("Fan 2") and "PROC 1 DIMM 3" in html
        assert "DIMM 4" not in html and "1 other component OK." in html
        assert "bg-red-100" in html.split("Hardware (iLO/BMC)")[1].split("data-action")[0]

    def test_unknown_condition_is_never_counted_as_ok(self):
        html = _render({"controller": CTL, "health": _health(
            fans=[{"name": "Fan 1", "condition": "other"}, {"name": "Fan 2", "condition": "ok"}],
            extra=[{"name": "Thing 1"}])})
        assert "All " not in html and "Fan 1" in html and "Thing 1" in html and ">unknown<" in html
        assert "1 other component OK." in html and "Fan 2" not in html

    def test_overall_not_ok_with_all_listed_components_ok_says_so(self):
        for overall in ("degraded", "failed"):
            h = _health(cpus=[{"name": "CPU 1", "condition": "ok"}])
            h["overall"] = overall
            assert "fault outside these components" in _render({"controller": CTL, "health": h})
        assert "fault outside" not in _render({"controller": CTL, "health": _health(cpus=[{"name": "CPU 1", "condition": "ok"}])})
        for overall in ("other", None):
            h = _health(cpus=[{"name": "CPU 1", "condition": "ok"}])
            h["overall"] = overall
            html = _render({"controller": CTL, "health": h})
            assert "did not report an overall condition" in html and "fault outside" not in html

    def test_attach_failure_is_not_shown_as_unlinked(self):
        html = _render({"unavailable": True})
        assert "could not be loaded" in html and "no controller linked" not in html

    def test_stale_with_error_keeps_previous_reading(self):
        html = _render({"controller": CTL, "health": _health(cpus=[{"name": "CPU 1", "condition": "ok"}]),
                        "stale": True, "error": "timeout", "error_at": NOW})
        assert ">stale<" in html and "showing the previous reading" in html and "1 component OK: CPU ×1." in html


def test_diagnostics_page_renders_and_wires_the_section():
    pxmx = (WEBUI / "js" / "pxmx-console.js").read_text(encoding="utf-8")
    assert "lmViews.ilohealth(n.hw_health)" in pxmx and "lmViews.ilohealthWire(container)" in pxmx
    assert 'src="js/views/ilo-health.js' in (WEBUI / "index.html").read_text(encoding="utf-8")
    nw = (WEBUI / "js" / "nw.js").read_text(encoding="utf-8")
    assert "function nwShowDevice(" in nw and "if (row) nwOpenDevice(row.id);" in nw
