"""Network module: one row per physical box.

A core switch answers SSH/SNMP on every SVI, so discovery adds it once per IP.
``_nwCollapse`` (``WebUI/js/nw.js``) folds rows that are the same hardware —
same serial, else base MAC, else same name/hostname + type — within a tenant,
keeping every address the box answered on. These run the real function under
node.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

NW_JS = Path(__file__).resolve().parents[2] / "WebUI" / "js" / "nw.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helper")


def _collapse(rows):
    src = NW_JS.read_text()
    start = src.index("function _nwCollapse")
    fn = src[start:src.index("\n}\n", start) + 3]
    harness = fn + f"\nconsole.log(JSON.stringify(_nwCollapse({json.dumps(rows)})));"
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True,
                         check=True)
    return json.loads(out.stdout)


def _row(i, name, addr, **kw):
    return dict({"id": str(i), "name": name, "address": addr, "tenant_id": "t1",
                 "object_type": "cx_switch", "reachable": True}, **kw)


def test_same_box_at_several_addresses_collapses_to_one_row():
    out = _collapse([
        _row(1, "CORE-SW1", "10.0.0.1", reachable=False),
        _row(2, "core-sw1", "10.0.1.1"),
        _row(3, "CORE-SW1", "10.0.2.1"),
    ])
    assert len(out) == 1
    # A reachable member is the primary (opened on click / polled).
    assert out[0]["id"] == "2" and out[0]["reachable"] is True
    assert out[0]["_addresses"] == ["10.0.0.1", "10.0.1.1", "10.0.2.1"]


def test_serial_merges_even_when_names_differ():
    out = _collapse([_row(1, "SW2", "10.0.0.2", serial="SG1"),
                     _row(2, "10.9.9.9", "10.9.9.9", serial="SG1")])
    assert len(out) == 1 and out[0]["serial"] == "SG1"


def test_different_serials_or_tenants_never_merge():
    out = _collapse([
        _row(1, "DUP", "1.1.1.1", serial="S1"),
        _row(2, "DUP", "1.1.1.2", serial="S2"),
        _row(3, "DUP", "1.1.1.1", serial="S1", tenant_id="t2"),
    ])
    assert len(out) == 3
