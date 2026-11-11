"""The Associated Spoke dropdown (IPAM/NAC/LDAP instances and Managed Devices)
must list only spokes running the product's code, not every bare agent.

Runs the real _productSpokes from the WebUI bundle under jsc/node.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest
from webui_src import main_js_source

_JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A"
        "/Helpers/jsc")

_IPAM = {"moduleType": "ipam", "alsoBareAgent": True}

_SPOKES = [
    {"spoke_id": "lm-agent-netbox", "module_type": "ipam"},
    {"spoke_id": "lm-agent", "module_type": "agent"},
    {"spoke_id": "other-agent", "module_type": "agent"},
    {"spoke_id": "fw-1", "module_type": "firewall"},
]


def _function(src, name):
    m = re.search(r"function " + name + r"\(", src)
    assert m, f"{name} not found in WebUI bundle"
    depth = 0
    for i in range(src.index("{", m.start()), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
    raise AssertionError("unbalanced " + name)


def _product_spokes(product, spokes, current=""):
    script = "\n".join([
        "var OUT = typeof print === 'function' ? print : console.log;",
        "function _spokeBindable(s) { return true; }",
        _function(main_js_source(), "_productSpokes"),
        "OUT(JSON.stringify(_productSpokes(%s, %s, %s).map(s => s.spoke_id)));"
        % (json.dumps(product), json.dumps(spokes), json.dumps(current)),
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


def test_ipam_dropdown_lists_only_spokes_running_netbox():
    assert _product_spokes(_IPAM, _SPOKES) == ["lm-agent-netbox"]


def test_currently_bound_bare_agent_stays_listed_so_edit_cannot_unbind():
    assert _product_spokes(_IPAM, _SPOKES, "lm-agent") == [
        "lm-agent-netbox", "lm-agent"]
