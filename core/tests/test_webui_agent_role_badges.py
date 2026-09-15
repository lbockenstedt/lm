"""The Agents tile's role cell must agree with the Roles dialog.

Deploy roles (dns-server, dhcp-server, netbox-server) are INSTALLS, not hosted
sub-spokes, so they never appear in the agent's ``active`` list; and the live
``GET_DEPLOY_STATUS`` map is in-memory on the agent, so it is empty after any
agent restart. The tile therefore used to render "none (idle)" for a node that
was demonstrably running Unbound/Kea, while the Roles dialog -- which reads the
durable ``installed_deploy_roles`` / ``active_deploy_roles`` markers -- listed
them as loaded. Both views must read the same durable source.

These tests do not just grep: they extract the real role-cell callback out of
main.js and EXECUTE it against stub inputs, so an assertion cannot pass against
an empty or stubbed-out implementation.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest

MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))

_ANCHOR = ("Promise.all([fetchAgentRoleState(aid), fetchDeployStatus(aid)])"
           ".then(([roleState, ds]) => {")

_JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A"
        "/Helpers/jsc")


def _role_cell_callback() -> str:
    """Return the body of the Agents-tile role-cell callback."""
    src = open(MAIN_JS, encoding="utf-8").read()
    start = src.index(_ANCHOR)
    open_brace = src.index("{", start + len(_ANCHOR) - 1)
    depth = 0
    for i in range(open_brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[open_brace + 1:i]
    raise AssertionError("unbalanced role-cell callback")


# ── source-shape guards ──────────────────────────────────────────────────────

def test_tile_fetches_the_durable_role_state_not_just_active():
    """fetchLoadedRoles() returns only `active`, which can never contain a
    deploy role. The tile must pull the full role state instead."""
    src = open(MAIN_JS, encoding="utf-8").read()
    assert _ANCHOR in src, "tile must fetch full role state, not fetchLoadedRoles"
    assert "Promise.all([fetchLoadedRoles(aid), fetchDeployStatus(aid)])" not in src


def test_tile_reads_both_durable_marker_and_unit_state():
    body = _role_cell_callback()
    assert "roleState.installed_deploy_roles" in body
    assert "roleState.active_deploy_roles" in body


def test_live_deploy_status_is_not_duplicated_by_the_durable_badge():
    body = _role_cell_callback()
    assert "shownDeploy" in body
    assert re.search(r"shownDeploy\.add\(dep\.role\)", body)


def test_netbox_badge_falls_back_to_the_durable_marker():
    """fetchDeployStatus is Global-Admin-only (it POSTs /api/agent/*), so a
    tenant admin gets null and used to lose the NetBox badge entirely."""
    body = _role_cell_callback()
    assert "installedDeploy.includes('netbox-server')" in body


# ── behavioural test: execute the real callback ──────────────────────────────

_HARNESS = r"""
var OUT = (typeof print === 'function') ? print : console.log;
var AGENT_ROLES = {
  'dns-server': {name: 'DNS Server', deploy: true},
  'dhcp-server': {name: 'DHCP Server', deploy: true},
  'netbox-server': {name: 'NetBox Server', deploy: true},
  'simulation': {name: 'Simulation'}
};
function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
var CSS = { escape: function (s) { return s; } };
var aid = 'AGENT1';
var __html = null;
var __cell = { set outerHTML(v) { __html = v; } };
var agentsWrap = { querySelector: function () { return __cell; } };

function render(roleState, ds) {
  __html = null;
__BODY__
  return __html;
}

var CASES = __CASES__;
var results = [];
for (var i = 0; i < CASES.length; i++) {
  results.push(render(CASES[i].roleState, CASES[i].ds));
}
OUT(JSON.stringify(results));
"""


def _run_js(cases):
    body = _role_cell_callback()
    script = (_HARNESS
              .replace("__BODY__", body)
              .replace("__CASES__", json.dumps(cases)))
    if os.path.exists(_JSC):
        runtime = [_JSC]
    elif shutil.which("node"):
        runtime = [shutil.which("node")]
    else:  # pragma: no cover - no JS runtime on this host
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


# MIPBE-SVCS-01/02: DNS + DHCP installed and enabled, agent restarted since so
# the live deploy map is empty. This is the exact reported bug.
_MIPBE = {"roleState": {"active": [],
                        "installed_deploy_roles": ["dhcp-server", "dns-server"],
                        "active_deploy_roles": ["dhcp-server", "dns-server"]},
          "ds": None}

_STOPPED = {"roleState": {"active": [],
                          "installed_deploy_roles": ["dns-server"],
                          "active_deploy_roles": []},
            "ds": None}

_LIVE_DEPLOY = {"roleState": {"active": [],
                              "installed_deploy_roles": ["dns-server"],
                              "active_deploy_roles": []},
                "ds": {"deploys": [{"role": "dns-server", "state": "running"}]}}

_IDLE = {"roleState": {"active": [], "installed_deploy_roles": [],
                       "active_deploy_roles": []},
         "ds": None}

_NETBOX_MARKER_ONLY = {
    "roleState": {"active": [], "installed_deploy_roles": ["netbox-server"],
                  "active_deploy_roles": ["netbox-server"]},
    "ds": None}

_HOSTED = {"roleState": {"active": [{"role": "simulation",
                                     "sub_spoke_id": "AGENT1-simulation"}],
                         "installed_deploy_roles": [],
                         "active_deploy_roles": []},
           "ds": None}


def test_installed_and_enabled_deploy_roles_render_as_badges():
    html, = _run_js([_MIPBE])
    assert "DNS Server: installed" in html
    assert "DHCP Server: installed" in html
    assert "none (idle)" not in html
    assert "installed (stopped)" not in html


def test_installed_but_disabled_deploy_role_is_flagged_stopped():
    html, = _run_js([_STOPPED])
    assert "DNS Server: installed (stopped)" in html


def test_live_deploy_status_wins_and_is_not_duplicated():
    html, = _run_js([_LIVE_DEPLOY])
    assert html.count("DNS Server") == 1
    assert "deploying" in html
    assert "installed (stopped)" not in html


def test_agent_with_nothing_loaded_still_reads_idle():
    html, = _run_js([_IDLE])
    assert "none (idle)" in html


def test_netbox_marker_alone_restores_badge_and_reset_knob():
    html, = _run_js([_NETBOX_MARKER_ONLY])
    assert ">NetBox<" in html
    assert "resetNetboxAdmin" in html
    # netbox-server must not ALSO render a generic deploy badge.
    assert "NetBox Server: installed" not in html


def test_hosted_sub_spoke_roles_still_render():
    html, = _run_js([_HOSTED])
    assert "Simulation" in html
    assert "none (idle)" not in html
