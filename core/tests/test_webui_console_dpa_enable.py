"""The Load Role modal must expose a (safe-by-default) Direct Port Access switch.

DPA is off by default and there was no operator path to turn it on, so the
console page never showed a DPA endpoint. The Load Role modal is that path: a
console-only 'Enable Direct Port Access' control whose value is projected into
the console role's LOAD_ROLE config (console_dpa_enabled / _bind / _allow),
keeping the localhost-bind + allow-list security posture.
"""

import os
import re


MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _fn(name):
    """Brace-balanced body of an `(async) function <name>(` in main.js."""
    src = open(MAIN_JS, encoding="utf-8").read()
    start = src.index(f"function {name}(")
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"unbalanced function {name}")


def test_modal_has_console_dpa_control():
    body = _fn("showLoadRoleModal")
    assert 'id="console-dpa-cfg"' in body
    assert 'id="crole-dpa-enabled"' in body
    assert 'id="crole-dpa-bind"' in body
    assert 'id="crole-dpa-allow"' in body
    # Safe default: localhost bind pre-filled.
    assert 'id="crole-dpa-bind" type="text" value="127.0.0.1"' in body


def test_dpa_panel_is_shown_only_for_the_console_role():
    body = _fn("syncNetboxCreds")
    assert "document.querySelector('.role-check[value=\"console\"]')" in body
    assert "document.getElementById('console-dpa-cfg')" in body
    # bind/allow detail (and the network-exposure warning) gated on DPA enabled.
    assert "document.getElementById('crole-dpa-detail')" in body
    assert "document.getElementById('crole-dpa-warn')" in body


def test_loadrole_projects_dpa_into_console_config():
    body = _fn("loadRole")
    assert "crole-dpa-enabled" in body
    assert "console_dpa_enabled: true" in body
    assert "console_dpa_bind" in body
    assert "console_dpa_allow" in body
    # Attached to the console role only, mirroring netbox/ldap.
    assert "roleId === 'console' && consoleCfg" in body
    # Off unless the operator ticks it (no config object otherwise).
    assert "let consoleCfg = null;" in body
