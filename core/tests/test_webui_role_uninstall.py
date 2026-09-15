"""WebUI surface for UNINSTALL_ROLE.

An unloaded deploy role is STOPPED but still installed, so it drops out of
``active_deploy_roles`` and the Load Role modal used to render no control for it
at all — the node sat on "installed (stopped)" with nothing in the UI able to
clear it. The modal must therefore build its controls from the INSTALLED set as
well as the active one, and offer Uninstall for anything still on disk.
"""

import os
import re


MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _fn(name):
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
    raise AssertionError(f"unbalanced {name} function")


def _modal():
    return _fn("showLoadRoleModal")


# ── the control is offered for a STOPPED-but-installed server ────────────────

def test_controls_are_built_from_the_installed_set_not_just_the_active_one():
    body = _modal()
    assert "new Set(roleState.installed_deploy_roles || [])" in body
    assert "uninstallableServers" in body
    # the rendered id list must include them, or a stopped role shows nothing
    assert re.search(r"\.\.\.uninstallableServers", body)


def test_uninstall_button_is_rendered_for_installed_servers():
    body = _modal()
    assert "uninstallRole(" in body
    assert ">Uninstall<" in body


def test_stopped_server_is_labelled_as_such():
    body = _modal()
    assert "(stopped)" in body


def test_uninstall_is_blocked_while_the_management_module_is_loaded():
    """Mirrors the agent-side guard — purging Kea out from under a live dhcp
    sub-spoke would leave both in an undefined state."""
    body = _modal()
    idx = body.index("uninstallRole(")
    window = body[idx:idx + 400]
    assert "moduleLoaded ?" in window
    assert "disabled" in window


def test_uninstall_is_not_offered_during_an_in_flight_deploy():
    body = _modal()
    idx = body.index("uninstallableServers")
    window = body[idx:idx + 400]
    assert "roleState.deploy?.state === 'running'" in window


def test_control_ids_are_deduped():
    """A role that is both active and installed must render one card, not two."""
    body = _modal()
    assert re.search(r"loadedControlIds\s*=\s*\[\.\.\.new Set\(\[", body)


# ── the handler ──────────────────────────────────────────────────────────────

def test_uninstall_handler_exists_and_confirms_first():
    body = _fn("uninstallRole")
    assert "showConfirmToast" in body
    assert "PERMANENTLY REMOVED" in body
    assert "cannot be undone" in body


def test_uninstall_handler_uses_the_right_endpoints():
    body = _fn("uninstallRole")
    # Global Admin -> arbitrary-command relay; tenant-admin -> scoped route.
    assert "'UNINSTALL_ROLE'" in body
    assert "/uninstall-role" in body
    assert "isAdmin" in body


def test_uninstall_handler_refreshes_the_views_on_success():
    body = _fn("uninstallRole")
    assert "loadSpokesAndAgents()" in body
    assert "showLoadRoleModal(spokeId)" in body


def test_uninstall_handler_reports_the_agent_message_on_failure():
    """The agent explains WHY a purge did not complete (held package, surviving
    binary); swallowing that would leave the operator with a bare 'failed'."""
    body = _fn("uninstallRole")
    assert "payload?.message" in body
    assert "Failed to uninstall role: " in body


def test_uninstall_handler_warns_the_operation_is_slow():
    body = _fn("uninstallRole")
    assert "few minutes" in body


def test_unload_still_says_the_package_is_left_behind():
    """Unload and Uninstall must stay clearly different in the UI copy."""
    body = _fn("unloadRole")
    assert "remain installed" in body
