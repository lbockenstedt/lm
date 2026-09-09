"""Loaded agent roles must not remain selectable in the Load Role modal."""

import os
import re


MAIN_JS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))


def _show_load_role_modal():
    src = open(MAIN_JS, encoding="utf-8").read()
    start = src.index("async function showLoadRoleModal(")
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError("unbalanced showLoadRoleModal function")


def test_loaded_roles_are_filtered_before_rendering():
    body = _show_load_role_modal()
    assert re.search(
        r"new Set\(\(active \|\| \[\]\)\.map\(a => a\.role\)\)", body)
    assert "new Set(roleState.active_deploy_roles || [])" in body
    assert re.search(
        r"Object\.entries\(AGENT_ROLES\)\s*"
        r"\.filter\(\(\[id\]\) => !loadedRoleIds\.has\(id\) "
        r"&& !activeDeployRoleIds\.has\(id\)\)", body)
    assert "loadedByRole" not in body
    assert ">loaded<" not in body


def test_running_deploy_role_is_not_offered_again():
    body = _show_load_role_modal()
    assert "roleState.deploy?.state === 'running'" in body
    assert "activeDeployRoleIds.add(roleState.deploy.role)" in body


def test_active_server_roles_have_an_unload_action():
    body = _show_load_role_modal()
    assert 'id="active-server-roles"' in body
    assert "id === 'dns-server' || id === 'dhcp-server'" in body
    assert "unloadRole('${spokeId}','${id}')" in body


def test_all_loaded_state_disables_activation():
    body = _show_load_role_modal()
    assert "All available roles are already loaded." in body
    assert "availableRoles.length === 0" in body
    assert "activateButton.disabled = true" in body
