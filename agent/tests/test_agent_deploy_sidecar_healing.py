"""Self-heal for a deploy role's cluster sidecar unit
(``lm-dhcp-worker``/``lm-dns-worker``/``kea-ha-agent``) being disabled or
stopped while the role's primary daemon units are healthy.

Production symptom this guards: kea-dhcp4-server and kea-ctrl-agent were
enabled and running on both nodes of a Kea HA pair, but
``lm-dhcp-worker.service`` was disabled+dead on both — nothing was dialling
the HA coordinator, so every node reported "cluster member not connected",
the last config apply failed at install-hooks, and Kea never bound its
listener. Unlike ``kea_manager.py``'s ``_heal_inactive_units`` (which runs
INSIDE the worker and heals its daemon peers), the worker process cannot
resurrect itself — this self-heal runs from the sibling agent process
instead, and is exercised opportunistically any time the hub polls role
status (``_active_deploy_roles``, called from GET_AVAILABLE_ROLES /
GET_DEPLOY_STATUS).
"""
from types import SimpleNamespace

import agent_spoke
from agent_spoke import _active_deploy_roles, _heal_deploy_role_sidecars


def _proc(returncode=0, stdout=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


def _fake_run(unit_state, calls):
    """``unit_state``: {unit: {"loaded": bool, "enabled": bool, "active": bool}}."""
    def run(cmd, **kwargs):
        calls.append(list(cmd))
        unit = cmd[-1]
        state = unit_state.get(unit, {})
        if cmd[:3] == ["systemctl", "show", "-p"]:
            return _proc(stdout="loaded" if state.get("loaded") else "not-found")
        if cmd[:2] == ["systemctl", "is-enabled"]:
            return _proc(returncode=0 if state.get("enabled") else 1)
        if cmd[:2] == ["systemctl", "is-active"]:
            return _proc(returncode=0 if state.get("active") else 1)
        if cmd[:2] == ["systemctl", "enable"]:
            state["enabled"] = True
            state["active"] = True
            return _proc(returncode=0)
        raise AssertionError(f"unexpected systemctl call: {cmd}")
    return run


def test_role_not_installed_is_never_touched(monkeypatch):
    calls = []
    monkeypatch.setattr(agent_spoke.subprocess, "run",
                        _fake_run({"lm-dhcp-worker": {"loaded": True}}, calls))

    actions = _heal_deploy_role_sidecars([])

    assert actions == []
    assert calls == []


def test_unit_not_present_on_host_is_skipped_not_enabled(monkeypatch):
    """A single-host (non-clustered) node never got the sidecar unit at all —
    LoadState != loaded — so this must not try to enable a unit that does not
    exist."""
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run({"lm-dhcp-worker": {"loaded": False},
                   "kea-ha-agent": {"loaded": False}}, calls))

    actions = _heal_deploy_role_sidecars(["dhcp-server"])

    assert actions == []
    assert not any(c[:2] == ["systemctl", "enable"] for c in calls)


def test_already_enabled_and_active_sidecar_is_left_alone(monkeypatch):
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run({"lm-dhcp-worker": {"loaded": True, "enabled": True, "active": True},
                   "kea-ha-agent": {"loaded": True, "enabled": True, "active": True}},
                  calls))

    actions = _heal_deploy_role_sidecars(["dhcp-server"])

    assert actions == []
    assert not any(c[:2] == ["systemctl", "enable"] for c in calls)


def test_disabled_dead_sidecar_is_enabled_and_started(monkeypatch):
    """The exact production symptom: lm-dhcp-worker present but disabled+dead
    while the role is installed — must be enabled --now and reported."""
    calls = []
    state = {"kea-dhcp4-server": {"loaded": True, "enabled": True, "active": True},
             "kea-ctrl-agent": {"loaded": True, "enabled": True, "active": True},
             "lm-dhcp-worker": {"loaded": True, "enabled": False, "active": False},
             "kea-ha-agent": {"loaded": True, "enabled": True, "active": True}}
    monkeypatch.setattr(agent_spoke.subprocess, "run", _fake_run(state, calls))

    actions = _heal_deploy_role_sidecars(["dhcp-server"])

    assert actions == ["enabled+started lm-dhcp-worker (was disabled/stopped)"]
    assert ["systemctl", "enable", "--now", "lm-dhcp-worker"] in calls


def test_unloaded_role_sidecars_stay_disabled(monkeypatch):
    """UNLOAD_ROLE disables primary + sidecar units but leaves the marker;
    the heal must not undo that."""
    calls = []
    state = {"kea-dhcp4-server": {"loaded": True, "enabled": False, "active": False},
             "kea-ctrl-agent": {"loaded": True, "enabled": False, "active": False},
             "lm-dhcp-worker": {"loaded": True, "enabled": False, "active": False},
             "kea-ha-agent": {"loaded": True, "enabled": False, "active": False},
             "unbound": {"loaded": True, "enabled": False, "active": False},
             "lm-dns-worker": {"loaded": True, "enabled": False, "active": False}}
    monkeypatch.setattr(agent_spoke.subprocess, "run", _fake_run(state, calls))

    actions = _heal_deploy_role_sidecars(["dhcp-server", "dns-server"])

    assert actions == []
    assert not any(c[:2] == ["systemctl", "enable"] for c in calls)


def test_indeterminate_sidecar_state_is_not_mutated(monkeypatch):
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        unit = cmd[-1]
        if cmd[:3] == ["systemctl", "show", "-p"]:
            return _proc(stdout="loaded")
        if unit in ("lm-dhcp-worker", "kea-ha-agent") and cmd[1] in ("is-enabled", "is-active"):
            raise agent_spoke.subprocess.TimeoutExpired(cmd, 10)
        if cmd[1] in ("is-enabled", "is-active"):
            return _proc(returncode=0)
        raise AssertionError(cmd)

    monkeypatch.setattr(agent_spoke.subprocess, "run", run)

    assert _heal_deploy_role_sidecars(["dhcp-server"]) == []
    assert not any(c[:2] == ["systemctl", "enable"] for c in calls)


def test_enable_failure_is_logged_not_raised(monkeypatch):
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:3] == ["systemctl", "show", "-p"]:
            return _proc(stdout="loaded")
        if cmd[:2] in (["systemctl", "is-enabled"], ["systemctl", "is-active"]):
            return _proc(returncode=1)
        if cmd[:2] == ["systemctl", "enable"]:
            return _proc(returncode=1, stdout="")
        raise AssertionError(cmd)

    monkeypatch.setattr(agent_spoke.subprocess, "run", run)

    actions = _heal_deploy_role_sidecars(["dhcp-server"])

    assert actions == []  # nothing to report — the failure only logs


def test_active_deploy_roles_runs_the_heal_and_still_reports_primary_units(monkeypatch):
    """``_active_deploy_roles`` must self-heal the sidecar as a side effect
    without changing its own primary-unit-based active/installed contract."""
    calls = []
    state = {
        "kea-dhcp4-server": {"loaded": True, "enabled": True, "active": True},
        "kea-ctrl-agent": {"loaded": True, "enabled": True, "active": True},
        "lm-dhcp-worker": {"loaded": True, "enabled": False, "active": False},
        "kea-ha-agent": {"loaded": True, "enabled": True, "active": True},
    }
    monkeypatch.setattr(agent_spoke.subprocess, "run", _fake_run(state, calls))

    active = _active_deploy_roles(["dhcp-server"])

    assert active == ["dhcp-server"]
    assert ["systemctl", "enable", "--now", "lm-dhcp-worker"] in calls


def test_active_deploy_roles_survives_a_heal_that_raises(monkeypatch):
    """A broken self-heal must never take down role-status reporting."""
    def boom(installed_roles):
        raise RuntimeError("systemctl not on PATH")

    monkeypatch.setattr(agent_spoke, "_heal_deploy_role_sidecars", boom)
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        lambda *a, **k: _proc(returncode=0))

    active = _active_deploy_roles(["dhcp-server"])

    assert active == ["dhcp-server"]
