"""Deploy roles must not be reinstalled on every agent reconnect, and every
deploy role must be unloadable.

Field report: an agent (SHARED-MIPBE-SVCS02) showed "DHCP Server (Kea):
deploying… / DNS Server (Unbound): deploying… / NetBox Server: deploying…"
permanently, reinstalling Kea and Unbound on every reboot, with no way to stop
the hub deploying NetBox to it.

Three defects combined:

1. ``LOAD_ROLE`` for a deploy role ALWAYS re-ran the installer. Hosted roles
   (``_ROLE_MAP``) short-circuit when already loaded; deploy roles had no
   equivalent guard even though ``_DEPLOY_ROLE_MARKERS`` already answers "is
   this installed?". The hub re-pushes LOAD_ROLE for every recorded role on
   reconnect, so every reboot reinstalled software that was already there.

2. ``UNLOAD_ROLE`` only handled deploy roles present in ``_DEPLOY_ROLE_UNITS``
   (dns-server/dhcp-server). ``netbox-server``/``ldap-server``/``ab`` fell
   through to the hosted-role branch and came back ``ERROR: Role
   'netbox-server' is not loaded``. The hub only forgets an assignment when
   UNLOAD_ROLE does NOT error, so the role stayed on record forever and was
   re-pushed on every reconnect — NetBox could never be stopped.

3. (hub side, see core/tests/test_readopt_skips_deploy_roles.py) the readopt
   loop treated deploy roles as hosted sub-spokes.
"""
import asyncio

from agent_spoke import (GenericAgent, _DEPLOY_ROLES, _DEPLOY_ROLE_MARKERS,
                         _DEPLOY_ROLE_UNITS)


def _agent():
    return GenericAgent("agent-under-test", {})


async def _load(agent, role, **extra):
    return await agent.handle_command("LOAD_ROLE", {"role": role, **extra})


async def _unload(agent, role):
    return await agent.handle_command("UNLOAD_ROLE", {"role": role})


# ── 1. every deploy role has an install marker ───────────────────────────────

def test_every_deploy_role_has_an_install_marker():
    """The idempotency guard is only as good as the marker table — a deploy
    role with no marker would silently fall back to reinstall-every-time."""
    missing = set(_DEPLOY_ROLES) - set(_DEPLOY_ROLE_MARKERS)
    assert not missing, f"deploy roles with no install marker: {missing}"


# ── 2. LOAD_ROLE is idempotent when already installed ────────────────────────

def _stub_deploy(agent, monkeypatch):
    """Record deploy attempts without ever spawning the installer.

    Both the command build and the background runner are replaced: letting the
    real ``_run_deploy`` through starts a subprocess and leaves a pending task
    behind, which hangs the run.
    """
    ran = []
    monkeypatch.setattr(agent, "_build_deploy_cmd", lambda *a, **k: ["true"])

    async def _fake_run(role_name, cmd):
        ran.append(role_name)

    monkeypatch.setattr(agent, "_run_deploy", _fake_run)
    return ran


def _set_marker(monkeypatch, role, path, exists):
    """Point ``role``'s install marker at a real (or deliberately missing) path
    instead of monkeypatching ``os.path.exists`` globally."""
    if exists:
        path.write_text("installed")
    monkeypatch.setitem(_DEPLOY_ROLE_MARKERS, role, str(path))


def test_load_role_does_not_reinstall_when_marker_present(monkeypatch, tmp_path):
    """The reboot-reinstall bug: dhcp-server is already installed, so a
    re-pushed LOAD_ROLE must NOT run the installer again."""
    agent = _agent()
    ran = _stub_deploy(agent, monkeypatch)
    _set_marker(monkeypatch, "dhcp-server", tmp_path / "kea-dhcp4", exists=True)

    res = asyncio.run(_load(agent, "dhcp-server"))

    assert res["status"] == "SUCCESS", res
    assert res.get("already_installed") is True, res
    assert not ran, "installer was re-run for an already-installed deploy role"
    assert "dhcp-server" not in agent._deploy_tasks


def test_load_role_installs_when_marker_absent(monkeypatch, tmp_path):
    """Not vacuous: a genuinely missing install still deploys."""
    agent = _agent()
    ran = _stub_deploy(agent, monkeypatch)
    _set_marker(monkeypatch, "dhcp-server", tmp_path / "absent", exists=False)

    res = asyncio.run(_load(agent, "dhcp-server"))

    assert res["status"] == "SUCCESS", res
    assert not res.get("already_installed"), res
    assert ran == ["dhcp-server"], "installer was NOT run for a missing deploy role"


def test_force_re_runs_the_installer_even_when_installed(monkeypatch, tmp_path):
    """The repair path stays available."""
    agent = _agent()
    ran = _stub_deploy(agent, monkeypatch)
    _set_marker(monkeypatch, "dns-server", tmp_path / "unbound", exists=True)

    res = asyncio.run(_load(agent, "dns-server", force=True))

    assert res["status"] == "SUCCESS", res
    assert not res.get("already_installed"), res
    assert ran == ["dns-server"], "force did not re-run the installer"


# ── 3. UNLOAD_ROLE works for unit-less deploy roles ──────────────────────────

def test_unload_netbox_server_succeeds_so_the_hub_forgets_it():
    """netbox-server has no managed units; unloading it must still succeed,
    because the hub only drops the durable assignment on a non-ERROR reply."""
    agent = _agent()
    res = asyncio.run(_unload(agent, "netbox-server"))

    assert res["status"] == "SUCCESS", res
    assert res.get("deploy") is True, res
    assert "not loaded" not in (res.get("message") or "").lower()


def test_every_unitless_deploy_role_can_be_unloaded():
    """ab and ldap-server had the same dead end as netbox-server."""
    for role in sorted(set(_DEPLOY_ROLES) - set(_DEPLOY_ROLE_UNITS)):
        res = asyncio.run(_unload(_agent(), role))
        assert res["status"] == "SUCCESS", f"{role}: {res}"


def test_unload_unitless_role_refuses_while_its_deploy_is_running():
    """Don't yank an assignment out from under a live install."""

    async def _run():
        agent = _agent()

        async def _never():
            await asyncio.sleep(3600)

        task = asyncio.create_task(_never())
        agent._deploy_tasks["netbox-server"] = task
        try:
            return await _unload(agent, "netbox-server")
        finally:
            task.cancel()

    res = asyncio.run(_run())
    assert res["status"] == "ERROR", res
    assert "still running" in res["message"]


def test_unload_unitless_role_does_not_touch_installed_software(monkeypatch):
    """Unload means 'stop deploying this here', not 'uninstall'."""
    import subprocess
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: calls.append(a) or None)
    res = asyncio.run(_unload(_agent(), "netbox-server"))
    assert res["status"] == "SUCCESS", res
    assert not calls, "unloading a unit-less deploy role shelled out"


def test_unit_backed_deploy_roles_still_stop_their_units():
    """Not vacuous: dns-server/dhcp-server keep the stop-and-disable path."""
    assert "dns-server" in _DEPLOY_ROLE_UNITS
    assert "dhcp-server" in _DEPLOY_ROLE_UNITS
    assert "netbox-server" not in _DEPLOY_ROLE_UNITS
