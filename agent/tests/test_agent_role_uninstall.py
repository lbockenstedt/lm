"""UNINSTALL_ROLE — the true inverse of a deploy-role install.

UNLOAD_ROLE only stops and disables the units ("stop managing this", not
"uninstall"), so a decommissioned node kept reporting its DHCP/DNS role as
"installed (stopped)" forever: the installed badge is driven by the service
BINARY still being on disk (``_DEPLOY_ROLE_MARKERS``), which unload never
touches. There was no way back to a clean node short of rebuilding it.

These tests run the purge against a REAL temporary filesystem (the recipe and
marker are repointed into tmp_path) rather than asserting on mock call lists,
because the property that matters is the observable end state: the marker and
the config/state trees are actually gone.
"""
import asyncio
import types
from pathlib import Path

import agent_spoke
from agent_spoke import GenericAgent


def _sandbox(monkeypatch, tmp_path, role="dhcp-server", *, make_marker=True):
    """Repoint one purge recipe at tmp_path and populate it. Returns the spec."""
    marker = tmp_path / "usr/sbin/kea-dhcp4"
    marker.parent.mkdir(parents=True, exist_ok=True)
    if make_marker:
        marker.write_text("#!/bin/sh\n")

    etc = tmp_path / "etc/kea"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "kea-dhcp4.conf").write_text("{}")
    var = tmp_path / "var/lib/kea"
    var.mkdir(parents=True, exist_ok=True)
    (var / "leases.csv").write_text("")

    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / "lm-dhcp-worker.service").write_text("[Unit]\n")
    (unit_dir / "kea-ha-agent.service").write_text("[Unit]\n")

    spec = {
        "packages": ("kea-dhcp4-server", "kea-ctrl-agent", "kea-common"),
        "unit_files": ("lm-dhcp-worker.service", "kea-ha-agent.service"),
        "paths": (str(etc), str(var)),
    }
    monkeypatch.setattr(agent_spoke, "_SYSTEMD_UNIT_DIR", str(unit_dir))
    monkeypatch.setattr(agent_spoke, "_DEPLOY_ROLE_PURGE", {role: spec})
    monkeypatch.setattr(agent_spoke, "_DEPLOY_ROLE_MARKERS",
                        {**agent_spoke._DEPLOY_ROLE_MARKERS, role: str(marker)})
    return types.SimpleNamespace(marker=marker, etc=etc, var=var,
                                 unit_dir=unit_dir, spec=spec)


def _fake_run(calls, *, purge_removes=None, rc_for=None):
    """subprocess.run double that records argv and deletes the marker when the
    package that owns it is purged — so the test exercises the real
    marker_before/marker_after probe."""
    def run(cmd, **kwargs):
        calls.append(list(cmd))
        rc = 0
        if rc_for:
            rc = rc_for(cmd)
        if rc == 0 and purge_removes and "purge" in cmd:
            for pkg, victim in purge_removes.items():
                if pkg in cmd and victim.exists():
                    victim.unlink()
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="")
    return run


# ── refusals ─────────────────────────────────────────────────────────────────

def test_uninstall_refuses_unknown_role():
    agent = GenericAgent("agent-1", {})
    result = asyncio.run(agent.handle_command("UNINSTALL_ROLE", {"role": "nope"}))
    assert result["status"] == "ERROR"
    assert "cannot be uninstalled" in result["message"]


def test_uninstall_refuses_hosted_role_that_is_not_a_deploy_role():
    """A management module (``dhcp``) is not something we can purge — only the
    dhcp-SERVER deploy role is."""
    agent = GenericAgent("agent-1", {})
    result = asyncio.run(agent.handle_command("UNINSTALL_ROLE", {"role": "dhcp"}))
    assert result["status"] == "ERROR"
    assert "cannot be uninstalled" in result["message"]


def test_uninstall_refuses_while_management_module_loaded(monkeypatch, tmp_path):
    """Purging Kea out from under a live dhcp sub-spoke would leave both in an
    undefined state, so the module must be unloaded first."""
    _sandbox(monkeypatch, tmp_path)
    agent = GenericAgent("agent-1", {})
    agent._roles["dhcp"] = {}

    result = asyncio.run(
        agent.handle_command("UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert result["status"] == "ERROR"
    assert "management role" in result["message"]


def test_uninstall_refuses_while_deploy_in_flight(monkeypatch, tmp_path):
    _sandbox(monkeypatch, tmp_path)
    agent = GenericAgent("agent-1", {})

    async def _never():
        await asyncio.sleep(3600)

    async def _go():
        task = asyncio.ensure_future(_never())
        agent._deploy_tasks["dhcp-server"] = task
        try:
            return await agent.handle_command(
                "UNINSTALL_ROLE", {"role": "dhcp-server"})
        finally:
            task.cancel()

    result = asyncio.run(_go())
    assert result["status"] == "ERROR"
    assert "still running" in result["message"]


def test_refused_uninstall_leaves_the_host_untouched(monkeypatch, tmp_path):
    """A refusal must be inert — nothing stopped, nothing deleted."""
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(agent_spoke.subprocess, "run", _fake_run(calls))
    agent = GenericAgent("agent-1", {})
    agent._roles["dhcp"] = {}

    asyncio.run(agent.handle_command("UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert calls == []
    assert box.marker.exists()
    assert box.etc.exists()
    assert (box.unit_dir / "kea-ha-agent.service").exists()


# ── the happy path ───────────────────────────────────────────────────────────

def test_uninstall_removes_packages_units_and_config(monkeypatch, tmp_path):
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run(calls, purge_removes={"kea-dhcp4-server": box.marker}))

    agent = GenericAgent("agent-1", {})
    result = asyncio.run(
        agent.handle_command("UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert result["status"] == "SUCCESS", result
    assert result["deploy"] is True
    report = result["report"]
    assert report["marker_before"] is True
    assert report["marker_after"] is False
    assert not report["errors"], report["errors"]

    # The observable end state is what matters.
    assert not box.marker.exists()
    assert not box.etc.exists()
    assert not box.var.exists()
    assert not (box.unit_dir / "lm-dhcp-worker.service").exists()
    assert not (box.unit_dir / "kea-ha-agent.service").exists()
    assert set(report["packages_purged"]) == {
        "kea-dhcp4-server", "kea-ctrl-agent", "kea-common"}


def test_units_are_stopped_before_packages_are_purged(monkeypatch, tmp_path):
    """dpkg must not trip over a running daemon holding its own files open."""
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run(calls, purge_removes={"kea-dhcp4-server": box.marker}))

    asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    first_disable = next(i for i, c in enumerate(calls) if "disable" in c)
    first_purge = next(i for i, c in enumerate(calls) if "purge" in c)
    assert first_disable < first_purge, calls


def test_uninstall_stops_the_cluster_sidecars_too(monkeypatch, tmp_path):
    """Leaving lm-dhcp-worker/kea-ha-agent running would keep a removed node
    dialling its old coordinator and holding the HA port open."""
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run(calls, purge_removes={"kea-dhcp4-server": box.marker}))

    result = asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    stopped = result["report"]["units_stopped"]
    for unit in ("kea-dhcp4-server", "kea-ctrl-agent",
                 "lm-dhcp-worker", "kea-ha-agent"):
        assert unit in stopped, stopped


def test_daemon_reload_runs_after_unit_files_are_deleted(monkeypatch, tmp_path):
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run(calls, purge_removes={"kea-dhcp4-server": box.marker}))

    asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert ["systemctl", "daemon-reload"] in calls


def test_packages_are_purged_individually(monkeypatch, tmp_path):
    """apt aborts the WHOLE transaction on one unknown package, so a package
    that isn't installed on this release must not strand the others."""
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run(calls, purge_removes={"kea-dhcp4-server": box.marker}))

    asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    purges = [c for c in calls if "purge" in c]
    assert len(purges) == 3, purges
    for cmd in purges:
        # exactly one package name per invocation
        assert len([a for a in cmd if a.startswith("kea-")]) == 1, cmd


def test_unknown_package_is_not_reported_as_an_error(monkeypatch, tmp_path):
    box = _sandbox(monkeypatch, tmp_path)
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        if "purge" in cmd and "kea-ctrl-agent" in cmd:
            return types.SimpleNamespace(
                returncode=100, stdout="",
                stderr="E: Unable to locate package kea-ctrl-agent")
        if "purge" in cmd and "kea-dhcp4-server" in cmd and box.marker.exists():
            box.marker.unlink()
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(agent_spoke.subprocess, "run", run)
    result = asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert result["status"] == "SUCCESS", result
    assert result["report"]["errors"] == []
    assert "kea-ctrl-agent" not in result["report"]["packages_purged"]
    assert "kea-dhcp4-server" in result["report"]["packages_purged"]


# ── failure is reported honestly ─────────────────────────────────────────────

def test_surviving_marker_is_reported_as_error_not_success(monkeypatch, tmp_path):
    """The binary surviving the purge is the one outcome we must never call
    SUCCESS: the hub drops the role assignment on anything that isn't an
    ERROR, so the node would stop being managed while still advertising the
    role as installed."""
    box = _sandbox(monkeypatch, tmp_path)
    calls = []
    # purge_removes omitted -> the marker survives
    monkeypatch.setattr(agent_spoke.subprocess, "run", _fake_run(calls))

    result = asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert result["status"] == "ERROR", result
    assert result["report"]["marker_after"] is True
    assert str(box.marker) in result["message"]


# ── idempotence ──────────────────────────────────────────────────────────────

def test_uninstall_is_idempotent_on_an_already_clean_node(monkeypatch, tmp_path):
    """A node part-way through an uninstall must converge on a re-run rather
    than wedging, so absent packages, units and paths are simply skipped."""
    box = _sandbox(monkeypatch, tmp_path, make_marker=False)
    import shutil as _shutil
    _shutil.rmtree(box.etc)
    _shutil.rmtree(box.var)
    for f in box.unit_dir.glob("*"):
        f.unlink()

    calls = []
    monkeypatch.setattr(agent_spoke.subprocess, "run", _fake_run(calls))

    result = asyncio.run(GenericAgent("agent-1", {}).handle_command(
        "UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert result["status"] == "SUCCESS", result
    assert result["report"]["marker_before"] is False
    assert result["report"]["marker_after"] is False
    assert result["report"]["errors"] == []


def test_uninstall_clears_tracked_deploy_status(monkeypatch, tmp_path):
    """A stale 'unloaded'/'installed' entry would keep the WebUI's roles badge
    advertising a role this node no longer has."""
    box = _sandbox(monkeypatch, tmp_path)
    monkeypatch.setattr(
        agent_spoke.subprocess, "run",
        _fake_run([], purge_removes={"kea-dhcp4-server": box.marker}))

    agent = GenericAgent("agent-1", {})
    agent._deploy_status_by_role["dhcp-server"] = {"state": "unloaded"}

    asyncio.run(agent.handle_command("UNINSTALL_ROLE", {"role": "dhcp-server"}))

    assert "dhcp-server" not in agent._deploy_status_by_role


# ── the recipes themselves ───────────────────────────────────────────────────

def test_purge_recipes_cover_every_role_with_managed_units():
    """Any deploy role we can stop, we should also be able to uninstall —
    otherwise it can only ever reach the 'installed (stopped)' dead end."""
    assert set(agent_spoke._DEPLOY_ROLE_UNITS) <= set(agent_spoke._DEPLOY_ROLE_PURGE)


def test_purge_recipes_are_well_formed():
    for role, spec in agent_spoke._DEPLOY_ROLE_PURGE.items():
        assert role in agent_spoke._DEPLOY_ROLE_MARKERS, \
            f"{role}: no marker, so the uninstall could never be verified"
        assert spec["packages"], f"{role}: nothing to purge"
        for raw in spec["paths"]:
            # Guard against a recipe that would wipe the host.
            assert raw.startswith("/") and raw.count("/") >= 2, f"{role}: unsafe path {raw}"
            assert raw not in ("/", "/etc", "/var", "/usr", "/var/lib", "/run"), \
                f"{role}: refuses to own {raw}"
        for unit_file in spec.get("unit_files", ()):
            assert unit_file.endswith(".service"), f"{role}: {unit_file}"
            assert "/" not in unit_file, f"{role}: {unit_file} must be a bare unit name"


def test_dhcp_recipe_purges_kea_and_its_lm_sidecars():
    spec = agent_spoke._DEPLOY_ROLE_PURGE["dhcp-server"]
    assert "kea-dhcp4-server" in spec["packages"]
    assert "/etc/kea" in spec["paths"]
    # The LM-authored sidecar units are owned by no package, so dpkg will never
    # remove them — they must be deleted by hand or systemd keeps them on file.
    assert "lm-dhcp-worker.service" in spec["unit_files"]
    assert "kea-ha-agent.service" in spec["unit_files"]


def test_dns_recipe_purges_unbound_and_its_lm_sidecar():
    spec = agent_spoke._DEPLOY_ROLE_PURGE["dns-server"]
    assert "unbound" in spec["packages"]
    assert "/etc/unbound" in spec["paths"]
    assert "lm-dns-worker.service" in spec["unit_files"]
