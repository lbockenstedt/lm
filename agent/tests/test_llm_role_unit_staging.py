"""Role-load repair for missing LLM systemd units."""

import asyncio
import errno
import io
import logging
import os
from pathlib import Path
import subprocess

import pytest

import agent_spoke
import llm_spoke
from agent_spoke import GenericAgent

_UNITS = ("lm-llm-ollama.service", "lm-llm-candidate.service")


def _staging_agent(tmp_path, monkeypatch):
    """An agent whose LLM templates and systemd directory live in tmp_path."""
    templates = tmp_path / "lm" / "agent"
    templates.mkdir(parents=True)
    for name in _UNITS:
        (templates / name).write_text(f"[Unit]\nDescription={name}\n", encoding="utf-8")
    agent = GenericAgent("agent-test", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: tmp_path / "lm")
    _redirect_systemd(monkeypatch, tmp_path / "systemd")
    monkeypatch.setattr(agent_spoke.subprocess, "run", lambda args, **kwargs: None)
    return agent, templates, tmp_path / "systemd"


def _redirect_systemd(monkeypatch, unit_dir):
    """Redirect systemd unit paths into a test fixture directory."""
    real_path = Path

    def redirect(path):
        """Redirect systemd paths and preserve normal pathlib behavior elsewhere."""
        value = str(path)
        if value == "/etc/systemd/system":
            return unit_dir
        if value.startswith("/etc/systemd/system/"):
            return unit_dir / value.rsplit("/", 1)[-1]
        return real_path(path)

    monkeypatch.setattr(agent_spoke, "Path", redirect)


def test_llm_role_post_install_stages_only_missing_units(tmp_path, monkeypatch):
    """Loading LLM restores missing units once, without starting either service."""
    lm_root = tmp_path / "lm"
    agent_dir = lm_root / "agent"
    agent_dir.mkdir(parents=True)
    names = ("lm-llm-ollama.service", "lm-llm-candidate.service")
    for name in names:
        (agent_dir / name).write_text(f"[Unit]\nDescription={name}\n", encoding="utf-8")

    agent = GenericAgent("agent-test", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: lm_root)
    unit_dir = tmp_path / "systemd"

    calls = []

    def fake_run(args, **kwargs):
        """Record systemd calls without invoking the host service manager."""
        calls.append((args, kwargs))

    _redirect_systemd(monkeypatch, unit_dir)
    monkeypatch.setattr(agent_spoke.subprocess, "run", fake_run)

    agent._role_post_install("llm")

    assert {path.name for path in unit_dir.iterdir()} == set(names)
    for name in names:
        target = unit_dir / name
        assert target.read_text(encoding="utf-8") == (agent_dir / name).read_text(encoding="utf-8")
        assert target.stat().st_mode & 0o777 == 0o644
    assert [args for args, _ in calls] == [["systemctl", "daemon-reload"]]

    serving = unit_dir / names[0]
    serving.write_text("operator-managed\n", encoding="utf-8")
    agent._role_post_install("llm")

    assert serving.read_text(encoding="utf-8") == "operator-managed\n"
    assert len(calls) == 2


def test_llm_symlink_preserved_during_staging(tmp_path, monkeypatch):
    """Symlinks, including dangling ones, are preserved during staging."""
    lm_root = tmp_path / "lm"
    agent_dir = lm_root / "agent"
    agent_dir.mkdir(parents=True)
    names = ("lm-llm-ollama.service", "lm-llm-candidate.service")
    for name in names:
        (agent_dir / name).write_text(f"[Unit]\nDescription={name}\n", encoding="utf-8")

    agent = GenericAgent("agent-test", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: lm_root)
    unit_dir = tmp_path / "systemd"

    calls = []

    def fake_run(args, **kwargs):
        """Record systemd calls without invoking the host service manager."""
        calls.append((args, kwargs))

    _redirect_systemd(monkeypatch, unit_dir)
    monkeypatch.setattr(agent_spoke.subprocess, "run", fake_run)

    # Stage the ollama unit normally.
    agent._role_post_install("llm")
    assert (unit_dir / names[0]).is_file()

    # Replace ollama with a symlink to /dev/null (existing symlink, should be preserved).
    ollama_target = unit_dir / names[0]
    ollama_target.unlink()
    ollama_target.symlink_to("/dev/null")
    assert ollama_target.is_symlink()

    # Stage the candidate unit (ollama is a symlink → skip; candidate is missing → write).
    agent._role_post_install("llm")

    # The symlink must still be a symlink to /dev/null (unchanged).
    assert ollama_target.is_symlink()
    assert ollama_target.readlink() == Path("/dev/null")
    # The candidate unit must now exist as a regular file.
    assert (unit_dir / names[1]).is_file()
    assert (unit_dir / names[1]).read_text(encoding="utf-8") == (agent_dir / names[1]).read_text(encoding="utf-8")

    # Now replace candidate with a dangling symlink.
    candidate_target = unit_dir / names[1]
    candidate_target.unlink()
    candidate_target.symlink_to("/nonexistent/target")
    assert candidate_target.is_symlink()

    # Re-run: both entries exist (symlinks), so nothing should be written.
    agent._role_post_install("llm")

    assert ollama_target.is_symlink()
    assert ollama_target.readlink() == Path("/dev/null")
    assert candidate_target.is_symlink()
    assert candidate_target.readlink() == Path("/nonexistent/target")
    # One daemon-reload runs per _role_post_install call.
    assert len(calls) == 3


def test_llm_unit_write_failure_leaves_nothing_for_the_retry_to_skip(tmp_path, monkeypatch):
    """A unit write that stops partway (a full disk) leaves no partial unit.

    systemd reads an empty unit as masked, and staging never replaces an
    existing entry, so a partial file would block every later retry."""
    agent, templates, unit_dir = _staging_agent(tmp_path, monkeypatch)
    real_open = io.open
    failed = []

    def disk_full_once(file, mode="r", *args, **kwargs):
        """Open normally, but make the first binary write stop halfway."""
        handle = real_open(file, mode, *args, **kwargs)
        if "w" in mode and "b" in mode and not failed:
            failed.append(file)
            write = handle.write

            def partial_write(data):
                """Store half of ``data``, then fail like a full disk."""
                write(bytes(data)[: len(data) // 2])
                handle.flush()
                raise OSError(errno.ENOSPC, "No space left on device")

            handle.write = partial_write
        return handle

    monkeypatch.setattr(io, "open", disk_full_once)
    agent._role_post_install("llm")
    assert failed and "No space left" in agent._llm_post_install_error
    assert list(unit_dir.iterdir()) == []

    # The retry installs both units in full.
    agent._role_post_install("llm")
    assert agent._llm_post_install_error is None
    assert {path.name for path in unit_dir.iterdir()} == set(_UNITS)
    for name in _UNITS:
        assert (unit_dir / name).read_bytes() == (templates / name).read_bytes()
        assert (unit_dir / name).stat().st_mode & 0o777 == 0o644


def test_llm_unit_created_meanwhile_is_kept(tmp_path, monkeypatch):
    """A unit that appears after the existence check is never replaced."""
    agent, _templates, unit_dir = _staging_agent(tmp_path, monkeypatch)
    real_link = os.link

    def operator_first(src, dst, *args, **kwargs):
        """Let an operator's unit land just before staging publishes its own."""
        Path(dst).write_text("operator-managed\n", encoding="utf-8")
        return real_link(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "link", operator_first)
    agent._role_post_install("llm")
    assert agent._llm_post_install_error is None
    assert {path.name for path in unit_dir.iterdir()} == set(_UNITS)
    for name in _UNITS:
        assert (unit_dir / name).read_text(encoding="utf-8") == "operator-managed\n"


def test_llm_role_retries_daemon_reload_after_a_failed_attempt(tmp_path, monkeypatch):
    """A failed reload is retried even though the unit files were staged."""
    lm_root = tmp_path / "lm"
    agent_dir = lm_root / "agent"
    agent_dir.mkdir(parents=True)
    names = ("lm-llm-ollama.service", "lm-llm-candidate.service")
    for name in names:
        (agent_dir / name).write_text(f"[Unit]\nDescription={name}\n", encoding="utf-8")

    agent = GenericAgent("agent-test", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: lm_root)
    unit_dir = tmp_path / "systemd"

    attempts = []

    def fail_first_reload(args, **kwargs):
        """Fail once after staging, then allow the retry to complete."""
        attempts.append(args)
        if len(attempts) == 1:
            raise subprocess.CalledProcessError(1, args)

    _redirect_systemd(monkeypatch, unit_dir)
    monkeypatch.setattr(agent_spoke.subprocess, "run", fail_first_reload)

    agent._role_post_install("llm")
    assert {path.name for path in unit_dir.iterdir()} == set(names)

    agent._role_post_install("llm")

    assert attempts == [["systemctl", "daemon-reload"]] * 2


def test_llm_post_install_warns_once_per_distinct_failure(tmp_path, monkeypatch, caplog):
    """The minute-by-minute repair warns on a new error, not on each identical repeat."""
    lm_root = tmp_path / "lm"
    agent = GenericAgent("agent-test", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: lm_root)
    _redirect_systemd(monkeypatch, tmp_path / "systemd")
    reload_fails = True

    def reload(args, **kwargs):
        """Fail daemon-reload while the test asks for it."""
        if reload_fails:
            raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(agent_spoke.subprocess, "run", reload)

    def logged(level):
        """Count post-install failure records logged at ``level``."""
        return sum(1 for record in caplog.records
                   if record.levelno == level and "post-install" in record.getMessage())

    with caplog.at_level(logging.DEBUG, logger="GenericAgent"):
        # A permanent failure (no templates) warns once, then drops to DEBUG.
        agent._role_post_install("llm")
        agent._role_post_install("llm")
        assert (logged(logging.WARNING), logged(logging.DEBUG)) == (1, 1)
        # A different error warns again.
        (lm_root / "agent").mkdir(parents=True)
        for name in ("lm-llm-ollama.service", "lm-llm-candidate.service"):
            (lm_root / "agent" / name).write_text("[Unit]\n", encoding="utf-8")
        agent._role_post_install("llm")
        assert logged(logging.WARNING) == 2
        # A success resets it, so the same error coming back warns again.
        reload_fails = False
        agent._role_post_install("llm")
        assert agent._llm_post_install_error is None
        reload_fails = True
        agent._role_post_install("llm")
        assert logged(logging.WARNING) == 3


@pytest.mark.parametrize("hub_started", [True, False])
def test_llm_load_role_retries_reload_without_another_command(
        tmp_path, monkeypatch, hub_started):
    """A failed daemon-reload is retried autonomously while the role is loaded,
    but the repair never starts Ollama itself: only the hub starts it, and only
    for an approved, tenant-bound worker. ``hub_started`` False models a worker
    the hub never asked to start (pending approval or no tenant yet)."""
    lm_root = tmp_path / "lm"
    agent_dir = lm_root / "agent"
    agent_dir.mkdir(parents=True)
    names = ("lm-llm-ollama.service", "lm-llm-candidate.service")
    for name in names:
        (agent_dir / name).write_text(f"[Unit]\nDescription={name}\n", encoding="utf-8")

    agent = GenericAgent("agent-test", {})
    monkeypatch.setattr(agent, "_lm_root", lambda: lm_root)
    unit_dir = tmp_path / "systemd"

    reload_attempts = []
    monkeypatch.setattr(agent_spoke, "_LLM_POST_INSTALL_RETRY_INTERVAL", 0.5)
    runtime_attempts = []

    def fail_first_start(action):
        """Fail until a daemon-reload has succeeded, then allow the service to start."""
        runtime_attempts.append(action)
        return len(reload_attempts) > 1

    monkeypatch.setattr(llm_spoke, "cpu_capabilities", lambda: {"mode": "cpu"})
    monkeypatch.setattr(llm_spoke, "runtime_service", fail_first_start)
    monkeypatch.setattr(
        llm_spoke, "runtime_failure_code", lambda: "runtime_start_failed")

    def fail_first_reload(args, **kwargs):
        """Fail once, then allow the autonomous daemon-reload retry to succeed."""
        reload_attempts.append(args)
        if len(reload_attempts) == 1:
            raise subprocess.CalledProcessError(1, args)

    _redirect_systemd(monkeypatch, unit_dir)
    monkeypatch.setattr(agent_spoke.subprocess, "run", fail_first_reload)

    # Stub installation but exercise the actual post-install path.
    async def mock_install(role_name):
        """Run the actual LLM post-install path without package installation."""
        # Call the real post-install to exercise daemon-reload.
        agent._role_post_install(role_name)
        return {"status": "SUCCESS"}
    agent._install_role = mock_install

    worker = llm_spoke.LlmSpoke("agent-test-llm", {})
    agent._sync_load_role = lambda role_name, config, sub_spoke_id: worker

    # Build a minimal RoleConnection mock so the full LOAD_ROLE path
    # succeeds (the first call creates it; the second call hits the
    # already-loaded branch).
    def _FakeConn(role_name, base_id, hub_url, role_instance):
        """Provide the connection fields used by LOAD_ROLE's response."""
        conn = object.__new__(type("FakeConn", (), {}))
        conn.spoke_id = "agent-test-llm"
        conn.agent_control_plane = None
        conn.module_type = "llm"
        async def _run():
            """Model the hub's initial runtime-start command, if it sent one."""
            if hub_started:
                await role_instance.handle_command("LLM_START_RUNTIME", {})
        conn.run = _run
        return conn
    monkeypatch.setattr(agent_spoke, "RoleConnection", _FakeConn)

    # control_plane must be truthy to pass the cp check.
    agent.control_plane = type("FakeCP", (), {"hub_url": "ws://test"})()

    async def load_and_wait_for_retry():
        """Load once, let the unit repair finish, then start only on a hub command."""
        # Initial load stages the units but the first reload fails.
        result1 = await agent.handle_command("LOAD_ROLE", {"role": "llm"})
        assert result1["status"] == "SUCCESS"
        assert agent.llm_post_install_retry is True
        assert len(reload_attempts) == 1
        await agent._roles["llm"]["task"]
        hub_starts = ["start"] if hub_started else []
        assert runtime_attempts == hub_starts
        # The repair succeeds and does not start the runtime on its own.
        await asyncio.wait_for(agent._llm_post_install_retry_task, timeout=2)
        assert agent.llm_post_install_retry is False
        assert len(reload_attempts) == 2
        assert runtime_attempts == hub_starts
        assert worker._service_started is False
        # The next report carries a code the hub's gated retry starts from.
        status = await worker.get_status()
        assert status["code"] == "runtime_not_started"
        assert status.get("detail_code") == (
            "runtime_start_failed" if hub_started else None)
        # The hub's start command is what brings the repaired runtime up.
        assert (await worker.handle_command("LLM_START_RUNTIME", {}))["status"] == "SUCCESS"
        assert worker._service_started is True
        assert worker._runtime_issue is None

    asyncio.run(load_and_wait_for_retry())
