"""Clear Logs feature (WebUI Logs → Clear button).

Pins the three pieces of the fleet-wide log clear the WebUI "Clear" button
triggers via ``POST /setup/logs/clear``:

1. ``truncate_log_files`` (logging_setup.py) — truncates every ``*.log`` in a
   directory to zero bytes **in place** (same inode). Unlinking instead would
   detach each process's open ``RotatingFileHandler`` to a stale inode and
   silently lose every subsequent log line; truncating in place lets the
   handler's next write land at offset 0. Non-``.log`` files are left alone and
   a missing directory returns ``[]`` (the clear must never crash the caller).
2. ``CLEAR_LOGS`` hub→spoke command (control_plane.handle_system_command) —
   dispatches to ``truncate_log_files`` and returns the truncated file list, so
   every connected spoke/agent wipes its own on-disk logs.
3. ``Hub.clear_all_logs`` — clears the hub's in-memory deque + every relayed
   agent/spoke deque IN PLACE (keys preserved so a still-connected spoke keeps
   its buffer entry), truncates the hub box's on-disk logs, and broadcasts
   ``CLEAR_LOGS`` to every connected spoke; returns a summary for the route.
"""
import asyncio
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import logging_setup  # noqa: E402
from core.src.messaging import control_plane as cp  # noqa: E402


# ── truncate_log_files ──────────────────────────────────────────────────────

def test_truncate_log_files_truncates_in_place_same_inode(tmp_path):
    # Two .log files with content; a non-.log file must be left alone.
    a = tmp_path / "hub.log"
    b = tmp_path / "lm-dns.log"
    keep = tmp_path / "state.json"
    a.write_text("line1\nline2\nline3\n")
    b.write_text("dhcp lease\n")
    keep.write_text('{"keep": true}')
    inode_a = os.stat(a).st_ino

    truncated = logging_setup.truncate_log_files(str(tmp_path))

    assert sorted(truncated) == ["hub.log", "lm-dns.log"]
    assert a.read_text() == ""
    assert b.read_text() == ""
    # Same inode — truncation in place, NOT unlink+recreate. The whole point:
    # an open RotatingFileHandler keeps the same fd and writes at offset 0.
    assert os.stat(a).st_ino == inode_a
    # Non-.log file untouched.
    assert keep.read_text() == '{"keep": true}'


def test_truncate_log_files_missing_dir_returns_empty():
    # A path that doesn't exist must NOT raise — the clear is best-effort and
    # runs inside the hub event loop; a missing /var/log/lm (fresh box, perm
    # gap) returning [] is correct, not a crash.
    assert logging_setup.truncate_log_files("/no/such/lm/dir/here") == []


def test_truncate_log_files_empty_dir_returns_empty(tmp_path):
    assert logging_setup.truncate_log_files(str(tmp_path)) == []


def test_truncate_log_files_skips_subdirs(tmp_path):
    # A directory named *.log must not be opened with open(path,"w") (that
    # would raise IsADirectoryError); it's skipped, not crashed on.
    (tmp_path / "weird.log").mkdir()
    (tmp_path / "real.log").write_text("x\n")
    truncated = logging_setup.truncate_log_files(str(tmp_path))
    assert truncated == ["real.log"]


# ── CLEAR_LOGS spoke command ───────────────────────────────────────────────

class _BareSpoke(cp.BaseControlPlane):
    """BaseControlPlane that skips the heavy __init__ (WS/log-relay/install-uuid
    setup) but keeps the REAL handle_system_command — so CLEAR_LOGS runs the
    production code path, not a stub."""

    def __init__(self):
        self.spoke_id = "test-spoke"


@pytest.mark.asyncio
async def test_clear_logs_command_truncates_disk(tmp_path, monkeypatch):
    # Point truncate_log_files at a temp dir so the test doesn't touch the
    # real /var/log/lm. handle_system_command calls the module-level
    # truncate_log_files imported at control_plane import time, so patch THAT
    # binding.
    spoke = _BareSpoke()
    log = tmp_path / "lm-cppm.log"
    log.write_text("old line\n")

    def _stub(log_dir="/var/log/lm"):
        assert log_dir == "/var/log/lm"
        # Truncate the temp file to mimic the real helper.
        with open(log, "w"):
            pass
        return ["lm-cppm.log"]

    monkeypatch.setattr(cp, "truncate_log_files", _stub)
    result = await spoke.handle_system_command("CLEAR_LOGS", {})
    assert result["status"] == "SUCCESS"
    assert result["truncated"] == ["lm-cppm.log"]
    assert log.read_text() == ""


@pytest.mark.asyncio
async def test_clear_logs_command_unknown_type_returns_none():
    # Built-in dispatch falls through (returns None) for commands it doesn't
    # own — CLEAR_LOGS is a new branch, not a catch-all.
    spoke = _BareSpoke()
    assert await spoke.handle_system_command("SOME_OTHER_CMD", {}) is None


# ── Hub.clear_all_logs ──────────────────────────────────────────────────────

class _Hub:
    """Minimal stand-in exposing only what clear_all_logs / broadcast_clear_logs
    touch: the in-memory deques + active_connections. Avoids standing up the
    full Hub (uvicorn / mailbox / state) just to test the clear path."""

    def __init__(self):
        from collections import deque
        self.logs = deque(maxlen=500)
        self.agent_logs = {"spoke-a": deque(maxlen=500),
                           "spoke-b": deque(maxlen=500)}
        self.active_connections = {"spoke-a": object(), "spoke-b": object()}
        self.broadcast_calls = 0

    async def send_to_spoke(self, msg):
        return None  # fire-and-forget; broadcast_clear_logs gathers these

    async def broadcast_clear_logs(self):
        self.broadcast_calls += 1


def test_clear_all_logs_clears_in_memory_and_broadcasts(monkeypatch):
    # The deques start populated; clear_all_logs empties each IN PLACE (keys
    # preserved) + truncates the hub box's logs + broadcasts CLEAR_LOGS once.
    import main as main_mod

    hub = _Hub()
    hub.logs.append("hub-line-1")
    hub.logs.append("hub-line-2")
    hub.agent_logs["spoke-a"].append("a1")
    hub.agent_logs["spoke-b"].append("b1")
    hub.agent_logs["spoke-b"].append("b2")

    # clear_all_logs references the module-global truncate_log_files name, so
    # patch THAT binding on main_mod — the real helper isn't run here.
    monkeypatch.setattr(main_mod, "truncate_log_files",
                        lambda d="/var/log/lm": ["hub.log", "lm-cs.log"])

    result = asyncio.get_event_loop().run_until_complete(
        main_mod.LabManagerHub.clear_all_logs(hub))

    assert result["status"] == "ok"
    assert result["hub_lines"] == 2
    assert result["agent_lines"] == 3
    assert result["agent_buffers"] == 2
    assert sorted(result["disk_files_truncated"]) == ["hub.log", "lm-cs.log"]
    assert result["spokes_broadcast"] == 2
    # In-memory deques emptied IN PLACE — keys preserved (a still-connected
    # spoke keeps its buffer entry rather than dropping out of the agents list).
    assert set(hub.agent_logs.keys()) == {"spoke-a", "spoke-b"}
    assert len(hub.agent_logs["spoke-a"]) == 0
    assert len(hub.agent_logs["spoke-b"]) == 0
    assert len(hub.logs) == 0
    assert hub.broadcast_calls == 1