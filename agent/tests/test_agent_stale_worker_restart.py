"""An ACTIVE LM Python worker sidecar (``lm-dhcp-worker``/``lm-dns-worker``)
whose code on disk is newer than its running process is restarted by the
agent's role-status self-heal.

Production symptom: the agent's SPOKE_UPDATE pulled new code into /opt/lm and
restarted the agent, but lm-dhcp-worker kept running the old modules for two
days, so the (already updated) coordinator's KEAW_PACKET_TRACE came back
"unsupported worker operation" from both Kea nodes.
"""
import os
from types import SimpleNamespace

import pytest

import agent_spoke
from agent_spoke import _restart_stale_service_workers


@pytest.fixture
def box(tmp_path, monkeypatch):
    workdir = tmp_path / "lm" / "dhcp" / "src"
    workdir.mkdir(parents=True)
    msg = tmp_path / "lm" / "core" / "src" / "messaging"
    msg.mkdir(parents=True)
    (workdir / "dhcp_worker.py").write_text("")
    (msg / "service_cluster.py").write_text("")
    for p in (workdir / "dhcp_worker.py", msg / "service_cluster.py"):
        os.utime(p, (1000, 1000))
    state = {"active": "active", "pid": 4242, "start": 2000.0, "restart_rc": 0}
    calls = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["systemctl", "show"]:
            unit = cmd[-1]
            if unit != "lm-dhcp-worker":
                return SimpleNamespace(returncode=0, stdout="ActiveState=inactive\nMainPID=0\n", stderr="")
            return SimpleNamespace(returncode=0, stderr="", stdout=(
                f"ActiveState={state['active']}\nMainPID={state['pid']}\n"
                f"WorkingDirectory={workdir}\n"))
        if cmd[:2] == ["systemctl", "restart"]:
            return SimpleNamespace(returncode=state["restart_rc"], stdout="", stderr="")
        raise AssertionError(f"unexpected call: {cmd}")

    monkeypatch.setattr(agent_spoke.subprocess, "run", run)
    monkeypatch.setattr(agent_spoke, "_proc_start_epoch", lambda pid: state["start"])
    monkeypatch.setattr(agent_spoke, "_stale_worker_restarted_for", {})
    return SimpleNamespace(workdir=workdir, msg=msg, state=state, calls=calls)


def _restarts(calls):
    return [c for c in calls if c[:2] == ["systemctl", "restart"]]


def test_up_to_date_worker_is_left_alone(box):
    assert _restart_stale_service_workers(["dhcp-server"], now=5000) == []
    assert _restarts(box.calls) == []


def test_worker_older_than_its_code_is_restarted(box):
    os.utime(box.workdir / "dhcp_worker.py", (3000, 3000))
    actions = _restart_stale_service_workers(["dhcp-server"], now=5000)
    assert _restarts(box.calls) == [["systemctl", "restart", "lm-dhcp-worker"]]
    assert actions and "lm-dhcp-worker" in actions[0]


def test_shared_messaging_change_also_counts(box):
    os.utime(box.msg / "service_cluster.py", (3000, 3000))
    _restart_stale_service_workers(["dhcp-server"], now=5000)
    assert _restarts(box.calls) == [["systemctl", "restart", "lm-dhcp-worker"]]


def test_waits_for_a_pull_to_settle(box):
    os.utime(box.workdir / "dhcp_worker.py", (3000, 3000))
    _restart_stale_service_workers(["dhcp-server"], now=3005)
    assert _restarts(box.calls) == []


def test_restarts_only_once_per_code_version(box):
    os.utime(box.workdir / "dhcp_worker.py", (3000, 3000))
    box.state["restart_rc"] = 1  # restart "didn't take" — must not loop
    _restart_stale_service_workers(["dhcp-server"], now=5000)
    _restart_stale_service_workers(["dhcp-server"], now=5100)
    assert len(_restarts(box.calls)) == 1


def test_stopped_worker_is_not_started(box):
    os.utime(box.workdir / "dhcp_worker.py", (3000, 3000))
    box.state["active"] = "inactive"
    _restart_stale_service_workers(["dhcp-server"], now=5000)
    assert _restarts(box.calls) == []


def test_role_not_installed_is_never_touched(box):
    os.utime(box.workdir / "dhcp_worker.py", (3000, 3000))
    assert _restart_stale_service_workers([], now=5000) == []
    assert box.calls == []


def test_proc_start_epoch_parses_comm_with_spaces(tmp_path, monkeypatch):
    stat = "btime 1000\n"
    proc = "42 (python3 x) S " + " ".join(["0"] * 18) + " 500 0 0\n"
    files = {"/proc/stat": stat, "/proc/42/stat": proc}
    real_open = open

    def fake_open(path, *a, **k):
        if path in files:
            import io
            return io.StringIO(files[path])
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(agent_spoke.os, "sysconf", lambda name: 100)
    assert agent_spoke._proc_start_epoch(42) == 1005.0
