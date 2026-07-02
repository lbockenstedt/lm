"""Spoke failed-update rollback (Part B2) — ``BaseControlPlane``.

Pins the rollback contract shared by every spoke (cs + pxmx, both subclass
``BaseControlPlane``): before a git-pull swap the spoke snapshots the code +
records HEAD; a pull that lands on a **known-bad commit** is reset back to the
prior HEAD and skipped (no restart, no crash-loop); a pull that lands on a good
commit writes a pending-update manifest (``from_commit``/``to_commit``/
``service_unit``) and schedules the external health-gate watchdog before
exiting so systemd relaunches it. The ``healthy`` marker is cleared on boot and
touched once the new code reaches a functional auth state with the hub.

Uses a fake git (canned ``subprocess.run`` outputs), a tmp state dir, and a
fake ``os._exit`` (raises) so the exit-on-restart path is observable without
killing the test process.
"""

import os
import sys

import pytest

# conftest puts core/src on sys.path (update_recovery, security.*). control_plane
# uses relative imports that resolve only as core.src.messaging.control_plane,
# so also put the lm repo root (parent of core/) on sys.path for that module.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import update_recovery  # noqa: E402
from core.src.messaging import control_plane as cp  # noqa: E402


# ── fakes ───────────────────────────────────────────────────────────────────

class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _FakeGit:
    """Canned git runner. ``rev-parse HEAD`` returns head_before on the first
    call and head_after on the second (the snapshot-then-pull-then-recheck
    sequence both update paths use). Records reset/fetch/pull invocations."""
    def __init__(self, head_before, head_after, pull_rc=0, behind="5"):
        self.head_before = head_before
        self.head_after = head_after
        self.pull_rc = pull_rc
        self.behind = behind
        self.rev_parse_head_calls = 0
        self.reset_calls = []
        self.fetch_called = False
        self.pull_called = False

    def run(self, cmd, *a, **k):
        # cmd[0] is "git" for both _run_git and the direct subprocess.run calls.
        args = cmd[1:] if cmd and cmd[0] == "git" else cmd
        if args[:2] == ["rev-parse", "HEAD"]:
            self.rev_parse_head_calls += 1
            head = self.head_before if self.rev_parse_head_calls == 1 else self.head_after
            return _FakeCompleted(0, stdout=head + "\n")
        if args[:2] == ["rev-parse", "--abbrev-ref"]:
            return _FakeCompleted(0, stdout="main\n")
        if args[:2] == ["rev-list", "--count"]:
            return _FakeCompleted(0, stdout=self.behind + "\n")
        if args[:1] == ["fetch"]:
            self.fetch_called = True
            return _FakeCompleted(0)
        if args[:1] == ["pull"]:
            self.pull_called = True
            return _FakeCompleted(self.pull_rc)
        if args[:1] == ["reset"]:
            self.reset_calls.append(args[1:])
            return _FakeCompleted(0)
        # remote set-url / config / rebase --abort → ok
        return _FakeCompleted(0)


class _FakePopen:
    def __init__(self):
        self.calls = []
    def __call__(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        return self  # Popen() returns a process-like; we never wait on it
    def wait(self, *a, **k):
        return 0


class _Exited(BaseException):
    """Raised by the fake os._exit so the restart path is observable. Inherits
    from BaseException (not Exception) so the handlers' broad ``except
    Exception`` doesn't swallow it — the real os._exit never returns and is
    never caught, so the fake must escape the same try/except."""
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _fake_exit(code):
    raise _Exited(code)


class _TestSpoke(cp.BaseControlPlane):
    """Minimal spoke for rollback tests — tmp state dir, no .env I/O."""
    def __init__(self, spoke_id, state_dir):
        self._test_state_dir = state_dir
        # bypass BaseControlPlane.__init__ side effects (MessageSigner fine, but
        # _ensure_install_uuid writes a .env in cwd) — set the fields __init__ does.
        self.spoke_id = spoke_id
        self.secret = "x"
        self.hub_secrets = []
        self.hub_url = "ws://h"
        self.onboarding_psk = ""
        self.tenant_id_hint = ""
        self.modules = {}
        self.signer = None
        self.module_type = "test"
        self._updater_stop = None
        self._updater_thread = None
        self._log_relay_queue = None
        self._log_relay_handler = None
        self._hub_ws = None
        self._loop = None
        self._hub_secret_warned = False
        self.hostname = "testhost"
        self.install_uuid = "uuid-test"

    def _spoke_state_dir(self):
        return self._test_state_dir
    def get_service_name(self):
        return "lm-test"
    def _flush_log_relay_sync(self):
        pass
    async def _flush_log_relay_async(self):
        pass


@pytest.fixture
def spoke(tmp_path):
    return _TestSpoke("test-spoke-1", str(tmp_path / "state"))


# ── healthy marker ──────────────────────────────────────────────────────────

def test_healthy_marker_round_trip(spoke, tmp_path):
    sd = tmp_path / "state"
    spoke._touch_healthy_marker()
    assert (sd / "healthy").is_file()
    spoke._clear_healthy_marker()
    assert not (sd / "healthy").exists()


def test_clear_healthy_marker_idempotent_when_absent(spoke):
    # No marker yet → clear is a no-op, no raise.
    spoke._clear_healthy_marker()
    assert not os.path.exists(os.path.join(spoke._spoke_state_dir(), "healthy"))


# ── SPOKE_UPDATE handler ────────────────────────────────────────────────────

def _patch_runner(monkeypatch, fake_git):
    monkeypatch.setattr(cp.subprocess, "run", fake_git.run)
    monkeypatch.setattr(cp.subprocess, "Popen", _FakePopen())
    monkeypatch.setattr("os._exit", _fake_exit)
    # Avoid a real src/ copy: record the call + return a tmp backup dir.
    fake_snapshot_calls = []
    def _fake_snapshot_code(hub_root, ts, tree_list=None, state_dir=None):
        fake_snapshot_calls.append({"tree_list": tree_list, "state_dir": state_dir})
        bd = os.path.join(state_dir, "update-backup", ts)
        os.makedirs(bd, exist_ok=True)
        return bd
    monkeypatch.setattr(update_recovery, "snapshot_code", _fake_snapshot_code)
    return fake_snapshot_calls


@pytest.mark.asyncio
async def test_spoke_update_skips_known_bad_commit(spoke, tmp_path, monkeypatch):
    fake_git = _FakeGit(head_before="aaa111", head_after="bbb222")
    _patch_runner(monkeypatch, fake_git)
    # Pre-mark the post-pull commit bad.
    update_recovery.add_bad_commit("bbb222", state_dir=spoke._spoke_state_dir())
    # write a stale pending so we can assert it's cleared on skip
    update_recovery.write_pending("/stale", "old", "new", "ts",
                                   state_dir=spoke._spoke_state_dir())

    result = await spoke.handle_system_command(
        "SPOKE_UPDATE", {"repo_url": "https://example/repo.git"})

    assert result["status"] == "SUCCESS"
    assert "marked bad" in result["message"]
    # reset back to the pre-update HEAD so the spoke stays on known-good code
    assert any(r == ["--hard", "aaa111"] for r in fake_git.reset_calls)
    # pending manifest cleared (no in-flight update)
    assert update_recovery.read_pending(state_dir=spoke._spoke_state_dir()) is None
    # did NOT exit for restart (stayed on the old code)
    # (os._exit would have raised _Exited out of handle_system_command)


@pytest.mark.asyncio
async def test_spoke_update_normal_writes_pending_and_schedules_watchdog(spoke, tmp_path, monkeypatch):
    fake_git = _FakeGit(head_before="aaa111", head_after="bbb222")
    _patch_runner(monkeypatch, fake_git)
    fake_popen = cp.subprocess.Popen  # the _FakePopen installed by _patch_runner

    with pytest.raises(_Exited) as ei:
        await spoke.handle_system_command(
            "SPOKE_UPDATE", {"repo_url": "https://example/repo.git"})
    assert ei.value.code == 3  # exit 3 → systemd Restart=on-failure relaunches

    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert pending is not None
    assert pending["from_commit"] == "aaa111"
    assert pending["to_commit"] == "bbb222"
    assert pending["service_unit"] == "lm-test"
    assert pending["deadline"] == 90
    # watchdog scheduled with the per-spoke state dir + repo root + unit
    assert len(fake_popen.calls) == 1
    cmd = fake_popen.calls[0]
    assert cmd[0] == "sudo"
    assert "/usr/local/bin/lm-component-update-restart" in cmd
    assert "--unit" in cmd and "lm-test" in cmd
    assert "--state-dir" in cmd and spoke._spoke_state_dir() in cmd
    assert "--deadline" in cmd and "90" in cmd


@pytest.mark.asyncio
async def test_spoke_update_already_up_to_date_no_restart(spoke, monkeypatch):
    # head_after == head_before → no restart, no exit, SUCCESS "already up to date"
    fake_git = _FakeGit(head_before="aaa111", head_after="aaa111")
    _patch_runner(monkeypatch, fake_git)
    fake_popen = cp.subprocess.Popen

    result = await spoke.handle_system_command(
        "SPOKE_UPDATE", {"repo_url": "https://example/repo.git"})

    assert result["status"] == "SUCCESS"
    assert "Already up to date" in result["message"]
    assert fake_popen.calls == []  # no watchdog scheduled
    assert update_recovery.read_pending(state_dir=spoke._spoke_state_dir()) is None


# ── perform_self_update_check (sync updater thread path) ────────────────────

def test_self_update_skips_known_bad_commit(spoke, monkeypatch):
    fake_git = _FakeGit(head_before="aaa111", head_after="bbb222")
    _patch_runner(monkeypatch, fake_git)
    update_recovery.add_bad_commit("bbb222", state_dir=spoke._spoke_state_dir())

    # perform_self_update_check runs in the updater thread (sync). No _Exited
    # should be raised: a bad commit is skipped WITHOUT a restart.
    result = spoke.perform_self_update_check()
    assert result is False  # no restart performed
    assert any(r == ["--hard", "aaa111"] for r in fake_git.reset_calls)
    assert update_recovery.read_pending(state_dir=spoke._spoke_state_dir()) is None


def test_self_update_normal_writes_pending_and_exits(spoke, monkeypatch):
    fake_git = _FakeGit(head_before="aaa111", head_after="bbb222")
    _patch_runner(monkeypatch, fake_git)
    fake_popen = cp.subprocess.Popen

    with pytest.raises(_Exited) as ei:
        spoke.perform_self_update_check()
    assert ei.value.code == 3

    pending = update_recovery.read_pending(state_dir=spoke._spoke_state_dir())
    assert pending is not None
    assert pending["from_commit"] == "aaa111"
    assert pending["to_commit"] == "bbb222"
    assert pending["service_unit"] == "lm-test"
    assert len(fake_popen.calls) == 1


def test_self_update_already_up_to_date_no_restart(spoke, monkeypatch):
    fake_git = _FakeGit(head_before="aaa111", head_after="aaa111", behind="0")
    _patch_runner(monkeypatch, fake_git)
    fake_popen = cp.subprocess.Popen

    result = spoke.perform_self_update_check()
    assert result is False
    assert fake_popen.calls == []
    assert update_recovery.read_pending(state_dir=spoke._spoke_state_dir()) is None