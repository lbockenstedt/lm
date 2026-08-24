"""HubCertDistributionMixin._hub_self_restart — must report the REAL exit
status of the underlying `sudo -n lm-self-restart` command instead of
optimistically claiming success whenever the command merely LAUNCHED.

Root cause this locks in: RUN_COMMAND's transport envelope always reports
{"status": "SUCCESS"} once the RPC round-trips, regardless of whether the
command it ran actually exited 0 — the real result is nested at
resp["result"]["rc"]/["stderr"] (see command_runner.run_local_command). The
old code checked only the outer "status" field.
"""
import asyncio

import pytest

from hub_cert_distribution import HubCertDistributionMixin


def _mixin(hub_self=None):
    m = HubCertDistributionMixin()
    m._hub_self = hub_self
    return m


class _FakeHubSelf:
    def __init__(self, response=None, raises=None):
        self._response = response
        self._raises = raises
        self.calls = []

    async def run_command(self, command, allow_shell=True, timeout=10.0):
        self.calls.append(command)
        if self._raises:
            raise self._raises
        return self._response


def _run_result(ok=True, rc=0, stdout="", stderr=""):
    return {"status": "SUCCESS", "result": {"ok": ok, "rc": rc, "stdout": stdout, "stderr": stderr}}


# ── primary path (hub-self agent connected) ─────────────────────────────────

@pytest.mark.asyncio
async def test_primary_path_success_checks_the_nested_result_not_just_status():
    hub_self = _FakeHubSelf(response=_run_result(ok=True, rc=0))
    m = _mixin(hub_self)
    msg = await m._hub_self_restart()
    assert "restarting" in msg
    assert hub_self.calls == ["sudo -n /usr/local/bin/lm-self-restart"]  # not backgrounded


@pytest.mark.asyncio
async def test_primary_path_transport_success_but_command_failed_falls_back_and_raises(monkeypatch):
    """This is the exact bug: transport status=SUCCESS but the command itself
    exited non-zero (e.g. the real 'unable to change to root gid' case).
    Must NOT report success — falls back to direct path, which also fails
    here, so the final result must raise with the real error surfaced."""
    hub_self = _FakeHubSelf(response=_run_result(
        ok=False, rc=1, stderr="sudo: unable to change to root gid: Operation not permitted"))
    m = _mixin(hub_self)

    async def _fake_exec(*a, **k):
        raise FileNotFoundError("sudo not found")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    with pytest.raises(RuntimeError, match="could not schedule self-restart"):
        await m._hub_self_restart()


@pytest.mark.asyncio
async def test_primary_path_rpc_error_falls_back_to_direct_path(monkeypatch):
    hub_self = _FakeHubSelf(raises=RuntimeError("agent not connected"))
    m = _mixin(hub_self)

    calls = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def _fake_exec(*a, **k):
        calls["called"] = True
        return _FakeProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    msg = await m._hub_self_restart()
    assert "restarting" in msg
    assert calls.get("called") is True


# ── direct fallback path (no hub-self agent, or primary path failed) ────────

@pytest.mark.asyncio
async def test_direct_path_success(monkeypatch):
    class _FakeProc:
        returncode = 0

        async def communicate(self):
            return b"", b""

        def kill(self):
            pass

    async def _fake_exec(*a, **k):
        return _FakeProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    m = _mixin(hub_self=None)
    msg = await m._hub_self_restart()
    assert "restarting" in msg


@pytest.mark.asyncio
async def test_direct_path_raises_with_real_stderr_on_nonzero_exit(monkeypatch):
    class _FakeProc:
        returncode = 1

        async def communicate(self):
            return b"", b"sudo: unable to change to root gid: Operation not permitted\n"

        def kill(self):
            pass

    async def _fake_exec(*a, **k):
        return _FakeProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    m = _mixin(hub_self=None)
    with pytest.raises(RuntimeError, match="unable to change to root gid"):
        await m._hub_self_restart()


@pytest.mark.asyncio
async def test_direct_path_timeout_kills_process_and_raises(monkeypatch):
    killed = {"called": False}

    class _FakeProc:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(100)  # never completes within the test's short timeout

        def kill(self):
            killed["called"] = True

    async def _fake_exec(*a, **k):
        return _FakeProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    def _fake_wait_for(coro, timeout):
        coro.close()  # avoid an unawaited-coroutine warning — never actually run it
        raise asyncio.TimeoutError()
    monkeypatch.setattr(asyncio, "wait_for", _fake_wait_for)

    m = _mixin(hub_self=None)
    with pytest.raises(RuntimeError, match="timed out"):
        await m._hub_self_restart()
    assert killed["called"] is True


@pytest.mark.asyncio
async def test_direct_path_exec_failure_raises(monkeypatch):
    async def _fake_exec(*a, **k):
        raise FileNotFoundError("sudo: command not found")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    m = _mixin(hub_self=None)
    with pytest.raises(RuntimeError, match="could not schedule self-restart"):
        await m._hub_self_restart()


@pytest.mark.asyncio
async def test_no_hub_self_and_no_backgrounding_command_used(monkeypatch):
    """Confirms the command is no longer backgrounded/output-discarded —
    create_subprocess_exec is called with exactly the argv, not a shell
    string with '&' / redirects."""
    captured = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def _fake_exec(*args, **kwargs):
        captured["args"] = args
        return _FakeProc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    m = _mixin(hub_self=None)
    await m._hub_self_restart()
    assert captured["args"] == ("sudo", "-n", "/usr/local/bin/lm-self-restart")
