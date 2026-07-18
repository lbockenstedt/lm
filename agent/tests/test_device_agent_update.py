"""Feature (b): the device-mode ``SpokeClient`` (the dumb agent) handles the
``AGENT_UPDATE`` command the spoke forwards down the ``/ws/agent`` channel —
symmetric with the hub→spoke ``SPOKE_UPDATE``. The agent pulls its own repo (+
the shared /opt/lm core), arms its rollback watchdog, and ``os._exit(3)``s so
systemd ``Restart=on-failure`` reloads the new code. The whole git dance runs
off the event loop (``asyncio.to_thread``) so a slow link doesn't stall
in-flight primitives, mirroring the spoke handler. The actual pull/snapshot/
rollback body is shared via ``SelfUpdateMixin._perform_self_update_sync``.

Pins: missing ``repo_url`` → ERROR; the single-flight guard (a re-delivered
duplicate while an update is mid-flight short-circuits with an immediate ack
instead of spawning a concurrent git pull); the handler sets the
``_draining`` / ``_spoke_update_in_progress`` drain flags (so the code-drift
watchdog skips + the spoke queues pushes) and delegates to
``_perform_self_update_sync`` with ``reason="agent-update"`` + the forwarded
{repo_url, core_repo_url, core_branch}; and the finally clears the flags on a
non-exit return (so a no-op update doesn't blind the drift watchdog for the
process lifetime).
"""
import asyncio
import os

import spoke_client
from spoke_client import SpokeClient


def _client(tmp_path):
    return SpokeClient(
        "dev-1", "wss://spoke:443", secret="s",
        secret_path=str(tmp_path / "secret"),
        install_uuid_path=str(tmp_path / "install-uuid"),
    )


def _dispatch(c, data):
    # asyncio.run() creates a FRESH loop per call + closes it — robust against
    # other tests in the same session leaving the default event loop closed
    # (get_event_loop().run_until_complete would reuse a stale loop).
    return asyncio.run(c._dispatch("AGENT_UPDATE", data))


def test_missing_repo_url_returns_error(tmp_path):
    c = _client(tmp_path)
    res = _dispatch(c, {})
    assert res["status"] == "ERROR"
    assert "repo_url" in res["message"]
    # No update marked in flight → flags untouched.
    assert c._spoke_update_in_progress is False
    assert c._draining is False


def test_delegates_to_perform_self_update_with_agent_update_reason(tmp_path, monkeypatch):
    """A valid AGENT_UPDATE delegates to ``_perform_self_update_sync`` with the
    forwarded params + reason='agent-update', sets the drain flags during the
    run, returns the worker's result, and clears the flags after a non-exit
    return."""
    c = _client(tmp_path)
    seen = {}

    def _fake_worker(repo_url, core_repo_url=None, core_branch=None, reason="update"):
        seen.update(repo_url=repo_url, core_repo_url=core_repo_url,
                    core_branch=core_branch, reason=reason)
        # Assert the drain flags ARE set while the worker runs (the handler set
        # them before to_thread + clears them in finally AFTER we return).
        seen["draining_during"] = c._draining
        seen["inprog_during"] = c._spoke_update_in_progress
        return {"status": "SUCCESS", "message": "Updated from r"}
    monkeypatch.setattr(c, "_perform_self_update_sync", _fake_worker)

    res = _dispatch(c, {
        "repo_url": "https://example/lm.git",
        "core_repo_url": "https://example/lm.git",
        "core_branch": "main",
    })
    assert res["status"] == "SUCCESS"
    assert seen["repo_url"] == "https://example/lm.git"
    assert seen["core_repo_url"] == "https://example/lm.git"
    assert seen["core_branch"] == "main"
    assert seen["reason"] == "agent-update"
    # Flags were set during the worker run.
    assert seen["draining_during"] is True
    assert seen["inprog_during"] is True
    # finally cleared them on the non-exit return path.
    assert c._draining is False
    assert c._spoke_update_in_progress is False


def test_single_flight_guard_ignores_redelivery(tmp_path, monkeypatch):
    """A re-delivered AGENT_UPDATE while one is already in flight short-circuits
    with an immediate SUCCESS ack and does NOT spawn a second worker."""
    c = _client(tmp_path)
    c._spoke_update_in_progress = True  # simulate an in-flight update

    called = []
    monkeypatch.setattr(c, "_perform_self_update_sync",
                        lambda *a, **k: called.append("worker") or {"status": "SUCCESS"})

    res = _dispatch(c, {"repo_url": "https://example/lm.git"})
    assert res["status"] == "SUCCESS"
    assert "already in progress" in res["message"]
    assert called == []  # worker NOT invoked
    # The guard must not clobber the in-flight flag (the original run owns it).
    assert c._spoke_update_in_progress is True


def test_finally_clears_draining_on_worker_exception(tmp_path, monkeypatch):
    """If the worker RAISES (git error propagates), the finally still clears the
    drain flags so the code-drift watchdog resumes — no permanent blind spot."""
    c = _client(tmp_path)

    def _boom(*a, **k):
        raise RuntimeError("git exploded")
    monkeypatch.setattr(c, "_perform_self_update_sync", _boom)

    import pytest
    with pytest.raises(RuntimeError):
        _dispatch(c, {"repo_url": "https://example/lm.git"})
    assert c._draining is False
    assert c._spoke_update_in_progress is False


def test_device_client_resolves_update_helpers_via_mixin():
    """The device-mode SpokeClient gets the update helpers from SelfUpdateMixin
    (not a private copy), and provides its OWN get_service_name +
    _flush_log_relay_sync hooks the mixin calls."""
    from core.src.messaging.self_update import SelfUpdateMixin
    for m in ("_run_git", "_perform_self_update_sync", "_prepare_restart_with_watchdog",
              "_spoke_state_dir", "_snapshot_for_update", "_core_update_lock"):
        assert m not in SpokeClient.__dict__, f"{m} re-defined by SpokeClient"
        assert getattr(SpokeClient, m) is getattr(SelfUpdateMixin, m), (
            f"{m} not resolved via SelfUpdateMixin")
    # Hooks the mixin calls — provided by SpokeClient itself.
    for hook in ("_repo_root", "_resolve_core_root", "get_service_name",
                 "_flush_log_relay_sync", "_flush_log_relay_async"):
        assert hook in SpokeClient.__dict__, f"{hook} not provided by SpokeClient"


def test_get_service_name_is_lm_agent(tmp_path, monkeypatch):
    """The device-mode agent runs as the single ``lm-agent`` unit (hosting all
    roles), so the watchdog restarts that name — not an agent_id-derived name
    like a spoke's ``lm-<module>``."""
    c = _client(tmp_path)
    monkeypatch.delenv("LM_AGENT_SERVICE_NAME", raising=False)
    assert c.get_service_name() == "lm-agent"
    monkeypatch.setenv("LM_AGENT_SERVICE_NAME", "lm-agent-custom")
    assert c.get_service_name() == "lm-agent-custom"