"""Pins the per-command concurrency fix in ``BaseControlPlane``.

The receive loop used to handle each hub command inline
(``async for message → await handle_command → websocket.send(COMMAND_RESULT)``)
— strictly serial, no per-command task. A slow handler therefore blocked the
loop from reading/acking the next command, which on the cs spoke surfaced as
the hub's every-5s "Request Timeout from cs-svr-02-spoke after 5.0s" flood
(the CSBridgePoller fires ``CS_POLL_AGENT_INBOX`` every 5s; a ``SPOKE_RELAY``
awaiting a pxmx agent for up to 15s blocked the 5s poll from being acked).

The fix dispatches each command to a bounded concurrent task. These tests
exercise ``_handle_one_command`` (the per-command handler + ack) directly with
the same ``asyncio.create_task`` pattern the receive loop uses, pinning:

* a slow handler does NOT block a fast command's ack (the core invariant);
* a handler exception returns a clean ERROR ack instead of crashing;
* the concurrency / in-flight caps are env-tunable with sane defaults.
"""

import asyncio
import json
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging import control_plane as cp  # noqa: E402


# ── Fakes ────────────────────────────────────────────────────────────────────

class _Mod:
    """Test module: SLOW_CMD sleeps, RAISE_CMD throws, anything else is fast."""
    def __init__(self):
        self.calls = []

    async def handle_command(self, cmd_type, data):
        self.calls.append(cmd_type)
        if cmd_type == "SLOW_CMD":
            await asyncio.sleep(0.3)
        elif cmd_type == "RAISE_CMD":
            raise RuntimeError("boom")
        return {"status": "SUCCESS", "cmd": cmd_type}


class _Ws:
    """Records COMMAND_RESULT frames as {corr, data} dicts in send order."""
    def __init__(self):
        self.sent = []

    async def send(self, frame):
        # Frames are the wire form <sig>.<body>; parse the body.
        from security.signer import split_frame
        _sig, _body = split_frame(frame)
        m = json.loads(_body)
        self.sent.append({
            "corr": m.get("correlation_id"),
            "data": m.get("payload", {}).get("data"),
        })


class _ConcSpoke(cp.BaseControlPlane):
    """Lightweight BaseControlPlane that skips the heavy __init__ (log relay,
    install-uuid, socket lookups) and wires only what _handle_one_command
    reads: spoke_id, modules, and the dispatch helpers."""
    def __init__(self):
        self.spoke_id = "test-spoke"
        self.modules = {}
        self.module_type = "test"
        self.signer = None   # unsigned frames (_encode_frame → <empty-sig>.<body>)

    def _sign(self, msg):  # noqa: D401
        return "sig"

    async def handle_system_command(self, cmd_type, data):
        return None  # route everything to the module

    def _module_handles_command(self, module, cmd_type):
        return True


def _build():
    spoke = _ConcSpoke()
    spoke.modules = {"test": _Mod()}
    return spoke


# ── The core invariant ───────────────────────────────────────────────────────

async def test_slow_handler_does_not_block_fast_command_ack():
    """Two commands dispatched concurrently: SLOW (0.3s) + FAST (instant).
    The fast command's ack MUST land before the slow one's — proving a slow
    handler no longer serializes the receive/ack path. Under the prior inline
    serial loop, SLOW would have been awaited first and FAST's ack would have
    waited ~0.3s (crossing the hub's 5s deadline at scale)."""
    spoke = _build()
    ws = _Ws()
    send_lock = asyncio.Lock()
    sem = asyncio.Semaphore(spoke._max_concurrent_commands())
    tA = asyncio.create_task(
        spoke._handle_one_command(ws, "SLOW_CMD", {}, "corrA", send_lock, sem))
    tB = asyncio.create_task(
        spoke._handle_one_command(ws, "FAST_CMD", {}, "corrB", send_lock, sem))
    await asyncio.gather(tA, tB)
    corrs = [f["corr"] for f in ws.sent]
    assert "corrA" in corrs and "corrB" in corrs, corrs
    # Fast acked first, slow second — the whole point of the fix.
    assert corrs.index("corrB") < corrs.index("corrA"), corrs
    # Both acks carry their correlation_id + the module's result.
    by_corr = {f["corr"]: f["data"] for f in ws.sent}
    assert by_corr["corrA"]["status"] == "SUCCESS"
    assert by_corr["corrB"]["status"] == "SUCCESS"


# ── Exception isolation ──────────────────────────────────────────────────────

async def test_handler_exception_returns_clean_error_ack():
    """A handler that raises must produce a clean ERROR COMMAND_RESULT, not
    propagate (which would tear down the hub websocket under the prior loop)."""
    spoke = _build()
    ws = _Ws()
    send_lock = asyncio.Lock()
    sem = asyncio.Semaphore(8)
    await spoke._handle_one_command(ws, "RAISE_CMD", {}, "corrR", send_lock, sem)
    assert len(ws.sent) == 1
    assert ws.sent[0]["corr"] == "corrR"
    data = ws.sent[0]["data"]
    assert data["status"] == "ERROR"
    assert "RuntimeError" in data["message"]


# ── Env-tunable caps ─────────────────────────────────────────────────────────

def test_concurrency_limits_env_overridable(monkeypatch):
    monkeypatch.setenv("LM_SPOKE_MAX_CONCURRENT_COMMANDS", "3")
    monkeypatch.setenv("LM_SPOKE_MAX_INFLIGHT_COMMANDS", "20")
    spoke = _ConcSpoke()
    assert spoke._max_concurrent_commands() == 3
    assert spoke._max_inflight_commands() == 20


def test_concurrency_limits_default_and_clamped(monkeypatch):
    # Defaults when unset, and a non-numeric value falls back to the default.
    monkeypatch.delenv("LM_SPOKE_MAX_CONCURRENT_COMMANDS", raising=False)
    monkeypatch.delenv("LM_SPOKE_MAX_INFLIGHT_COMMANDS", raising=False)
    spoke = _ConcSpoke()
    assert spoke._max_concurrent_commands() == 8
    assert spoke._max_inflight_commands() == 64
    monkeypatch.setenv("LM_SPOKE_MAX_CONCURRENT_COMMANDS", "garbage")
    assert spoke._max_concurrent_commands() == 8  # fallback
    monkeypatch.setenv("LM_SPOKE_MAX_CONCURRENT_COMMANDS", "0")
    assert spoke._max_concurrent_commands() == 1  # clamped to >=1