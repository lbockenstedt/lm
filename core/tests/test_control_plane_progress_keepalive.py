"""Keepalive for slow spoke commands (hub↔spoke hop).

Companion to test_agent_hosting_progress_keepalive.py (the spoke↔agent hop).
When the hub asks a spoke to service a slow command (GET_NODE_STATS /
PXMX_LIST_VMS against a big Proxmox cluster), the spoke now emits periodic
SPOKE_PROGRESS frames (correlation_id == the hub's request msg_id) while the
handler runs, so the hub's request_response extends its deadline instead of
logging ``Request Timeout`` at the base 30s window.

These tests drive the real ``_handle_one_command`` dispatch and assert: a slow
KEEPALIVE command emits SPOKE_PROGRESS frames before its COMMAND_RESULT, a fast
one emits none, and a non-keepalive command never starts the emitter.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from messaging import control_plane as cp  # noqa: E402
from messaging.control_plane import BaseControlPlane  # noqa: E402
from security.signer import MessageSigner  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _RecordWS:
    """Records every framed send, classified by payload type."""

    def __init__(self):
        self.frames = []

    async def send(self, wire):
        # Frames are <sig>.<body>; body is JSON. Parse the type for assertions.
        try:
            body = wire.split(".", 1)[1]
            self.frames.append(json.loads(body))
        except Exception:
            self.frames.append({"_raw": wire})

    def types(self):
        return [f.get("payload", {}).get("type") for f in self.frames]


class _StubModule:
    """A module whose handle_command sleeps `delay`s to simulate a slow backend."""

    def __init__(self, delay):
        self.delay = delay

    def _module_handles(self, cmd_type):
        return True

    async def handle_command(self, cmd_type, data):
        await asyncio.sleep(self.delay)
        return {"status": "SUCCESS", "cmd": cmd_type}

    async def get_status(self):
        return {"status": "SUCCESS"}


class _Spoke:
    """Minimal harness binding the REAL _handle_one_command / _emit_spoke_progress
    / _send_cmd_result to a stub with just the attributes they touch."""

    def __init__(self, module, module_name="pxmx"):
        self.spoke_id = "test-spoke"
        self.modules = {module_name: module}
        self.signer = MessageSigner("test-spoke-secret-1234567890")
        self.secret = "test-spoke-secret-1234567890"
        self._handle_one_command = BaseControlPlane._handle_one_command.__get__(self)
        self._emit_spoke_progress = BaseControlPlane._emit_spoke_progress.__get__(self)
        self._send_cmd_result = BaseControlPlane._send_cmd_result.__get__(self)
        self._encode_frame = BaseControlPlane._encode_frame.__get__(self)
        # handle_system_command must return None so dispatch falls to the module.
        self.handle_system_command = self._sys_none
        self._module_handles_command = lambda module, cmd: module._module_handles(cmd)

    async def _sys_none(self, cmd_type, data):
        return None


def _dispatch(spoke, cmd_type, delay_interval=0.05):
    """Run one command through _handle_one_command with a short keepalive
    interval so a 'slow' handler triggers at least one SPOKE_PROGRESS."""
    ws = _RecordWS()
    sem = asyncio.Semaphore(4)
    orig = cp._KEEPALIVE_INTERVAL_S
    cp._KEEPALIVE_INTERVAL_S = delay_interval
    try:
        _run(spoke._handle_one_command(
            ws, cmd_type, {}, "corr-123", asyncio.Lock(), sem))
    finally:
        cp._KEEPALIVE_INTERVAL_S = orig
    return ws


def test_slow_keepalive_command_emits_progress_before_result():
    """A slow GET_NODE_STATS (in _KEEPALIVE_CMDS) emits >=1 SPOKE_PROGRESS frame,
    all correlated to the request, and the final COMMAND_RESULT comes last."""
    spoke = _Spoke(_StubModule(delay=0.18))
    ws = _dispatch(spoke, "GET_NODE_STATS", delay_interval=0.05)

    types = ws.types()
    assert "SPOKE_PROGRESS" in types
    assert types[-1] == "COMMAND_RESULT"
    # Progress frames carry the hub's correlation id so the waiter matches them.
    for f in ws.frames:
        if f.get("payload", {}).get("type") == "SPOKE_PROGRESS":
            assert f.get("correlation_id") == "corr-123"


def test_fast_keepalive_command_emits_no_progress():
    """A fast command finishes before the first keepalive interval, so only the
    COMMAND_RESULT is sent — no wasted progress frames on the common path."""
    spoke = _Spoke(_StubModule(delay=0.0))
    ws = _dispatch(spoke, "GET_NODE_STATS", delay_interval=0.2)

    assert ws.types() == ["COMMAND_RESULT"]


def test_non_keepalive_command_never_emits_progress():
    """A command NOT in _KEEPALIVE_CMDS never starts the emitter, even if slow."""
    spoke = _Spoke(_StubModule(delay=0.18))
    ws = _dispatch(spoke, "CS_GET_STATUS", delay_interval=0.05)

    assert "SPOKE_PROGRESS" not in ws.types()
    assert ws.types()[-1] == "COMMAND_RESULT"


def test_slow_cppm_nac_status_emits_progress():
    """Regression: the newer/larger CPPM servers answer CPPM_GET_NAC_STATUS
    slowly enough to blow the base request_response timeout. It's now in
    _KEEPALIVE_CMDS, so a slow nac read emits keepalives that extend the hub's
    deadline instead of logging ``Request Timeout: [CPPM_GET_NAC_STATUS]``."""
    assert "CPPM_GET_NAC_STATUS" in cp._KEEPALIVE_CMDS
    spoke = _Spoke(_StubModule(delay=0.18), module_name="cppm")
    ws = _dispatch(spoke, "CPPM_GET_NAC_STATUS", delay_interval=0.05)

    types = ws.types()
    assert "SPOKE_PROGRESS" in types
    assert types[-1] == "COMMAND_RESULT"
    for f in ws.frames:
        if f.get("payload", {}).get("type") == "SPOKE_PROGRESS":
            assert f.get("correlation_id") == "corr-123"


def test_slow_nw_poll_emits_progress():
    """Regression: NW_POLL chains probe + device_info + interfaces + arp + mac in
    one call over live SSH, so a big MAC/ARP table or a slow switch blows the
    hub's 60s base and logs ``Request Timeout: [NW_POLL]``. It's now in
    _KEEPALIVE_CMDS, so a slow poll emits SPOKE_PROGRESS keepalives that extend
    the hub's deadline instead of hard-failing at the base ceiling."""
    assert "NW_POLL" in cp._KEEPALIVE_CMDS
    spoke = _Spoke(_StubModule(delay=0.18), module_name="nw")
    ws = _dispatch(spoke, "NW_POLL", delay_interval=0.05)

    types = ws.types()
    assert "SPOKE_PROGRESS" in types
    assert types[-1] == "COMMAND_RESULT"
    for f in ws.frames:
        if f.get("payload", {}).get("type") == "SPOKE_PROGRESS":
            assert f.get("correlation_id") == "corr-123"
