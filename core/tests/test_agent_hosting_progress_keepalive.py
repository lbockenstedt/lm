"""Keepalive for slow agent commands (agent-hosting hop).

Symptom (RSVBE-LM-AGENT-proxmox, a cluster with many VMs): the hub logged
``Request Timeout: [GET_NODE_STATS]``/``[PXMX_LIST_VMS]`` after 30s and VMs never
populated, because the live aggregation path issues multi-round-trip
``RUN_COMMAND`` calls through ``send_to_agent`` and a busy backend answers slower
than the fixed timeout. The agent now emits ``AGENT_PROGRESS`` keepalives while
it works; the spoke's ``send_to_agent`` extends its soft deadline on each one
(capped by a hard ceiling) instead of killing a slow-but-alive request.

These tests drive the real ``send_to_agent`` wait loop + the real
``AGENT_PROGRESS`` receive branch and assert: (1) progress extends the deadline
so a late response still succeeds, (2) without progress the base timeout is
honored, (3) the hard ceiling still bounds a genuinely-hung agent, and (4) the
receive branch bumps the tracked deadline.
"""
import asyncio
import os
import sys
import time

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402
from core.src.security.signer import MessageSigner, encode_frame       # noqa: E402

SECRET = "test-agent-secret-1234567890"


class _Host(AgentHostingControlPlane):
    """Minimal harness — bypass BaseControlPlane.__init__, set only what the
    keepalive paths touch (mirrors test_agent_hosting_frame_decode._Host)."""

    def __init__(self, secret, hard_mult=6.0):
        self.agent_secret = secret
        self.agent_signer = MessageSigner(secret)
        self.spoke_id = "test-spoke"
        self.connected_agents = {}
        self.pending_agents = {}
        self.pending_responses = {}
        self.pending_progress = {}
        self._agent_progress_hard_mult = hard_mult
        self.relayed = []

    async def _on_agent_registered(self, agent_id):
        pass

    async def _on_agent_telemetry(self, agent_id, rec, data):
        pass

    async def _relay_agent_msg_up(self, agent_id, msg_type, data):
        self.relayed.append((agent_id, msg_type, data))


class _CaptureWS:
    async def send(self, data):
        pass


class _FakeAgentWS:
    """Feeds the auth handshake then yields the post-auth frames under test."""

    def __init__(self, frames, agent_id="pxmx-test-agent"):
        import json
        self._recv = [
            json.dumps({"agent_id": agent_id, "secret": SECRET,
                        "install_uuid": "uuid-1", "hostname": "test-host"}),
            json.dumps({"status": "HUB_OK"}),
        ]
        self._frames = list(frames)

    async def recv(self):
        return self._recv.pop(0)

    async def send(self, data):
        pass

    async def close(self, code=1000, reason=""):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._frames:
            return self._frames.pop(0)
        raise StopAsyncIteration


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_progress_extends_deadline_so_late_response_succeeds():
    """Base timeout 0.2s; the response arrives ~0.5s in. Without keepalive that
    would time out — but simulated AGENT_PROGRESS frames keep pushing the soft
    deadline forward, so the late SUCCESS is returned."""
    host = _Host(SECRET)
    host.connected_agents = {"a1": {"ws": _CaptureWS()}}

    async def driver():
        await asyncio.sleep(0.02)
        corr = next(iter(host.pending_progress))
        # Emit "progress" three times before the base 0.2s window would elapse.
        for _ in range(3):
            await asyncio.sleep(0.12)
            pd = host.pending_progress.get(corr)
            assert pd is not None
            pd["soft"] = min(time.time() + pd["grace"], pd["hard"])
        fut = host.pending_responses.get(corr)
        if fut and not fut.done():
            fut.set_result({"status": "SUCCESS", "vms": ["v1", "v2"]})

    async def scenario():
        res, _ = await asyncio.gather(
            host.send_to_agent("RUN_COMMAND", {}, agent_id="a1", timeout=0.2),
            driver())
        return res

    res = _run(scenario())
    assert res.get("status") == "SUCCESS" and res.get("vms") == ["v1", "v2"]


def test_no_progress_times_out_at_base_window():
    """With no keepalive frames the behavior is the old fixed timeout: a slow
    agent that never responds nor reports progress times out promptly."""
    host = _Host(SECRET)
    host.connected_agents = {"a1": {"ws": _CaptureWS()}}

    start = time.time()
    res = _run(host.send_to_agent("RUN_COMMAND", {}, agent_id="a1", timeout=0.3))
    elapsed = time.time() - start

    assert res.get("status") == "ERROR" and "timeout" in res.get("message", "").lower()
    # Timed out near the base window, NOT the hard ceiling (0.3 * 6 = 1.8s).
    assert elapsed < 1.0


def test_hard_ceiling_bounds_a_hung_agent_even_with_progress():
    """A genuinely-hung agent that keeps reporting progress but never responds
    must still fail — the hard ceiling (base × mult) caps the extension."""
    host = _Host(SECRET, hard_mult=3.0)
    host.connected_agents = {"a1": {"ws": _CaptureWS()}}

    async def spammer():
        await asyncio.sleep(0.02)
        corr = next(iter(host.pending_progress))
        # Keep bumping forever — but never resolve the future.
        while corr in host.pending_progress:
            pd = host.pending_progress.get(corr)
            if pd:
                pd["soft"] = min(time.time() + pd["grace"], pd["hard"])
            await asyncio.sleep(0.05)

    async def scenario():
        start = time.time()
        res, _ = await asyncio.gather(
            host.send_to_agent("RUN_COMMAND", {}, agent_id="a1", timeout=0.2),
            spammer())
        return res, time.time() - start

    res, elapsed = _run(scenario())
    assert res.get("status") == "ERROR"
    # Failed at ~ the hard ceiling (0.2 * 3 = 0.6s), not extended forever.
    assert 0.4 < elapsed < 1.5


def test_agent_progress_frame_bumps_tracked_deadline():
    """The real AGENT_PROGRESS receive branch pushes the soft deadline forward
    for the matching corr_id (and never resolves the response future)."""
    host = _Host(SECRET)
    t0 = time.time()
    host.pending_progress = {"c9": {"soft": t0, "hard": t0 + 100.0, "grace": 5.0}}

    frame = encode_frame(MessageSigner(SECRET), {
        "header": {"correlation_id": "c9"},
        "payload": {"type": "AGENT_PROGRESS", "data": {"command": "GET_VM_LIST"}},
    })
    _run(host._agent_handler(_FakeAgentWS([frame]), path="/ws/agent"))

    assert host.pending_progress["c9"]["soft"] > t0
    # Progress must not fabricate a response.
    assert "c9" not in host.pending_responses
