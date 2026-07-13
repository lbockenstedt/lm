"""Regression: ``send_to_agent`` must set ``header.correlation_id`` so the
agent's ``AGENT_RESPONSE`` reply can be matched back to the pending future.

The bug (cert distribution, 2026-07): the LE cert installs on the Proxmox
node (pvenode writes pveproxy-ssl.pem), but the Certificates UI shows every
hypervisor / simulation target FAILED with "Agent response timeout" and the
ledger never settles → retry loop. Root cause: ``send_to_agent`` keyed its
pending future on ``corr_id`` and sent ``header.message_id = corr_id`` but
never ``header.correlation_id``; the agent reads ``header.correlation_id``
(→ None), echoes ``correlation_id: None`` in the reply, and the spoke's
``AGENT_RESPONSE`` branch looks up ``pending_responses[None]`` → no match →
the future never resolves → ``send_to_agent`` times out. The cert IS on disk
but the ack is ALWAYS lost, so the UI can never report SUCCESS.

This test drives the inherited ``_agent_handler`` with a fake agent WS that
receives the command, echoes the correlation_id it read, and replies; it
asserts ``send_to_agent`` resolves to the agent's reply (NOT a timeout).
"""
import asyncio
import json
import os
import sys
import time
import uuid

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402
from core.src.security.signer import MessageSigner, encode_frame, split_frame  # noqa: E402

SECRET = "test-agent-secret-correlation-12345"


class _Host(AgentHostingControlPlane):
    def __init__(self, secret):
        self.agent_secret = secret
        self.spoke_id = "test-cs-spoke"
        self.agent_signer = MessageSigner(secret)
        self.connected_agents = {}
        self.pending_agents = {}
        self.pending_responses = {}
        self.relayed = []
        self.telemetry = []
        self.control_plane = None

    async def _on_agent_registered(self, agent_id):
        pass

    async def _on_agent_telemetry(self, agent_id, rec, data):
        pass

    async def _relay_agent_msg_up(self, agent_id, msg_type, data):
        self.relayed.append((agent_id, msg_type, data))


class _ReplyAgentWS:
    """Fake agent websocket: completes the plain-JSON auth handshake, then on
    each spoke→agent ``send()`` of a signed command frame, extracts the
    ``correlation_id`` the spoke set and replies with an ``AGENT_RESPONSE``
    echoing that same ``correlation_id`` (exactly what the real pxmx agent
    does at agent.py:2801-2811)."""

    def __init__(self, secret, agent_id="pxmx-test-agent"):
        self._secret = secret
        self._agent_id = agent_id
        self._recv = [
            json.dumps({"agent_id": agent_id, "secret": SECRET,
                        "install_uuid": "uuid-corr", "hostname": "test-host"}),
            json.dumps({"status": "HUB_OK"}),
        ]
        self._frames = []  # post-auth agent→spoke frames (replies we craft)
        self.sent = []
        self.closed = None

    async def recv(self):
        return self._recv.pop(0)

    async def send(self, data):
        self.sent.append(data)
        if isinstance(data, str) and data[:1] == "{":
            return  # auth handshake frame (HUB_VERIFIED) — not a command
        # Signed <sig>.<body> command from send_to_agent: echo correlation_id.
        sig, body = split_frame(data)
        cmd = json.loads(body)
        corr = cmd.get("header", {}).get("correlation_id")
        reply = {
            "header": {
                "message_id": str(uuid.uuid4()),
                "correlation_id": corr,
                "timestamp": time.time(),
                "sender_id": self._agent_id,
                "destination_id": "pxmx-spoke",
            },
            "payload": {"type": "AGENT_RESPONSE",
                        "data": {"status": "SUCCESS", "message": "pong"}},
        }
        self._frames.append(encode_frame(MessageSigner(self._secret), reply))

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._frames:
            return self._frames.pop(0)
        # Keep the loop alive briefly so send_to_agent can run; the test wraps
        # the whole thing in a tight wait_for so this never hangs the suite.
        await asyncio.sleep(0.01)
        if self._frames:
            return self._frames.pop(0)
        raise StopAsyncIteration


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_send_to_agent_reply_resolves_via_correlation_id():
    """send_to_agent must resolve to the agent's AGENT_RESPONSE (echoed
    correlation_id), NOT time out with "Agent response timeout"."""
    async def _go():
        host = _Host(SECRET)
        ws = _ReplyAgentWS(SECRET)
        task = asyncio.create_task(host._agent_handler(ws, path="/ws/agent"))
        # wait for the agent to register
        for _ in range(100):
            if "pxmx-test-agent" in host.connected_agents:
                break
            await asyncio.sleep(0.01)
        assert "pxmx-test-agent" in host.connected_agents, "agent never registered"
        res = await host.send_to_agent("PING_TEST", {},
                                       agent_id="pxmx-test-agent", timeout=5.0)
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        return res

    res = _run(_go())
    assert isinstance(res, dict), f"expected reply dict, got {res!r}"
    assert res.get("status") == "SUCCESS", (
        f"send_to_agent did not resolve the agent's reply — got {res!r} "
        "(correlation_id mismatch → the reply was dropped → timeout)")
    assert res.get("message") == "pong"