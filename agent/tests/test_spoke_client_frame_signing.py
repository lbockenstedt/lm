"""The device-mode agent runs RUN_COMMAND / WRITE_FILE as root, so after the
handshake it must dispatch only frames signed with its own secret. An unsigned
frame, a frame signed with another key, or any frame while the agent holds no
secret is dropped without dispatch or reply.
"""
import asyncio
import json

import pytest

from spoke_client import SpokeClient

try:
    from core.src.security.signer import MessageSigner, encode_frame
except ImportError:
    from security.signer import MessageSigner, encode_frame


class _WS:
    """Fake websocket that records what the agent sends back."""

    def __init__(self):
        """Start with no sent frames."""
        self.sent = []

    async def send(self, data):
        """Record one outgoing frame."""
        self.sent.append(data)


def _client(tmp_path, secret="s3cret"):
    """Build a device-mode agent with its secret files under tmp_path."""
    return SpokeClient(
        "dev-1", "wss://spoke:443", secret=secret,
        secret_path=str(tmp_path / "secret"),
        install_uuid_path=str(tmp_path / "install-uuid"),
    )


_MSG = {"header": {"correlation_id": "c1"},
        "payload": {"type": "RUN_COMMAND", "data": {"command": "id"}}}


def _run(client, wire):
    """Feed one wire frame to the agent; return (dispatched cmds, ws)."""
    seen = []

    async def _fake_dispatch(cmd, data):
        """Record the dispatch instead of running anything."""
        seen.append(cmd)
        return {"status": "SUCCESS"}

    client._dispatch = _fake_dispatch
    ws = _WS()
    asyncio.run(client._handle_frame(ws, wire))
    return seen, ws


@pytest.mark.parametrize("wire", [
    json.dumps(_MSG, separators=(",", ":")),          # raw JSON, no separator
    "." + json.dumps(_MSG, separators=(",", ":")),    # explicit empty signature
    encode_frame(MessageSigner("attacker-key"), _MSG),  # signed with another key
])
def test_unsigned_or_foreign_frames_are_not_dispatched(tmp_path, wire):
    seen, ws = _run(_client(tmp_path), wire)
    assert seen == [] and ws.sent == []


def test_frame_dropped_when_agent_has_no_secret(tmp_path):
    # An empty-key signature must not authenticate anything.
    seen, ws = _run(_client(tmp_path, secret=""), encode_frame(MessageSigner(""), _MSG))
    assert seen == [] and ws.sent == []


def test_validly_signed_frame_is_dispatched_and_answered(tmp_path):
    c = _client(tmp_path)
    seen, ws = _run(c, encode_frame(c.signer, _MSG))
    assert seen == ["RUN_COMMAND"]
    assert len(ws.sent) == 1 and json.loads(ws.sent[0].split(".", 1)[1])[
        "payload"]["type"] == "AGENT_RESPONSE"
