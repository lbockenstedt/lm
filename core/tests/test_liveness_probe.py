"""App-layer HUB_PING/HUB_PONG liveness probe — the half-open zombie check.

``_install_active_connection`` probes an existing same-key connection with
``existing.ping()`` to distinguish a half-open zombie (no pong → evict) from a
live-but-paused spoke (pongs → keep). uvicorn owns WS-layer keepalive pings and
does NOT surface pong waiters to the application, so the probe is an
application-layer round trip: ``StarletteWSAdapter.ping()`` sends a signed
``HUB_PING`` (via a hub-armed probe sender) and returns a future that resolves
when the spoke's ``COMMAND_RESULT`` reply arrives; the hub's inbound dispatch
calls ``adapter.resolve_pong(nonce)``. These tests pin that contract.

The probe-decision logic itself (fresh last_seen → keep; stale + pong → keep;
stale + no pong → evict) is covered by test_signature_rotation_window.py.
"""
import asyncio
import uuid

import pytest

from core.src.api import StarletteWSAdapter
from core.src.messaging.control_plane import BaseControlPlane


class _FakeWS:
    """Bare-minimum stand-in for a Starlette WebSocket — only what the adapter
    touches in these tests (send_text/close + state/client props are NOT
    exercised by ping/resolve_pong)."""
    def __init__(self):
        self.sent = []
    async def send_text(self, data):
        self.sent.append(data)
    async def close(self, code=1000, reason=""):
        pass


def _adapter():
    return StarletteWSAdapter(_FakeWS())


# ── adapter.ping / resolve_pong ───────────────────────────────────────────────

async def test_ping_returns_waiter_that_resolves_on_pong():
    ad = _adapter()
    sent = []
    async def sender(nonce):
        sent.append(nonce)
    ad.set_probe_sender(sender)

    fut = await ad.ping()
    assert isinstance(fut, asyncio.Future)
    assert not fut.done()
    assert len(sent) == 1 and sent[0]  # nonce was sent

    ad.resolve_pong(sent[0])
    assert fut.done()
    assert fut.result() is None  # resolved (not cancelled)


async def test_ping_with_no_probe_sender_raises():
    ad = _adapter()  # no set_probe_sender
    with pytest.raises(ConnectionError):
        await ad.ping()


async def test_ping_send_failure_raises_and_strands_no_waiter():
    ad = _adapter()
    async def sender(nonce):
        raise ConnectionError("socket gone")
    ad.set_probe_sender(sender)
    with pytest.raises(ConnectionError):
        await ad.ping()
    # No waiter was registered (send failed first) → no leak.
    assert ad._pending_pongs == {}


async def test_close_cancels_pending_ping_waiters():
    ad = _adapter()
    async def sender(nonce):
        return None
    ad.set_probe_sender(sender)
    fut = await ad.ping()
    assert not fut.done()
    await ad.close(1008, "Replaced by newer connection")
    assert fut.cancelled()
    assert ad._pending_pongs == {}


async def test_resolve_pong_unknown_nonce_is_noop():
    ad = _adapter()
    # No ping outstanding → resolving a stray nonce must not raise.
    ad.resolve_pong(uuid.uuid4().hex)


async def test_resolve_pong_late_duplicate_is_noop():
    ad = _adapter()
    async def sender(nonce):
        return None
    ad.set_probe_sender(sender)
    fut = await ad.ping()
    ad.resolve_pong(sent_nonce := next(iter(ad._pending_pongs)))
    assert fut.done()
    # A second pong for the same nonce (dup/late) must not error.
    ad.resolve_pong(sent_nonce)


# ── spoke HUB_PING handler ────────────────────────────────────────────────────

async def test_spoke_handle_hub_ping_echoes_nonce():
    """handle_system_command replies SUCCESS + the echoed nonce so the hub can
    correlate the COMMAND_RESULT back to the ping waiter."""
    class _Self:
        pass  # HUB_PING branch returns before touching any other attribute
    res = await BaseControlPlane.handle_system_command(
        _Self(), "HUB_PING", {"nonce": "abc123"})
    assert res == {"status": "SUCCESS", "nonce": "abc123"}


async def test_spoke_handle_hub_ping_missing_nonce_returns_none():
    class _Self:
        pass
    res = await BaseControlPlane.handle_system_command(_Self(), "HUB_PING", {})
    assert res == {"status": "SUCCESS", "nonce": None}


# ── hub probe glue: _send_liveness_ping + dispatch resolution ─────────────────

class _ProbeHub:
    """Just the attributes _send_liveness_ping + the dispatch hook touch."""
    def __init__(self):
        self._pending_liveness_nonces = set()
        self.message_count = 0
        self.active_connections = {}
        self._send_calls = []

    async def send_to_spoke(self, msg):
        self._send_calls.append(msg)


async def test_send_liveness_ping_registers_nonce_and_signs():
    """_send_liveness_ping records the nonce in _pending_liveness_nonces and
    delegates to send_to_spoke (which signs with the spoke's key)."""
    from core.src import main as main_mod
    hub = _ProbeHub()
    # Bind the real method onto the fake hub.
    send = main_mod.LabManagerHub._send_liveness_ping.__get__(hub, type(hub))
    nonce = uuid.uuid4().hex
    await send("s1", nonce)
    assert nonce in hub._pending_liveness_nonces
    assert len(hub._send_calls) == 1
    msg = hub._send_calls[0]
    assert msg.payload.type == "HUB_PING"
    assert msg.payload.data == {"nonce": nonce}
    assert msg.header.message_id == nonce        # echoed as the reply corr_id
    assert msg.header.destination_id == "s1"


async def test_send_liveness_ping_discards_nonce_on_send_failure():
    from core.src import main as main_mod
    hub = _ProbeHub()
    async def _boom(msg):
        raise ConnectionError("down")
    hub.send_to_spoke = _boom
    send = main_mod.LabManagerHub._send_liveness_ping.__get__(hub, type(hub))
    nonce = uuid.uuid4().hex
    with pytest.raises(ConnectionError):
        await send("s1", nonce)
    assert hub._pending_liveness_nonces == set()  # rolled back, no orphan


async def test_dispatch_resolves_adapter_waiter_for_liveness_reply(monkeypatch):
    """End-to-end glue: a COMMAND_RESULT whose correlation_id is a pending
    liveness nonce resolves the active adapter's ping waiter (the branch added
    at the top of the correlation_id dispatch). Verifies the contract the
    inbound dispatch relies on."""
    ad = _adapter()
    async def sender(nonce):
        return None
    ad.set_probe_sender(sender)
    fut = await ad.ping()
    nonce = next(iter(ad._pending_pongs))

    hub = _ProbeHub()
    hub.active_connections["s1"] = ad
    hub._pending_liveness_nonces.add(nonce)

    # Replay the exact dispatch branch from handle_connection.
    corr_id = nonce
    if corr_id in hub._pending_liveness_nonces:
        hub._pending_liveness_nonces.discard(corr_id)
        adapter = hub.active_connections.get("s1")
        if adapter is not None and hasattr(adapter, "resolve_pong"):
            adapter.resolve_pong(corr_id)
        hub.message_count += 1

    assert fut.done() and not fut.cancelled()
    assert hub._pending_liveness_nonces == set()
    assert hub.message_count == 1