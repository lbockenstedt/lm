"""``StarletteWSAdapter`` — the websockets-lib → Starlette ``WebSocket`` shim
that lets ``LabManagerHub.handle_connection`` (and ``send_to_spoke``) run
unchanged on the unified :443 FastAPI/uvicorn ``/ws/spoke`` route.

The spoke protocol is JSON text only, so ``recv``/``send`` map to
``receive_text``/``send_text``; ``async for msg in ws:`` maps to a receive
loop that propagates ``WebSocketDisconnect`` (so ``handle_connection``'s
``except`` clean-close branch runs, matching the websockets-lib path). Sends
are serialized with an ``asyncio.Lock`` so the many hub background loops that
push to a given spoke can't interleave ASGI send frames.
"""

import asyncio

from starlette.websockets import WebSocketDisconnect

import api as api_mod  # noqa: E402  (conftest puts core/src on sys.path)


class _FakeStarletteWS:
    """Minimal Starlette ``WebSocket`` surface the adapter touches.

    ``receive_text`` returns queued incoming text, then raises
    ``WebSocketDisconnect`` once the queue drains (mirrors a client close).
    ``close`` records the (code, reason) the adapter asked for, and optionally
    raises to exercise the adapter's swallowing of close-time errors.
    """

    def __init__(self, incoming=(), client=("10.0.0.5", 5000), close_raises=False):
        self._incoming = list(incoming)
        self._client = client
        self._close_raises = close_raises
        self.sent = []
        self.closed = None  # (code, reason) once close() is called

    @property
    def client(self):
        return self._client

    async def receive_text(self):
        if self._incoming:
            return self._incoming.pop(0)
        # Queue drained → client closed the socket. Starlette raises
        # WebSocketDisconnect; the adapter must let it propagate.
        raise WebSocketDisconnect(1000, "client closed")

    async def send_text(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=""):
        if self._close_raises:
            raise RuntimeError("close failed")
        self.closed = (code, reason)


# ── recv / send round-trip ────────────────────────────────────────────────────

def test_adapter_recv_and_send_roundtrip():
    ws = _FakeStarletteWS(incoming=["hello"])
    adapter = api_mod.StarletteWSAdapter(ws)

    got = asyncio.get_event_loop().run_until_complete(adapter.recv())
    asyncio.get_event_loop().run_until_complete(adapter.send("reply"))

    assert got == "hello"
    assert ws.sent == ["reply"]


# ── remote_address ────────────────────────────────────────────────────────────

def test_adapter_remote_address_from_client_tuple():
    ws = _FakeStarletteWS(client=("10.0.0.7", 9001))
    adapter = api_mod.StarletteWSAdapter(ws)

    assert adapter.remote_address == ("10.0.0.7", 9001)


def test_adapter_remote_address_none_when_no_client():
    ws = _FakeStarletteWS(client=None)
    adapter = api_mod.StarletteWSAdapter(ws)

    assert adapter.remote_address is None


# ── close ─────────────────────────────────────────────────────────────────────

def test_adapter_close_records_code_and_reason():
    ws = _FakeStarletteWS()
    adapter = api_mod.StarletteWSAdapter(ws)

    asyncio.get_event_loop().run_until_complete(adapter.close(1001, "bye"))

    assert ws.closed == (1001, "bye")


def test_adapter_close_swallows_underlying_errors():
    # A close-time failure on the socket must not propagate out of the adapter
    # (handle_connection's finally/except must still complete cleanly).
    ws = _FakeStarletteWS(close_raises=True)
    adapter = api_mod.StarletteWSAdapter(ws)

    # Must not raise.
    asyncio.get_event_loop().run_until_complete(adapter.close(1000, ""))


# ── async-for ─────────────────────────────────────────────────────────────────

def test_adapter_aiter_yields_messages_then_disconnect_propagates():
    """``async for msg in adapter`` yields each queued text frame, then lets the
    underlying ``WebSocketDisconnect`` propagate (NOT converted to
    ``StopAsyncIteration``) so ``handle_connection``'s ``except`` clean-close
    branch runs — matching the websockets-lib path."""
    ws = _FakeStarletteWS(incoming=["a", "b"])
    adapter = api_mod.StarletteWSAdapter(ws)

    async def collect():
        out = []
        raised = None
        try:
            async for msg in adapter:  # noqa: B007
                out.append(msg)
        except WebSocketDisconnect as exc:
            raised = exc
        return out, raised

    out, raised = asyncio.get_event_loop().run_until_complete(collect())

    # The two queued frames were yielded before the disconnect surfaced.
    assert out == ["a", "b"]
    assert isinstance(raised, WebSocketDisconnect)


# ── send serialization ────────────────────────────────────────────────────────

def test_adapter_concurrent_sends_are_serialized_in_order():
    """Two sends awaited concurrently must both land and in order — the
    ``asyncio.Lock`` serializes the ASGI send frames so background hub loops
    can't interleave writes to the same spoke socket."""
    ws = _FakeStarletteWS()
    adapter = api_mod.StarletteWSAdapter(ws)

    async def run():
        await asyncio.gather(adapter.send("one"), adapter.send("two"))

    asyncio.get_event_loop().run_until_complete(run())

    assert ws.sent == ["one", "two"]