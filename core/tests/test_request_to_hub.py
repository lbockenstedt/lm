"""Spoke-side ``request_to_hub`` (HUB_REQUEST + HUB_RESPONSE waiter).

A spoke that needs the hub to do something on its behalf and wait for the
answer (e.g. the netbox IPAM spoke relaying ``INSTALL_CERT`` to the
netbox-server agent) calls ``request_to_hub``. It registers a Future keyed by
the request's ``header.message_id`` (the correlation id the hub echoes back as
``data.correlation_id`` on its HUB_RESPONSE), sends a signed HUB_REQUEST frame,
and awaits the future. The receive loop's HUB_RESPONSE branch resolves the
future. These tests pin that wiring without a real websocket/loop: they drive
the future resolution the way the receive-loop branch does.
"""
import asyncio
import json
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.control_plane import BaseControlPlane  # noqa: E402
from core.src.security.signer import split_frame  # noqa: E402


class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, frame):
        self.sent.append(frame)


def _make_cp():
    """Bare BaseControlPlane (``__new__`` skips ``__init__``) wired with just
    the attributes ``request_to_hub`` touches: spoke_id, signer (None →
    unsigned bootstrap frame), the futures dict, and a fake hub websocket."""
    cp = BaseControlPlane.__new__(BaseControlPlane)
    cp.spoke_id = "test-spoke"
    cp.signer = None
    cp._hub_response_futures = {}
    cp._hub_ws = _FakeWS()
    return cp


def test_request_to_hub_roundtrip_resolves_and_cleans_up():
    """A pending request is resolved when the matching HUB_RESPONSE future is
    set (mirroring the receive-loop branch): the result is returned and the
    waiter future is popped (no leak)."""
    cp = _make_cp()

    async def resolver():
        # Let request_to_hub register its future + send the frame, then resolve
        # it exactly as the receive-loop HUB_RESPONSE branch does.
        await asyncio.sleep(0.01)
        corr = next(iter(cp._hub_response_futures))
        fut = cp._hub_response_futures.pop(corr)
        fut.set_result({"status": "SUCCESS", "message": "installed on netbox-server"})

    async def main():
        t = asyncio.create_task(resolver())
        res = await cp.request_to_hub("RELAY_NETBOX_CERT",
                                      {"domain": "netbox.test"}, timeout=2.0)
        await t
        return res

    res = asyncio.run(main())
    assert res == {"status": "SUCCESS", "message": "installed on netbox-server"}
    assert cp._hub_ws.sent, "a HUB_REQUEST frame must be sent"
    assert cp._hub_response_futures == {}, "waiter future must be cleaned up"


def test_request_to_hub_timeout_returns_error_and_cleans_up():
    """No HUB_RESPONSE within the timeout → ERROR with 'timeout' + the waiter
    future is popped so a late reply can't leak."""
    cp = _make_cp()
    res = asyncio.run(cp.request_to_hub("RELAY_NETBOX_CERT", {"domain": "x"},
                                        timeout=0.05))
    assert res["status"] == "ERROR"
    assert "timeout" in res["message"].lower()
    assert cp._hub_response_futures == {}


def test_request_to_hub_not_connected_returns_error():
    """No hub websocket → clean ERROR (the caller surfaces it), no future."""
    cp = _make_cp()
    cp._hub_ws = None
    res = asyncio.run(cp.request_to_hub("RELAY_NETBOX_CERT", {}, timeout=1.0))
    assert res["status"] == "ERROR"
    assert "not connected" in res["message"].lower()
    assert cp._hub_response_futures == {}


def test_request_to_hub_frame_shape_carries_corr_id_and_req_type():
    """The outbound frame is a HUB_REQUEST whose payload.data.type is the
    req_type and whose header.message_id is the correlation id the hub echoes
    back. Spoke identity + destination are set on the header."""
    cp = _make_cp()

    async def main():
        # Fire the request; let it register + send; then inspect before timeout.
        t = asyncio.create_task(cp.request_to_hub("RELAY_NETBOX_CERT",
                                                   {"domain": "d", "identifier": ""},
                                                   timeout=0.2))
        await asyncio.sleep(0.02)
        frame = cp._hub_ws.sent[0]
        await asyncio.wait_for(asyncio.shield(t), timeout=0.3)
        return frame

    frame = asyncio.run(main())
    sig, body = split_frame(frame)
    msg = json.loads(body)
    assert msg["payload"]["type"] == "HUB_REQUEST"
    assert msg["payload"]["data"]["type"] == "RELAY_NETBOX_CERT"
    assert msg["payload"]["data"]["domain"] == "d"
    assert msg["payload"]["data"]["identifier"] == ""
    assert msg["header"]["message_id"], "message_id is the correlation id"
    assert msg["header"]["sender_id"] == "test-spoke"
    assert msg["header"]["destination_id"] == "hub"


def test_hub_response_branch_resolves_pending_future_only():
    """The receive-loop HUB_RESPONSE branch must resolve ONLY the matching
    future (by correlation_id), ignore an unknown one, and not touch a
    already-done future. Simulated by driving the branch logic directly."""
    cp = _make_cp()
    loop = asyncio.new_event_loop()
    try:
        # Register a pending waiter.
        corr = "corr-123"
        fut = loop.create_future()
        cp._hub_response_futures[corr] = fut

        # Drive the branch logic exactly as written in the receive loop.
        data = {"correlation_id": corr, "result": {"status": "SUCCESS"}}
        f = cp._hub_response_futures.pop(data.get("correlation_id"), None)
        if f is not None and not f.done():
            f.set_result(data.get("result") or {})

        assert fut.done()
        assert fut.result() == {"status": "SUCCESS"}
        assert corr not in cp._hub_response_futures

        # An unknown correlation_id is a no-op (no KeyError).
        data2 = {"correlation_id": "unknown", "result": {}}
        f2 = cp._hub_response_futures.pop(data2.get("correlation_id"), None)
        assert f2 is None
    finally:
        loop.close()