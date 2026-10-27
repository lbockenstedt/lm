"""R1: request_response wakes on its reply instead of polling every 100ms.

These bind the REAL ``request_response`` and the REAL ``_route_spoke_reply``
(the delivery path every spoke reply goes through) to a minimal hub stub, so
what is under test is the actual hand-off between them:

* a reply wakes the waiter at once (the old loop always slept >= 100ms first);
* a reply processed WHILE send_to_spoke is still awaiting is no longer lost
  (the old code registered the request only after the send, so that reply
  was dropped as an "unknown ack" and the caller waited out the timeout);
* SPOKE_PROGRESS keepalives still extend the deadline, and the hard ceiling
  still bounds it;
* late and duplicate replies are dropped without leaking a cache entry;
* timeout, cancellation and a failed send all leave no bookkeeping behind;
* many concurrent requests each get their own reply;
* a writer that fills response_cache without the event is still picked up
  by the 1s fallback poll.
"""
import asyncio
import os
import random
import sys
import time
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import main  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Mailbox:
    def __init__(self):
        self.acks = []

    async def acknowledge(self, ack):
        self.acks.append(ack.correlation_id)


class _Hub:
    """Just the state request_response + _route_spoke_reply touch."""

    def __init__(self, hard_mult=6.0):
        self.response_cache = {}
        self._outstanding_requests = set()
        self._progress_deadlines = {}
        self._response_waiters = {}
        self._recent_request_timeouts = {}
        self._RECENT_TIMEOUT_TTL = 30
        self._request_timeouts_total = 0
        self._request_progress_hard_mult = hard_mult
        self._pending_liveness_nonces = set()
        self._pending_broadcast_ids = {}
        self.active_connections = {}
        self.spoke_versions = {}
        self.spoke_commits = {}
        self.message_count = 0
        self.mailbox = _Mailbox()
        self.sent = []
        self.on_send = None  # optional async hook(msg) run inside send_to_spoke
        self.is_draining = lambda sid: False
        self._clear_drain_on_update_reply = lambda sid, corr_id, reply: None
        bind = lambda name: getattr(main.LabManagerHub, name).__get__(self)
        self.request_response = bind("request_response")
        self._route_spoke_reply = bind("_route_spoke_reply")
        self._track_role_rpc = bind("_track_role_rpc")

    async def send_to_spoke(self, msg, signing_secret=None):
        self.sent.append(msg)
        if self.on_send:
            await self.on_send(msg)

    def _spoke_label(self, sid):
        return sid

    def _prune_recent_timeouts(self):
        pass

    # Deliver a frame through the real reply router, as handle_connection does.
    async def deliver(self, corr_id, ptype="COMMAND_RESULT", data=None):
        conn = types.SimpleNamespace(spoke_id="spoke-1", pk="spoke-1", peer_ip="10.0.0.1")
        payload = {"type": ptype, "data": data if data is not None else {"status": "SUCCESS"}}
        msg_data = {"correlation_id": corr_id, "payload": payload}
        await self._route_spoke_reply(conn, msg_data, payload)

    def assert_clean(self):
        assert self._outstanding_requests == set()
        assert self._progress_deadlines == {}
        assert self._response_waiters == {}
        assert self.response_cache == {}


def test_reply_wakes_waiter_immediately():
    hub = _Hub()

    async def reply_soon(msg):
        async def later():
            await asyncio.sleep(0.005)
            await hub.deliver(msg.header.message_id, data={"status": "SUCCESS", "n": 1})
        asyncio.ensure_future(later())
    hub.on_send = reply_soon

    async def scenario():
        t0 = time.monotonic()
        res = await hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=5)
        return res, time.monotonic() - t0

    res, elapsed = _run(scenario())
    assert res["payload"]["data"]["n"] == 1
    # Old loop: never under 100ms. Event wake: about the 5ms reply delay.
    assert elapsed < 0.08, elapsed
    hub.assert_clean()


def test_reply_processed_during_send_is_not_lost():
    """The spoke's reply is routed while send_to_spoke is still awaiting
    (the socket write yielded). The request must already be registered."""
    hub = _Hub()

    async def reply_inside_send(msg):
        await hub.deliver(msg.header.message_id, data={"status": "SUCCESS", "fast": True})
    hub.on_send = reply_inside_send

    async def scenario():
        t0 = time.monotonic()
        res = await hub.request_response("spoke-1", "GET_AGENTS", {}, timeout=0.5)
        return res, time.monotonic() - t0

    res, elapsed = _run(scenario())
    assert res.get("payload", {}).get("data", {}).get("fast") is True, res
    assert elapsed < 0.08
    assert hub.mailbox.acks == []  # not misrouted as an unknown ack
    assert hub._request_timeouts_total == 0
    hub.assert_clean()


def test_spoke_progress_extends_then_reply_wakes():
    hub = _Hub()

    async def scenario():
        task = asyncio.ensure_future(
            hub.request_response("spoke-1", "PXMX_LIST_VMS", {}, timeout=0.2))
        await asyncio.sleep(0.01)
        mid = hub.sent[0].header.message_id
        for _ in range(3):  # keepalives carry it well past the 0.2s base
            await asyncio.sleep(0.12)
            await hub.deliver(mid, ptype="SPOKE_PROGRESS", data={})
        t_reply = time.monotonic()
        await hub.deliver(mid, data={"status": "SUCCESS", "vms": [1, 2]})
        res = await task
        return res, time.monotonic() - t_reply

    res, wake = _run(scenario())
    assert res["payload"]["data"]["vms"] == [1, 2]
    assert wake < 0.05
    assert hub._request_timeouts_total == 0
    hub.assert_clean()


def test_hard_ceiling_still_bounds_keepalives():
    hub = _Hub(hard_mult=3.0)

    async def scenario():
        t0 = time.monotonic()
        task = asyncio.ensure_future(
            hub.request_response("spoke-1", "PXMX_LIST_VMS", {}, timeout=0.2))
        await asyncio.sleep(0.01)
        mid = hub.sent[0].header.message_id
        while not task.done():
            await hub.deliver(mid, ptype="SPOKE_PROGRESS", data={})
            await asyncio.sleep(0.05)
        return await task, time.monotonic() - t0

    res, elapsed = _run(scenario())
    assert res["status"] == "ERROR"
    assert 0.5 < elapsed < 0.9, elapsed  # hard = 0.2 * 3
    hub.assert_clean()


def test_timeout_then_late_reply_is_dropped_without_leak():
    hub = _Hub()

    async def scenario():
        res = await hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=0.1)
        mid = hub.sent[0].header.message_id
        assert mid in hub._recent_request_timeouts
        await hub.deliver(mid)  # arrives after the waiter gave up
        return res, mid

    res, mid = _run(scenario())
    assert res == {"status": "ERROR", "message": "Timed out waiting for spoke response"}
    assert hub._request_timeouts_total == 1
    assert mid not in hub._recent_request_timeouts  # classified as late
    assert hub.mailbox.acks == []  # not an "unknown message ID" warning
    hub.assert_clean()


def test_duplicate_reply_after_settle_does_not_leak():
    hub = _Hub()

    async def reply_twice(msg):
        async def later():
            await asyncio.sleep(0.005)
            await hub.deliver(msg.header.message_id)
        asyncio.ensure_future(later())
    hub.on_send = reply_twice

    async def scenario():
        res = await hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=1)
        await hub.deliver(hub.sent[0].header.message_id)  # duplicate
        return res

    assert _run(scenario())["payload"]["data"]["status"] == "SUCCESS"
    hub.assert_clean()


def test_cancelled_waiter_cleans_up():
    hub = _Hub()

    async def scenario():
        task = asyncio.ensure_future(
            hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=5))
        await asyncio.sleep(0.02)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return hub.sent[0].header.message_id

    mid = _run(scenario())
    assert mid in hub._recent_request_timeouts  # a late reply logs as "late"
    hub.assert_clean()


def test_failed_send_raises_and_cleans_up():
    hub = _Hub()

    async def boom(msg):
        raise ConnectionError("Spoke spoke-1 is not connected")
    hub.on_send = boom

    try:
        _run(hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=1))
    except ConnectionError:
        pass
    else:
        raise AssertionError("send failure must still raise to the caller")
    assert hub._recent_request_timeouts == {}
    assert hub._request_timeouts_total == 0
    hub.assert_clean()


def test_many_concurrent_requests_each_get_their_own_reply():
    hub = _Hub()
    rng = random.Random(7)

    async def reply_random(msg):
        async def later():
            await asyncio.sleep(rng.uniform(0, 0.03))
            await hub.deliver(msg.header.message_id,
                              data={"status": "SUCCESS", "echo": msg.payload.data["i"]})
        asyncio.ensure_future(later())
    hub.on_send = reply_random

    async def scenario():
        t0 = time.monotonic()
        res = await asyncio.gather(*[
            hub.request_response("spoke-1", "GET_NODE_STATS", {"i": i}, timeout=2)
            for i in range(200)])
        return res, time.monotonic() - t0

    res, elapsed = _run(scenario())
    assert [r["payload"]["data"]["echo"] for r in res] == list(range(200))
    assert elapsed < 0.5, elapsed
    hub.assert_clean()


def test_cache_written_without_event_is_found_by_fallback_poll():
    """Writers that fill response_cache directly (test harnesses) still work:
    the waiter re-checks the cache at least every _RESPONSE_FALLBACK_POLL_S."""
    hub = _Hub()

    async def scenario():
        task = asyncio.ensure_future(
            hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=5))
        await asyncio.sleep(0.02)
        hub.response_cache[hub.sent[0].header.message_id] = {"status": "SUCCESS"}
        t0 = time.monotonic()
        res = await task
        return res, time.monotonic() - t0

    res, waited = _run(scenario())
    assert res == {"status": "SUCCESS"}
    assert waited <= main._RESPONSE_FALLBACK_POLL_S + 0.2
    hub.assert_clean()


def test_unrelated_reply_still_goes_to_mailbox():
    """A correlation id nobody is waiting for is unchanged: mailbox ack."""
    hub = _Hub()
    _run(hub.deliver("not-a-request"))
    assert hub.mailbox.acks == ["not-a-request"]
    assert hub.response_cache == {}
