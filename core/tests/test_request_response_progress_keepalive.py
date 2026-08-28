"""Keepalive extension for the hub's request_response waiter (hub↔spoke hop).

A spoke servicing a slow command emits SPOKE_PROGRESS frames whose
correlation_id == the hub's request msg_id. The hub bumps that request's soft
deadline (capped by a hard ceiling) instead of logging ``Request Timeout`` at
the base window. These tests bind the REAL ``request_response`` to a minimal hub
stub (transport stubbed) and assert: progress extends the wait so a late reply
succeeds, no progress honors the base timeout, and the hard ceiling still bounds
a hung spoke.
"""
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import main  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Hub:
    def __init__(self, hard_mult=6.0):
        self.response_cache = {}
        self._outstanding_requests = set()
        self._progress_deadlines = {}
        self._recent_request_timeouts = {}
        self._RECENT_TIMEOUT_TTL = 30
        self._request_timeouts_total = 0
        self._request_progress_hard_mult = hard_mult
        self.sent = []
        self.request_response = main.LabManagerHub.request_response.__get__(self)
        # request_response now updates the durable agent->role registry for
        # every settled command. Borrow the real hook: it early-returns for
        # anything that isn't LOAD_ROLE/UNLOAD_ROLE (all of these tests), and
        # is fail-open, so it can't perturb the timeout behaviour under test.
        self._track_role_rpc = main.LabManagerHub._track_role_rpc.__get__(self)

    async def send_to_spoke(self, msg, signing_secret=None):
        self.sent.append(msg)

    def _spoke_label(self, sid):
        return sid

    def _prune_recent_timeouts(self):
        pass


def test_spoke_progress_extends_deadline_for_late_reply():
    hub = _Hub()

    async def driver():
        await asyncio.sleep(0.02)
        msg_id = next(iter(hub._progress_deadlines))
        # Simulate SPOKE_PROGRESS arriving before the base 0.2s window elapses.
        for _ in range(3):
            await asyncio.sleep(0.12)
            pd = hub._progress_deadlines.get(msg_id)
            assert pd is not None
            pd["soft"] = min(time.time() + pd["grace"], pd["hard"])
        hub.response_cache[msg_id] = {"status": "SUCCESS", "nodes": 42}

    async def scenario():
        res, _ = await asyncio.gather(
            hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=0.2),
            driver())
        return res

    res = _run(scenario())
    assert res.get("status") == "SUCCESS" and res.get("nodes") == 42


def test_no_progress_honors_base_timeout():
    hub = _Hub()
    start = time.time()
    res = _run(hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=0.3))
    elapsed = time.time() - start

    assert res.get("status") == "ERROR"
    assert hub._request_timeouts_total == 1
    assert elapsed < 1.0  # base window, not the 1.8s hard ceiling


def test_hard_ceiling_bounds_a_hung_spoke():
    hub = _Hub(hard_mult=3.0)

    async def spammer():
        await asyncio.sleep(0.02)
        msg_id = next(iter(hub._progress_deadlines))
        while msg_id in hub._progress_deadlines:
            pd = hub._progress_deadlines.get(msg_id)
            if pd:
                pd["soft"] = min(time.time() + pd["grace"], pd["hard"])
            await asyncio.sleep(0.05)

    async def scenario():
        start = time.time()
        res, _ = await asyncio.gather(
            hub.request_response("spoke-1", "GET_NODE_STATS", {}, timeout=0.2),
            spammer())
        return res, time.time() - start

    res, elapsed = _run(scenario())
    assert res.get("status") == "ERROR"
    assert 0.4 < elapsed < 1.5  # ~ hard ceiling (0.2 * 3), not forever


def test_default_base_timeout_is_cloud_generous():
    """Regression: the request_response base window defaults to the fleet
    default (env LM_REQUEST_DEFAULT_TIMEOUT_S, 60s) when a caller omits
    ``timeout=`` — NOT the old 5s. 5s was below the 8s SPOKE_PROGRESS interval,
    so keepalive commands called with the default could never emit a heartbeat
    before the base deadline fired, and a live-but-busy spoke on a cloud fleet
    was killed at 5s. A disconnected spoke still fails fast (send_to_spoke
    raises), so the larger default only extends patience for a slow-but-live
    spoke."""
    hub = _Hub()
    hub._default_request_timeout = 60.0

    async def scenario():
        # Reply lands at ~0.05s; capture the base soft deadline the waiter set.
        async def reply():
            await asyncio.sleep(0.05)
            msg_id = next(iter(hub._progress_deadlines))
            pd = hub._progress_deadlines[msg_id]
            # No SPOKE_PROGRESS was sent, so soft is purely the base window.
            assert pd["grace"] == 60.0
            assert pd["soft"] - pd["hard"] < 0  # hard = base * mult > soft
            hub.response_cache[msg_id] = {"status": "SUCCESS"}

        res, _ = await asyncio.gather(
            hub.request_response("spoke-1", "PXMX_LIST_VMS", {}), reply())
        return res

    assert _run(scenario()).get("status") == "SUCCESS"
