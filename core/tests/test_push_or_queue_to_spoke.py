"""LabManagerHub.push_or_queue_to_spoke — config-push routes (hub-config,
central-api, sim-conf, SET_AGENT_CONFIG, ...) used a bare request_response,
so a spoke that was approved+bound but momentarily unreachable (mid
self-update restart, brief reconnect blip) made the caller report "pushed to
0 spokes" even though the spoke was genuinely fine a few seconds earlier.

push_or_queue_to_spoke tries the live path first, and on failure — including
a request_response timeout, which means "no reply" not "rejected" — falls
back to mailbox.push, the same durable delivery SPOKE_UPDATE already uses:
persisted to disk, retried on backoff, delivered on reconnect.
"""
import asyncio

import main as main_module  # noqa: E402  (core/src on sys.path via conftest)
from main import LabManagerHub


class _FakeMailbox:
    def __init__(self):
        self.pushed = []

    async def push(self, message, send_func):
        self.pushed.append(message)


class _FakeHub:
    def __init__(self, request_response_result=None, request_response_exc=None):
        self.mailbox = _FakeMailbox()
        self._result = request_response_result
        self._exc = request_response_exc
        self.calls = []
        # Drain bookkeeping: the timeout fallback calls mark_draining so the hub
        # stops poking a spoke that didn't reply. Record calls so the test can
        # assert the fallback fires.
        self.drained = []

    def mark_draining(self, spoke_id, window=None):
        self.drained.append((spoke_id, window))

    async def request_response(self, spoke_id, command_type, data, timeout=5.0):
        self.calls.append((spoke_id, command_type, data, timeout))
        if self._exc:
            raise self._exc
        return self._result

    send_to_spoke = None  # never actually called; mailbox.push is faked


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_live_success_returns_result_not_queued():
    hub = _FakeHub(request_response_result={"status": "SUCCESS", "message": "ok"})

    outcome = _run(LabManagerHub.push_or_queue_to_spoke(
        hub, "cs-svr-02-spoke", "CS_CONFIG_UPDATE", {"usb_auto_provision": "on"}))

    assert outcome["status"] == "ok"
    assert outcome["queued"] is False
    assert outcome["result"]["status"] == "SUCCESS"
    assert hub.mailbox.pushed == []  # never fell back to the mailbox


def test_connection_error_falls_back_to_mailbox_queue():
    hub = _FakeHub(request_response_exc=ConnectionError("Spoke cs-svr-02-spoke is not connected"))

    outcome = _run(LabManagerHub.push_or_queue_to_spoke(
        hub, "cs-svr-02-spoke", "CS_CONFIG_UPDATE", {"usb_auto_provision": "on"}))

    assert outcome["status"] == "ok"
    assert outcome["queued"] is True
    assert len(hub.mailbox.pushed) == 1
    queued_msg = hub.mailbox.pushed[0]
    assert queued_msg.header.destination_id == "cs-svr-02-spoke"
    assert queued_msg.payload.type == "CS_CONFIG_UPDATE"
    assert queued_msg.payload.data == {"usb_auto_provision": "on"}


def test_timeout_shaped_reply_falls_back_to_mailbox_queue():
    # request_response's OWN timeout path returns a dict, not an exception —
    # this must still trigger the queue fallback (it means no reply arrived).
    hub = _FakeHub(request_response_result={
        "status": "ERROR", "message": "Timed out waiting for spoke response"})

    outcome = _run(LabManagerHub.push_or_queue_to_spoke(
        hub, "cs-svr-02-spoke", "CS_CONFIG_UPDATE", {"usb_auto_provision": "on"}))

    assert outcome["queued"] is True
    assert len(hub.mailbox.pushed) == 1
    # The timeout fallback also marks the spoke draining so the next push skips
    # the 5s live wait and queues directly (a missed drain signal).
    assert hub.drained == [("cs-svr-02-spoke", 90.0)]


def test_genuine_spoke_refusal_is_not_queued():
    # A real ERROR reply from the spoke (not a timeout) is a refusal, not an
    # unreachability signal — queuing it would just repeat the same rejection.
    hub = _FakeHub(request_response_result={"status": "ERROR", "message": "bad config: unknown key"})

    outcome = _run(LabManagerHub.push_or_queue_to_spoke(
        hub, "cs-svr-02-spoke", "CS_CONFIG_UPDATE", {"bogus": "1"}))

    assert outcome["queued"] is False
    assert outcome["result"]["status"] == "ERROR"
    assert hub.mailbox.pushed == []
