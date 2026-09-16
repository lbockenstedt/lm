"""LabManagerHub.request_response — skip live queries to a spoke that is mid
self-update (draining).

Background sync loops (discovery syncs, staleness sweep) and status polls call
``request_response`` on a fixed cadence. While a spoke is restarting on new
code they used to each SEND a query and wait the full timeout, logging a
"Timed out waiting for spoke response" ERROR per call — the "extra errors on
Update" flood. The guard short-circuits with an instant, timeout-shaped result
carrying an ``updating`` flag: no send, no wait, no ERROR log. The message text
is kept byte-identical to a real timeout so existing consumers
(push_or_queue's queue fallback, cs_bridge retry) are unaffected; the
``updating`` flag lets the API layer render an "update in progress" notice.
"""
import asyncio

from main import LabManagerHub


class _FakeHub:
    def __init__(self, draining):
        self._draining = draining
        self._default_request_timeout = 60.0
        self.sent = []

    def is_draining(self, spoke_id):
        return self._draining

    async def send_to_spoke(self, msg, signing_secret=None):
        # Reaching here means the guard did NOT short-circuit.
        self.sent.append((msg, signing_secret))
        raise RuntimeError("send-reached")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_draining_spoke_short_circuits_without_send():
    hub = _FakeHub(draining=True)

    result = _run(LabManagerHub.request_response(
        hub, "dns-role-spoke", "DNS_LIST", {}))

    assert result["status"] == "ERROR"
    assert result["updating"] is True
    assert result["draining"] is True
    # Byte-identical to a real timeout so push_or_queue / cs_bridge keep working.
    assert result["message"] == "Timed out waiting for spoke response"
    # No frame was ever put on the wire to the restarting spoke.
    assert hub.sent == []


def test_signing_secret_bypasses_guard_even_while_draining():
    """SPOKE_UPDATE_SESSION_KEY delivery (signed with the pre-rotation secret)
    MUST still reach an alive-but-draining spoke, so it bypasses the guard —
    proven here by the send path being reached (our fake raises there)."""
    hub = _FakeHub(draining=True)

    try:
        _run(LabManagerHub.request_response(
            hub, "dns-role-spoke", "SPOKE_UPDATE_SESSION_KEY", {},
            signing_secret="old-secret"))
    except RuntimeError as e:
        assert str(e) == "send-reached"
    else:
        raise AssertionError("guard should not short-circuit the signed path")

    assert len(hub.sent) == 1
