"""A reconnecting spoke must not stay "draining" for the full drain window.

The hub marks a spoke draining (DRAIN_WINDOW_S, 180s) when it pushes
SPOKE_UPDATE, and while draining every request_response short-circuits as
"Timed out waiting for spoke response". Only cs spokes ever reported
``draining: false``, so DHCP/DNS/hypervisor spokes looked dead for 3 minutes
after every hub restart even though they reconnected within seconds. A fresh
connection now clears the mark, unless the reconnect flush itself delivers a
new SPOKE_UPDATE.
"""
import asyncio
import time
import types

from main import LabManagerHub
from messaging.mailbox import Mailbox
from messaging.protocol import Message, MessageHeader, MessagePayload

SID = "8889182b-a4c5-58df-8456-d2fe1e048edd"


def _update(dest: str) -> Message:
    return Message(header=MessageHeader(message_id="u1", destination_id=dest),
                   payload=MessagePayload(type="SPOKE_UPDATE",
                                          data={"repo_url": "r", "branch": "main"}))


class _Hub:
    DRAIN_WINDOW_S = 180.0
    _drain_key = LabManagerHub._drain_key
    mark_draining = LabManagerHub.mark_draining
    is_draining = LabManagerHub.is_draining
    clear_draining = LabManagerHub.clear_draining
    _flush_spoke_backlog = LabManagerHub._flush_spoke_backlog

    def __init__(self, mailbox):
        self._draining_spokes = {}
        self._cs_connect_defer = {}
        self.mailbox = mailbox

    def _primary_key(self, sid):
        return sid

    async def send_to_spoke(self, msg, signing_secret=None):
        pass


def _conn():
    return types.SimpleNamespace(spoke_id=SID, pk=SID, mtls_enroll_only=False)


def test_reconnect_clears_drain_mark(tmp_path):
    hub = _Hub(Mailbox(state_dir=str(tmp_path)))
    hub.mark_draining(SID)

    asyncio.run(hub._flush_spoke_backlog(_conn()))

    assert not hub.is_draining(SID)


def test_reconnect_that_delivers_an_update_stays_draining(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    asyncio.run(mb.queue_for_spoke(SID, _update(SID)))
    hub = _Hub(mb)

    asyncio.run(hub._flush_spoke_backlog(_conn()))

    assert hub.is_draining(SID)


def test_deferred_update_does_not_count_as_delivered(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    asyncio.run(mb.queue_for_spoke(SID, _update(SID)))
    mb._spoke_update_delivered[f"{SID}|r|main"] = time.time()  # in cooldown
    hub = _Hub(mb)
    hub.mark_draining(SID)

    asyncio.run(hub._flush_spoke_backlog(_conn()))

    assert not hub.is_draining(SID)
    assert len(mb.spoke_queues[SID]) == 1  # still queued for later
