"""Hub drain state must survive the connect-id ↔ guid alias split.

A cs spoke connects as ``cs-svr-01`` but its hub state is keyed by its guid
(``spoke_id_alias``). The push fan-out marks drain by guid while CS_TELEMETRY
ingest clears it by the raw connect-id; before normalizing via ``_primary_key``
the clear never matched, and push_or_queue re-armed the 90s window on its own
draining short-circuit every 45s reconcile tick — the cs spoke was skipped by
every live request (quota state, pxmx-site-map) indefinitely.
"""
import asyncio
import time

from main import LabManagerHub

GUID = "a1e70438-3b71-4c59-8074-734443d2625a"


class _Hub:
    DRAIN_WINDOW_S = 90.0
    _drain_key = LabManagerHub._drain_key
    mark_draining = LabManagerHub.mark_draining
    is_draining = LabManagerHub.is_draining
    clear_draining = LabManagerHub.clear_draining
    push_or_queue_to_spoke = LabManagerHub.push_or_queue_to_spoke

    def __init__(self):
        self._draining_spokes = {}
        self.spoke_id_alias = {"cs-svr-01": GUID}
        self.pushed = []

        class _MB:
            async def push(_s, msg, send):
                self.pushed.append(msg)
        self.mailbox = _MB()

    def _primary_key(self, sid):
        return self.spoke_id_alias.get(sid, sid)

    async def request_response(self, spoke_id, command_type, data, timeout=None):
        if self.is_draining(spoke_id):
            return {"status": "ERROR", "message": "Timed out waiting for spoke response",
                    "updating": True, "draining": True}
        return {"status": "SUCCESS"}

    async def send_to_spoke(self, msg, signing_secret=None):
        pass


def test_raw_id_clear_drops_guid_mark():
    hub = _Hub()
    hub.mark_draining(GUID)
    assert hub.is_draining("cs-svr-01")
    hub.clear_draining("cs-svr-01")
    assert not hub.is_draining(GUID)


def test_raw_id_mark_seen_by_guid():
    hub = _Hub()
    hub.mark_draining("cs-svr-01")
    assert hub.is_draining(GUID)


def test_draining_short_circuit_does_not_rearm_window():
    hub = _Hub()
    hub.mark_draining(GUID, window=5.0)
    until = hub._draining_spokes[GUID]
    res = asyncio.new_event_loop().run_until_complete(
        hub.push_or_queue_to_spoke(GUID, "CS_CONFIG_UPDATE", {}))
    assert res["queued"] is True
    # The short-circuit queued it but must NOT extend the drain window to 90s.
    assert hub._draining_spokes[GUID] == until
    assert until < time.time() + 10


def test_real_timeout_still_marks_draining():
    hub = _Hub()

    async def _timeout(*a, **k):
        return {"status": "ERROR", "message": "Timed out waiting for spoke response"}
    hub.request_response = _timeout
    asyncio.new_event_loop().run_until_complete(
        hub.push_or_queue_to_spoke("cs-svr-01", "CS_CONFIG_UPDATE", {}))
    assert hub.is_draining(GUID)
