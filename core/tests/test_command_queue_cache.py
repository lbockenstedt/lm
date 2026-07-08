"""``_cached_command_queue`` — the cache-first path for the VM Server → Command
Queue view.

The cs spoke includes ``command_queue`` in every ~10s ``CS_TELEMETRY`` frame,
which the hub stores at ``simulations_cache[spoke_id]``. The
``GET /sim/api/{tenant}/proxmx/commands`` route serves from that cache so the
page loads instantly instead of a live 15s ``request_response`` that stalls
when the spoke is busy (the every-5s "Request Timeout from cs-svr-02-spoke"
flood). This test pins the cache lookup's contract: a cached list is returned;
a missing entry or a non-list value returns None so the route falls back to the
live fetch rather than rendering a malformed queue.
"""

from simulations.routes import _cached_command_queue


class _Hub:
    """Minimal stub exposing only the ``simulations_cache`` attr the helper reads."""
    def __init__(self, cache):
        self.simulations_cache = cache


def test_cached_queue_returned():
    hub = _Hub({"cs-spoke-1": {"command_queue": [{"id": "a", "action": "start_vm"}]}})
    cq = _cached_command_queue(hub, "cs-spoke-1")
    assert cq == [{"id": "a", "action": "start_vm"}]


def test_missing_spoke_returns_none():
    # Cold start / spoke reconnecting — no cache entry for this spoke yet.
    hub = _Hub({"cs-spoke-1": {"command_queue": []}})
    assert _cached_command_queue(hub, "cs-spoke-2") is None


def test_missing_queue_key_returns_none():
    # The spoke is cached but its telemetry frame didn't carry command_queue.
    hub = _Hub({"cs-spoke-1": {"proxmox": {}}})
    assert _cached_command_queue(hub, "cs-spoke-1") is None


def test_non_list_queue_returns_none():
    # A malformed payload must not be served as a queue — fall back to live.
    hub = _Hub({"cs-spoke-1": {"command_queue": {"not": "a list"}}})
    assert _cached_command_queue(hub, "cs-spoke-1") is None


def test_empty_queue_is_returned_not_none():
    # An empty list is a valid cached state (no pending commands) — return it
    # so the route renders "Queue (0)" from cache instead of round-tripping.
    hub = _Hub({"cs-spoke-1": {"command_queue": []}})
    assert _cached_command_queue(hub, "cs-spoke-1") == []


def test_hub_without_simulations_cache_attr_returns_none():
    # A hub that never registered simulations routes (no attr) — degrade to None.
    hub = object()
    assert _cached_command_queue(hub, "cs-spoke-1") is None