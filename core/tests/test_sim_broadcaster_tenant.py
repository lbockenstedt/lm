"""SimulationsBroadcaster sends a frame to the sockets of its tenant as the
access checks compare tenant ids (access.same_tenant). A socket subscribes
under its session's tenant id and a frame arrives under the spoke's tag, so a
raw key lookup sent a socket subscribed as "ACME" nothing tagged "acme"."""
import asyncio

import pytest

import access
from simulations.broadcaster import SimulationsBroadcaster


class _Sock:
    """A WebUI socket that records the frames sent to it."""

    def __init__(self):
        """Start with no frames."""
        self.sent = []

    async def send_json(self, message):
        """Record one frame."""
        self.sent.append(message)


def _frames(subscribed_as, tagged):
    """How many frames a socket subscribed under ``subscribed_as`` gets from
    one broadcast tagged ``tagged``."""
    b, ws = SimulationsBroadcaster(), _Sock()
    b.subscribe(ws, subscribed_as)
    asyncio.run(b.broadcast("spoke-1", {"x": 1}, tagged))
    return len(ws.sent)


@pytest.fixture
def twins(monkeypatch):
    """Set which tenant ids have legacy twins (none unless a test says so)."""
    def _set(*ids):
        """Mark ``ids`` (casefolded) as shared by tenants spelt differently."""
        monkeypatch.setattr(access, "_AMBIGUOUS_TENANT_IDS", frozenset(ids))
    _set()
    return _set


def test_a_socket_gets_its_tenants_frames_in_any_spelling(twins):
    assert _frames("ACME", "acme") == 1
    assert _frames(" acme", "ACME") == 1
    assert _frames("ACME", "beta") == 0


def test_twins_get_only_their_own_frames(twins):
    twins("acme")
    assert _frames("ACME", "acme") == 0
    assert _frames("acme", "acme") == 1


def test_a_frame_with_a_blank_tenant_reaches_nobody(twins):
    """A blank id names no tenant, so a socket with none gets nothing."""
    assert _frames("", "  ") == 0
    assert _frames(None, None) == 0
