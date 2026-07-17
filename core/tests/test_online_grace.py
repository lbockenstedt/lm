"""Display online/offline uses a last_seen GRACE window, not instantaneous WS
membership — so a transient loop stall / brief reconnect never flips a module
offline; only genuine long absence does. (hub.is_spoke_in_contact / spokes_in_contact)"""
import time
import types

from _fakes import FakeState
import main

Hub = main.LabManagerHub


class _HB:
    def __init__(self, last_seen):
        self.last_seen = last_seen


class _Stub:
    pass


def _make(active, last_seen, grace=180):
    h = _Stub()
    h.state = FakeState(global_config={"display": {"online_grace_s": grace}})
    h.active_connections = {sid: object() for sid in active}
    h.heartbeat = _HB(last_seen)
    h.spoke_id_alias = {}  # Phase 2: is_spoke_in_contact resolves via _primary_key
    for n in ("_online_grace_s", "is_spoke_in_contact", "spokes_in_contact", "_primary_key"):
        setattr(h, n, types.MethodType(getattr(Hub, n), h))
    return h


def test_connected_is_in_contact():
    h = _make(active=["a"], last_seen={})
    assert h.is_spoke_in_contact("a") is True


def test_recently_seen_but_disconnected_is_still_online():
    # dropped 5s ago (transient stall / reconnect) → still online within grace
    h = _make(active=[], last_seen={"a": time.time() - 5}, grace=180)
    assert h.is_spoke_in_contact("a") is True
    assert "a" in h.spokes_in_contact()


def test_long_absence_reads_offline():
    h = _make(active=[], last_seen={"a": time.time() - 500}, grace=180)
    assert h.is_spoke_in_contact("a") is False
    assert "a" not in h.spokes_in_contact()


def test_never_seen_is_offline():
    h = _make(active=[], last_seen={})
    assert h.is_spoke_in_contact("ghost") is False


def test_grace_is_configurable():
    ls = {"a": time.time() - 30}
    assert _make([], ls, grace=10).is_spoke_in_contact("a") is False   # 30s > 10s grace
    assert _make([], ls, grace=60).is_spoke_in_contact("a") is True    # 30s < 60s grace
