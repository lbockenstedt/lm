"""NW devices follow the tenant that finds them once their agent has moved.

A record whose nw agent now belongs to another tenant (or was deleted) is
"unanchored". A verified sighting by another tenant moves it: a scan seeing the
same IP + hostname (or the same agent at that IP), the moved agent reaching it
with a matching hostname/serial, or another record polling the same chassis
serial. Anchored records never move, so two tenants seeing one box can't bounce it.
"""
import asyncio

from nw_discovery_sync import NwDiscoverySyncMixin
from _fakes import FakeState


class _Hub(NwDiscoverySyncMixin):
    def __init__(self, devices, spokes, identity=None):
        self.state = FakeState(system_state={
            "global_config": {"nw_devices": devices},
            "module_metadata": {sid: {"tenant_id": t} for sid, t in spokes.items()}})
        self._identity = identity or {}
        self.pushed = []

    def nw_cache_get_device(self, did, endpoint):
        info = self._identity.get(did)
        return {"data": info} if info and endpoint == "info" else None

    async def nw_push_fleet(self, sid):
        self.pushed.append(sid)


def _dev(i, tenant, spoke, name="SW1", addr="10.0.0.1", **kw):
    return dict({"id": i, "tenant_id": tenant, "spoke_id": spoke, "name": name,
                 "address": addr, "object_type": "cx_switch",
                 "vault_credential": {"bucket": tenant, "name": "old"}}, **kw)


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def test_scan_moves_unanchored_device_on_ip_and_hostname():
    d = _dev("a", "old", "agent1")
    hub = _Hub([d], {"agent1": "new"})
    hit = hub.nw_find_relocation([d], "new", "agent1", "10.0.0.1", "sw1.lab.local", "cx_switch")
    assert hit and hit[1] == ["ip", "hostname"]
    hub.nw_relocate_device(d, "new", "agent1", hit[1],
                           {"vault_credential": {"bucket": "new", "name": "c"}, "username": "admin"})
    assert d["tenant_id"] == "new" and d["vault_credential"]["bucket"] == "new"
    assert d["moved_from"]["tenant_id"] == "old"


def test_scan_same_agent_same_ip_without_name():
    d = _dev("a", "old", "agent1")
    hub = _Hub([d], {"agent1": "new"})
    assert hub.nw_find_relocation([d], "new", "agent1", "10.0.0.1", "", "")[1] == ["ip", "same agent"]


def test_anchored_or_unverified_devices_never_move():
    anchored = _dev("a", "old", "agent1")
    hub = _Hub([anchored], {"agent1": "old", "agent2": "new"})
    assert hub.nw_find_relocation([anchored], "new", "agent2", "10.0.0.1", "SW1") is None
    loose = _dev("b", "old", "gone-agent")
    hub = _Hub([loose], {"agent2": "new"})
    # IP alone from a different agent (tenants overlap address space) is not enough.
    assert hub.nw_find_relocation([loose], "new", "agent2", "10.0.0.1", "OTHER") is None
    assert hub.nw_find_relocation([loose], "new", "agent2", "10.0.0.1", "SW1")
    shared = _dev("c", "shared", "gone-agent")
    assert not _Hub([shared], {}).nw_relocatable(shared, "new")


def test_poll_by_moved_agent_relocates_record():
    d = _dev("a", "old", "agent1")
    hub = _Hub([d], {"agent1": "new"})
    moves = _run(hub.nw_reconcile_tenant_after_poll(
        d, {"hostname": "SW1", "serial": "S1"}, True, {"serial": "S1"}))
    assert d["tenant_id"] == "new" and moves[0]["evidence"] == ["ip", "serial", "agent"]
    assert "agent1" in hub.pushed
    unreachable = _dev("b", "old", "agent1")
    hub = _Hub([unreachable], {"agent1": "new"})
    assert _run(hub.nw_reconcile_tenant_after_poll(unreachable, {"hostname": "SW1"}, False)) == []
    assert unreachable["tenant_id"] == "old"


def test_poll_serial_match_folds_stale_record_from_other_tenant():
    stale = _dev("old-row", "old", "gone-agent", addr="10.0.0.1")
    live = _dev("new-row", "new", "agent2", addr="10.9.0.1", name="SW1-renamed")
    hub = _Hub([stale, live], {"agent2": "new"}, identity={"old-row": {"serial": "S1"}})
    moves = _run(hub.nw_reconcile_tenant_after_poll(live, {"serial": "s1"}, True))
    devs = hub.state.system_state["global_config"]["nw_devices"]
    assert [x["id"] for x in devs] == ["new-row"]
    assert live["alt_addresses"] == ["10.0.0.1"] and moves[0]["merged_into"] == "new-row"
