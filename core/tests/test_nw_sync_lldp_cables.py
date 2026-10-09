"""``_nw_sync_lldp_cables`` — write LLDP's live truth into NetBox as real
``dcim.cable`` rows via ``NETBOX_SYNC_CABLE``.

This is the write-back half of NetBox cable modelling: ``build_topology``
already reads NetBox cables as a link source (see ``test_nw_topology.py``);
this is what makes a FRESH LLDP adjacency discovered on a scan show up as a
NetBox cable on the NEXT scan too, instead of only ever living in nw's
in-memory LLDP cache.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.nw import _nw_sync_lldp_cables  # noqa: E402


class _FakeHub:
    def __init__(self, response_status="SUCCESS"):
        self.calls = []
        self._status = response_status

    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        self.calls.append((spoke_id, cmd, dict(data)))
        return {"payload": {"data": {"status": self._status}}}


def test_an_lldp_edge_is_synced_to_netbox_as_a_cable():
    hub = _FakeHub()
    edges = [{"a": "n1", "a_port": "1/1/1", "b": "n2", "b_port": "1/1/48",
             "source": "lldp"}]
    names = {"n1": "acme-sw", "n2": "acme-edge-1"}
    asyncio.run(_nw_sync_lldp_cables(hub, "ipam-spoke", edges, names))
    assert hub.calls == [("ipam-spoke", "NETBOX_SYNC_CABLE",
                          {"a_device": "acme-sw", "a_port": "1/1/1",
                           "b_device": "acme-edge-1", "b_port": "1/1/48"})]


def test_an_edge_whose_node_name_is_unresolved_is_skipped():
    """A node id that somehow has no name (shouldn't normally happen) must
    not crash the sync or send a half-empty cable request."""
    hub = _FakeHub()
    edges = [{"a": "n1", "a_port": "1/1/1", "b": "ghost", "b_port": "1/1/48",
             "source": "lldp"}]
    names = {"n1": "acme-sw"}
    asyncio.run(_nw_sync_lldp_cables(hub, "ipam-spoke", edges, names))
    assert hub.calls == []


def test_a_netbox_error_on_one_edge_does_not_stop_the_rest():
    class _FlakyHub(_FakeHub):
        async def request_response(self, spoke_id, cmd, data, timeout=30.0):
            self.calls.append((spoke_id, cmd, dict(data)))
            if data["a_device"] == "boom":
                raise Exception("NetBox 503")
            return {"payload": {"data": {"status": "SUCCESS"}}}

    hub = _FlakyHub()
    edges = [
        {"a": "n1", "a_port": "1", "b": "n2", "b_port": "2", "source": "lldp"},
        {"a": "n3", "a_port": "1", "b": "n4", "b_port": "2", "source": "lldp"},
    ]
    names = {"n1": "boom", "n2": "ok1", "n3": "fine", "n4": "ok2"}
    asyncio.run(_nw_sync_lldp_cables(hub, "ipam-spoke", edges, names))
    assert len(hub.calls) == 2  # both attempted despite the first raising
