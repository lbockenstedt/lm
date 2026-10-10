"""LLDP -> NetBox write-back: the topology graph's LLDP-confirmed links are
sent to the NetBox spoke as ONE ``NETBOX_SYNC_LLDP`` request carrying every
identity of each end (name, MACs, IPs, fleet id), so the spoke can match
MAC-first and create LLDP-only neighbours, instead of the old per-edge
exact-name ``NETBOX_SYNC_CABLE`` that silently skipped any name mismatch."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nw_discovery_sync import NwDiscoverySyncMixin  # noqa: E402
from nw_topology import build_topology, netbox_lldp_links  # noqa: E402
from routes.nw import _nw_sync_lldp_netbox  # noqa: E402


class _FakeHub:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        self.calls.append((spoke_id, cmd, data))
        if self.fail:
            raise Exception("NetBox 503")
        return {"payload": {"data": {"status": "SUCCESS", "message": "1 cabled"}}}


def _graph():
    fleet = [{"id": "crsw1", "name": "MIPBE-SSPLM-N31-CRSW1", "address": "172.21.0.2",
              "object_type": "switch"}]
    lldp = {"crsw1": [
        {"local_port": "1/1/40", "remote_chassis": "98:f2:b3:b8:a8:00",
         "remote_port": "28", "remote_name": "MIPBE-SSPLM-N31-TOR"},
        {"local_port": "1/1/2", "remote_chassis": "b0:26:28:2d:52:90",
         "remote_port": "b0:26:28:2d:52:91", "remote_descr": "nic1",
         "remote_name": "mipbe-ssplm-pxmx02.orange-tme.com"},
    ]}
    return build_topology(fleet=fleet, lldp_by_device=lldp, infer_from_macs=False)


def _by_remote(links):
    return {(l["b"] if l["a"]["nw_device_id"] else l["a"])["name"]: l for l in links}


def test_links_carry_identities_and_readable_nic_port():
    links = netbox_lldp_links(_graph())
    assert len(links) == 2
    got = _by_remote(links)
    tor = got["MIPBE-SSPLM-N31-TOR"]
    me, other = ((tor["a"], tor["b"]) if tor["a"]["nw_device_id"] else (tor["b"], tor["a"]))
    assert me["nw_device_id"] == "crsw1" and "172.21.0.2" in me["addresses"]
    assert "98:f2:b3:b8:a8:00" in other["macs"] and other["nw_device_id"] == ""
    srv = got["mipbe-ssplm-pxmx02.orange-tme.com"]
    ports = {srv["a_port"], srv["b_port"]}
    assert ports == {"1/1/2", "nic1"}  # MAC port id -> the NIC's description


def test_non_lldp_or_half_known_edges_are_not_sent():
    graph = {"nodes": [{"id": "a", "name": "A", "sources": ["fleet"], "device_id": "a"},
                       {"id": "b", "name": "B", "sources": ["lldp"]}],
             "edges": [{"source": "mac", "a": "a", "a_port": "1", "b": "b", "b_port": "2"},
                       {"source": "lldp", "a": "a", "a_port": "1", "b": "b", "b_port": ""},
                       {"source": "lldp", "a": "a", "a_port": "1", "b": "ghost", "b_port": "2"}]}
    assert netbox_lldp_links(graph) == []


def test_route_sends_one_request_and_swallows_errors():
    hub = _FakeHub()
    asyncio.run(_nw_sync_lldp_netbox(hub, "ipam", [{"a": {}, "a_port": "1"}], "default"))
    assert hub.calls == [("ipam", "NETBOX_SYNC_LLDP",
                          {"links": [{"a": {}, "a_port": "1"}], "tenant_slug": "default"})]
    asyncio.run(_nw_sync_lldp_netbox(_FakeHub(fail=True), "ipam", [{}]))  # no raise


class _State:
    def __init__(self, devices):
        self.system_state = {"global_config": {"nw_devices": devices}}

    def get_tenant(self, tid):
        return {"default": {"netbox_tenant_slug": "default"},
                "acme": {"netbox_tenant_slug": "acme-nb"}}.get(tid)


class _Hub(NwDiscoverySyncMixin, _FakeHub):
    def __init__(self, devices, lldp):
        _FakeHub.__init__(self)
        self.state = _State(devices)
        self._lldp = lldp

    def get_spoke_by_type(self, t):
        return "ipam" if t == "ipam" else None

    def get_all_spokes_by_type(self, t):
        return ["nw1"]

    def nw_cache_get_device(self, did, endpoint):
        return {"data": self._lldp.get(did, [])}

    def nw_cache_device_fetched_at(self, did):
        return 9e18  # fresh: no live refresh


def test_hub_push_groups_by_tenant_with_its_netbox_slug():
    devices = [{"id": "sw1", "name": "SW1", "tenant_id": ""},
               {"id": "sw2", "name": "SW2", "tenant_id": "acme"}]
    row = {"local_port": "1", "remote_chassis": "aa:bb:cc:00:00:01",
           "remote_port": "2", "remote_name": "NEIGH"}
    hub = _Hub(devices, {"sw1": [row], "sw2": [dict(row, remote_chassis="aa:bb:cc:00:00:02")]})
    res = asyncio.run(hub.push_lldp_links_to_netbox())
    assert res["status"] == "SUCCESS"
    sent = {c[2]["tenant_slug"]: c[2]["links"] for c in hub.calls if c[1] == "NETBOX_SYNC_LLDP"}
    assert set(sent) == {"default", "acme-nb"}
    assert all(len(v) == 1 for v in sent.values())
    hub.calls.clear()
    asyncio.run(hub.push_lldp_links_to_netbox("acme"))
    assert [c[2]["tenant_slug"] for c in hub.calls] == ["acme-nb"]
