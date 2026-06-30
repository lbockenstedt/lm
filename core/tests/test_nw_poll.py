"""Critical path — NW POLL NOW: ``NwDiscoverySyncMixin.poll_nw_device``.

Locks in: the spoke resolves the owning nw spoke + device cfg, sends ``NW_POLL``,
attributes the device to a tenant by its **management-address** prefix
containment, and pushes a ``NETBOX_SYNC_NW_DEVICE`` payload (device + interfaces
+ tenant_slug + defaults + source) to the ipam spoke. Mirrors the canned-relay
``_SyncHub`` pattern in ``test_fw_discovery_sync.py``; real
``access.attribute_by_prefix`` runs through it (needs ``get_spoke_by_type('ipam')``
+ ``state.get_tenant`` + a ``NETBOX_GET_PREFIXES`` canned response).
"""
import asyncio
import logging

import pytest

import nw_discovery_sync
from nw_discovery_sync import NwDiscoverySyncMixin
from _fakes import FakeState

logging.disable(logging.CRITICAL)


# ── constants / contract ──────────────────────────────────────────────────────
def test_poll_command_constants():
    assert NwDiscoverySyncMixin._NW_POLL_COMMAND == "NW_POLL"
    assert NwDiscoverySyncMixin._NW_DEVICE_PUSH_COMMAND == "NETBOX_SYNC_NW_DEVICE"


# ── canned-relay hub ──────────────────────────────────────────────────────────
class _PollHub(NwDiscoverySyncMixin):
    """Minimal hub stand-in: canned request_response + spoke routing. Captures
    the NETBOX_SYNC_NW_DEVICE payload so the test can assert its shape."""

    def __init__(self, responses=None, tenants=None, global_config=None,
                 nw_spokes=None, netbox_spoke="netbox-1"):
        self.state = FakeState(
            system_state={"global_config": global_config or {}},
            tenants=tenants or {"acme": {"name": "Acme",
                                         "netbox_tenant_slug": "acme"}},
        )
        self._responses = responses or {}
        self._nw_spokes = nw_spokes if nw_spokes is not None else ["nw-1"]
        self._netbox_spoke = netbox_spoke
        self.request_log = []
        self.pushed_payload = None

    def get_spoke_by_type(self, module_type):
        return self._netbox_spoke if module_type == "ipam" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._nw_spokes) if module_type == "nw" else []

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        if command == "NETBOX_SYNC_NW_DEVICE":
            self.pushed_payload = payload
        return self._responses[(spoke_id, command)]


def _poll_response(reachable=True, model="GW-100"):
    return {"payload": {"data": {
        "status": "SUCCESS",
        "data": {
            "reachable": reachable, "latency_ms": 7,
            "device_info": {"model": model, "serial": "S1", "firmware": "1.0",
                            "interfaces_count": 1},
            "interfaces": [{"name": "1", "ip": "10.20.0.1",
                            "mac": "aa:bb:cc:dd:ee:ff", "vlan": "",
                            "status": "up", "speed": 1_000_000_000}],
            "arp": [{"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:ff",
                     "interface": "1"}],
            "mac_table": [{"mac": "aa:bb:cc:dd:ee:ff", "vlan": "10",
                           "interface": "1"}],
        },
        "errors": [],
    }}}


def _prefixes_payload():
    return {"payload": {"data": {"status": "SUCCESS",
                                 "prefixes": [{"prefix": "10.20.0.0/24"}]}}}


def _sync_nw_device_ok():
    return {"payload": {"data": {"status": "SUCCESS", "pushed": 1, "errors": 0,
                                "skipped": 0, "deleted": 0,
                                "interfaces_total": 1, "message": "ok"}}}


def _global_config(device):
    return {"nw_devices": [device],
            "nw_netbox_device_sync": {"defaults": {"device_type": "network-device",
                                                   "role": "router",
                                                   "site": "main"}}}


# ── poll + push + tenant attribution ──────────────────────────────────────────
def test_poll_nw_device_success_pushes_with_tenant_slug():
    device = {"id": "gw1", "name": "core-gw", "object_type": "gateway",
              "address": "10.20.0.1", "spoke_id": "nw-1"}
    hub = _PollHub(
        global_config=_global_config(device),
        responses={
            ("nw-1", "NW_POLL"): _poll_response(),
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-1", "NETBOX_SYNC_NW_DEVICE"): _sync_nw_device_ok(),
        },
    )
    res = asyncio.run(hub.poll_nw_device("gw1"))
    assert res["status"] == "SUCCESS"
    assert res["reachable"] is True
    assert res["tenant_slug"] == "acme"  # 10.20.0.1 ∈ 10.20.0.0/24
    # Push payload shape
    p = hub.pushed_payload
    assert p is not None
    assert p["device"]["name"] == "core-gw"
    assert p["device"]["model"] == "GW-100"
    assert p["device"]["address"] == "10.20.0.1"
    assert p["tenant_slug"] == "acme"
    assert p["source"] == "Network Devices"
    assert p["defaults"]["device_type"] == "network-device"
    assert len(p["interfaces"]) == 1
    # NetBox push summary threaded through
    assert res["netbox_push"]["pushed"] == 1
    assert res["netbox_push"]["interfaces_total"] == 1


def test_poll_nw_device_unattributed_is_empty_tenant_slug():
    # 10.99.0.1 sits in no tenant prefix → unattributed → "" slug, still pushed.
    device = {"id": "gw2", "name": "edge-gw", "object_type": "gateway",
              "address": "10.99.0.1", "spoke_id": "nw-1"}
    hub = _PollHub(
        global_config=_global_config(device),
        responses={
            ("nw-1", "NW_POLL"): _poll_response(),
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-1", "NETBOX_SYNC_NW_DEVICE"): _sync_nw_device_ok(),
        },
    )
    res = asyncio.run(hub.poll_nw_device("gw2"))
    assert res["reachable"] is True
    assert res["tenant_slug"] == ""
    assert hub.pushed_payload["tenant_slug"] == ""


def test_poll_nw_device_unreachable_is_error_status():
    device = {"id": "gw3", "name": "dead-gw", "object_type": "gateway",
              "address": "10.20.0.1", "spoke_id": "nw-1"}
    hub = _PollHub(
        global_config=_global_config(device),
        responses={
            ("nw-1", "NW_POLL"): _poll_response(reachable=False),
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-1", "NETBOX_SYNC_NW_DEVICE"): _sync_nw_device_ok(),
        },
    )
    res = asyncio.run(hub.poll_nw_device("gw3"))
    assert res["reachable"] is False
    assert res["status"] in ("ERROR", "PARTIAL")


def test_poll_nw_device_no_spoke_connected():
    device = {"id": "gw4", "name": "x", "object_type": "gateway",
              "address": "10.20.0.1", "spoke_id": "nw-1"}
    hub = _PollHub(global_config=_global_config(device), nw_spokes=[])
    res = asyncio.run(hub.poll_nw_device("gw4"))
    assert res["status"] == "ERROR"
    assert "no nw spoke" in res["message"]


def test_poll_nw_device_unknown_device_errors():
    hub = _PollHub(global_config=_global_config(
        {"id": "gw1", "name": "core-gw", "object_type": "gateway",
         "address": "10.20.0.1", "spoke_id": "nw-1"}))
    res = asyncio.run(hub.poll_nw_device("does-not-exist"))
    assert res["status"] == "ERROR"
    assert "not configured" in res["message"]