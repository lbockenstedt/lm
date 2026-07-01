"""Critical path — Network Devices → NetBox device-discovery sync.

``NwDiscoverySyncMixin`` pulls the ARP table (+ the MAC table, when the source
provides a ``mac_command``) from every device on every connected nw spoke,
attaches the source-switch identity + port to each record (so NetBox answers
"where is this MAC?"), attributes IP-bearing records to a tenant by prefix
containment, and pushes per-tenant (``replace=True``). MAC-only sightings (no IP
→ no tenant) are pushed UNSCOPED (``tenant_slug=""``, ``replace=False``) so the
MAC is still recorded in NetBox carrying its switch/port — a later IP sighting
for that MAC adopts the device via the netbox sink's MAC-match tier.

Mirrors the canned-relay ``_SyncHub`` pattern in ``test_fw_discovery_sync.py``;
real ``access.attribute_by_prefix`` runs through it (needs
``get_spoke_by_type('ipam')`` + ``state.get_tenant`` + a ``NETBOX_GET_PREFIXES``
canned response).
"""
import logging

import pytest

import nw_discovery_sync
from nw_discovery_sync import NwDiscoverySyncMixin
from _fakes import FakeState

logging.disable(logging.CRITICAL)


REQUIRED_SOURCE_KEYS = {"module_type", "arp_command", "label"}


# ── registry / config contract ───────────────────────────────────────────────

def test_nw_sources_registry_shape():
    for name, entry in NwDiscoverySyncMixin.NW_DISCOVERY_SOURCES.items():
        assert REQUIRED_SOURCE_KEYS <= set(entry), \
            f"source {name} missing keys: {REQUIRED_SOURCE_KEYS - set(entry)}"
    assert "nw" in NwDiscoverySyncMixin.NW_DISCOVERY_SOURCES


def test_nw_source_contract_has_mac_command():
    se = NwDiscoverySyncMixin.NW_DISCOVERY_SOURCES["nw"]
    assert se["module_type"] == "nw"
    assert se["arp_command"] == "NW_GET_ARP"
    assert se["mac_command"] == "NW_GET_MAC_TABLE"
    assert se["label"] == "Network Devices"


def test_nw_cfg_key_and_target_are_fixed():
    assert NwDiscoverySyncMixin._NW_DISCOVERY_CFG_KEY == "nw_netbox_device_sync"
    assert NwDiscoverySyncMixin._NW_DISCOVERY_TARGET_MODULE == "ipam"
    assert NwDiscoverySyncMixin._NW_DISCOVERY_PUSH_COMMAND == "NETBOX_SYNC_DEVICES"


# ── canned-relay hub ────────────────────────────────────────────────────────

class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = {}

    async def set_nw_discovery_sync_status(self, tenant_id, status):
        self.recorded[tenant_id] = status


class _SyncHub(NwDiscoverySyncMixin):
    """Minimal hub stand-in: canned request_response + spoke routing. Captures
    every NETBOX_SYNC_DEVICES payload so the test can assert the per-tenant vs
    unscoped pushes."""

    def __init__(self, responses=None, tenants=None, global_config=None,
                 nw_spokes=None, netbox_spoke="netbox-1"):
        self.state = FakeState(
            system_state={"global_config": global_config or {}},
            tenants=tenants or {"acme": {"name": "Acme",
                                         "netbox_tenant_slug": "acme"}},
        )
        self.simulations_store = _FakeSimulationsStore()
        self._responses = responses or {}
        # NOTE: do NOT name this ``_nw_spokes`` — that shadows the mixin's
        # ``_nw_spokes()`` method (which ``_nw_pull_discovered`` calls).
        self._nw_spoke_list = nw_spokes if nw_spokes is not None else ["nw-1"]
        self._netbox_spoke = netbox_spoke
        self.request_log = []
        self.sync_payloads = []

    def get_spoke_by_type(self, module_type):
        return self._netbox_spoke if module_type == "ipam" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._nw_spoke_list) if module_type == "nw" else []

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        if command == "NETBOX_SYNC_DEVICES":
            self.sync_payloads.append(payload)
            return self._responses.get((spoke_id, command)) or \
                {"payload": {"data": {"status": "SUCCESS", "pushed": 1,
                                      "errors": 0, "skipped": 0, "deleted": 0,
                                      "message": "ok"}}}
        return self._responses[(spoke_id, command)]


def _arp_payload():
    # one attributed endpoint 10.20.0.5 on port Gi1/0/5
    return {"payload": {"data": {"status": "SUCCESS", "data": [
        {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:05", "interface": "Gi1/0/5"},
    ]}}}


def _mac_table_payload():
    # ee05 also seen on the MAC table (merges with the ARP record, no new row);
    # ee99 is MAC-only (no IP) → pushed unscoped.
    return {"payload": {"data": {"status": "SUCCESS", "data": [
        {"mac": "aa:bb:cc:dd:ee:05", "vlan": "10", "interface": "Gi1/0/5"},
        {"mac": "aa:bb:cc:dd:ee:99", "vlan": "20", "interface": "Gi1/0/9"},
    ]}}}


def _prefixes_payload():
    return {"payload": {"data": {"status": "SUCCESS",
                                "prefixes": [{"prefix": "10.20.0.0/24"}]}}}


def _global_config():
    return {
        "nw_devices": [{"id": "core-sw1", "name": "core-sw1",
                        "address": "10.20.0.1", "spoke_id": "nw-1"}],
        "nw_netbox_device_sync": {"defaults": {"device_type": "network-device",
                                               "role": "router", "site": "main"}},
    }


def _hub_with_responses(netbox_spoke="netbox-1", nw_spokes=None):
    return _SyncHub(
        responses={
            ("nw-1", "NW_GET_ARP"): _arp_payload(),
            ("nw-1", "NW_GET_MAC_TABLE"): _mac_table_payload(),
            (netbox_spoke, "NETBOX_GET_PREFIXES"): _prefixes_payload(),
        },
        global_config=_global_config(),
        nw_spokes=nw_spokes,
        netbox_spoke=netbox_spoke,
    )


# ── pull: enrichment + MAC-table merge ───────────────────────────────────────

@pytest.mark.asyncio
async def test_pull_enriches_records_with_source_switch_identity():
    h = _hub_with_responses()
    records, info = await h._nw_pull_discovered()
    assert not info["errors"]
    by_mac = {r["mac"]: r for r in records}
    # ARP endpoint carries the source switch name + mgmt IP + port.
    r05 = by_mac["aa:bb:cc:dd:ee:05"]
    assert r05["source_switch_name"] == "core-sw1"
    assert r05["source_switch_ip"] == "10.20.0.1"
    assert r05["source_switch_port"] == "Gi1/0/5"
    assert r05["ip"] == "10.20.0.5"
    # MAC-only sighting from the MAC table (ee99) — no IP, still enriched.
    r99 = by_mac["aa:bb:cc:dd:ee:99"]
    assert r99["ip"] == ""
    assert r99["source_switch_name"] == "core-sw1"
    assert r99["source_switch_port"] == "Gi1/0/9"


@pytest.mark.asyncio
async def test_pull_merges_mac_table_and_arp_into_one_record():
    # ee05 appears in BOTH the ARP table (with IP) and the MAC table (no IP);
    # the merge (keyed by MAC) folds them into ONE IP-bearing record, not two.
    h = _hub_with_responses()
    records, _ = await h._nw_pull_discovered()
    macs = [r["mac"] for r in records]
    assert macs.count("aa:bb:cc:dd:ee:05") == 1
    r05 = next(r for r in records if r["mac"] == "aa:bb:cc:dd:ee:05")
    assert r05["ip"] == "10.20.0.5"   # IP filled from the ARP sighting


# ── full cycle: per-tenant (IP) + unscoped (MAC-only) pushes ─────────────────

@pytest.mark.asyncio
async def test_run_all_pushes_ip_records_per_tenant_and_mac_only_unscoped():
    h = _hub_with_responses()
    agg = await h.run_nw_discovery_sync_all()

    assert agg["discovered_total"] == 2          # ee05 + ee99
    assert agg["mac_only_total"] == 1           # ee99
    # Two NETBOX_SYNC_DEVICES pushes: the tenant (acme) push + the unscoped one.
    assert len(h.sync_payloads) == 2

    tenant_push = next(p for p in h.sync_payloads if p.get("tenant_slug") == "acme")
    assert tenant_push["replace"] is True
    assert tenant_push["source"] == "Network Devices"
    assert tenant_push["tenant_id"] == "acme"
    # The attributed endpoint carries its source-switch identity to NetBox.
    assert len(tenant_push["devices"]) == 1
    d = tenant_push["devices"][0]
    assert d["ip"] == "10.20.0.5"
    assert d["mac"] == "aa:bb:cc:dd:ee:05"
    assert d["source_switch_name"] == "core-sw1"
    assert d["source_switch_port"] == "Gi1/0/5"

    unscoped = next(p for p in h.sync_payloads if p.get("tenant_slug") == "")
    assert unscoped["replace"] is False
    assert unscoped["tenant_id"] == ""
    assert len(unscoped["devices"]) == 1
    u = unscoped["devices"][0]
    assert u["ip"] == ""                          # MAC-only
    assert u["mac"] == "aa:bb:cc:dd:ee:99"
    assert u["source_switch_port"] == "Gi1/0/9"


@pytest.mark.asyncio
async def test_run_all_no_mac_only_when_source_has_no_mac_command():
    # A source with no mac_command (ARP-only) → no MAC-only sightings, no
    # unscoped push.
    h = _hub_with_responses()
    # Give THIS instance a source entry with no mac_command. Do NOT mutate the
    # shared class attribute (NW_DISCOVERY_SOURCES is class-level) — an instance
    # attribute shadows it without leaking into other tests.
    base_src = NwDiscoverySyncMixin.NW_DISCOVERY_SOURCES["nw"]
    h.NW_DISCOVERY_SOURCES = {"nw": {k: v for k, v in base_src.items()
                                     if k != "mac_command"}}
    agg = await h.run_nw_discovery_sync_all()
    assert agg["mac_only_total"] == 0
    # Only the tenant push happened.
    assert len(h.sync_payloads) == 1
    assert h.sync_payloads[0]["tenant_slug"] == "acme"


@pytest.mark.asyncio
async def test_run_all_mac_only_unscoped_when_no_tenant_matches():
    # No tenant prefix contains the endpoint IP → IP record is dropped, but the
    # MAC-only sighting is still pushed unscoped.
    h = _SyncHub(
        responses={
            ("nw-1", "NW_GET_ARP"): {"payload": {"data": {"status": "SUCCESS",
                "data": [{"ip": "10.30.0.5", "mac": "aa:bb:cc:dd:ee:05",
                          "interface": "Gi1/0/5"}]}}},
            ("nw-1", "NW_GET_MAC_TABLE"): {"payload": {"data": {"status": "SUCCESS",
                "data": [{"mac": "aa:bb:cc:dd:ee:99", "vlan": "20",
                          "interface": "Gi1/0/9"}]}}},
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
        },
        global_config=_global_config(),
    )
    agg = await h.run_nw_discovery_sync_all()
    assert agg["dropped_unattributed"] == 1       # 10.30.0.5 matched no tenant
    assert len(agg["results"]) == 0               # no tenant push
    assert agg["mac_only_total"] == 1
    # The only push is the unscoped MAC-only one.
    assert len(h.sync_payloads) == 1
    assert h.sync_payloads[0]["tenant_slug"] == ""
    assert h.sync_payloads[0]["replace"] is False


# ── on-demand single-tenant sync skips the global MAC-only push ───────────────

@pytest.mark.asyncio
async def test_sync_tenant_nw_devices_is_tenant_scoped_no_unscoped_push():
    h = _hub_with_responses()
    status = await h.sync_tenant_nw_devices("acme")
    assert status["status"] == "success"
    # On-demand is tenant-scoped: exactly one push (the acme one), no unscoped
    # MAC-only push (that runs in the full cycle only).
    assert len(h.sync_payloads) == 1
    assert h.sync_payloads[0]["tenant_slug"] == "acme"
    assert h.sync_payloads[0]["replace"] is True


# ── unscoped push when NetBox spoke offline ───────────────────────────────────

@pytest.mark.asyncio
async def test_run_all_unscoped_push_error_when_netbox_offline():
    h = _hub_with_responses(netbox_spoke="netbox-1")
    # NetBox spoke offline → get_spoke_by_type returns None.
    h.get_spoke_by_type = lambda module_type: None
    h._netbox_spoke = None
    agg = await h.run_nw_discovery_sync_all()
    # No pushes dispatched; the unscoped push status reports the offline error.
    assert agg["mac_only_status"]["status"] == "error"
    assert h.sync_payloads == []