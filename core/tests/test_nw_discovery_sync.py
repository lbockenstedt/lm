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
import asyncio
import logging
import time

import pytest

import nw_discovery_sync
from nw_discovery_sync import NwDiscoverySyncMixin
from _fakes import FakeState


# Silence the module's own noisy sync logging for THIS module's tests only.
# NOT a bare module-level ``logging.disable(logging.CRITICAL)``: pytest imports
# every test module during collection, so that set a GLOBAL suppression that
# outlived this file and silently broke unrelated tests which assert on log
# output (test_update_recovery / test_spoke_log_relay saw empty log files).
@pytest.fixture(autouse=True)
def _quiet_logging():
    prev = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(prev)


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
        self.refreshed_caches = []
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



    # The sync mixins invalidate the tenant module-cache at the end of a cycle
    # that actually changed spoke data (main.Hub.refresh_module_cache). Record
    # the keys so tests can assert the refresh fired instead of silently
    # tolerating its absence.
    def refresh_module_cache(self, key):
        self.refreshed_caches.append(key)


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


# ── reconcile_nw_device_name: reset stored display name to the box hostname ───

def test_reconcile_name_updates_when_hostname_differs():
    hub = _SyncHub(global_config=_global_config())
    cfg = {"id": "core-sw1", "name": "core-sw1"}
    changed = hub.reconcile_nw_device_name(cfg, {"hostname": "DIST-SW"})
    assert changed is True
    assert cfg["name"] == "DIST-SW"


def test_reconcile_name_noop_when_matching_or_absent():
    hub = _SyncHub(global_config=_global_config())
    # Already matches → no change.
    cfg = {"id": "x", "name": "DIST-SW"}
    assert hub.reconcile_nw_device_name(cfg, {"hostname": "DIST-SW"}) is False
    assert cfg["name"] == "DIST-SW"
    # Poll read no hostname → never clobbers the existing name.
    cfg2 = {"id": "y", "name": "friendly-name"}
    assert hub.reconcile_nw_device_name(cfg2, {"hostname": ""}) is False
    assert hub.reconcile_nw_device_name(cfg2, {}) is False
    assert cfg2["name"] == "friendly-name"


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


# ── full cycle: MAC sightings for the static reservations' device replacement ─

@pytest.mark.asyncio
async def test_a_cycle_with_a_device_on_a_disconnected_spoke_is_not_a_full_sweep():
    # Every device polled: the old-MAC watch runs from this cycle.
    h = _hub_with_responses()
    await h.run_nw_discovery_sync_all()
    assert h._static_res_macs["since"] is not None
    assert "aa:bb:cc:dd:ee:05" in h._static_res_macs["seen"]
    # A device bound to an nw spoke that is not connected was never polled.
    h = _hub_with_responses()
    h.state.system_state["global_config"]["nw_devices"].append(
        {"id": "edge-sw2", "name": "edge-sw2", "spoke_id": "nw-2"})
    await h.run_nw_discovery_sync_all()
    assert h._static_res_macs["since"] is None
    # An unbound device next to bound ones is polled by no spoke either.
    h = _hub_with_responses()
    h.state.system_state["global_config"]["nw_devices"].append(
        {"id": "edge-sw3", "name": "edge-sw3"})
    await h.run_nw_discovery_sync_all()
    assert h._static_res_macs["since"] is None


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

# ── DHCP/DNS identity cross-reference (ARP/MAC sightings carry no hostname) ──

class _IdentityHub(_SyncHub):
    def get_all_spokes_by_type(self, module_type):
        return {"nw": list(self._nw_spoke_list), "dhcp": ["dhcp-1"],
                "dns": ["dns-1"]}.get(module_type, [])


def _identity_hub(global_config=None, leases=None, reservations=None, dns=None):
    gc = global_config or _global_config()
    ok = lambda key, rows: {"payload": {"data": {"status": "SUCCESS", key: rows}}}
    return _IdentityHub(
        responses={
            ("nw-1", "NW_GET_ARP"): {"payload": {"data": {"status": "SUCCESS", "data": [
                {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:05", "interface": "Gi1/0/5"},
                {"ip": "10.20.0.7", "mac": "aa:bb:cc:dd:ee:07", "interface": "Gi1/0/7"},
                {"ip": "10.20.0.8", "mac": "aa:bb:cc:dd:ee:08", "interface": "Gi1/0/8"},
            ]}}},
            ("nw-1", "NW_GET_MAC_TABLE"): _mac_table_payload(),
            ("netbox-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("dhcp-1", "DHCP_LIST_RES"): ok("reservations", reservations if reservations is not None else [
                {"ip": "10.20.0.5", "mac": "AA-BB-CC-DD-EE-05", "hostname": "printer1"}]),
            ("dhcp-1", "DHCP_LIST_LEASES"): ok("leases", leases if leases is not None else [
                # lease name loses to the reservation for the same MAC
                {"ip-address": "10.20.0.5", "hw-address": "aa:bb:cc:dd:ee:05", "hostname": "lease-name", "state": 0},
                # MAC-only sighting ee99 gets its lease IP + name (trailing dot stripped)
                {"ip-address": "10.20.0.99", "hw-address": "aa:bb:cc:dd:ee:99", "hostname": "laptop99.", "state": 0},
                # declined/expired lease ignored
                {"ip-address": "10.20.0.7", "hw-address": "aa:bb:cc:dd:ee:07", "hostname": "stale", "state": 1},
            ]),
            ("dns-1", "DNS_LIST"): ok("records", dns if dns is not None else [
                {"name": "static8.lab", "type": "A", "value": "10.20.0.8"},
                {"name": "alias", "type": "CNAME", "value": "static8.lab"},
            ]),
        },
        global_config=gc,
    )


@pytest.mark.asyncio
async def test_pull_cross_references_dhcp_and_dns_identity():
    h = _identity_hub()
    records, info = await h._nw_pull_discovered()
    assert not info["errors"]
    by_mac = {r["mac"]: r for r in records}
    assert by_mac["aa:bb:cc:dd:ee:05"]["hostname"] == "printer1"      # reservation wins
    assert by_mac["aa:bb:cc:dd:ee:99"]["ip"] == "10.20.0.99"         # MAC-only → lease IP
    assert by_mac["aa:bb:cc:dd:ee:99"]["hostname"] == "laptop99"
    assert by_mac["aa:bb:cc:dd:ee:07"]["hostname"] == ""             # non-active lease skipped
    assert by_mac["aa:bb:cc:dd:ee:08"]["hostname"] == "static8.lab"  # DNS A by IP


@pytest.mark.asyncio
async def test_mac_only_sighting_with_lease_is_pushed_to_tenant_not_unscoped():
    h = _identity_hub()
    agg = await h.run_nw_discovery_sync_all()
    assert agg["mac_only_total"] == 0
    tenant_push = next(p for p in h.sync_payloads if p.get("tenant_slug") == "acme")
    names = {d["mac"]: d["hostname"] for d in tenant_push["devices"]}
    assert names["aa:bb:cc:dd:ee:99"] == "laptop99"
    assert not any(p.get("tenant_slug") == "" for p in h.sync_payloads)


@pytest.mark.asyncio
async def test_stale_lease_ip_never_steals_a_live_arp_address():
    h = _identity_hub(leases=[
        {"ip-address": "10.20.0.5", "hw-address": "aa:bb:cc:dd:ee:99", "hostname": "old", "state": 0}])
    records, _ = await h._nw_pull_discovered()
    by_mac = {r["mac"]: r for r in records}
    assert by_mac["aa:bb:cc:dd:ee:99"]["ip"] == ""
    assert by_mac["aa:bb:cc:dd:ee:05"]["ip"] == "10.20.0.5"


@pytest.mark.asyncio
async def test_identity_enrichment_opt_out_and_spoke_failure_tolerated():
    gc = _global_config()
    gc["nw_netbox_device_sync"]["enrich_from_dhcp"] = False
    h = _identity_hub(global_config=gc)
    records, _ = await h._nw_pull_discovered()
    assert all(r["hostname"] == "" for r in records)
    assert not any(c.startswith(("DHCP_", "DNS_")) for _, c, _ in h.request_log)

    h2 = _identity_hub()
    del h2._responses[("dhcp-1", "DHCP_LIST_RES")]   # request raises KeyError
    records2, info2 = await h2._nw_pull_discovered()
    assert not info2["errors"]
    assert {r["mac"]: r for r in records2}["aa:bb:cc:dd:ee:05"]["hostname"] == "lease-name"


# ── LLDP / fleet identity: static infrastructure has no DHCP/DNS name ────────

def _lldp_cache(*rows):
    return {"sw-a": {"lldp": {"status": "SUCCESS", "data": list(rows)}}}


_VPNC_ROW = {"local_port": "1/1/7", "remote_port": "GE0/0/0",
             "remote_chassis": "00:1A:1E:04:2F:00",
             "remote_name": "MIPBE-SSPLM-N31-VPNC1.example.com",
             "remote_mgmt_ip": "172.21.2.3"}


@pytest.mark.asyncio
async def test_identity_index_learns_lldp_and_fleet_names_without_dhcp():
    gc = _global_config()
    gc["nw_netbox_device_sync"]["enrich_from_dhcp"] = False
    h = _SyncHub(global_config=gc)
    h.nw_device_cache = _lldp_cache(
        _VPNC_ROW,
        # Junk / IP-only names never become hostnames.
        {"remote_chassis": "aa:bb:cc:00:00:01", "remote_name": "10.9.9.9",
         "remote_mgmt_ip": "10.9.9.9"})
    by_mac, by_ip = await h._nw_identity_index()
    ent = by_mac["00:1a:1e:04:2f:00"]
    assert ent["hostname"] == "MIPBE-SSPLM-N31-VPNC1"
    assert ent["hostname_source"] == "lldp" and ent["ip"] == "172.21.2.3"
    assert by_ip["172.21.2.3"] == "MIPBE-SSPLM-N31-VPNC1"
    assert by_ip["10.20.0.1"] == "core-sw1"        # NW fleet's own name
    assert "10.9.9.9" not in by_ip
    assert h._nw_ip_host_src["172.21.2.3"] == "lldp"


def test_lldp_never_overrides_dhcp_or_dns_identity():
    h = _SyncHub(global_config=_global_config())
    h.nw_device_cache = _lldp_cache(_VPNC_ROW)
    by_mac = {"00:1a:1e:04:2f:00": {"ip": "172.21.2.3", "hostname": "res-name",
                                     "hostname_source": "reservation"}}
    by_ip = {"172.21.2.3": "dns-name"}
    src = {"172.21.2.3": "dns"}
    h._nw_add_device_identities(by_mac, by_ip, src)
    assert by_mac["00:1a:1e:04:2f:00"]["hostname"] == "res-name"
    assert by_ip["172.21.2.3"] == "dns-name" and src["172.21.2.3"] == "dns"


def test_reconcile_name_falls_back_to_lldp_for_ip_named_device():
    h = _SyncHub(global_config=_global_config())
    h.nw_device_cache = _lldp_cache(_VPNC_ROW)
    cfg = {"id": "fb8e", "name": "172.21.2.3", "address": "172.21.2.3"}
    assert h.reconcile_nw_device_name(cfg, {"hostname": ""}) is True
    assert cfg["name"] == "MIPBE-SSPLM-N31-VPNC1"
    # A human-chosen name is never replaced by LLDP.
    cfg2 = {"id": "x", "name": "edge-gw", "address": "172.21.2.3"}
    assert h.reconcile_nw_device_name(cfg2, {}) is False
    assert cfg2["name"] == "edge-gw"


def test_lldp_self_identity_ambiguous_names_are_not_used():
    h = _SyncHub(global_config=_global_config())
    h.nw_device_cache = _lldp_cache(
        _VPNC_ROW, dict(_VPNC_ROW, remote_name="OTHER-BOX",
                        remote_chassis="00:1a:1e:04:2f:99"))
    assert h._nw_lldp_self_identity("172.21.2.3") == {"name": "", "mac": ""}


@pytest.mark.asyncio
async def test_push_inventory_fills_missing_base_mac_from_lldp():
    h = _SyncHub(responses={("netbox-1", "NETBOX_SYNC_NW_DEVICE"): {
        "payload": {"data": {"status": "SUCCESS", "pushed": 0, "errors": 0}}}},
        global_config=_global_config())
    h.nw_device_cache = _lldp_cache(_VPNC_ROW)
    cfg = {"id": "fb8e", "name": "MIPBE-SSPLM-N31-VPNC1", "address": "172.21.2.3"}
    await h.push_nw_device_inventory(cfg, {"mac": ""}, [])
    sent = next(p for _, c, p in h.request_log if c == "NETBOX_SYNC_NW_DEVICE")
    assert sent["device"]["mac"] == "00:1a:1e:04:2f:00"
    # A MAC the poll did read is kept.
    await h.push_nw_device_inventory(cfg, {"mac": "11:22:33:44:55:66"}, [])
    sent = [p for _, c, p in h.request_log if c == "NETBOX_SYNC_NW_DEVICE"][-1]
    assert sent["device"]["mac"] == "11:22:33:44:55:66"


# ── overlapping tenant address space (one VRF per tenant) ────────────────────

class _OverlapHub(_SyncHub):
    """RA and LRB both own 172.16.1.0/24 (separate VRFs), each with its own
    nw spoke + switch that sees the same gateway IP and VRRP MAC."""

    def __init__(self):
        super().__init__(
            tenants={"ra": {"name": "RA", "netbox_tenant_slug": "ra"},
                     "lrb": {"name": "LRB", "netbox_tenant_slug": "lrb"}},
            global_config={"nw_devices": [
                {"id": "ra-sw", "name": "ra-sw", "address": "172.16.1.2",
                 "spoke_id": "nw-ra", "tenant_id": "ra"},
                {"id": "lrb-sw", "name": "lrb-sw", "address": "172.16.1.2",
                 "spoke_id": "nw-lrb"}]},
            nw_spokes=["nw-ra", "nw-lrb"])
        self.state.system_state["module_metadata"] = {"nw-lrb": {"tenant_id": "lrb"}}

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        if command == "NETBOX_GET_PREFIXES":
            pref = {"ra": ["172.16.1.0/24"], "lrb": ["172.16.1.0/24"]}.get(
                payload.get("tenant"), [])
            return {"payload": {"data": {"status": "SUCCESS",
                                         "prefixes": [{"prefix": p} for p in pref]}}}
        if command == "NW_GET_ARP":
            return {"payload": {"data": {"status": "SUCCESS", "data": [
                {"ip": "172.16.1.1", "mac": "00:00:5e:00:01:01", "interface": "vlan1"}]}}}
        if command == "NETBOX_SYNC_DEVICES":
            return await super().request_response(spoke_id, command, payload, timeout)
        return {"payload": {"data": {"status": "SUCCESS", "data": []}}}


@pytest.mark.asyncio
async def test_overlapping_ip_lands_in_each_discovering_tenant():
    h = _OverlapHub()
    await h.run_nw_discovery_sync_all()
    by_slug = {p["tenant_slug"]: p["devices"] for p in h.sync_payloads}
    # Each agent's sighting goes to its own tenant (device tenant_id for RA,
    # the spoke's tenant for LRB) — not both to whichever tenant came first.
    assert [(d["ip"], d["source_switch_name"]) for d in by_slug["ra"]] == [("172.16.1.1", "ra-sw")]
    assert [(d["ip"], d["source_switch_name"]) for d in by_slug["lrb"]] == [("172.16.1.1", "lrb-sw")]


@pytest.mark.asyncio
async def test_inventory_push_uses_device_tenant_for_overlapping_mgmt_ip():
    h = _OverlapHub()
    h._responses[("netbox-1", "NETBOX_SYNC_NW_DEVICE")] = {
        "payload": {"data": {"status": "SUCCESS"}}}
    cfg = h.state.system_state["global_config"]["nw_devices"][1]
    _, _, slug = await h.push_nw_device_inventory(cfg, {}, [])
    assert slug == "lrb"


@pytest.mark.asyncio
async def test_stub_merged_only_when_live_poll_of_its_ip_returns_the_same_serial():
    h = _SyncHub(responses={
        ("netbox-1", "NETBOX_LIST_STUBS"): {"payload": {"data": {"stubs": [
            {"id": 8, "name": "OLD-A", "ip": "172.21.2.2"},
            {"id": 9, "name": "OTHER-B", "ip": "172.21.2.9"},
            {"id": 10, "name": "FAR", "ip": "10.9.9.9"}]}}},
        ("netbox-1", "NETBOX_MERGE_STUB"): {"payload": {"data": {"status": "SUCCESS", "merged": True}}},
    }, global_config=_global_config())
    serials = {"172.21.2.2": "SN1", "172.21.2.9": "SN-OTHER"}
    base = h.request_response

    async def rr(spoke_id, command, payload, timeout=30.0):
        if command == "NW_GET_DEVICE_INFO":
            h.request_log.append((spoke_id, command, payload))
            return {"payload": {"data": {"status": "SUCCESS",
                                         "data": {"serial": serials[payload["address"]]}}}}
        return await base(spoke_id, command, payload, timeout)
    h.request_response = rr
    cfg = {"id": "nw1", "name": "CRSW1", "address": "172.21.0.11", "spoke_id": "nw-1",
           "object_type": "cx_switch"}
    assert await h.nw_merge_stubs_by_live_poll(cfg, "SN1") == 1
    merges = [p for _, c, p in h.request_log if c == "NETBOX_MERGE_STUB"]
    assert merges == [{"stub_id": 8, "nw_device_id": "nw1", "serial": "SN1"}]
    # Out-of-/16 stubs are never probed; a repeat within the TTL probes nothing.
    assert all(p["address"] != "10.9.9.9" for _, c, p in h.request_log if c == "NW_GET_DEVICE_INFO")
    n = len(h.request_log)
    await h.nw_merge_stubs_by_live_poll(cfg, "SN1")
    assert len([1 for _, c, _p in h.request_log[n:] if c == "NW_GET_DEVICE_INFO"]) == 0



@pytest.mark.asyncio
async def test_devices_sharing_a_login_reuse_a_stub_probe_answer():
    h = _SyncHub(responses={
        ("netbox-1", "NETBOX_LIST_STUBS"): {"payload": {"data": {"stubs": [
            {"id": 8, "name": "SVI-OF-B", "ip": "172.21.2.2"},
            {"id": 9, "name": "LAPTOP", "ip": "172.21.2.9"}]}}},
        ("netbox-1", "NETBOX_MERGE_STUB"): {"payload": {"data": {"status": "SUCCESS", "merged": True}}},
    }, global_config=_global_config())
    serials = {"172.21.2.2": "SN-B", "172.21.2.9": ""}
    base = h.request_response

    async def rr(spoke_id, command, payload, timeout=30.0):
        if command == "NW_GET_DEVICE_INFO":
            h.request_log.append((spoke_id, command, payload))
            return {"payload": {"data": {"status": "SUCCESS",
                                         "data": {"serial": serials[payload["address"]]}}}}
        return await base(spoke_id, command, payload, timeout)
    h.request_response = rr
    login = {"spoke_id": "nw-1", "object_type": "cx_switch", "transport": "ssh",
             "username": "admin", "vault_credential": {"bucket": "b", "name": "sw"}}
    dev_a = dict(login, id="nwA", name="SW-A", address="172.21.0.11")
    dev_b = dict(login, id="nwB", name="SW-B", address="172.21.0.12")
    other = dict(dev_b, id="nwC", vault_credential={"bucket": "b", "name": "other"})
    probes = lambda: [p for _, c, p in h.request_log if c == "NW_GET_DEVICE_INFO"]  # noqa: E731
    assert await h.nw_merge_stubs_by_live_poll(dev_a, "SN-A") == 0
    assert len(probes()) == 2
    # B logs in the same way: A's answers are reused, so B merges its stub without probing.
    assert await h.nw_merge_stubs_by_live_poll(dev_b, "SN-B") == 1
    assert len(probes()) == 2
    # A device with another credential still probes for itself.
    await h.nw_merge_stubs_by_live_poll(other, "SN-B")
    assert len(probes()) == 4


@pytest.mark.asyncio
async def test_failed_stub_probe_is_retried_within_the_hour_and_budget_skips_not_stops():
    # Six uncached stubs, then the device's own stub, whose answer is cached.
    stubs = [{"id": i, "name": "S%d" % i, "ip": "172.21.2.%d" % i} for i in range(1, 8)]
    h = _SyncHub(responses={
        ("netbox-1", "NETBOX_LIST_STUBS"): {"payload": {"data": {"stubs": stubs}}},
        ("netbox-1", "NETBOX_MERGE_STUB"): {"payload": {"data": {"status": "SUCCESS", "merged": True}}},
    }, global_config=_global_config())
    base = h.request_response
    failing = {"on": True}

    async def rr(spoke_id, command, payload, timeout=30.0):
        if command == "NW_GET_DEVICE_INFO":
            h.request_log.append((spoke_id, command, payload))
            if failing["on"]:
                return {"status": "ERROR", "message": "Request Timeout"}
            return {"payload": {"data": {"status": "SUCCESS", "data": {"serial": "SN-X"}}}}
        return await base(spoke_id, command, payload, timeout)
    h.request_response = rr
    cfg = {"id": "nw1", "name": "SW", "address": "172.21.0.11", "spoke_id": "nw-1",
           "object_type": "cx_switch"}
    login = nw_discovery_sync._nw_stub_login(cfg, "nw-1")
    h._nw_stub_probe_cache = {(7, login): (time.time() + 3600, "SN1")}
    probes = lambda: [p for _, c, p in h.request_log if c == "NW_GET_DEVICE_INFO"]  # noqa: E731
    # Five probes (the budget), the sixth stub is skipped, the cached one still merges.
    assert await h.nw_merge_stubs_by_live_poll(cfg, "SN1") == 1
    assert len(probes()) == 5
    # The failures are not trusted for a day: after the retry window they are probed again.
    failing["on"] = False
    for key, (expires, got) in list(h._nw_stub_probe_cache.items()):
        if key[0] != 7:
            assert expires - time.time() <= h._NW_STUB_PROBE_RETRY_S
            h._nw_stub_probe_cache[key] = (time.time() - 1, got)
    await h.nw_merge_stubs_by_live_poll(cfg, "SN1")
    assert len(probes()) == 10

def test_oobm_address_is_the_one_on_the_mgmt_interface():
    from nw_discovery_sync import nw_oobm_address
    dev = {"address": "172.21.0.11", "alt_addresses": ["10.0.4.2", "1.1.1.1"]}
    rows = [{"name": "vlan10", "ip": "172.21.0.11"}, {"name": "mgmt", "ip": "10.0.4.2/24"}]
    assert nw_oobm_address(dev, {"data": rows}) == "10.0.4.2"
    assert nw_oobm_address(dev, [{"name": "vlan10", "ip": "172.21.0.11"}]) == ""
    assert nw_oobm_address(dev, None) == ""


@pytest.mark.asyncio
async def test_pull_prefers_access_port_over_uplink_deterministically():
    # MAC ee05 is learned on a distribution switch uplink (many MACs) and on
    # the access switch port; the access port must win whatever the fetch order.
    def uplink():
        return {"payload": {"data": {"status": "SUCCESS", "data": [
            {"mac": f"aa:bb:cc:dd:00:{i:02x}", "interface": "Po1"} for i in range(5)
        ] + [{"mac": "aa:bb:cc:dd:ee:05", "interface": "Po1"}]}}}

    def access():
        return {"payload": {"data": {"status": "SUCCESS", "data": [
            {"mac": "aa:bb:cc:dd:ee:05", "interface": "Gi1/0/5"}]}}}

    for first, second in (("a-dist", "z-acc"), ("z-dist", "a-acc")):
        h = _hub_with_responses()
        h.state.system_state["global_config"]["nw_devices"] = [
            {"id": first, "name": first, "address": "10.0.0.1", "spoke_id": "nw-1"},
            {"id": second, "name": second, "address": "10.0.0.2", "spoke_id": "nw-1"}]
        h._responses[("nw-1", "NW_GET_ARP")] = {"payload": {"data": {
            "status": "SUCCESS", "data": []}}}
        calls = {}

        async def rr(spoke_id, command, payload, timeout=30.0, _h=h, _c=calls,
                     _first=first):
            if command == "NW_GET_MAC_TABLE":
                return uplink() if payload["device_id"] == _first else access()
            return _h._responses[(spoke_id, command)]
        h.request_response = rr
        records, _ = await h._nw_pull_discovered()
        r = next(x for x in records if x["mac"] == "aa:bb:cc:dd:ee:05")
        assert r["source_switch_port"] == "Gi1/0/5"


@pytest.mark.asyncio
async def test_pull_prefers_physical_port_over_logical_interface():
    # Live churn: a firewall MAC seen on a peer switch's lag255 / a VTEP's
    # vxlan1 (one MAC each) beat the physical port it plugs into (two MACs),
    # and which logical sighting won changed run to run. A physical port must
    # win over any LAG/VXLAN/SVI regardless of MAC counts or fetch order.
    tables = {
        "a-peer": [{"mac": "aa:bb:cc:dd:ee:05", "interface": "lag255"}],
        "b-vtep": [{"mac": "aa:bb:cc:dd:ee:05", "interface": "vxlan1(10.0.0.5)"}],
        "z-edge": [{"mac": "aa:bb:cc:dd:ee:05", "interface": "1/1/14"},
                   {"mac": "aa:bb:cc:dd:ee:06", "interface": "1/1/14"}],
    }
    for order in (["a-peer", "b-vtep", "z-edge"], ["z-edge", "b-vtep", "a-peer"]):
        h = _hub_with_responses()
        h.state.system_state["global_config"]["nw_devices"] = [
            {"id": n, "name": n, "address": f"10.0.0.{i}", "spoke_id": "nw-1"}
            for i, n in enumerate(order, 1)]
        h._responses[("nw-1", "NW_GET_ARP")] = {"payload": {"data": {
            "status": "SUCCESS", "data": []}}}

        async def rr(spoke_id, command, payload, timeout=30.0, _h=h):
            if command == "NW_GET_MAC_TABLE":
                return {"payload": {"data": {"status": "SUCCESS",
                                             "data": tables[payload["device_id"]]}}}
            return _h._responses[(spoke_id, command)]
        h.request_response = rr
        records, _ = await h._nw_pull_discovered()
        r = next(x for x in records if x["mac"] == "aa:bb:cc:dd:ee:05")
        assert (r["source_switch_name"], r["source_switch_port"]) == ("z-edge", "1/1/14")


@pytest.mark.asyncio
async def test_pull_same_named_switches_pick_one_ip_stably():
    # Two fleet entries share a switch name (different mgmt IPs); the winner's
    # switch_ip must not depend on fetch order.
    for addrs in (("10.0.0.2", "10.0.0.1"), ("10.0.0.1", "10.0.0.2")):
        h = _hub_with_responses()
        h.state.system_state["global_config"]["nw_devices"] = [
            {"id": f"d{i}", "name": "SPSW-1", "address": a, "spoke_id": "nw-1"}
            for i, a in enumerate(addrs)]
        h._responses[("nw-1", "NW_GET_ARP")] = {"payload": {"data": {
            "status": "SUCCESS", "data": []}}}

        async def rr(spoke_id, command, payload, timeout=30.0, _h=h):
            if command == "NW_GET_MAC_TABLE":
                return {"payload": {"data": {"status": "SUCCESS", "data": [
                    {"mac": "aa:bb:cc:dd:ee:05", "interface": "1/1/1"}]}}}
            return _h._responses[(spoke_id, command)]
        h.request_response = rr
        records, _ = await h._nw_pull_discovered()
        r = next(x for x in records if x["mac"] == "aa:bb:cc:dd:ee:05")
        assert r["source_switch_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_pull_keeps_last_sighting_until_a_better_one_appears():
    # Live churn: a MAC seen only on VLAN SVIs moved between switches every
    # run as their ARP-table sizes shifted. Keep the previous sighting while
    # it is still reported; switch only when a physical port shows up.
    def svi(n):
        return [{"mac": "aa:bb:cc:dd:ee:05", "interface": "vlan10"}] + [
            {"mac": f"aa:bb:cc:dd:00:{i:02x}", "interface": "vlan10"} for i in range(n)]

    h = _hub_with_responses()
    h.state.system_state["global_config"]["nw_devices"] = [
        {"id": n, "name": n, "address": a, "spoke_id": "nw-1"}
        for n, a in (("a-sw", "10.0.0.1"), ("b-sw", "10.0.0.2"))]
    h._responses[("nw-1", "NW_GET_ARP")] = {"payload": {"data": {
        "status": "SUCCESS", "data": []}}}
    tables = {}

    async def rr(spoke_id, command, payload, timeout=30.0):
        if command == "NW_GET_MAC_TABLE":
            return {"payload": {"data": {"status": "SUCCESS",
                                         "data": tables[payload["device_id"]]}}}
        return h._responses[(spoke_id, command)]
    h.request_response = rr

    async def winner():
        records, _ = await h._nw_pull_discovered()
        r = next(x for x in records if x["mac"] == "aa:bb:cc:dd:ee:05")
        return r["source_switch_name"], r["source_switch_port"]

    tables.update({"a-sw": svi(1), "b-sw": svi(5)})
    assert await winner() == ("a-sw", "vlan10")
    tables.update({"a-sw": svi(5), "b-sw": svi(1)})   # counts swap
    assert await winner() == ("a-sw", "vlan10")
    tables["b-sw"] = [{"mac": "aa:bb:cc:dd:ee:05", "interface": "1/1/7"}]
    assert await winner() == ("b-sw", "1/1/7")
    tables["a-sw"] = []                                  # old sighting gone
    tables["b-sw"] = svi(3)
    assert await winner() == ("b-sw", "vlan10")


class _BusyNetboxHub(_OverlapHub):
    """NetBox takes 50 ms per sync push; records how many pushes overlap."""

    def __init__(self):
        super().__init__()
        self.inflight = 0
        self.max_inflight = 0

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        if command != "NETBOX_SYNC_DEVICES":
            return await super().request_response(spoke_id, command, payload, timeout)
        self.inflight += 1
        self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            await asyncio.sleep(0.05)
            return await super().request_response(spoke_id, command, payload, timeout)
        finally:
            self.inflight -= 1


@pytest.mark.asyncio
async def test_netbox_pushes_are_one_tenant_at_a_time():
    """The background sync must not stack tenant pushes on NetBox at once."""
    h = _BusyNetboxHub()
    await h.run_nw_discovery_sync_all()
    assert len(h.sync_payloads) >= 2
    assert h.max_inflight == 1


def test_sweep_loop_runs_tenants_side_by_side(monkeypatch):
    """A slow tenant's sweep batch must not hold up another tenant's."""
    class _Stop(Exception):
        pass

    sleeps = []

    async def fake_sleep(_s):
        sleeps.append(_s)
        if len(sleeps) > 1:          # boot wait, then stop after the first tick
            raise _Stop

    monkeypatch.setattr(nw_discovery_sync.asyncio, "sleep", fake_sleep)
    hub = NwDiscoverySyncMixin()
    hub.state = type("S", (), {"tenant_state": {"tenants": {"slow": {}, "fast": {}}}})()
    hub.get_all_spokes_by_type = lambda _t: ["nw-1"]
    hub.nw_sweep_enabled_for_tenant = lambda tid: tid != "default"
    fast_done = None
    order = []

    async def step(tid):
        if tid == "slow":
            await asyncio.wait_for(fast_done.wait(), 1)   # only finishes once "fast" has
        else:
            fast_done.set()
        order.append(tid)
    hub.run_nw_sweep_step = step

    async def run():
        nonlocal fast_done
        fast_done = asyncio.Event()
        with pytest.raises(_Stop):
            await hub.run_nw_sweep_loop()
    asyncio.run(run())
    assert order == ["fast", "slow"]


def test_sweep_loop_caps_tenants_running_at_once(monkeypatch):
    """No more than NW_SWEEP_PARALLEL_TENANTS sweep batches run together."""
    class _Stop(Exception):
        pass

    sleeps = []
    real_sleep = asyncio.sleep

    async def fake_sleep(_s):
        sleeps.append(_s)
        if len(sleeps) > 1:          # boot wait, then stop after the first tick
            raise _Stop

    monkeypatch.setattr(nw_discovery_sync.asyncio, "sleep", fake_sleep)
    hub = NwDiscoverySyncMixin()
    hub.state = type("S", (), {"tenant_state": {"tenants": {f"t{i}": {} for i in range(6)}}})()
    hub.get_all_spokes_by_type = lambda _t: ["nw-1"]
    hub.nw_sweep_enabled_for_tenant = lambda tid: tid != "default"
    running, peak, done = 0, 0, []

    async def step(tid):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        for _ in range(3):           # yield so the other batches get a chance to start
            await real_sleep(0)
        running -= 1
        done.append(tid)
    hub.run_nw_sweep_step = step

    async def run():
        with pytest.raises(_Stop):
            await hub.run_nw_sweep_loop()
    asyncio.run(run())
    assert len(done) == 6
    assert peak == nw_discovery_sync.NW_SWEEP_PARALLEL_TENANTS


def test_sweep_loop_reaches_tenants_with_no_nw_agent_connected(monkeypatch):
    """With no nw spoke at all the step still runs, so it can record "no-agent"."""
    class _Stop(Exception):
        pass

    sleeps = []

    async def fake_sleep(_s):
        sleeps.append(_s)
        if len(sleeps) > 1:
            raise _Stop

    monkeypatch.setattr(nw_discovery_sync.asyncio, "sleep", fake_sleep)
    hub = NwDiscoverySyncMixin()
    hub.state = type("S", (), {"tenant_state": {"tenants": {"acme": {}}}})()
    hub.get_all_spokes_by_type = lambda _t: []
    hub.nw_sweep_enabled_for_tenant = lambda tid: tid != "default"
    ran = []

    async def step(tid):
        ran.append(tid)
    hub.run_nw_sweep_step = step

    async def run():
        with pytest.raises(_Stop):
            await hub.run_nw_sweep_loop()
    asyncio.run(run())
    assert ran == ["acme"]


def test_sweep_loop_includes_the_admin_tenant_without_a_tenant_record(monkeypatch):
    class _Stop(Exception):
        pass

    sleeps = []

    async def fake_sleep(_s):
        sleeps.append(_s)
        if len(sleeps) > 1:          # boot wait, then stop after the first tick
            raise _Stop

    monkeypatch.setattr(nw_discovery_sync.asyncio, "sleep", fake_sleep)
    hub = NwDiscoverySyncMixin()
    hub.state = type("S", (), {"tenant_state": {"tenants": {"acme": {}}}})()
    hub.nw_sweep_enabled_for_tenant = lambda tid: tid == "default"
    swept = []

    async def step(tid):
        swept.append(tid)
    hub.run_nw_sweep_step = step

    async def run():
        with pytest.raises(_Stop):
            await hub.run_nw_sweep_loop()
    asyncio.run(run())
    assert swept == ["default"]


@pytest.mark.asyncio
async def test_fleet_of_device_pushes_holds_only_a_few_netbox_slots():
    h = _SyncHub(global_config=_global_config())
    in_flight, peak = [0], [0]

    async def slow_netbox(spoke_id, command, payload, timeout=30.0):
        if command != "NETBOX_SYNC_NW_DEVICE":
            return {}
        in_flight[0] += 1
        peak[0] = max(peak[0], in_flight[0])
        await asyncio.sleep(0.01)
        in_flight[0] -= 1
        return {"payload": {"data": {"status": "SUCCESS", "pushed": 1, "errors": 0}}}
    h.request_response = slow_netbox
    await asyncio.gather(*(h.push_nw_device_inventory(
        {"id": f"d{i}", "name": f"sw{i}", "address": f"10.0.0.{i}"}, {}, []) for i in range(12)))
    assert peak[0] == nw_discovery_sync.NW_NETBOX_PUSHES_AT_ONCE
