"""Critical path — Firewall → NetBox device-discovery sync.

``test_fw_discovery_sync.py`` locks in the source registry shape + fallback
(the contract that makes adding a firewall product a one-entry change), the MAC
normalization + DHCP/ARP merge/dedup, the prefix-containment attribution (and
its drop+count of unattributed IPs), and the per-tenant push payload
(``replace=True`` + ``defaults`` forwarded, tenant slug from the tenant cfg) —
using a FakeHub whose ``request_response`` returns canned OPNsense DHCP/ARP +
NetBox NETBOX_GET_PREFIXES / NETBOX_SYNC_DEVICES payloads. Mirrors
``test_vm_sync.py`` (registry) + ``test_endpoint_sync_flow.py`` (canned relay).
"""

import logging

import pytest

import fw_discovery_sync
from fw_discovery_sync import FwDiscoverySyncMixin
from _fakes import FakeState


REQUIRED_SOURCE_KEYS = {"module_type", "dhcp_command", "arp_command", "label"}


# ── registry / config contract (sync) ───────────────────────────────────────

def test_firewall_sources_registry_shape():
    for name, entry in FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES.items():
        assert REQUIRED_SOURCE_KEYS <= set(entry), \
            f"source {name} missing keys: {REQUIRED_SOURCE_KEYS - set(entry)}"
    assert "opnsense" in FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES


def test_opnsense_source_contract():
    se = FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]
    assert se["module_type"] == "firewall"
    assert se["dhcp_command"] == "OPNSENSE_GET_DHCP_LEASES"
    assert se["arp_command"] == "OPNSENSE_GET_ARP_TABLE"
    assert se["label"] == "OPNsense"


def test_cfg_key_and_target_are_fixed():
    assert FwDiscoverySyncMixin._FW_DISCOVERY_CFG_KEY == "opnsense_netbox_device_sync"
    assert FwDiscoverySyncMixin._FW_DISCOVERY_TARGET_MODULE == "ipam"
    assert FwDiscoverySyncMixin._FW_DISCOVERY_PUSH_COMMAND == "NETBOX_SYNC_DEVICES"


def test_default_source_is_opnsense_when_unconfigured():
    m = FwDiscoverySyncMixin()
    m.state = FakeState(global_config={})
    assert m._fw_discovery_source() is FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]


def test_unknown_source_falls_back_to_opnsense_case_insensitive():
    m = FwDiscoverySyncMixin()
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"source": "  PALO-ALTO-SOMEDAY  "}}})
    assert m._fw_discovery_source() is FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"source": "  OPNSENSE  "}}})
    assert m._fw_discovery_source() is FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]


# ── MAC normalization (sync) ────────────────────────────────────────────────

def test_norm_mac_canonicalizes_separators():
    assert FwDiscoverySyncMixin._fw_norm_mac("AA-BB-CC-DD-EE-05") == "aa:bb:cc:dd:ee:05"
    assert FwDiscoverySyncMixin._fw_norm_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert FwDiscoverySyncMixin._fw_norm_mac("AA.BB.CC.DD.EE.05") == "aa:bb:cc:dd:ee:05"


def test_norm_mac_drops_unknown_and_blank():
    assert FwDiscoverySyncMixin._fw_norm_mac("unknown") == ""
    assert FwDiscoverySyncMixin._fw_norm_mac("") == ""
    assert FwDiscoverySyncMixin._fw_norm_mac(None) == ""


# ── firewall spoke resolution (sync) ────────────────────────────────────────

def test_firewall_spokes_pinned_vs_all():
    m = FwDiscoverySyncMixin()
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"firewall_id": "fw1"}}})
    m.get_spoke_for_firewall = lambda fid: "opn-fw1" if fid == "fw1" else None
    m.get_all_spokes_by_type = lambda mt: ["opn-a", "opn-b"]
    assert m._fw_firewall_spokes() == ["opn-fw1"]
    # unpinned → all connected firewall spokes
    m.state = FakeState(system_state={"global_config": {}})
    assert m._fw_firewall_spokes() == ["opn-a", "opn-b"]
    # pinned but firewall not found → empty (no fallback to all)
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"firewall_id": "ghost"}}})
    assert m._fw_firewall_spokes() == []


# ── canned-relay hub (async) ────────────────────────────────────────────────

class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = {}

    async def set_fw_discovery_sync_status(self, tenant_id, status):
        self.recorded[tenant_id] = status


class _SyncHub(FwDiscoverySyncMixin):
    """Minimal hub stand-in: canned request_response + spoke routing. The real
    ``access.fetch_tenant_prefixes`` runs through this (it only needs
    hub.get_spoke_by_type('ipam') + hub.state.get_tenant, both faked)."""

    def __init__(self, responses=None, tenants=None, global_config=None,
                 fw_spokes=None, netbox_spoke="netbox-spoke-1"):
        # The sync mixins read cfg from ``state.system_state["global_config"]``
        # (not FakeState._global_config), so embed it there.
        self.state = FakeState(
            system_state={"global_config": global_config or {}},
            tenants=tenants or {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}},
        )
        self.simulations_store = _FakeSimulationsStore()
        self._responses = responses or {}
        self._fw_spokes = fw_spokes if fw_spokes is not None else ["opn-fw1"]
        self._netbox_spoke = netbox_spoke
        self.request_log = []

    def get_spoke_by_type(self, module_type):
        return self._netbox_spoke if module_type == "ipam" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._fw_spokes) if module_type == "firewall" else []

    def get_spoke_for_firewall(self, firewall_id):
        return self._fw_spokes[0] if self._fw_spokes else None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        return self._responses[(spoke_id, command)]


def _dhcp_payload():
    return {"payload": {"data": {"status": "SUCCESS", "data": [
        # dynamic lease — also appears in ARP (merge test); DHCP hostname wins
        {"ip": "10.20.0.5", "hostname": "ws-dhcp", "mac": "AA-BB-CC-DD-EE-05", "lease_end": "999"},
    ]}}}


def _arp_payload():
    return {"payload": {"data": {"status": "SUCCESS", "data": [
        # same device as the DHCP lease, no hostname → merge keeps DHCP hostname
        {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:05", "hostname": "", "interface": "lan"},
        # static-IP device DHCP can't see — only in ARP, attributed to acme
        {"ip": "10.20.0.50", "mac": "aa:bb:cc:dd:ee:50", "hostname": "static-dev", "interface": "lan"},
        # unattributed: no tenant prefix contains 10.30.0.99 → dropped + counted
        {"ip": "10.30.0.99", "mac": "aa:bb:cc:dd:ee:99", "hostname": "", "interface": "wan"},
    ]}}}


def _prefixes_payload():
    return {"payload": {"data": {"status": "SUCCESS", "prefixes": [
        {"prefix": "10.20.0.0/24"},
    ]}}}


def _sync_devices_ok(n):
    return {"payload": {"data": {"status": "SUCCESS", "pushed": n, "errors": 0,
                                 "skipped": 0, "deleted": 0, "message": "ok"}}}


def _hub_with_full_responses(sync_n=2):
    return _SyncHub(responses={
        ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
        ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
        ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
        ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(sync_n),
    })


@pytest.mark.asyncio
async def test_pull_merges_dhcp_arp_and_normalizes_mac():
    h = _hub_with_full_responses()
    records, info = await h._fw_pull_discovered()
    # 3 distinct devices: the DHCP+ARP pair merged into one, plus two ARP-only.
    assert len(records) == 3
    by_ip = {r["ip"]: r for r in records}
    merged = by_ip["10.20.0.5"]
    assert merged["mac"] == "aa:bb:cc:dd:ee:05"          # normalized from AA-BB-...
    assert merged["hostname"] == "ws-dhcp"               # DHCP hostname won over ARP's blank
    assert by_ip["10.20.0.50"]["hostname"] == "static-dev"
    assert info["errors"] == []


@pytest.mark.asyncio
async def test_pull_uses_source_data_to_select_tables():
    # source_data=arp → only ARP fetched (no DHCP command issued)
    h = _SyncHub(global_config={"opnsense_netbox_device_sync": {"source_data": "arp"}},
                 responses={
        ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
        ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
    })
    records, _ = await h._fw_pull_discovered()
    cmds = [c for _, c, _ in h.request_log]
    assert "OPNSENSE_GET_DHCP_LEASES" not in cmds
    assert "OPNSENSE_GET_ARP_TABLE" in cmds
    assert len(records) == 3  # the three ARP rows


@pytest.mark.asyncio
async def test_attribute_buckets_by_prefix_and_drops_unattributed():
    h = _hub_with_full_responses()
    records, _ = await h._fw_pull_discovered()
    buckets, dropped = await h._fw_attribute(records)
    assert set(buckets.keys()) == {"acme"}
    assert len(buckets["acme"]) == 2          # 10.20.0.5 + 10.20.0.50
    assert dropped == 1                        # 10.30.0.99 unmatched


@pytest.mark.asyncio
async def test_sync_tenant_devices_pushes_replace_true_with_defaults():
    h = _SyncHub(
        global_config={"opnsense_netbox_device_sync": {
            "defaults": {"role": "discovered", "device_type": "discovered", "site": "main"},
        }},
        responses={
            ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
            ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
            ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(2),
        },
    )
    status = await h.sync_tenant_devices("acme")
    assert status["status"] == "success"
    assert status["pushed"] == 2
    assert status["tenant_name"] == "Acme"
    assert status["dropped_unattributed"] == 1
    assert status["discovered_total_global"] == 3
    # The push command carried replace=True + the tenant slug + defaults.
    push = next(p for sid, cmd, p in h.request_log
                if cmd == "NETBOX_SYNC_DEVICES" and sid == "netbox-spoke-1")
    assert push["replace"] is True
    assert push["tenant_slug"] == "acme"
    assert push["source"] == "OPNsense"
    assert push["defaults"]["role"] == "discovered"
    assert len(push["devices"]) == 2
    # source_of_truth relayed (default netbox → only-add-missing on the spoke).
    assert push["source_of_truth"] == "netbox"
    # Per-tenant status persisted to the store.
    assert h.simulations_store.recorded["acme"]["status"] == "success"


@pytest.mark.asyncio
async def test_sync_tenant_devices_relays_configured_source_of_truth():
    # device_sync=external in global_config → the spoke receives "external"
    # (overwrite) instead of the default netbox.
    h = _SyncHub(
        global_config={"opnsense_netbox_device_sync": {
            "defaults": {"role": "discovered", "device_type": "discovered", "site": "main"},
        }, "source_of_truth": {"device_sync": "external"}},
        responses={
            ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
            ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
            ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(2),
        },
    )
    await h.sync_tenant_devices("acme")
    push = next(p for sid, cmd, p in h.request_log
                if cmd == "NETBOX_SYNC_DEVICES" and sid == "netbox-spoke-1")
    assert push["source_of_truth"] == "external"


@pytest.mark.asyncio
async def test_sync_tenant_devices_skipped_when_netbox_offline():
    h = _SyncHub(netbox_spoke=None, responses={
        ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
        ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
        # no netbox → no NETBOX_GET_PREFIXES / NETBOX_SYNC_DEVICES responses
    })
    # get_spoke_by_type('ipam') returns None → fetch_tenant_prefixes returns []
    # → everything dropped; push records an error (NetBox not connected).
    status = await h.sync_tenant_devices("acme")
    assert status["status"] == "error"
    assert "NetBox spoke not connected" in status["message"]


@pytest.mark.asyncio
async def test_run_all_returns_summary_with_dropped():
    h = _hub_with_full_responses()
    agg = await h.run_fw_discovery_sync_all()
    assert agg["discovered_total"] == 3
    assert agg["dropped_unattributed"] == 1
    assert len(agg["results"]) == 1
    assert agg["results"][0]["tenant_id"] == "acme"
    assert agg["results"][0]["pushed"] == 2


@pytest.mark.asyncio
async def test_push_with_errors_emits_sync_error_marker_with_message(caplog):
    """A per-tenant push that returns batch SUCCESS with per-record errors must
    emit a [sync-error] WARNING carrying the sink's first-error message — so the
    cause reaches the hub log + GET_ERROR_LOGS (bugfixer). This is the LRB case
    (pushed 1, 180 errors) that previously slipped past collect_error_logs
    because ``errors=180`` doesn't match ``\\berror\\b``."""
    with caplog.at_level(logging.WARNING, logger="Hub"):
        h = _SyncHub(responses={
            ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
            ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
            ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"):
                {"payload": {"data": {"status": "SUCCESS", "pushed": 1, "errors": 180,
                                      "skipped": 0, "deleted": 0,
                                      "message": "1 upserted, 180 errors — first error: device_type required"}}},
        })
        status = await h.sync_tenant_devices("acme")
    assert status["status"] == "success"
    assert status["errors"] == 180
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("[sync-error]" in r.getMessage()
               and "first error: device_type required" in r.getMessage()
               and "tenant=acme" in r.getMessage() for r in warns), \
        "expected a [sync-error] WARNING with the sink's first-error message"