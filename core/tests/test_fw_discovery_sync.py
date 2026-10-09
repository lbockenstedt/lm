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


REQUIRED_SOURCE_KEYS = {"module_type", "dhcp_command", "label"}
_OPNSENSE = FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]
_KEA = FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["kea"]


# ── registry / config contract (sync) ───────────────────────────────────────

def test_firewall_sources_registry_shape():
    for name, entry in FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES.items():
        assert REQUIRED_SOURCE_KEYS <= set(entry), \
            f"source {name} missing keys: {REQUIRED_SOURCE_KEYS - set(entry)}"
        # arp_command is OPTIONAL — a source may have no ARP table at all (Kea
        # only knows what it leased). If declared it must be usable, because
        # the pull skips ARP entirely on a falsy value.
        if "arp_command" in entry:
            assert entry["arp_command"], f"source {name} has an empty arp_command"
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
    m.get_all_spokes_by_type = lambda mt: ["opn-1"] if mt == "firewall" else []
    assert m._fw_discovery_source() is FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]


def test_unknown_source_falls_back_to_auto_case_insensitive():
    # An unrecognized explicit name now falls back to "auto" (every connected
    # source) rather than a single hard-coded product — same safety net, wider.
    m = FwDiscoverySyncMixin()
    m.get_all_spokes_by_type = lambda mt: ["opn-1"] if mt == "firewall" else []
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"source": "  PALO-ALTO-SOMEDAY  "}}})
    assert m._fw_discovery_source() is FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"source": "  OPNSENSE  "}}})
    assert m._fw_discovery_source() is FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]


def test_discovery_sources_auto_resolves_every_connected_source():
    m = FwDiscoverySyncMixin()
    m.get_all_spokes_by_type = lambda mt: ["opn-1"] if mt == "firewall" else (["dhcp-1"] if mt == "dhcp" else [])
    m.state = FakeState(system_state={"global_config": {}})
    names = {n for n, _ in m._fw_discovery_sources()}
    assert names == {"opnsense", "kea"}


def test_discovery_sources_pinned_name_returns_only_that_one():
    m = FwDiscoverySyncMixin()
    m.get_all_spokes_by_type = lambda mt: ["opn-1"] if mt == "firewall" else (["dhcp-1"] if mt == "dhcp" else [])
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"source": "kea"}}})
    names = [n for n, _ in m._fw_discovery_sources()]
    assert names == ["kea"]


def test_discovery_sources_excludes_disconnected_sources_in_auto_mode():
    m = FwDiscoverySyncMixin()
    m.get_all_spokes_by_type = lambda mt: [] if mt == "dhcp" else ["opn-1"]
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"source": "auto"}}})
    names = {n for n, _ in m._fw_discovery_sources()}
    assert names == {"opnsense"}


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
    opnsense = FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["opnsense"]
    m = FwDiscoverySyncMixin()
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"firewall_id": "fw1"}}})
    m.get_spoke_for_firewall = lambda fid: "opn-fw1" if fid == "fw1" else None
    m.get_all_spokes_by_type = lambda mt: ["opn-a", "opn-b"]
    assert m._fw_firewall_spokes(opnsense) == ["opn-fw1"]
    # unpinned → all connected firewall spokes
    m.state = FakeState(system_state={"global_config": {}})
    assert m._fw_firewall_spokes(opnsense) == ["opn-a", "opn-b"]
    # pinned but firewall not found → empty (no fallback to all)
    m.state = FakeState(system_state={"global_config": {"opnsense_netbox_device_sync": {"firewall_id": "ghost"}}})
    assert m._fw_firewall_spokes(opnsense) == []


# ── canned-relay hub (async) ────────────────────────────────────────────────

class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = {}
        self._last_nonzero_tenants = {}

    async def set_fw_discovery_sync_status(self, tenant_id, status):
        self.recorded[tenant_id] = status

    async def get_fw_discovery_last_nonzero_tenants(self, source_label):
        return list(self._last_nonzero_tenants.get(source_label) or [])

    async def set_fw_discovery_last_nonzero_tenants(self, source_label, tenant_ids):
        self._last_nonzero_tenants[source_label] = sorted(set(tenant_ids or []))


class _SyncHub(FwDiscoverySyncMixin):
    """Minimal hub stand-in: canned request_response + spoke routing. The real
    ``access.fetch_tenant_prefixes`` runs through this (it only needs
    hub.get_spoke_by_type('ipam') + hub.state.get_tenant, both faked)."""

    def __init__(self, responses=None, tenants=None, global_config=None,
                 fw_spokes=None, netbox_spoke="netbox-spoke-1",
                 fw_spoke_type="firewall"):
        # The sync mixins read cfg from ``state.system_state["global_config"]``
        # (not FakeState._global_config), so embed it there.
        self.state = FakeState(
            system_state={"global_config": global_config or {}},
            tenants=tenants or {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}},
        )
        self.refreshed_caches = []
        self.simulations_store = _FakeSimulationsStore()
        self._responses = responses or {}
        self._fw_spokes = fw_spokes if fw_spokes is not None else ["opn-fw1"]
        self._fw_spoke_type = fw_spoke_type
        self._netbox_spoke = netbox_spoke
        self.request_log = []

    def get_spoke_by_type(self, module_type):
        return self._netbox_spoke if module_type == "ipam" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._fw_spokes) if module_type == self._fw_spoke_type else []

    def get_spoke_for_firewall(self, firewall_id):
        return self._fw_spokes[0] if self._fw_spokes else None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        return self._responses[(spoke_id, command)]



    # The sync mixins invalidate the tenant module-cache at the end of a cycle
    # that actually changed spoke data (main.Hub.refresh_module_cache). Record
    # the keys so tests can assert the refresh fired instead of silently
    # tolerating its absence.
    def refresh_module_cache(self, key):
        self.refreshed_caches.append(key)


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
    records, info = await h._fw_pull_discovered(_OPNSENSE)
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
    records, _ = await h._fw_pull_discovered(_OPNSENSE)
    cmds = [c for _, c, _ in h.request_log]
    assert "OPNSENSE_GET_DHCP_LEASES" not in cmds
    assert "OPNSENSE_GET_ARP_TABLE" in cmds
    assert len(records) == 3  # the three ARP rows


@pytest.mark.asyncio
async def test_pull_error_surfaces_opnsense_details_message_not_generic_fallback():
    """OPNsense's engine classifies an API/transport failure as
    ``{"status": "ERROR", "details": {...real error...}}`` — it never puts the
    real reason under a top-level "message" key. Reading only "message" here
    silently fell back to the generic string "error" in production (hub.log
    showed e.g. "DHCP(<spoke>): error" for every cycle), hiding the actual
    OPNsense API failure. The real text must be pulled out of "details"."""
    h = _SyncHub(responses={
        ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): {"payload": {"data": {
            "status": "ERROR",
            "details": {"status": "ERROR", "message": "Empty response from server"},
        }}},
        ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): {"payload": {"data": {
            "status": "ERROR",
            "details": {"error": "invalid API credentials"},
        }}},
        ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
    })
    _, info = await h._fw_pull_discovered(_OPNSENSE)
    assert any("Empty response from server" in e for e in info["errors"])
    assert any("invalid API credentials" in e for e in info["errors"])
    assert not any(e.endswith(": error") for e in info["errors"])


@pytest.mark.asyncio
async def test_attribute_buckets_by_prefix_and_drops_unattributed():
    h = _hub_with_full_responses()
    records, _ = await h._fw_pull_discovered(_OPNSENSE)
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


@pytest.mark.asyncio
async def test_run_all_skips_push_entirely_when_pull_has_any_error():
    """A multi-spoke source where one spoke's fetch fails must not push at
    all — a partial record set could make the sink's replace=True delete
    devices only the failed spoke knew about."""
    h = _SyncHub(
        fw_spokes=["opn-fw1", "opn-fw2"],
        responses={
            ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
            ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
            # opn-fw2 has NO canned response at all → request_response raises
            # KeyError → _fetch records it as a pull error for this source.
            ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(2),
        },
    )
    agg = await h.run_fw_discovery_sync_all()
    assert agg["results"] == []
    assert not any(cmd == "NETBOX_SYNC_DEVICES" for _, cmd, _ in h.request_log)


@pytest.mark.asyncio
async def test_sync_tenant_devices_skips_push_when_pull_has_any_error():
    h = _SyncHub(
        fw_spokes=["opn-fw1", "opn-fw2"],
        responses={
            ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
            ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
            ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(2),
        },
    )
    status = await h.sync_tenant_devices("acme")
    assert status["status"] == "error"
    assert "pull failed" in status["message"]
    assert not any(cmd == "NETBOX_SYNC_DEVICES" for _, cmd, _ in h.request_log)


@pytest.mark.asyncio
async def test_run_all_reconciles_tenant_that_drops_to_zero_records():
    """A tenant with devices this cycle, then zero the next (clean pull, no
    errors), must still get an empty replace=True push so the sink deletes
    the now-stale NetBox devices — ``buckets`` has no entry for a
    zero-record tenant, so without explicit reconciliation it would never be
    pushed again at all."""
    h = _hub_with_full_responses()
    await h.run_fw_discovery_sync_all()
    assert any(cmd == "NETBOX_SYNC_DEVICES" for _, cmd, _ in h.request_log)

    # Next cycle: this source now returns zero usable records for the tenant.
    h._responses[("opn-fw1", "OPNSENSE_GET_DHCP_LEASES")] = {
        "payload": {"data": {"status": "SUCCESS", "data": []}}}
    h._responses[("opn-fw1", "OPNSENSE_GET_ARP_TABLE")] = {
        "payload": {"data": {"status": "SUCCESS", "data": []}}}
    h.request_log.clear()
    agg = await h.run_fw_discovery_sync_all()
    push = next(p for sid, cmd, p in h.request_log
                if cmd == "NETBOX_SYNC_DEVICES" and sid == "netbox-spoke-1")
    assert push["tenant_slug"] == "acme"
    assert push["devices"] == []
    assert agg["results"][0]["tenant_id"] == "acme"
    assert len(agg["results"]) == 1
    assert agg["results"][0]["tenant_id"] == "acme"
    assert agg["results"][0]["pushed"] == 2


@pytest.mark.asyncio
async def test_push_with_errors_emits_sync_error_marker_with_message(caplog):
    """A per-tenant push that returns batch SUCCESS with per-record errors must
    emit a [sync-error] WARNING carrying the sink's first-error message — so the
    cause reaches the hub log + GET_ERROR_LOGS (ab). This is the LRB case
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
    assert status["status"] == "error"
    assert status["errors"] == 180
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("[sync-error]" in r.getMessage()
               and "first error: device_type required" in r.getMessage()
               and "tenant=acme" in r.getMessage() for r in warns), \
        "expected a [sync-error] WARNING with the sink's first-error message"

# ── Kea (LM DHCP) source ────────────────────────────────────────────────────
# When DHCP moves off the firewall onto the LM DHCP module, OPNsense stops
# seeing leases and nothing reaches NetBox — the leases are visible in the DHCP
# UI (which reads Kea directly) and go nowhere else. These lock in the Kea
# source end-to-end: spoke selection by the registry's module_type, Kea's own
# response envelope/field names, and no ARP command being invented for it.

def test_kea_source_contract():
    se = FwDiscoverySyncMixin.FIREWALL_DISCOVERY_SOURCES["kea"]
    assert se["module_type"] == "dhcp"          # not "firewall"
    assert se["dhcp_command"] == "DHCP_LIST_LEASES"
    assert se["rows_key"] == "leases"           # Kea answers {"leases": [...]}
    assert "arp_command" not in se              # Kea has no ARP table


def _kea_cfg(**over):
    cfg = {"source": "kea"}
    cfg.update(over)
    return {"opnsense_netbox_device_sync": cfg}


def _kea_lease_payload():
    # Kea's native envelope + field names, as dhcp_spoke returns them:
    # {"status": "SUCCESS", "leases": [{"ip-address", "hw-address", ...}]}
    return {"payload": {"data": {"status": "SUCCESS", "leases": [
        {"ip-address": "10.20.0.5", "hw-address": "AA-BB-CC-DD-EE-05",
         "hostname": "kea-ws", "state": 0},
        {"ip-address": "10.20.0.77", "hw-address": "aa:bb:cc:dd:ee:77",
         "hostname": "", "state": 0},
    ]}}}


def _kea_hub(**over):
    return _SyncHub(global_config=_kea_cfg(**over), fw_spokes=["dhcp-spoke-1"],
                    fw_spoke_type="dhcp", responses={
        ("dhcp-spoke-1", "DHCP_LIST_LEASES"): _kea_lease_payload(),
        ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
        ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(2),
    })


def test_kea_source_selects_dhcp_spokes_not_firewall_spokes():
    h = _kea_hub()
    assert h._fw_firewall_spokes(_KEA) == ["dhcp-spoke-1"]


def test_pinned_firewall_id_is_ignored_for_a_non_firewall_source():
    # firewall_id pins an OPNsense box; it must not hijack the Kea pull. The
    # old hard-coded path took the pinned branch for ANY source and would
    # return the firewall spoke here.
    h = _kea_hub(firewall_id="fw-abc")
    h.get_spoke_for_firewall = lambda firewall_id: "opn-fw1"
    assert h._fw_firewall_spokes(_KEA) == ["dhcp-spoke-1"]


@pytest.mark.asyncio
async def test_kea_leases_are_parsed_from_native_envelope_and_fields():
    h = _kea_hub()
    records, info = await h._fw_pull_discovered(_KEA)
    assert info["errors"] == []
    by_ip = {r["ip"]: r for r in records}
    assert set(by_ip) == {"10.20.0.5", "10.20.0.77"}
    # hw-address read + normalized even though the key isn't "mac"
    assert by_ip["10.20.0.5"]["mac"] == "aa:bb:cc:dd:ee:05"
    assert by_ip["10.20.0.5"]["hostname"] == "kea-ws"
    assert by_ip["10.20.0.77"]["mac"] == "aa:bb:cc:dd:ee:77"


@pytest.mark.asyncio
async def test_kea_pull_never_issues_an_arp_command():
    # source_data defaults to "both"; with no arp_command the ARP fetch must be
    # skipped rather than falling back to OPNSENSE_GET_ARP_TABLE, which a DHCP
    # spoke cannot answer (it would error every cycle).
    h = _kea_hub()
    records, info = await h._fw_pull_discovered(_KEA)
    cmds = [c for _, c, _ in h.request_log]
    assert "OPNSENSE_GET_ARP_TABLE" not in cmds
    assert "DHCP_LIST_LEASES" in cmds
    assert info["errors"] == []
    assert len(records) == 2


@pytest.mark.asyncio
async def test_kea_discovered_leases_reach_the_netbox_push():
    h = _kea_hub()
    records, _ = await h._fw_pull_discovered(_KEA)
    buckets, dropped = await h._fw_attribute(records)
    assert dropped == 0
    assert {r["ip"] for r in buckets["acme"]} == {"10.20.0.5", "10.20.0.77"}


@pytest.mark.asyncio
async def test_dhcp_hostname_wins_over_arp_on_merge():
    # Regression: the merge compared _src against lowercase "dhcp" while the
    # fetch tags rows "DHCP", so this rule never fired and ARP's hostname could
    # overwrite the authoritative DHCP one.
    h = _SyncHub(responses={
        ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): {"payload": {"data": {
            "status": "SUCCESS", "data": [
                {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:05", "hostname": "from-dhcp"},
            ]}}},
        ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): {"payload": {"data": {
            "status": "SUCCESS", "data": [
                {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:05", "hostname": "from-arp"},
            ]}}},
        ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
    })
    records, _ = await h._fw_pull_discovered(_OPNSENSE)
    assert len(records) == 1
    assert records[0]["hostname"] == "from-dhcp"


# ── multi-source ("auto") end-to-end ────────────────────────────────────────
# With both OPNsense and Kea connected and no pinned "source", the resolver
# must pull+push BOTH, entirely separately (never merged into one NETBOX_SYNC_
# DEVICES payload — that would let one source's replace=True wrongly delete
# the other's devices), then combine the two resulting statuses into the one
# record the status store/UI expects.

def _dual_source_hub(**responses_extra):
    h = _SyncHub(
        global_config={},  # unset → "auto"
        fw_spokes=["opn-fw1"], fw_spoke_type="firewall",
        responses={
            ("opn-fw1", "OPNSENSE_GET_DHCP_LEASES"): _dhcp_payload(),
            ("opn-fw1", "OPNSENSE_GET_ARP_TABLE"): _arp_payload(),
            ("dhcp-spoke-1", "DHCP_LIST_LEASES"): _kea_lease_payload(),
            ("netbox-spoke-1", "NETBOX_GET_PREFIXES"): _prefixes_payload(),
            ("netbox-spoke-1", "NETBOX_SYNC_DEVICES"): _sync_devices_ok(2),
            **responses_extra,
        },
    )
    # _SyncHub.get_all_spokes_by_type only knows one fw_spoke_type; patch it to
    # report both "firewall" (opnsense) and "dhcp" (kea) as connected.
    h.get_all_spokes_by_type = lambda mt: (
        ["opn-fw1"] if mt == "firewall" else (["dhcp-spoke-1"] if mt == "dhcp" else []))
    h.get_spoke_for_firewall = lambda fid: None
    return h


def test_auto_resolves_both_connected_sources():
    h = _dual_source_hub()
    names = [n for n, _ in h._fw_discovery_sources()]
    assert set(names) == {"opnsense", "kea"}


@pytest.mark.asyncio
async def test_auto_mode_pushes_each_source_separately_not_merged():
    h = _dual_source_hub()
    status = await h.sync_tenant_devices("acme")
    pushes = [p for sid, cmd, p in h.request_log if cmd == "NETBOX_SYNC_DEVICES"]
    # Two independent pushes, one per source — never one merged payload.
    assert len(pushes) == 2
    sources_pushed = {p["source"] for p in pushes}
    assert sources_pushed == {"OPNsense", "Kea (LM DHCP)"}
    for p in pushes:
        assert p["replace"] is True
        assert p["tenant_slug"] == "acme"
    # Combined status sums both sources' pushed counts.
    assert status["pushed"] == 4
    assert len(status["sources"]) == 2
    assert status["status"] == "success"


@pytest.mark.asyncio
async def test_auto_mode_combines_statuses_when_one_source_errors():
    # Kea's push fails (NetBox rejects it) while OPNsense succeeds — the
    # combined status must still read "error" so the UI surfaces the failure,
    # while OPNsense's successful push is NOT lost.
    h = _dual_source_hub()
    call_count = {"n": 0}
    orig = h.request_response

    async def flaky(spoke_id, command, payload, timeout=30.0):
        if command == "NETBOX_SYNC_DEVICES":
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise RuntimeError("netbox spoke timed out")
        return await orig(spoke_id, command, payload, timeout)

    h.request_response = flaky
    status = await h.sync_tenant_devices("acme")
    assert status["status"] == "error"
    assert any(s.get("status") == "success" for s in status["sources"])
    assert any(s.get("status") == "error" for s in status["sources"])


def test_combine_statuses_single_source_passthrough():
    m = FwDiscoverySyncMixin()
    s = {"tenant_id": "acme", "status": "success", "pushed": 2, "errors": 0,
         "skipped": 0, "deleted": 0, "message": "ok", "source": "OPNsense"}
    combined = m._fw_combine_statuses([s])
    assert combined["pushed"] == 2
    assert combined["sources"] == [s]


def test_combine_statuses_merges_counters_and_escalates_status():
    m = FwDiscoverySyncMixin()
    s1 = {"tenant_id": "acme", "tenant_name": "Acme", "status": "success",
          "pushed": 2, "errors": 0, "skipped": 0, "deleted": 0,
          "message": "2 device(s) sent", "source": "OPNsense", "last_sync_ts": "a"}
    s2 = {"tenant_id": "acme", "tenant_name": "Acme", "status": "error",
          "pushed": 0, "errors": 1, "skipped": 0, "deleted": 0,
          "message": "NetBox spoke not connected", "source": "Kea (LM DHCP)", "last_sync_ts": "b"}
    combined = m._fw_combine_statuses([s1, s2])
    assert combined["status"] == "error"
    assert combined["pushed"] == 2
    assert combined["errors"] == 1
    assert "OPNsense: 2 device(s) sent" in combined["message"]
    assert "Kea (LM DHCP): NetBox spoke not connected" in combined["message"]
    assert combined["sources"] == [s1, s2]
