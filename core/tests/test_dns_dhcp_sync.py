"""Unit tests for the NetBox → Unbound/Kea auto-sync mixin (DnsDhcpSyncMixin).

Covers the shared extraction helpers, the ok / skipped / error status paths of
``sync_dns_from_netbox`` + ``sync_dhcp_from_netbox`` (the same helpers the
on-demand API routes call), and the config defaults that drive the loop cadence.
"""

import pytest

from dns_dhcp_sync import build_dns_records, build_dhcp_payload, DnsDhcpSyncMixin
from _fakes import FakeState


def _ips_payload():
    return {"ip_addresses": [
        {"address": "10.0.0.5/24", "dns_name": "host1.lab",
         "custom_fields": {"mac_address": "aa:bb:cc:dd:ee:ff"}},
        {"address": "10.0.0.6/24", "dns_name": "", "custom_fields": {}},   # no dns_name/mac → dropped
        {"address": "", "dns_name": "noaddr.lab"},                          # no address → dropped
    ]}


def _prefixes_payload():
    return {"prefixes": [
        {"prefix": "10.0.0.0/24", "description": "lab", "status": "active",
         "custom_fields": {"gateway": "10.0.0.1", "dns_servers": "10.0.0.53,10.0.0.54",
                            "dhcp_enabled": True}},
        {"prefix": "", "description": "skip-me"},                           # empty prefix → dropped
    ]}


class _DdsHub(DnsDhcpSyncMixin):
    """Minimal hub stand-in: canned request_response + configurable spoke routing."""

    def __init__(self, *, ipam="netbox-1", dns="dns-1", dhcp="dhcp-1",
                 system_state=None, raise_on=None):
        self.state = FakeState(system_state=system_state or {})
        self._spokes = {"ipam": ipam, "dns": dns, "dhcp": dhcp}
        self._raise_on = raise_on
        self.request_log = []

    def get_spoke_by_type(self, module_type):
        return self._spokes.get(module_type)

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        if self._raise_on and command == self._raise_on:
            raise RuntimeError("boom")
        if command == "NETBOX_GET_IPS":
            return {"payload": {"data": _ips_payload()}}
        if command == "NETBOX_GET_PREFIXES":
            return {"payload": {"data": _prefixes_payload()}}
        if command in ("DNS_SYNC", "DHCP_SYNC"):
            return {"payload": {"data": {"status": "SUCCESS", "added": 1, "skipped": 0}}}
        return {}


# ── extraction helpers ──────────────────────────────────────────────────────

def test_build_dns_records_only_named_with_address():
    recs = build_dns_records(_ips_payload())
    assert recs == [{"name": "host1.lab", "type": "A", "value": "10.0.0.5", "ttl": 300}]


def test_build_dns_records_ipv6_becomes_aaaa():
    """An IPv6 NetBox address must sync as AAAA, not A — Unbound's own record
    validation rejects an IPv6 value under type A, so before this fix a
    dual-stack device's v6 address was silently dropped by the sync loop."""
    ips = {"ip_addresses": [
        {"address": "2001:470:4948:1::10/64", "dns_name": "host1.lab",
         "custom_fields": {}},
        {"address": "10.0.0.5/24", "dns_name": "host1.lab", "custom_fields": {}},
        {"address": "not-an-ip/64", "dns_name": "broken.lab", "custom_fields": {}},
    ]}
    recs = build_dns_records(ips)
    assert {"name": "host1.lab", "type": "AAAA", "value": "2001:470:4948:1::10", "ttl": 300} in recs
    assert {"name": "host1.lab", "type": "A", "value": "10.0.0.5", "ttl": 300} in recs
    assert len(recs) == 2  # the malformed address is skipped, not mis-synced


def test_build_dhcp_payload_subnets_and_reservations():
    subs, res = build_dhcp_payload(_prefixes_payload(), _ips_payload())
    assert len(subs) == 1
    assert subs[0]["subnet"] == "10.0.0.0/24"
    assert subs[0]["gateway"] == "10.0.0.1"
    assert subs[0]["dns_servers"] == ["10.0.0.53", "10.0.0.54"]
    assert res == [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff",
                    "hostname": "host1.lab", "subnet": ""}]


def test_build_dhcp_payload_reads_advanced_dhcp_option_custom_fields():
    pfx = {"prefixes": [
        {"prefix": "10.0.2.0/24", "description": "advanced opts", "status": "active",
         "custom_fields": {
             "dhcp_enabled": True,
             "gateway": "10.0.2.1",
             "dns_servers": "10.0.2.53",
             "search_domain": "lab.local, corp.local",
             "domain_name": "lab.local",
             "ntp_servers": "10.0.2.4",
             "tftp_server_name": "tftp.lab.local",
             "boot_file_name": "pxelinux.0",
             "netbios_name_servers": "10.0.2.5",
             "broadcast_address": "10.0.2.255",
             "lease_time": 7200,
             "exclusion_ranges": "10.0.2.1-10.0.2.20, 10.0.2.200-10.0.2.254",
         }},
    ]}
    subs, _ = build_dhcp_payload(pfx, {"ip_addresses": []})
    assert len(subs) == 1
    s = subs[0]
    assert s["search_domains"] == ["lab.local", "corp.local"]
    assert s["domain_name"] == "lab.local"
    assert s["ntp_servers"] == ["10.0.2.4"]
    assert s["tftp_server_name"] == "tftp.lab.local"
    assert s["boot_file_name"] == "pxelinux.0"
    assert s["netbios_name_servers"] == ["10.0.2.5"]
    assert s["broadcast_address"] == "10.0.2.255"
    assert s["lease_time"] == 7200
    assert s["exclusion_ranges"] == "10.0.2.1-10.0.2.20, 10.0.2.200-10.0.2.254"


def test_build_dhcp_payload_advanced_options_default_empty():
    subs, _ = build_dhcp_payload(_prefixes_payload(), _ips_payload())
    s = subs[0]
    assert s["search_domains"] == []
    assert s["domain_name"] == ""
    assert s["ntp_servers"] == []
    assert s["lease_time"] is None


def test_build_dhcp_payload_skips_container_prefix():
    """A NetBox 'container' prefix (a parent/aggregate block, e.g. a tenant's
    whole /17) must never be synced as a DHCP scope itself, even if somehow
    dhcp_enabled were set on it."""
    pfx = {"prefixes": [
        {"prefix": "172.17.0.0/17", "description": "SHARED tenant block",
         "status": "container", "custom_fields": {"dhcp_enabled": True}},
    ]}
    subs, _ = build_dhcp_payload(pfx, {"ip_addresses": []})
    assert subs == []


def test_build_dhcp_payload_skips_prefix_not_opted_in():
    """A normal (non-container) prefix without dhcp_enabled set must be
    excluded — the checkbox is the only way a prefix becomes a Kea scope."""
    pfx = {"prefixes": [
        {"prefix": "10.0.1.0/24", "description": "not opted in",
         "status": "active", "custom_fields": {}},
    ]}
    subs, _ = build_dhcp_payload(pfx, {"ip_addresses": []})
    assert subs == []


def test_build_dhcp_payload_includes_carved_child_prefix():
    """Carving a smaller child prefix out of a container parent and enabling
    dhcp_enabled on the CHILD (not the parent) is the supported way to scope
    DHCP down from a large tenant allocation."""
    pfx = {"prefixes": [
        {"prefix": "172.17.0.0/17", "description": "SHARED parent",
         "status": "container", "custom_fields": {}},
        {"prefix": "172.17.0.0/24", "description": "SHARED - VLAN10",
         "status": "active", "custom_fields": {"dhcp_enabled": True}},
    ]}
    subs, _ = build_dhcp_payload(pfx, {"ip_addresses": []})
    assert len(subs) == 1
    assert subs[0]["subnet"] == "172.17.0.0/24"
    assert subs[0]["description"] == "SHARED - VLAN10"


# ── sync_dns_from_netbox ─────────────────────────────────────────────────────

async def test_sync_dns_ok():
    hub = _DdsHub()
    r = await hub.sync_dns_from_netbox()
    assert r["status"] == "ok"
    assert r["records_synced"] == 1
    # DNS_SYNC was pushed with the built records
    pushed = [c for c in hub.request_log if c[1] == "DNS_SYNC"]
    assert pushed and pushed[0][2]["records"][0]["name"] == "host1.lab"
    # status recorded for the WebUI tile
    assert hub.dns_dhcp_sync_status["dns"]["status"] == "ok"


async def test_sync_dns_skipped_when_dns_spoke_offline():
    hub = _DdsHub(dns=None)
    r = await hub.sync_dns_from_netbox()
    assert r["status"] == "skipped" and "DNS" in r["reason"]
    assert not any(c[1] == "DNS_SYNC" for c in hub.request_log)


async def test_sync_dns_skipped_when_netbox_offline():
    hub = _DdsHub(ipam=None)
    r = await hub.sync_dns_from_netbox()
    assert r["status"] == "skipped" and "NetBox" in r["reason"]


async def test_sync_dns_error_path_records_status():
    hub = _DdsHub(raise_on="NETBOX_GET_IPS")
    r = await hub.sync_dns_from_netbox()
    assert r["status"] == "error" and r["error"]
    assert hub.dns_dhcp_sync_status["dns"]["status"] == "error"


# ── sync_dhcp_from_netbox ────────────────────────────────────────────────────

async def test_sync_dhcp_ok():
    hub = _DdsHub()
    r = await hub.sync_dhcp_from_netbox()
    assert r["status"] == "ok"
    assert r["subnets_synced"] == 1 and r["reservations_synced"] == 1
    pushed = [c for c in hub.request_log if c[1] == "DHCP_SYNC"]
    assert pushed and pushed[0][2]["subnets"][0]["subnet"] == "10.0.0.0/24"


async def test_sync_dhcp_skipped_when_dhcp_spoke_offline():
    hub = _DdsHub(dhcp=None)
    r = await hub.sync_dhcp_from_netbox()
    assert r["status"] == "skipped" and "DHCP" in r["reason"]


async def test_sync_dhcp_error_path():
    hub = _DdsHub(raise_on="DHCP_SYNC")
    r = await hub.sync_dhcp_from_netbox()
    assert r["status"] == "error"


# ── config defaults ──────────────────────────────────────────────────────────

def test_dds_cfg_defaults_enabled_and_interval():
    hub = _DdsHub()
    cfg = hub._dds_cfg()
    assert cfg["enabled"] is True and cfg["interval"] == 300


def test_dds_cfg_reads_overrides():
    hub = _DdsHub(system_state={"global_config": {
        "dns_dhcp_sync": {"enabled": False, "interval": 60}}})
    cfg = hub._dds_cfg()
    assert cfg["enabled"] is False and cfg["interval"] == 60


# ── DHCP scope domain suffix ────────────────────────────────────────────────

def _scoped_prefixes():
    return {"prefixes": [
        {"prefix": "10.0.0.0/16", "status": "active",
         "custom_fields": {"dhcp_enabled": True, "domain_name": "corp.example"}},
        {"prefix": "10.0.5.0/24", "status": "active",
         "custom_fields": {"dhcp_enabled": True, "domain_name": "Lab.Example."}},
        {"prefix": "10.9.0.0/24", "status": "active",          # not a DHCP scope
         "custom_fields": {"dhcp_enabled": False, "domain_name": "nope.example"}},
        {"prefix": "10.8.0.0/24", "status": "active",          # invalid domain ignored
         "custom_fields": {"dhcp_enabled": True, "domain_name": "bad domain"}},
    ]}


def test_build_dns_records_appends_containing_scope_domain():
    ips = {"ip_addresses": [
        {"address": "10.0.5.7/24", "dns_name": "printer1"},     # most specific scope wins
        {"address": "10.0.9.7/24", "dns_name": "laptop2"},      # falls to the /16
        {"address": "10.0.5.8/24", "dns_name": "already.fq.dn"},  # dotted → untouched
        {"address": "10.9.0.4/24", "dns_name": "nodhcp"},       # not in a DHCP scope
        {"address": "10.8.0.4/24", "dns_name": "badscope"},
        {"address": "192.168.1.1/24", "dns_name": "outside"},
    ]}
    names = {r["value"]: r["name"] for r in build_dns_records(ips, _scoped_prefixes())}
    assert names == {"10.0.5.7": "printer1.lab.example", "10.0.9.7": "laptop2.corp.example",
                     "10.0.5.8": "already.fq.dn", "10.9.0.4": "nodhcp",
                     "10.8.0.4": "badscope", "192.168.1.1": "outside"}


def test_build_dns_records_without_prefixes_is_unchanged():
    assert build_dns_records(_ips_payload()) == build_dns_records(_ips_payload(), {"prefixes": []})


@pytest.mark.asyncio
async def test_sync_dns_qualifies_names_with_scope_domain():
    hub = _DdsHub()
    hub_prefixes = {"prefixes": [{"prefix": "10.0.0.0/24", "status": "active",
                                  "custom_fields": {"dhcp_enabled": True, "domain_name": "lab"}}]}
    ips = {"ip_addresses": [{"address": "10.0.0.9/24", "dns_name": "ws9"}]}

    async def rr(spoke_id, command, payload, timeout=30.0):
        hub.request_log.append((spoke_id, command, payload))
        if command == "NETBOX_GET_IPS":
            return {"payload": {"data": ips}}
        if command == "NETBOX_GET_PREFIXES":
            return {"payload": {"data": hub_prefixes}}
        return {"payload": {"data": {"status": "SUCCESS"}}}
    hub.request_response = rr
    res = await hub.sync_dns_from_netbox()
    assert res["status"] == "ok"
    sent = next(p for _, c, p in hub.request_log if c == "DNS_SYNC")
    assert sent["records"][0]["name"] == "ws9.lab"


# ── real-time DHCP→DNS hook reconcile ──────────────────────────────────────

class _HookHub(_DdsHub):
    def __init__(self, node_status, gc=None, config_reply=None):
        super().__init__(system_state={"global_config": gc or {}})
        self.node_status = node_status
        self.config_reply = config_reply or {"status": "SUCCESS"}

    def _get_dhcp_spokes(self):
        return ["dhcp-1"]

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        if command == "DHCP_DNS_HOOK_STATUS":
            return {"payload": {"data": self.node_status}}
        if command == "DHCP_DNS_HOOK_CONFIG":
            return {"payload": {"data": self.config_reply}}
        return {}


def _node(enabled, loaded, **over):
    s = {"enabled": enabled, "targets": ["127.0.0.1@8953"], "domain": "", "ttl": 300,
         "register_ptr": False}
    s.update(over)
    return {"status": "SUCCESS", "settings": s, "loaded_in_running_config": loaded}


def _configs(hub):
    return [p for _, c, p in hub.request_log if c == "DHCP_DNS_HOOK_CONFIG"]


def test_dns_hook_desired_defaults_on():
    d = _HookHub(_node(False, False))._dns_hook_desired()
    assert d == {"enabled": True, "targets": ["127.0.0.1@8953"], "domain": "",
                 "ttl": 300, "register_ptr": False}


@pytest.mark.asyncio
async def test_dns_hook_enabled_by_default_on_unconfigured_spoke():
    hub = _HookHub(_node(False, False))
    res = await hub._reconcile_dns_hook()
    assert res["status"] == "ok" and res["applied"] == ["dhcp-1"]
    assert _configs(hub)[0]["settings"]["enabled"] is True
    assert hub.dns_dhcp_sync_status["dns_hook"]["enabled"] is True


@pytest.mark.asyncio
async def test_dns_hook_converged_spoke_is_not_repushed():
    hub = _HookHub(_node(True, True))
    res = await hub._reconcile_dns_hook()
    assert res["applied"] == [] and _configs(hub) == []


@pytest.mark.asyncio
async def test_dns_hook_knob_off_disables_and_ptr_drift_repushes():
    hub = _HookHub(_node(True, True), gc={"dhcp_dns_hook": {"enabled": False}})
    await hub._reconcile_dns_hook()
    assert _configs(hub)[0]["settings"]["enabled"] is False

    off = _HookHub(_node(False, False), gc={"dhcp_dns_hook": {"enabled": False}})
    await off._reconcile_dns_hook()
    assert _configs(off) == []

    ptr = _HookHub(_node(True, True), gc={"dhcp_dns_hook": {"register_ptr": True}})
    await ptr._reconcile_dns_hook()
    assert _configs(ptr)[0]["settings"]["register_ptr"] is True


@pytest.mark.asyncio
async def test_dns_hook_ha_pair_one_member_drifted_and_errors_reported():
    ha = {"status": "SUCCESS", "members": {"a": _node(True, True), "b": _node(False, False)}}
    hub = _HookHub(ha)
    await hub._reconcile_dns_hook()
    assert len(_configs(hub)) == 1

    bad = _HookHub(_node(False, False), config_reply={"status": "ERROR", "message": "nope"})
    res = await bad._reconcile_dns_hook()
    assert res["status"] == "error" and res["errors"] == {"dhcp-1": "nope"}

    old = _HookHub({"status": "ERROR", "error": "Unknown command: DHCP_DNS_HOOK_STATUS"})
    res = await old._reconcile_dns_hook()
    assert res["status"] == "error" and _configs(old) == []


# ── NetBox fetch failure must never wipe Kea ────────────────────────────────

class _MultiIpamHub(_DdsHub):
    """Two IPAM spokes: ``nb-broken`` answers like a netbox role with no URL
    configured (status ERROR, no prefixes key), ``nb-good`` is healthy."""

    def __init__(self, ipams, broken=("nb-broken",), **kw):
        super().__init__(ipam=ipams[0], **kw)
        self._ipams = list(ipams)
        self._broken = set(broken)

    def get_all_spokes_by_type(self, module_type):
        if module_type == "ipam":
            return list(self._ipams)
        return [self._spokes[module_type]] if self._spokes.get(module_type) else []

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        if spoke_id in self._broken and command.startswith("NETBOX_GET_"):
            self.request_log.append((spoke_id, command, payload))
            return {"payload": {"data": {"status": "ERROR", "message":
                    "HTTPConnectionPool(host='localhost', port=8000): Connection refused"}}}
        return await super().request_response(spoke_id, command, payload, timeout)


@pytest.mark.asyncio
async def test_netbox_error_never_pushes_empty_dhcp_payload():
    hub = _MultiIpamHub(["nb-broken"])
    await hub._sync_dns_dhcp_once()
    assert not [c for _, c, _ in hub.request_log if c in ("DHCP_SYNC", "DNS_SYNC")]
    assert hub.dns_dhcp_sync_status["dhcp"]["status"] == "error"
    assert "Connection refused" in hub.dns_dhcp_sync_status["dhcp"]["error"]

    res = await hub.sync_dhcp_from_netbox()
    assert res["status"] == "error"
    assert not [c for _, c, _ in hub.request_log if c == "DHCP_SYNC"]


@pytest.mark.asyncio
async def test_netbox_fetch_fails_over_to_healthy_ipam_spoke():
    hub = _MultiIpamHub(["nb-broken", "nb-good"])
    await hub._sync_dns_dhcp_once()
    sent = [p for _, c, p in hub.request_log if c == "DHCP_SYNC"]
    assert sent and [s["subnet"] for s in sent[0]["subnets"]] == ["10.0.0.0/24"]


def test_ipam_candidates_prefer_instance_bound_spoke():
    hub = _MultiIpamHub(["nb-broken", "nb-good"], system_state={"global_config": {
        "ipam_instances": [{"spoke_id": "nb-good", "url": "https://nb"}]}})
    assert hub._ipam_spoke_candidates() == ["nb-good", "nb-broken"]
