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
        {"prefix": "10.0.0.0/24", "description": "lab",
         "custom_fields": {"gateway": "10.0.0.1", "dns_servers": "10.0.0.53,10.0.0.54"}},
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


def test_build_dhcp_payload_subnets_and_reservations():
    subs, res = build_dhcp_payload(_prefixes_payload(), _ips_payload())
    assert len(subs) == 1
    assert subs[0]["subnet"] == "10.0.0.0/24"
    assert subs[0]["gateway"] == "10.0.0.1"
    assert subs[0]["dns_servers"] == ["10.0.0.53", "10.0.0.54"]
    assert res == [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff",
                    "hostname": "host1.lab", "subnet": ""}]


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
