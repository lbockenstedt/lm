"""Discovery records carry where their hostname came from.

DNS A records and DHCP reservations are operator assertions (one name = one
device, so the NetBox sink joins a second address to the same device); a DHCP
lease hostname is device-chosen (many Sonos speakers say "sonoszp").
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nw_discovery_sync import NwDiscoverySyncMixin  # noqa: E402


class _Hub(NwDiscoverySyncMixin):
    def __init__(self, replies):
        self._replies = replies

    def _nw_discovery_cfg(self):
        return {}

    def get_all_spokes_by_type(self, mtype):
        return [mtype]

    async def request_response(self, sid, cmd, payload, timeout=0):
        return self._replies.get(cmd, {"status": "SUCCESS"})


def test_records_are_tagged_with_their_hostname_source():
    hub = _Hub({
        "DHCP_LIST_RES": {"status": "SUCCESS", "reservations": [
            {"ip": "10.0.0.5", "mac": "aa:aa:aa:aa:aa:05", "hostname": "agg"}]},
        "DHCP_LIST_LEASES": {"status": "SUCCESS", "leases": [
            {"ip": "10.0.0.9", "mac": "aa:aa:aa:aa:aa:09", "hostname": "sonoszp", "state": 0}]},
        "DNS_LIST": {"status": "SUCCESS", "records": [
            {"type": "A", "name": "agg.example.com.", "value": "10.0.0.27"}]},
    })
    by_mac, by_ip = asyncio.run(hub._nw_identity_index())
    recs = [{"ip": "10.0.0.5", "mac": "aa:aa:aa:aa:aa:05", "hostname": ""},
            {"ip": "10.0.0.9", "mac": "aa:aa:aa:aa:aa:09", "hostname": ""},
            {"ip": "10.0.0.27", "mac": "aa:aa:aa:aa:aa:27", "hostname": ""}]
    hub._nw_apply_identity(recs, by_mac, by_ip, hub._nw_ip_host_src)
    assert [r.get("hostname_source") for r in recs] == ["reservation", "lease", "dns"]


def test_apply_identity_still_works_without_a_source_map():
    recs = [{"ip": "10.0.0.5", "mac": "", "hostname": ""}]
    NwDiscoverySyncMixin._nw_apply_identity(recs, {}, {"10.0.0.5": "h"})
    assert recs[0]["hostname"] == "h" and "hostname_source" not in recs[0]
