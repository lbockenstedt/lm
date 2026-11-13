"""Tests for static_ip_reservations: static hosts become NetBox DHCP reservations.

All data is RFC 1918 / RFC 5737 example data.
"""

import asyncio

from _fakes import FakeState
from dns_dhcp_sync import DnsDhcpSyncMixin, build_dhcp_payload
from static_ip_reservations import (plan_static_reservations,
                                    reserve_static_hosts_once)

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"


def _pfx():
    """One DHCP-enabled scope, one container and one non-DHCP prefix."""
    return {"prefixes": [
        {"prefix": "10.20.0.0/24", "status": "active", "vrf": "lab",
         "custom_fields": {"dhcp_enabled": True}},
        {"prefix": "10.0.0.0/8", "status": "container",
         "custom_fields": {"dhcp_enabled": True}},
        {"prefix": "10.30.0.0/24", "status": "active", "custom_fields": {}},
    ]}


def _ip(address, ip_id, **cf):
    """A NETBOX_GET_IPS row."""
    return {"id": ip_id, "address": address, "status": "active", "vrf": "lab",
            "custom_fields": cf}


def _ips(*rows):
    """Wrap rows as a NETBOX_GET_IPS reply."""
    return {"ip_addresses": list(rows)}


def _static(ip, mac=MAC_A, source="agent"):
    """A candidate reported as static."""
    return {"ip": ip, "mac": mac, "mode": "static", "source": source}


def _reasons(plan, key):
    """``{ip: reason}`` for one plan bucket."""
    return {x["ip"]: x["reason"] for x in plan[key]}


# ── planner ─────────────────────────────────────────────────────────────────

def test_static_host_without_lease_is_reserved():
    plan = plan_static_reservations(_pfx(), _ips(_ip("10.20.0.50/24", 7)), [],
                                    [_static("10.20.0.50")])
    assert plan["reserve"] == [{"ip_id": 7, "ip": "10.20.0.50", "mac": MAC_A,
                                "source": "agent"}]
    assert not plan["conflicts"]


def test_dynamic_lease_is_not_reserved():
    leases = [{"ip-address": "10.20.0.50", "hw-address": MAC_A, "state": 0}]
    plan = plan_static_reservations(_pfx(), _ips(_ip("10.20.0.50/24", 7)), leases,
                                    [_static("10.20.0.50", source="sweep")])
    assert plan["reserve"] == []
    assert _reasons(plan, "skipped") == {"10.20.0.50": "dynamic lease"}


def test_mac_holding_a_lease_elsewhere_is_not_reserved():
    leases = [{"ip-address": "10.20.0.60", "hw-address": MAC_A}]
    plan = plan_static_reservations(_pfx(), _ips(_ip("10.20.0.50/24", 7)), leases,
                                    [_static("10.20.0.50")])
    assert plan["reserve"] == []
    assert _reasons(plan, "skipped") == {"10.20.0.50": "mac holds a lease"}


def test_agent_dhcp_mode_vetoes_sweep():
    cands = [_static("10.20.0.50", source="sweep"),
             {"ip": "10.20.0.50", "mac": MAC_A, "mode": "dhcp", "source": "agent"}]
    plan = plan_static_reservations(_pfx(), _ips(_ip("10.20.0.50/24", 7)), [], cands)
    assert plan["reserve"] == []
    assert _reasons(plan, "skipped") == {"10.20.0.50": "agent reports dhcp"}


def test_existing_reservation_for_other_mac_is_a_conflict_not_overwritten():
    row = _ip("10.20.0.50/24", 7, mac_address=MAC_B, dhcp_reservation=True)
    plan = plan_static_reservations(_pfx(), _ips(row), [], [_static("10.20.0.50")])
    assert plan["reserve"] == []
    assert _reasons(plan, "conflicts") == {"10.20.0.50": "reserved for another mac"}


def test_lease_for_other_mac_and_stale_netbox_mac_are_conflicts():
    rows = _ips(_ip("10.20.0.50/24", 7), _ip("10.20.0.51/24", 8, mac_address=MAC_B))
    leases = [{"ip-address": "10.20.0.50", "hw-address": MAC_B}]
    cands = [_static("10.20.0.50"), _static("10.20.0.51", mac="02:00:00:00:00:0c")]
    plan = plan_static_reservations(_pfx(), rows, leases, cands)
    assert plan["reserve"] == []
    assert _reasons(plan, "conflicts") == {"10.20.0.50": "leased to another mac",
                                           "10.20.0.51": "netbox mac differs"}


def test_already_reserved_same_mac_is_idempotent():
    row = _ip("10.20.0.50/24", 7, mac_address=MAC_A.upper(), dhcp_reservation=True)
    plan = plan_static_reservations(_pfx(), _ips(row), [], [_static("10.20.0.50")])
    assert plan["reserve"] == [] and not plan["conflicts"]
    assert _reasons(plan, "skipped") == {"10.20.0.50": "already reserved"}


def test_out_of_scope_unknown_mac_and_missing_ip_are_skipped():
    rows = _ips(_ip("10.30.0.5/24", 1), _ip("10.20.0.51/24", 2))
    cands = [_static("10.30.0.5", mac="02:00:00:00:00:01"),   # prefix not DHCP-enabled
             _static("10.40.0.5", mac="02:00:00:00:00:02"),   # only under the container
             _static("10.20.0.51", mac="incomplete"),         # MAC unknown
             _static("10.20.0.52", mac="02:00:00:00:00:03")]  # no NetBox IP object
    plan = plan_static_reservations(_pfx(), rows, [], cands)
    assert plan["reserve"] == []
    assert _reasons(plan, "skipped") == {
        "10.30.0.5": "outside any dhcp scope", "10.40.0.5": "outside any dhcp scope",
        "10.20.0.51": "mac unknown or ambiguous", "10.20.0.52": "no netbox ip"}


def test_mac_seen_at_two_addresses_is_skipped():
    rows = _ips(_ip("10.20.0.50/24", 7), _ip("10.20.0.51/24", 8))
    plan = plan_static_reservations(_pfx(), rows, [],
                                    [_static("10.20.0.50"), _static("10.20.0.51")])
    assert plan["reserve"] == []
    assert set(_reasons(plan, "skipped").values()) == {"mac seen at several addresses"}


def test_reserved_row_becomes_a_kea_reservation():
    """The written shape is exactly what build_dhcp_payload turns into Kea."""
    row = _ip("10.20.0.50/24", 7, mac_address=MAC_A, dhcp_reservation=True)
    _subnets, res = build_dhcp_payload(_pfx(), _ips(row))
    assert [(r["ip"], r["mac"]) for r in res] == [("10.20.0.50", MAC_A)]


# ── the pass ────────────────────────────────────────────────────────────────

class _Hub(DnsDhcpSyncMixin):
    """Hub stand-in: tenant-bound agents, one Kea spoke, one NetBox spoke."""

    def __init__(self, *, leases_reply=None, agent_addresses=None, live_arp=None,
                 seen=None, spoke_tenants=None, ips=None):
        tenants = {"t-a": {"netbox_tenant_slug": "tenant-a"},
                   "t-b": {"netbox_tenant_slug": "tenant-b"},
                   "shared": {"netbox_tenant_slug": "shared"}}
        self.state = FakeState(
            system_state={"global_config": {"nw_seen_hosts": seen or {}}},
            tenants=tenants,
            spoke_tenants=spoke_tenants if spoke_tenants is not None
            else {"agent-1": "t-a"})
        self.active_connections = {"agent-1", "agent-2", "dhcp-1", "netbox-1"}
        self.approved_modules = {"dhcp-1": True}
        self._leases_reply = leases_reply if leases_reply is not None else {
            "status": "SUCCESS", "leases": [], "strict": True}
        self._agent_addresses = agent_addresses or {}
        self._ips = ips if ips is not None else _ips(_ip("10.20.0.50/24", 7))
        if live_arp is not None:
            self._nw_live_arp = live_arp
        self.log = []
        self.refreshed = []

    def get_spoke_by_type(self, module_type):
        return {"ipam": "netbox-1", "dhcp": "dhcp-1"}.get(module_type)

    def get_all_spokes_by_type(self, module_type):
        return {"agent": ["agent-1", "agent-2"], "dhcp": ["dhcp-1"],
                "ipam": ["netbox-1"]}.get(module_type, [])

    def refresh_module_cache(self, key):
        self.refreshed.append(key)

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.log.append((spoke_id, command, payload))
        if command == "GET_HOST_ADDRESSING":
            return {"payload": {"data": {"status": "SUCCESS",
                                         "addresses": self._agent_addresses.get(spoke_id, [])}}}
        if command == "DHCP_LIST_LEASES":
            return {"payload": {"data": self._leases_reply}}
        if command == "NETBOX_GET_PREFIXES":
            return {"payload": {"data": _pfx()}}
        if command == "NETBOX_GET_IPS":
            return {"payload": {"data": self._ips}}
        if command == "NETBOX_UPDATE_IP_ADDR":
            return {"payload": {"data": {"status": "SUCCESS", "id": payload["ip_id"]}}}
        return {}

    def writes(self):
        return [p for _s, c, p in self.log if c == "NETBOX_UPDATE_IP_ADDR"]


def _agent_static(ip="10.20.0.50", mac=MAC_A, mode="static"):
    return {"agent-1": [{"ip": ip, "mac": mac, "mode": mode, "interface": "eth0"}]}


def _run(hub, now=1_000_000.0):
    return asyncio.run(reserve_static_hosts_once(hub, now=now, force=True))


def test_pass_writes_reservation_for_tenant_agent_with_tenant_filter():
    hub = _Hub(agent_addresses=_agent_static())
    st = _run(hub)
    assert hub.writes() == [{"ip_id": 7, "custom_fields": {
        "mac_address": MAC_A, "dhcp_reservation": True}}]
    assert [r["ip"] for r in st["reserved"]] == ["10.20.0.50"]
    assert hub.dns_dhcp_sync_status["static_reservations"]["reserved"]
    assert hub.refreshed == ["netbox_ips"]
    # Only the owning tenant's NetBox scope was read, and leases were read strictly.
    reads = [p for _s, c, p in hub.log if c in ("NETBOX_GET_IPS", "NETBOX_GET_PREFIXES")]
    assert reads and all(p == {"tenant": "tenant-a"} for p in reads)
    assert ("dhcp-1", "DHCP_LIST_LEASES", {"strict": True}) in hub.log


def test_pass_ignores_unbound_and_shared_agents():
    hub = _Hub(agent_addresses={"agent-1": _agent_static()["agent-1"],
                                "agent-2": _agent_static()["agent-1"]},
               spoke_tenants={"agent-2": "shared"})
    _run(hub)
    assert hub.writes() == []
    assert not [1 for s, c, _p in hub.log if c == "GET_HOST_ADDRESSING"]


def test_pass_skips_when_lease_read_is_not_strict():
    """An old dhcp spoke (no strict echo) or a failed HA member must not read as
    "no leases" — the whole tenant is skipped."""
    for reply in ({"status": "SUCCESS", "leases": []},
                  {"status": "SUCCESS", "leases": [], "strict": True,
                   "member_errors": {"kea-2": "no response"}},
                  {"status": "ERROR", "message": "lease read failed"}):
        hub = _Hub(agent_addresses=_agent_static(), leases_reply=reply)
        st = _run(hub)
        assert hub.writes() == []
        assert st["errors"] and st["status"] == "error"


def test_pass_dynamic_lease_and_conflict_write_nothing():
    hub = _Hub(agent_addresses=_agent_static(), leases_reply={
        "status": "SUCCESS", "strict": True,
        "leases": [{"ip-address": "10.20.0.50", "hw-address": MAC_B}]})
    st = _run(hub)
    assert hub.writes() == []
    assert st["conflicts"] == [{"tenant": "t-a", "ip": "10.20.0.50", "mac": MAC_A,
                                "reason": "leased to another mac"}]


def test_pass_uses_fresh_sweep_arp_only():
    now = 1_000_000.0
    seen = {"t-b": {"10.20.0.50": {"address": "10.20.0.50", "last_seen": now - 60}}}
    fresh = {"t-b": {"at": now - 60, "macs": {"10.20.0.50": MAC_A}}}
    stale = {"t-b": {"at": now - 3 * 3600, "macs": {"10.20.0.50": MAC_A}}}
    hub = _Hub(spoke_tenants={}, seen=seen, live_arp=stale)
    _run(hub, now)
    assert hub.writes() == []
    hub = _Hub(spoke_tenants={}, seen=seen, live_arp=fresh)
    st = _run(hub, now)
    assert [(r["tenant"], r["source"]) for r in st["reserved"]] == [("t-b", "sweep")]
    reads = [p for _s, c, p in hub.log if c == "NETBOX_GET_IPS"]
    assert reads == [{"tenant": "tenant-b"}]


def test_pass_is_throttled_and_has_kill_switch():
    hub = _Hub(agent_addresses=_agent_static())
    asyncio.run(reserve_static_hosts_once(hub, now=1000.0))
    assert asyncio.run(reserve_static_hosts_once(hub, now=1100.0)) == {"status": "throttled"}
    hub.state.system_state["global_config"]["static_ip_reservations"] = {"enabled": False}
    assert asyncio.run(reserve_static_hosts_once(hub, now=99999.0)) == {"status": "disabled"}


def test_discovery_keeps_unambiguous_live_arp_per_tenant():
    """The nw discovery cycle stashes {ip: mac} per tenant; an IP answering
    with two MACs is dropped."""
    from nw_discovery_sync import NwDiscoverySyncMixin

    hub = NwDiscoverySyncMixin()
    hub._nw_remember_live_arp({"t-a": [
        {"ip": "10.20.0.50", "mac": MAC_A},
        {"ip": "10.20.0.51", "mac": MAC_A},
        {"ip": "10.20.0.51", "mac": MAC_B},
        {"ip": "10.20.0.52", "mac": ""}]})
    assert hub._nw_live_arp["t-a"]["macs"] == {"10.20.0.50": MAC_A}
    assert hub._nw_live_arp["t-a"]["at"] > 0
