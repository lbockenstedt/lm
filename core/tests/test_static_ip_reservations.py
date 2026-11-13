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
        "10.20.0.51": "malformed mac", "10.20.0.52": "no netbox ip"}


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
                 seen=None, spoke_tenants=None, ips=None, dhcp_spokes=None,
                 leases_by_spoke=None, subnets_reply=None, module_metadata=None):
        tenants = {"t-a": {"netbox_tenant_slug": "tenant-a"},
                   "t-b": {"netbox_tenant_slug": "tenant-b"},
                   "shared": {"netbox_tenant_slug": "shared"}}
        self.state = FakeState(
            system_state={"global_config": {"nw_seen_hosts": seen or {},
                                            "static_ip_reservations": {"enabled": True}},
                          "module_metadata": module_metadata or {}},
            tenants=tenants,
            spoke_tenants=spoke_tenants if spoke_tenants is not None
            else {"agent-1": "t-a"})
        self._dhcp = dhcp_spokes or ["dhcp-1"]
        self.active_connections = {"agent-1", "agent-2", "netbox-1", *self._dhcp}
        self.approved_modules = {s: True for s in self._dhcp}
        self.spoke_module_types = {"agent-1": "agent", "agent-2": "agent",
                                   "netbox-1": "ipam", **{s: "dhcp" for s in self._dhcp}}
        self._leases_reply = leases_reply if leases_reply is not None else {
            "status": "SUCCESS", "leases": [], "strict": True}
        self._leases_by_spoke = leases_by_spoke or {}
        # Default Kea pool .100-.200, so 10.20.0.50 is outside it.
        self._subnets_reply = subnets_reply if subnets_reply is not None else {
            "status": "SUCCESS", "strict": True, "subnets": [
                {"subnet": "10.20.0.0/24", "pools": [{"pool": "10.20.0.100 - 10.20.0.200"}]}]}
        self._agent_addresses = agent_addresses or {}
        self._ips = ips if ips is not None else _ips(_ip("10.20.0.50/24", 7))
        if live_arp is not None:
            self._nw_live_arp = live_arp
        self.log = []
        self.refreshed = []

    def get_spoke_by_type(self, module_type):
        return {"ipam": "netbox-1", "dhcp": "dhcp-1"}.get(module_type)

    def get_all_spokes_by_type(self, module_type):
        return {"agent": ["agent-1", "agent-2"], "dhcp": list(self._dhcp),
                "ipam": ["netbox-1"]}.get(module_type, [])

    def refresh_module_cache(self, key):
        self.refreshed.append(key)

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.log.append((spoke_id, command, payload))
        if command == "GET_HOST_ADDRESSING":
            return {"payload": {"data": {"status": "SUCCESS",
                                         "addresses": self._agent_addresses.get(spoke_id, [])}}}
        if command == "DHCP_LIST_LEASES":
            return {"payload": {"data": self._leases_by_spoke.get(spoke_id, self._leases_reply)}}
        if command == "DHCP_LIST_SUBNETS":
            return {"payload": {"data": self._subnets_reply}}
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


# ── review fixes ────────────────────────────────────────────────────────────

def _vrf_pfx(*prefixes):
    """DHCP-enabled prefixes given as (cidr, vrf)."""
    return {"prefixes": [{"prefix": p, "status": "active", "vrf": v,
                          "custom_fields": {"dhcp_enabled": True}} for p, v in prefixes]}


def _vrf_ip(vrf):
    """10.20.0.50 as a NetBox IP row in ``vrf``."""
    return _ips({"id": 7, "address": "10.20.0.50/24", "status": "active",
                 "vrf": vrf, "custom_fields": {}})


def test_vrf_must_match_exactly():
    """The scope is the DHCP prefix in exactly the IP's VRF; overlapping space
    in another VRF, or one side global, never counts."""
    # Overlap: a more specific prefix in another VRF must not hide the IP's own scope.
    pfx = _vrf_pfx(("10.20.0.0/24", "red"), ("10.20.0.0/25", "blue"))
    plan = plan_static_reservations(pfx, _vrf_ip("red"), [], [_static("10.20.0.50")])
    assert [r["ip"] for r in plan["reserve"]] == ["10.20.0.50"]
    # Nested VRF objects normalise (dict → id) on both sides.
    pfx = _vrf_pfx(("10.20.0.0/24", {"id": 3, "name": "red"}))
    plan = plan_static_reservations(pfx, _vrf_ip({"id": 3, "name": "red"}), [],
                                    [_static("10.20.0.50")])
    assert [r["ip"] for r in plan["reserve"]] == ["10.20.0.50"]
    # One-sided empty: VRF prefix with a global IP, global prefix with a VRF IP.
    for pfx_vrf, ip_vrf in (("red", None), ("", "red")):
        plan = plan_static_reservations(_vrf_pfx(("10.20.0.0/24", pfx_vrf)),
                                        _vrf_ip(ip_vrf), [], [_static("10.20.0.50")])
        assert plan["reserve"] == []
        assert _reasons(plan, "skipped") == {"10.20.0.50": "vrf differs from scope"}


def test_malformed_or_conflicting_mac_vetoes_the_candidate():
    """A bad MAC from one source is never dropped in favour of the other."""
    rows = _ips(_ip("10.20.0.50/24", 7), _ip("10.20.0.51/24", 8))
    cands = [_static("10.20.0.50", mac="gg:gg:gg:gg:gg:gg", source="sweep"),
             _static("10.20.0.50"),
             _static("10.20.0.51", mac=MAC_B), _static("10.20.0.51", mac="02:00:00:00:00:0c",
                                                       source="sweep")]
    plan = plan_static_reservations(_pfx(), rows, [], cands)
    assert plan["reserve"] == []
    assert _reasons(plan, "skipped") == {"10.20.0.50": "malformed mac",
                                         "10.20.0.51": "conflicting macs"}


def test_sweep_only_host_needs_an_ip_outside_every_kea_pool():
    """A sweep-seen host inside a pool may be an offline DHCP client; outside
    the pools it cannot be one. Agent-reported static needs no pool check."""
    subnets = [{"subnet": "10.20.0.0/24", "pools": [{"pool": "10.20.0.10 - 10.20.0.99"}]}]
    rows = _ips(_ip("10.20.0.50/24", 7), _ip("10.20.0.150/24", 8), _ip("10.20.0.60/24", 9))
    cands = [_static("10.20.0.50", source="sweep"),
             _static("10.20.0.150", mac=MAC_B, source="sweep"),
             _static("10.20.0.60", mac="02:00:00:00:00:0c")]
    plan = plan_static_reservations(_pfx(), rows, [], cands, subnets)
    assert sorted(r["ip"] for r in plan["reserve"]) == ["10.20.0.150", "10.20.0.60"]
    assert _reasons(plan, "skipped") == {"10.20.0.50": "inside a dhcp pool"}
    # Pools unknown: sweep-only candidates are skipped.
    plan = plan_static_reservations(_pfx(), rows, [], cands[1:2])
    assert _reasons(plan, "skipped") == {"10.20.0.150": "kea pools unknown"}


def test_pass_sweep_host_inside_kea_pool_is_not_reserved():
    now = 1_000_000.0
    seen = {"t-b": {"10.20.0.150": {"address": "10.20.0.150", "last_seen": now - 60}}}
    arp = {"t-b": {"at": now - 60, "macs": {"10.20.0.150": MAC_A}}}
    hub = _Hub(spoke_tenants={}, seen=seen, live_arp=arp,
               ips=_ips(_ip("10.20.0.150/24", 8)))
    st = _run(hub, now)
    assert hub.writes() == [] and st["reserved"] == []
    assert ("dhcp-1", "DHCP_LIST_SUBNETS", {"strict": True}) in hub.log


def test_pass_uses_the_tenants_own_kea_not_the_shared_one():
    """Own Kea beats shared: shared Kea down, or holding another tenant's lease
    for the same address, does not affect a tenant with its own Kea."""
    md = {"dhcp-a": {"tenant_id": "t-a", "module_type": "dhcp"}}
    for shared_reply in ({"status": "ERROR", "message": "kea down"},
                         {"status": "SUCCESS", "strict": True, "leases": [
                             {"ip-address": "10.20.0.50", "hw-address": MAC_B}]}):
        hub = _Hub(agent_addresses=_agent_static(), dhcp_spokes=["dhcp-1", "dhcp-a"],
                   spoke_tenants={"agent-1": "t-a", "dhcp-a": "t-a"}, module_metadata=md,
                   leases_by_spoke={"dhcp-1": shared_reply})
        st = _run(hub)
        assert [r["ip"] for r in st["reserved"]] == ["10.20.0.50"]
        assert not st["errors"] and not st["conflicts"]
        kea_reads = {s for s, c, _p in hub.log if c == "DHCP_LIST_LEASES"}
        assert kea_reads == {"dhcp-a"}


def test_failed_pass_is_not_throttled():
    """The throttle is stamped only after a pass completes."""
    hub = _Hub(agent_addresses=_agent_static())

    def _boom(_spokes):
        raise RuntimeError("scope read failed")
    hub._scope_groups = _boom
    try:
        asyncio.run(reserve_static_hosts_once(hub, now=1000.0))
    except RuntimeError:
        pass
    del hub._scope_groups
    st = asyncio.run(reserve_static_hosts_once(hub, now=1100.0))
    assert [r["ip"] for r in st["reserved"]] == ["10.20.0.50"]


def test_the_pass_is_off_until_an_operator_turns_it_on():
    hub = _Hub(agent_addresses=_agent_static())
    del hub.state.system_state["global_config"]["static_ip_reservations"]
    assert asyncio.run(reserve_static_hosts_once(hub, now=1000.0)) == {"status": "disabled"}
    assert hub.writes() == []


def test_a_structured_netbox_dhcp_status_is_not_reserved():
    row = dict(_ip("10.20.0.50/24", 7), status={"value": "dhcp", "label": "DHCP"})
    plan = plan_static_reservations(_pfx(), _ips(row), [], [_static("10.20.0.50")])
    assert plan["reserve"] == []
    assert _reasons(plan, "skipped") == {"10.20.0.50": "netbox status is dhcp"}


def test_pass_hands_unchanged_reads_to_the_sync_but_not_written_ones():
    """A tenant the pass wrote to must be re-read by the sync; one it only
    read is handed over so the sync does not read it again."""
    key = DnsDhcpSyncMixin._filters_key({"tenant": "tenant-a"})
    hub = _Hub(agent_addresses=_agent_static(mode="unknown"))
    _run(hub)
    assert hub.writes() == [] and key in hub._take_netbox_reads()
    hub = _Hub(agent_addresses=_agent_static())
    _run(hub)
    assert hub.writes() and key not in hub._take_netbox_reads()


def test_pass_reads_and_writes_the_same_ipam_spoke():
    """NetBox ids are per instance: when the first IPAM spoke's read fails the
    pass must not fail over to another instance and then write its id back."""
    class _TwoIpam(_Hub):
        def get_all_spokes_by_type(self, module_type):
            if module_type == "ipam":
                return ["netbox-1", "netbox-2"]
            return super().get_all_spokes_by_type(module_type)

        async def request_response(self, spoke_id, command, payload, timeout=30.0):
            if spoke_id == "netbox-1" and command == "NETBOX_GET_IPS":
                self.log.append((spoke_id, command, payload))
                return {"payload": {"data": {"status": "ERROR", "message": "down"}}}
            return await super().request_response(spoke_id, command, payload, timeout)

    hub = _TwoIpam(agent_addresses=_agent_static())
    st = _run(hub)
    assert hub.writes() == []
    assert not [1 for s, _c, _p in hub.log if s == "netbox-2"]
    assert st["errors"] and "netbox read" in st["errors"][0]["error"]


def _sweep_hub_with_agent_reply(reply, now):
    """Tenant t-b: a fresh sweep host plus one bound agent answering ``reply``."""
    class _AgentReply(_Hub):
        async def request_response(self, spoke_id, command, payload, timeout=30.0):
            if command == "GET_HOST_ADDRESSING":
                self.log.append((spoke_id, command, payload))
                if isinstance(reply, Exception):
                    raise reply
                return {"payload": {"data": reply}}
            return await super().request_response(spoke_id, command, payload, timeout)

    seen = {"t-b": {"10.20.0.50": {"address": "10.20.0.50", "last_seen": now - 60}}}
    fresh = {"t-b": {"at": now - 60, "macs": {"10.20.0.50": MAC_A}}}
    return _AgentReply(spoke_tenants={"agent-1": "t-b"}, seen=seen, live_arp=fresh)


def test_a_failed_agent_poll_holds_back_its_tenants_sweep_hosts():
    """The agent might have said dhcp/unknown for the swept address, so a
    timeout or error must not read as "the agent has nothing to say"."""
    now = 1_000_000.0
    for reply in (TimeoutError("no reply"), {"status": "ERROR", "message": "ip failed"}):
        hub = _sweep_hub_with_agent_reply(reply, now)
        st = _run(hub, now)
        assert hub.writes() == []
        assert st["errors"] == [{"tenant": "t-b", "error": "agent poll failed; sweep hosts wait"}]
        assert st["status"] == "error"
    # An agent too old to know the command is like a host with no agent.
    hub = _sweep_hub_with_agent_reply(
        {"status": "ERROR", "message": "Unknown agent command 'GET_HOST_ADDRESSING'. "}, now)
    st = _run(hub, now)
    assert [r["source"] for r in st["reserved"]] == ["sweep"]


def test_a_reservation_without_a_netbox_id_does_not_stop_the_rest(monkeypatch):
    import static_ip_reservations as sir
    real = sir.plan_static_reservations

    def _plan(*args, **kwargs):
        plan = real(*args, **kwargs)
        plan["reserve"] = [dict(plan["reserve"][0], ip_id=None, ip="10.20.0.49")] + plan["reserve"]
        return plan

    monkeypatch.setattr(sir, "plan_static_reservations", _plan)
    hub = _Hub(agent_addresses=_agent_static())
    _run(hub)
    assert [w["ip_id"] for w in hub.writes()] == [7]


def test_a_failed_kea_subnet_read_is_an_error_not_a_quiet_skip():
    now = 1_000_000.0
    seen = {"t-b": {"10.20.0.50": {"address": "10.20.0.50", "last_seen": now - 60}}}
    fresh = {"t-b": {"at": now - 60, "macs": {"10.20.0.50": MAC_A}}}
    hub = _Hub(spoke_tenants={}, seen=seen, live_arp=fresh,
               subnets_reply={"status": "ERROR", "message": "kea down"})
    st = _run(hub, now)
    assert hub.writes() == []
    assert st["status"] == "error"
    assert st["errors"] == [{"tenant": "t-b", "error": "no strict kea subnet read"}]


def test_a_tenant_whose_own_kea_is_offline_is_an_error(monkeypatch):
    import static_ip_reservations as sir
    monkeypatch.setattr(sir, "_tenant_kea_spokes", lambda *a: [])
    hub = _Hub(agent_addresses=_agent_static())
    monkeypatch.setattr(sir, "tenant_has_own_spoke", lambda h, t, m: True)
    st = _run(hub)
    assert st["status"] == "error"
    assert st["errors"] == [{"tenant": "t-a", "error": "own kea not connected"}]
    # No Kea of its own and none shared: nothing to protect, not an error.
    monkeypatch.setattr(sir, "tenant_has_own_spoke", lambda h, t, m: False)
    st = _run(_Hub(agent_addresses=_agent_static()))
    assert st["status"] == "ok" and st["errors"] == []
