"""Tests for static_ip_reservations, the hub side of static-host DHCP
reservations: what the hub relays to the netbox spoke, how it reads older
peers, and the status and rollback it keeps. The planner and the NetBox
writes live in the netbox spoke (``NETBOX_RESERVE_STATIC_HOSTS``) and are
tested there.

All data is RFC 1918 example data.
"""

import asyncio
import json

import pytest

from _fakes import FakeState
from dns_dhcp_sync import DnsDhcpSyncMixin, build_dhcp_payload
from static_ip_reservations import (COMMAND, is_unknown_command,
                                    reserve_static_hosts_once,
                                    roll_back_if_sync_failed, status_for_tenant)

MAC_A = "02:00:00:00:00:0a"
MAC_B = "02:00:00:00:00:0b"
NOW = 1_000_000.0

# Real "I do not know this command" replies seen across the fleet.
LEGACY_UNKNOWN = [
    {"status": "ERROR", "message": "Unknown agent command 'GET_HOST_ADDRESSING'. "
                                   "Loaded roles: ['base']"},           # agent
    {"status": "ERROR", "message": "Unknown command: NETBOX_RESERVE_STATIC_HOSTS"},  # netbox
    {"status": "ERROR", "error": "Unknown command: GET_HOST_ADDRESSING"},  # dhcp/dns/henet
    {"status": "ERROR", "code": "UNKNOWN_COMMAND", "message": "no such command"},
    {"status": "ERROR", "code": "UNSUPPORTED_COMMAND"},
]


def _change(ref="0", ip="10.20.0.50", mac=MAC_A, ip_id=7):
    """One change row as the spoke reports it."""
    return {"ref": ref, "ip": ip, "ip_id": ip_id, "mac": mac, "source": "agent",
            "before": {"mac_address": None, "dhcp_reservation": None},
            "after": {"mac_address": mac, "dhcp_reservation": True}}


class _Hub(DnsDhcpSyncMixin):
    """Hub stand-in: tenant-bound agents, Kea spokes, one netbox spoke whose
    answer to the pass command is ``spoke_reply`` (a dict or a callable of
    the payload)."""

    def __init__(self, *, leases_reply=None, agent_addresses=None, live_arp=None,
                 seen=None, spoke_tenants=None, dhcp_spokes=None, leases_by_spoke=None,
                 subnets_reply=None, module_metadata=None, spoke_reply=None, agent_reply=None):
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
        self._subnets_reply = subnets_reply if subnets_reply is not None else {
            "status": "SUCCESS", "strict": True, "subnets": [
                {"subnet": "10.20.0.0/24", "pools": [{"pool": "10.20.0.100 - 10.20.0.200"}],
                 "reservations": []}]}
        self._agent_addresses = agent_addresses or {}
        self._agent_reply = agent_reply
        self._spoke_reply = spoke_reply if spoke_reply is not None else (
            lambda p: {"status": "SUCCESS", "changes": [], "conflicts": [], "errors": [],
                       "evaluated": [t["ref"] for t in p["tenants"]]})
        if live_arp is not None:
            self._nw_live_arp = live_arp
        self.log = []
        self.refreshed = []

    def get_spoke_by_type(self, module_type):
        return {"ipam": "netbox-1", "dhcp": "dhcp-1"}.get(module_type)

    def get_all_spokes_by_type(self, module_type):
        # Connected spokes only, like the real hub.
        return [s for s in {"agent": ["agent-1", "agent-2"], "dhcp": list(self._dhcp),
                            "ipam": ["netbox-1"]}.get(module_type, [])
                if s in self.active_connections]

    def refresh_module_cache(self, key):
        self.refreshed.append(key)

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.log.append((spoke_id, command, payload))
        if command == "GET_HOST_ADDRESSING":
            reply = self._agent_reply
            if isinstance(reply, Exception):
                raise reply
            if reply is None:
                reply = {"status": "SUCCESS",
                         "addresses": self._agent_addresses.get(spoke_id, [])}
            return {"payload": {"data": reply}}
        if command == "DHCP_LIST_LEASES":
            return {"payload": {"data": self._leases_by_spoke.get(spoke_id, self._leases_reply)}}
        if command == "DHCP_LIST_SUBNETS":
            return {"payload": {"data": self._subnets_reply}}
        if command == COMMAND:
            reply = self._spoke_reply
            if isinstance(reply, Exception):
                raise reply
            return {"payload": {"data": reply(payload) if callable(reply) else reply}}
        return {}

    def sent(self):
        """Payloads of the pass command sent to the netbox spoke."""
        return [p for _s, c, p in self.log if c == COMMAND]


def _agent_static(ip="10.20.0.50", mac=MAC_A, mode="static"):
    return {"agent-1": [{"ip": ip, "mac": mac, "mode": mode, "interface": "eth0"}]}


def _sweep_hub(**kw):
    """Tenant t-b: one sweep host seen a minute ago with a live-ARP MAC."""
    seen = {"t-b": {"10.20.0.50": {"address": "10.20.0.50", "last_seen": NOW - 60},
                    "10.20.0.51": {"address": "10.20.0.51", "last_seen": NOW - 60}}}
    arp = {"t-b": {"at": NOW - 120, "macs": {"10.20.0.50": MAC_A}}}
    kw.setdefault("spoke_tenants", {})
    return _Hub(seen=seen, live_arp=arp, **kw)


def _run(hub, now=NOW):
    return asyncio.run(reserve_static_hosts_once(hub, now=now, force=True))


# ── what the hub relays ─────────────────────────────────────────────────────

def test_pass_relays_each_tenants_inputs_in_one_command_without_tenant_ids():
    hub = _Hub(agent_addresses=_agent_static())
    _run(hub)
    [payload] = hub.sent()
    assert payload["tenants"] == [{
        "ref": "0", "filters": {"tenant": "tenant-a"},
        "agent_addresses": [{"ip": "10.20.0.50", "mac": MAC_A, "mode": "static"}],
        "sweep": [], "kea": "k0", "replace_watch": []}]
    assert payload["auto_replace"] is True
    assert payload["kea"]["k0"]["leases"] == []
    assert payload["kea"]["k0"]["subnets"][0]["subnet"] == "10.20.0.0/24"
    assert payload["max_writes"] == 25
    assert '"t-a"' not in json.dumps(payload)
    assert ("dhcp-1", "DHCP_LIST_LEASES", {"strict": True}) in hub.log


def test_sweep_hosts_are_relayed_with_ages_only_when_arp_has_a_mac():
    hub = _sweep_hub()
    _run(hub)
    [payload] = hub.sent()
    assert payload["tenants"][0]["filters"] == {"tenant": "tenant-b"}
    assert payload["tenants"][0]["sweep"] == [
        {"ip": "10.20.0.50", "mac": MAC_A, "arp_age": 120.0, "seen_age": 60.0}]


def test_pass_ignores_unbound_and_shared_agents():
    hub = _Hub(agent_addresses={"agent-1": _agent_static()["agent-1"],
                                "agent-2": _agent_static()["agent-1"]},
               spoke_tenants={"agent-2": "shared"})
    st = _run(hub)
    assert hub.sent() == [] and st["status"] == "skipped"
    assert not [1 for s, c, _p in hub.log if c == "GET_HOST_ADDRESSING"]


def test_a_tenant_without_a_strict_kea_read_is_held_back_as_an_error():
    """An old dhcp spoke (no strict echo), a failed HA member, an error or
    rows that are not a list must not read as "no leases"."""
    for reply in ({"status": "SUCCESS", "leases": []},
                  {"status": "SUCCESS", "leases": [], "strict": True,
                   "member_errors": {"kea-2": "no response"}},
                  {"status": "ERROR", "message": "lease read failed"},
                  {"status": "SUCCESS", "strict": True, "leases": {"10.20.0.60": MAC_B}}):
        hub = _Hub(agent_addresses=_agent_static(), leases_reply=reply)
        st = _run(hub)
        assert hub.sent() == []
        assert st["status"] == "error"
        assert st["errors"] == [{"tenant": "t-a", "error": "no strict kea read"}]
    hub = _Hub(agent_addresses=_agent_static(),
               subnets_reply={"status": "ERROR", "message": "kea down"})
    assert _run(hub)["errors"] == [{"tenant": "t-a", "error": "no strict kea read"}]


def test_pass_uses_the_tenants_own_kea_not_the_shared_one():
    md = {"dhcp-a": {"tenant_id": "t-a", "module_type": "dhcp"}}
    hub = _Hub(agent_addresses=_agent_static(), dhcp_spokes=["dhcp-1", "dhcp-a"],
               spoke_tenants={"agent-1": "t-a", "dhcp-a": "t-a"}, module_metadata=md,
               leases_by_spoke={"dhcp-1": {"status": "ERROR", "message": "kea down"}})
    st = _run(hub)
    assert len(hub.sent()) == 1 and not st["errors"]
    assert {s for s, c, _p in hub.log if c == "DHCP_LIST_LEASES"} == {"dhcp-a"}


def test_a_tenant_whose_own_kea_is_offline_is_an_error(monkeypatch):
    import static_ip_reservations as sir
    monkeypatch.setattr(sir, "_tenant_kea_spokes", lambda *a: ("", []))
    monkeypatch.setattr(sir, "tenant_has_own_spoke", lambda h, t, m: True)
    st = _run(_Hub(agent_addresses=_agent_static()))
    assert st["status"] == "error"
    assert st["errors"] == [{"tenant": "t-a", "error": "own kea not connected"}]
    # No Kea of its own and none shared: nothing to protect, not an error.
    monkeypatch.setattr(sir, "tenant_has_own_spoke", lambda h, t, m: False)
    st = _run(_Hub(agent_addresses=_agent_static()))
    assert st["status"] == "skipped" and st["errors"] == []


def test_tenants_on_a_shared_kea_read_it_once_per_pass():
    hub = _Hub(agent_addresses={"agent-1": _agent_static()["agent-1"],
                                "agent-2": _agent_static(mac=MAC_B)["agent-1"]},
               spoke_tenants={"agent-1": "t-a", "agent-2": "t-b"})
    _run(hub)
    [payload] = hub.sent()
    assert [t["kea"] for t in payload["tenants"]] == ["k0", "k0"]
    assert list(payload["kea"]) == ["k0"]
    kea = sorted((s, c) for s, c, _p in hub.log if c.startswith("DHCP_LIST_"))
    assert kea == [("dhcp-1", "DHCP_LIST_LEASES"), ("dhcp-1", "DHCP_LIST_SUBNETS")]
    # The next pass reads Kea again (the map lives for one pass only).
    _run(hub, NOW + 10_000)
    assert len([1 for _s, c, _p in hub.log if c == "DHCP_LIST_LEASES"]) == 2


# ── older peers (rolling upgrade) ───────────────────────────────────────────

@pytest.mark.parametrize("reply", LEGACY_UNKNOWN)
def test_every_legacy_unknown_command_shape_is_recognised(reply):
    assert is_unknown_command(reply)


@pytest.mark.parametrize("reply", [
    {"status": "ERROR", "message": "ip failed"},
    {"status": "ERROR", "error": "netbox 500"},
    {"status": "SUCCESS", "message": "Unknown command: X"},
    None, "Unknown command: X"])
def test_a_real_failure_is_not_read_as_an_older_peer(reply):
    assert not is_unknown_command(reply)


@pytest.mark.parametrize("reply", LEGACY_UNKNOWN)
def test_an_agent_too_old_for_the_command_does_not_hold_its_tenant(reply):
    hub = _sweep_hub(spoke_tenants={"agent-1": "t-b"}, agent_reply=reply)
    st = _run(hub)
    [payload] = hub.sent()
    assert payload["tenants"][0]["agent_addresses"] == []
    assert [r["ip"] for r in payload["tenants"][0]["sweep"]] == ["10.20.0.50"]
    assert st["errors"] == []


def test_a_failed_agent_poll_holds_back_its_tenant():
    """The agent might have said dhcp for the swept address."""
    for reply in (TimeoutError("no reply"), {"status": "ERROR", "message": "ip failed"}):
        hub = _sweep_hub(spoke_tenants={"agent-1": "t-b"}, agent_reply=reply)
        st = _run(hub)
        assert hub.sent() == []
        assert st["status"] == "error"
        assert st["errors"] == [{"tenant": "t-b", "error": "agent poll failed; tenant waits"}]


@pytest.mark.parametrize("reply", [LEGACY_UNKNOWN[1], {"status": "ERROR", "code": "UNKNOWN_COMMAND"}])
def test_a_netbox_spoke_too_old_for_the_pass_is_unsupported(reply):
    hub = _Hub(agent_addresses=_agent_static(), spoke_reply=reply)
    st = _run(hub)
    assert st["status"] == "unsupported" and st["reserved"] == []
    assert st["errors"] == [{"tenant": None, "error": "netbox spoke too old; update it"}]
    assert hub.refreshed == []


def test_a_spoke_failure_or_a_reply_without_a_report_is_an_error():
    for reply in (TimeoutError("no reply"), {"status": "ERROR", "message": "netbox down"},
                  {"status": "SUCCESS"}):
        st = _run(_Hub(agent_addresses=_agent_static(), spoke_reply=reply))
        assert st["status"] == "error" and st["reserved"] == []
        assert st["errors"][0]["tenant"] is None


# ── status ──────────────────────────────────────────────────────────────────

def test_the_spokes_report_is_stored_per_tenant_with_before_and_after():
    hub = _Hub(agent_addresses=_agent_static(),
               spoke_reply={"status": "SUCCESS", "changes": [_change()], "conflicts": [],
                            "errors": [], "evaluated": ["0"], "skipped": 2})
    st = _run(hub)
    assert st["status"] == "ok" and st["clean"] == ["t-a"] and st["skipped"] == 2
    [row] = st["reserved"]
    assert row["tenant"] == "t-a" and "ref" not in row
    assert row["before"] == {"mac_address": None, "dhcp_reservation": None}
    assert row["after"] == {"mac_address": MAC_A, "dhcp_reservation": True}
    assert hub.dns_dhcp_sync_status["static_reservations"]["reserved"] == [row]
    assert hub.refreshed == ["netbox_ips"]
    assert hub._static_res_pending["changes"] == [_change()]


def test_skip_reasons_are_stored_and_logged_and_an_older_spoke_sends_none(caplog):
    reasons = {"no netbox ip": 30, "outside any dhcp scope": 12}
    reply = {"status": "SUCCESS", "changes": [], "conflicts": [], "errors": [],
             "evaluated": ["0"], "skipped": 42, "skipped_reasons": reasons,
             "skipped_by_ref": {"0": reasons, "9": {"no netbox ip": 1}}}
    with caplog.at_level("INFO", logger="Hub"):
        st = _run(_Hub(agent_addresses=_agent_static(), spoke_reply=reply))
    assert st["skipped_reasons"] == reasons
    # Per tenant by ref; an unknown ref is dropped.
    assert st["skipped_by_tenant"] == [{"tenant": "t-a", "reasons": reasons}]
    assert ("static reservations: 0 reserved, 0 replaced, 0 conflicts, 0 errors; "
            "skipped: no netbox ip=30, outside any dhcp scope=12") in caplog.messages
    del reply["skipped_reasons"], reply["skipped_by_ref"]
    assert _run(_Hub(agent_addresses=_agent_static(), spoke_reply=reply))["skipped_reasons"] == {}


def test_a_pass_with_no_tenant_to_check_logs_why(caplog):
    with caplog.at_level("INFO", logger="Hub"):
        st = _run(_Hub(agent_addresses=_agent_static(),
                       subnets_reply={"status": "ERROR", "message": "kea down"}))
        _run(_Hub())
        _run(_Hub(agent_addresses=_agent_static(), agent_reply=TimeoutError("no reply")))
    assert st["skipped_reasons"] == {}
    assert caplog.messages.count("static reservations: no tenant to check; "
                                 "no strict kea read=1") == 1
    assert ("static reservations: no tenant to check; "
            "no agent or sweep rows=1") in caplog.messages
    assert "static reservations: no tenant to check; agent poll failed=1" in caplog.messages


def test_errors_take_precedence_over_conflicts_and_conflicts_over_ok():
    conflict = {"ref": "0", "ip": "10.20.0.50", "mac": MAC_A, "reason": "leased to another mac"}
    err = {"ref": "0", "ip": "10.20.0.51", "error": "netbox 500"}
    base = {"status": "SUCCESS", "changes": [], "evaluated": ["0"]}
    st = _run(_Hub(agent_addresses=_agent_static(),
                   spoke_reply=dict(base, conflicts=[conflict], errors=[])))
    assert st["status"] == "conflicts"
    assert st["conflicts"] == [{"tenant": "t-a", "ip": "10.20.0.50", "mac": MAC_A,
                                "reason": "leased to another mac"}]
    st = _run(_Hub(agent_addresses=_agent_static(),
                   spoke_reply=dict(base, conflicts=[conflict], errors=[err])))
    assert st["status"] == "error" and st["clean"] == []


def test_a_pass_the_spoke_rolled_back_reports_what_it_undid():
    reply = {"status": "ERROR", "changes": [], "conflicts": [], "evaluated": ["0"],
             "errors": [{"ref": "0", "ip": "10.20.0.51", "error": "netbox 500"}],
             "rolled_back": [_change()], "rollback_failed": [], "message": "rolled back"}
    hub = _Hub(agent_addresses=_agent_static(), spoke_reply=reply)
    st = _run(hub)
    assert st["status"] == "error" and st["reserved"] == []
    assert [r["tenant"] for r in st["rolled_back"]] == ["t-a"]
    assert hub.refreshed == ["netbox_ips"] and hub._static_res_pending is None


def test_pass_is_throttled_and_off_records_why():
    hub = _Hub(agent_addresses=_agent_static())
    asyncio.run(reserve_static_hosts_once(hub, now=1000.0))
    assert asyncio.run(reserve_static_hosts_once(hub, now=1100.0)) == {"status": "throttled"}
    st = asyncio.run(reserve_static_hosts_once(hub, now=1200.0, sync_enabled=False))
    assert (st["status"], st["reason"]) == ("disabled", "dns/dhcp sync is off")
    hub.state.system_state["global_config"]["static_ip_reservations"] = {"enabled": False}
    st = asyncio.run(reserve_static_hosts_once(hub, now=99999.0))
    assert (st["status"], st["reason"]) == ("disabled", "turned off")
    assert hub.dns_dhcp_sync_status["static_reservations"]["status"] == "disabled"


def test_the_pass_is_off_until_an_operator_turns_it_on():
    hub = _Hub(agent_addresses=_agent_static())
    del hub.state.system_state["global_config"]["static_ip_reservations"]
    assert asyncio.run(reserve_static_hosts_once(hub, now=1000.0))["status"] == "disabled"
    assert hub.sent() == []


def test_failed_pass_is_not_throttled():
    hub = _Hub(agent_addresses=_agent_static())

    def _boom(_spokes):
        raise RuntimeError("scope read failed")
    hub._scope_groups = _boom
    with pytest.raises(RuntimeError):
        asyncio.run(reserve_static_hosts_once(hub, now=1000.0))
    del hub._scope_groups
    asyncio.run(reserve_static_hosts_once(hub, now=1100.0))
    assert len(hub.sent()) == 1


# ── rollback after a failed DHCP sync ───────────────────────────────────────

def _reserved_hub(rollback_reply):
    """A hub whose last pass reserved one IP; the spoke answers a rollback
    with ``rollback_reply`` (a callable of the changes, or an exception)."""
    def _reply(payload):
        if "rollback" in payload:
            if isinstance(rollback_reply, Exception):
                raise rollback_reply
            return rollback_reply(payload["rollback"])
        return {"status": "SUCCESS", "changes": [_change()], "conflicts": [],
                "errors": [], "evaluated": ["0"]}

    hub = _Hub(agent_addresses=_agent_static(), spoke_reply=_reply)
    _run(hub)
    hub.refreshed.clear()
    return hub


def test_a_failed_dhcp_sync_rolls_the_pass_back():
    hub = _reserved_hub(lambda changes: {"status": "SUCCESS", "rolled_back": changes,
                                         "rollback_failed": []})
    hub._dhcp_delivered = set()
    st = asyncio.run(roll_back_if_sync_failed(hub))
    [rollback] = [p for p in hub.sent() if "rollback" in p]
    assert rollback["rollback"] == [_change()]     # opaque refs, no tenant ids
    assert st["status"] == "error" and st["reserved"] == []
    assert [r["ip"] for r in st["rolled_back"]] == ["10.20.0.50"]
    assert st["errors"] == [{"tenant": "t-a", "ip": "10.20.0.50",
                             "error": "dhcp sync failed; reservation rolled back"}]
    assert hub.refreshed == ["netbox_ips"]
    # Once only.
    assert asyncio.run(roll_back_if_sync_failed(hub)) is None


def test_a_rollback_reports_ips_edited_since_as_left_in_place():
    def _reply(changes):
        kept = [dict(changes[0], reason="changed in netbox since it was read")]
        return {"status": "SUCCESS", "rolled_back": [], "rollback_kept": kept,
                "rollback_failed": []}
    hub = _reserved_hub(_reply)
    hub._dhcp_delivered = set()
    st = asyncio.run(roll_back_if_sync_failed(hub))
    assert [r["ip"] for r in st["rollback_kept"]] == ["10.20.0.50"]
    assert st["errors"] == [{"tenant": "t-a", "ip": "10.20.0.50", "error":
                             "dhcp sync failed; left in place: changed in netbox since it was read"}]
    assert status_for_tenant(st, "t-a")["rollback_kept"] and \
        status_for_tenant(st, "t-b")["rollback_kept"] == []


def test_a_rollback_that_cannot_reach_the_spoke_says_what_is_left():
    hub = _reserved_hub(TimeoutError("no reply"))
    hub._dhcp_delivered = set()
    st = asyncio.run(roll_back_if_sync_failed(hub))
    assert st["rolled_back"] == [] and [r["ip"] for r in st["rollback_failed"]] == ["10.20.0.50"]
    assert st["errors"][0]["error"].startswith("dhcp sync failed; rollback failed")


def test_no_rollback_when_the_scope_was_delivered_or_no_sync_ran_yet():
    hub = _reserved_hub(lambda c: {"status": "SUCCESS", "rolled_back": c})
    assert asyncio.run(roll_back_if_sync_failed(hub)) is None   # no sync since the pass
    assert hub._static_res_pending
    hub._dhcp_delivered = {""}
    assert asyncio.run(roll_back_if_sync_failed(hub)) is None
    assert not [p for p in hub.sent() if "rollback" in p] and not hub._static_res_pending
    assert hub.dns_dhcp_sync_status["static_reservations"]["status"] == "ok"


def test_only_the_tenant_whose_dhcp_scope_failed_is_rolled_back():
    def _reply(payload):
        if "rollback" in payload:
            return {"status": "SUCCESS", "rolled_back": payload["rollback"]}
        return {"status": "SUCCESS", "conflicts": [], "errors": [], "evaluated": ["0", "1"],
                "changes": [_change("0"), _change("1", "10.30.0.5", MAC_B, 8)]}
    hub = _Hub(agent_addresses={"agent-1": _agent_static()["agent-1"],
                                "agent-2": _agent_static("10.30.0.5", MAC_B)["agent-1"]},
               spoke_tenants={"agent-1": "t-a", "agent-2": "t-b", "dhcp-b": "t-b"},
               dhcp_spokes=["dhcp-1", "dhcp-b"],
               module_metadata={"dhcp-b": {"tenant_id": "t-b", "module_type": "dhcp"}},
               spoke_reply=_reply)
    _run(hub)
    scopes = hub._static_res_pending["scopes"]
    assert scopes["0"] == "" and scopes["1"].startswith("tenant:")
    hub._dhcp_delivered = {""}                       # t-b's own Kea push failed
    st = asyncio.run(roll_back_if_sync_failed(hub))
    [rollback] = [p for p in hub.sent() if "rollback" in p]
    assert [c["ip"] for c in rollback["rollback"]] == ["10.30.0.5"]
    assert [(r["tenant"], r["ip"]) for r in st["reserved"]] == [("t-a", "10.20.0.50")]
    assert [(r["tenant"], r["ip"]) for r in st["rolled_back"]] == [("t-b", "10.30.0.5")]
    assert status_for_tenant(st, "t-a")["status"] == "ok"
    assert status_for_tenant(st, "t-b")["status"] == "error"


def test_the_ref_alone_decides_a_rows_tenant():
    hub = _Hub(agent_addresses=_agent_static(),
               spoke_reply={"status": "SUCCESS", "evaluated": ["0"], "conflicts": [],
                            "changes": [_change("9"), dict(_change("0"), tenant="t-b")],
                            "errors": [{"ref": "9", "ip": "10.99.0.1", "error": "x"}]})
    st = _run(hub)
    assert [r["tenant"] for r in st["reserved"]] == ["t-a"]     # the ref decides
    assert st["errors"] == [{"tenant": None,
                             "error": "netbox spoke reported an error for an unknown tenant"}]


# ── neighbours ──────────────────────────────────────────────────────────────

def _ip(address, ip_id, **cf):
    """A NETBOX_GET_IPS row."""
    return {"id": ip_id, "address": address, "status": "active", "vrf": "lab",
            "custom_fields": cf}


def _ips(*rows):
    return {"ip_addresses": list(rows)}


def _pfx():
    return {"prefixes": [{"prefix": "10.20.0.0/24", "status": "active", "vrf": "lab",
                          "custom_fields": {"dhcp_enabled": True}}]}


def test_reserved_row_becomes_a_kea_reservation():
    """The written shape is exactly what build_dhcp_payload turns into Kea."""
    row = _ip("10.20.0.50/24", 7, mac_address=MAC_A, dhcp_reservation=True)
    _subnets, res = build_dhcp_payload(_pfx(), _ips(row))
    assert [(r["ip"], r["mac"]) for r in res] == [("10.20.0.50", MAC_A)]


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


# ── the sync loop's tick ────────────────────────────────────────────────────

def _tick(hub, monkeypatch, sync_enabled):
    """Run one DNS/DHCP sync-loop tick with the sync on or off."""
    import dns_dhcp_sync

    async def _once(body, **_kw):
        await body()
    monkeypatch.setattr(dns_dhcp_sync, "run_sync_loop", _once)
    hub._dds_cfg = lambda: {"enabled": sync_enabled, "interval": 300}

    async def _no_hook():
        pass
    hub._reconcile_dns_hook = _no_hook
    asyncio.run(hub.run_dns_dhcp_sync_loop())


def test_a_tick_with_the_sync_off_records_the_pass_as_disabled(monkeypatch):
    hub = _Hub(agent_addresses=_agent_static())
    _tick(hub, monkeypatch, sync_enabled=False)
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert (st["status"], st["reason"]) == ("disabled", "dns/dhcp sync is off")
    assert hub.sent() == []


def test_a_tick_whose_dhcp_sync_fails_rolls_the_pass_back(monkeypatch):
    hub = _reserved_hub(lambda changes: {"status": "SUCCESS", "rolled_back": changes})
    hub._static_res_last = 0

    async def _failed_sync():
        hub._dhcp_delivered = set()
    hub._sync_dns_dhcp_once = _failed_sync
    _tick(hub, monkeypatch, sync_enabled=True)
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert st["status"] == "error" and [r["ip"] for r in st["rolled_back"]] == ["10.20.0.50"]


def test_a_tick_whose_dhcp_sync_raises_still_rolls_the_pass_back(monkeypatch):
    hub = _reserved_hub(lambda changes: {"status": "SUCCESS", "rolled_back": changes})
    hub._static_res_last = 0

    async def _raising_sync():
        hub._dhcp_delivered = set()
        raise RuntimeError("payload build failed")
    hub._sync_dns_dhcp_once = _raising_sync
    with pytest.raises(RuntimeError):
        _tick(hub, monkeypatch, sync_enabled=True)
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert [r["ip"] for r in st["rolled_back"]] == ["10.20.0.50"]
