"""Device replacement in the static-IP reservation pass, the hub side: the
waiting state the hub keeps for the spoke (``replace_watch``), the
``auto_replace`` switch, older spokes, the rollback of a replacement, and
the "Use new MAC" button with its route. The planner and the NetBox writes
are tested in the netbox spoke.

All data is example data (documentation range, locally administered MACs).
"""

import asyncio

from static_ip_reservations import (REPLACE_COMMAND, _undo, note_mac_sightings,
                                    roll_back_if_sync_failed, status_for_tenant,
                                    use_new_mac)
from test_static_ip_reservations import NOW, _Hub, _agent_static, _run

IP = "192.0.2.50"
OLD = "02:00:00:00:00:0a"
NEW = "02:00:00:00:00:0b"
DAY = 24 * 3600


def _pending(ref="0"):
    """The spoke's row for an IP waiting to move from OLD to NEW."""
    return {"ref": ref, "ip": IP, "old_mac": OLD, "new_mac": NEW, "first_seen_age": 0}


def _conflict(ref="0"):
    """The spoke's "different MAC at this IP" conflict for IP."""
    return {"ref": ref, "ip": IP, "mac": NEW, "old_mac": OLD,
            "reason": "reserved for another mac", "replace": "waiting before replacing"}


def _replaced(ref="0"):
    """The spoke's row for IP moved from OLD to NEW."""
    return {"ref": ref, "ip": IP, "ip_id": 7, "old_mac": OLD, "new_mac": NEW,
            "source": "agent",
            "before": {"mac_address": OLD, "dhcp_reservation": True},
            "after": {"mac_address": NEW, "dhcp_reservation": True},
            "interface": {"object": "dcim.macaddress", "id": 3,
                          "before": {"mac_address": OLD}, "after": {"mac_address": NEW}}}


def _report(payload, **rows):
    """A current spoke's pass report with ``rows``."""
    out = {"status": "SUCCESS", "changes": [], "replaced": [], "pending_replace": [],
           "conflicts": [], "errors": [], "evaluated": [t["ref"] for t in payload["tenants"]]}
    out.update(rows)
    return out


class _ReplaceHub(_Hub):
    """``_Hub`` whose netbox spoke also answers the button's command with
    ``button_reply`` (a dict or a callable of the payload)."""

    def __init__(self, button_reply=None, **kw):
        kw.setdefault("subnets_reply", {"status": "SUCCESS", "strict": True, "subnets": [
            {"subnet": "192.0.2.0/24", "pools": [{"pool": "192.0.2.100 - 192.0.2.200"}],
             "reservations": []}]})
        super().__init__(**kw)
        self.button_reply = button_reply
        self._dds_cfg = lambda: {"enabled": True, "interval": 300}

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        if command == REPLACE_COMMAND:
            self.log.append((spoke_id, command, payload))
            r = self.button_reply
            return {"payload": {"data": r(payload) if callable(r) else r}}
        return await super().request_response(spoke_id, command, payload, timeout)

    def button_sent(self):
        """Payloads of the button's command."""
        return [p for _s, c, p in self.log if c == REPLACE_COMMAND]


def _watched_hub(**kw):
    """Tenant t-a with an agent reporting NEW at IP and a spoke that keeps
    reporting the IP as pending."""
    kw.setdefault("spoke_reply", lambda p: _report(p, pending_replace=[_pending()],
                                                   conflicts=[_conflict()]))
    return _ReplaceHub(agent_addresses=_agent_static(ip=IP, mac=NEW), **kw)


# ── the waiting state ───────────────────────────────────────────────────────

def test_the_new_mac_wait_spans_passes_and_reaches_the_spoke_as_an_age():
    hub = _watched_hub()
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    first, second = hub.sent()
    assert first["tenants"][0]["replace_watch"] == []
    [w] = second["tenants"][0]["replace_watch"]
    assert (w["ip"], w["old_mac"], w["new_mac"], w["first_seen_age"]) == (IP, OLD, NEW, 1800)
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert st["pending_replace"][0]["first_seen_age"] == 1800
    assert st["pending_replace"][0]["tenant"] == "t-a"


def test_a_different_new_mac_restarts_the_wait():
    other = "02:00:00:00:00:0c"
    replies = iter([[_pending()], [dict(_pending(), new_mac=other)], []])
    hub = _watched_hub(spoke_reply=lambda p: _report(p, pending_replace=next(replies)))
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    _run(hub, NOW + 3600)
    [w] = hub.sent()[2]["tenants"][0]["replace_watch"]
    assert (w["new_mac"], w["first_seen_age"]) == (other, 1800)


def test_the_old_mac_has_no_unseen_age_without_a_complete_sweep():
    hub = _watched_hub(live_arp={"t-a": {"at": NOW, "macs": {}}})
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    assert hub.sent()[1]["tenants"][0]["replace_watch"][0]["old_unseen_age"] is None


def _swept_hub(old_seen_at=None, complete=True):
    """A hub whose sweep has watched without a gap for over a day; OLD last
    seen at ``old_seen_at`` (never when None)."""
    hub = _watched_hub()
    start = NOW - DAY - 3600
    hub._static_res_agent_since = {"t-a": start}
    for t in range(int(start), int(NOW) + 1, 3600):
        seen = [OLD] if old_seen_at is not None and t <= old_seen_at else []
        note_mac_sightings(hub, seen, complete or t < NOW - 600, t)
    hub._nw_live_arp = {"t-a": {"at": NOW, "macs": {}}}
    return hub


def test_the_old_mac_unseen_age_counts_from_its_last_sighting():
    hub = _swept_hub(old_seen_at=NOW - 2 * 3600)
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    w = hub.sent()[1]["tenants"][0]["replace_watch"][0]
    assert w["old_unseen_age"] == 1800 + 2 * 3600


def test_the_old_mac_unseen_age_covers_a_full_day_of_sweeps():
    hub = _swept_hub()
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    assert hub.sent()[1]["tenants"][0]["replace_watch"][0]["old_unseen_age"] >= DAY


def test_a_sweep_cycle_with_a_failed_device_restarts_the_old_mac_clock():
    hub = _swept_hub(complete=False)
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    assert hub.sent()[1]["tenants"][0]["replace_watch"][0]["old_unseen_age"] is None


def test_an_agent_reporting_the_old_mac_counts_as_a_sighting():
    hub = _swept_hub()
    hub._agent_addresses = {"agent-1": [{"ip": IP, "mac": NEW, "mode": "static"},
                                        {"ip": "192.0.2.60", "mac": OLD, "mode": "static"}]}
    _run(hub, NOW)
    _run(hub, NOW + 1800)
    assert hub.sent()[1]["tenants"][0]["replace_watch"][0]["old_unseen_age"] == 0


def test_a_failed_agent_poll_restarts_the_old_mac_clock():
    hub = _swept_hub()
    hub._agent_reply = TimeoutError("agent timed out")
    _run(hub, NOW)
    assert "t-a" not in hub._static_res_agent_since


def test_an_agent_too_old_to_report_macs_restarts_the_old_mac_clock():
    hub = _swept_hub()
    hub._agent_reply = {"status": "ERROR", "message": "Unknown command: GET_HOST_ADDRESSING"}
    _run(hub, NOW)
    assert "t-a" not in hub._static_res_agent_since


def test_a_pending_row_says_when_no_source_can_confirm_the_old_mac_is_gone():
    hub = _swept_hub()
    _run(hub, NOW)
    assert hub.dns_dhcp_sync_status["static_reservations"]["pending_replace"][0][
        "old_mac_unconfirmed"] is False
    hub = _watched_hub()
    _run(hub, NOW)
    assert hub.dns_dhcp_sync_status["static_reservations"]["pending_replace"][0][
        "old_mac_unconfirmed"] is True


def test_a_pass_with_no_tenant_to_send_restarts_every_wait():
    hub = _watched_hub()
    hub._static_res_watch = {"t-a": {IP: {"old_mac": OLD, "new_mac": NEW, "first_seen": 0.0}}}
    hub._agent_addresses = {}
    hub._nw_live_arp = {}
    _run(hub, NOW)
    assert hub.sent() == [] and hub._static_res_watch == {}


def test_a_disconnected_agent_restarts_the_old_mac_clock():
    hub = _swept_hub()
    hub.state.system_state["module_metadata"]["agent-1"] = {"module_type": "agent"}
    hub.approved_modules["agent-1"] = True
    hub.active_connections.discard("agent-1")
    _run(hub, NOW)
    assert "t-a" not in hub._static_res_agent_since


# ── auto_replace and older spokes ───────────────────────────────────────────

def test_auto_replace_off_sends_no_watch_and_says_so():
    hub = _watched_hub(spoke_reply=lambda p: _report(p, conflicts=[_conflict()]))
    hub.state.system_state["global_config"]["static_ip_reservations"]["auto_replace"] = False
    _run(hub, NOW)
    [payload] = hub.sent()
    assert payload["auto_replace"] is False and "replace_watch" not in payload["tenants"][0]
    assert hub._static_res_watch == {}
    assert hub.dns_dhcp_sync_status["static_reservations"]["auto_replace"] is False


def test_auto_replace_defaults_on():
    hub = _watched_hub()
    _run(hub, NOW)
    assert hub.sent()[0]["auto_replace"] is True


def test_an_older_spoke_reply_marks_replacement_unsupported():
    hub = _ReplaceHub(agent_addresses=_agent_static(ip=IP, mac=NEW))
    _run(hub, NOW)
    assert hub.dns_dhcp_sync_status["static_reservations"]["replace_supported"] is False
    assert asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))["status"] == "unsupported"
    assert hub.button_sent() == []


def test_a_replacement_is_shown_per_tenant_and_rolled_back_when_the_sync_fails():
    def _reply(p):
        if "rollback" in p:
            return {"status": "SUCCESS", "rolled_back": p["rollback"]}
        return _report(p, replaced=[_replaced()])
    hub = _ReplaceHub(agent_addresses=_agent_static(ip=IP, mac=NEW), spoke_reply=_reply)
    _run(hub, NOW)
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert st["replace_supported"] is True and st["replaced"][0]["tenant"] == "t-a"
    assert status_for_tenant(st, "t-b")["replaced"] == []
    assert "netbox_ips" in hub.refreshed
    hub._dhcp_delivered = set()
    st = asyncio.run(roll_back_if_sync_failed(hub))
    [rollback] = [p["rollback"] for p in hub.sent() if "rollback" in p]
    assert rollback[0]["interface"]["id"] == 3
    assert st["replaced"] == [] and st["rolled_back"][0]["ip"] == IP


# ── the "Use new MAC" button ────────────────────────────────────────────────

def _button_hub(reply):
    """A hub whose last pass showed IP as a "different MAC" conflict for t-a."""
    hub = _watched_hub(button_reply=reply)
    _run(hub, NOW)
    return hub


def test_the_button_moves_one_ip_now_without_the_waits():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    res = asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW, now=NOW + 60))
    assert res["status"] == "ok" and res["replaced"]["tenant"] == "t-a"
    [payload] = hub.button_sent()
    assert (payload["ip"], payload["old_mac"], payload["new_mac"]) == (IP, OLD, NEW)
    [t] = payload["tenants"]
    assert t["ref"] == "m" and t["filters"] == {"tenant": "tenant-a"}
    assert "replace_watch" not in t and t["kea"] in payload["kea"]
    assert "'t-a'" not in str(payload)
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert st["conflicts"] == [] and st["pending_replace"] == []
    assert st["replaced"][0]["new_mac"] == NEW


def test_the_button_shows_the_spokes_safety_check():
    hub = _button_hub({"status": "ERROR", "replaced": [],
                       "message": "cannot replace: old mac holds a lease"})
    res = asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))
    assert res == {"status": "error", "error": "cannot replace: old mac holds a lease"}
    assert len(hub.dns_dhcp_sync_status["static_reservations"]["conflicts"]) == 1


def test_a_repeated_button_press_after_a_lost_reply_is_still_rolled_back_on_failure():
    hub = _button_hub(lambda p: _report(p, already=True, replaced=[_replaced("m")],
                                        message=f"{IP} is already reserved for the new mac"))
    res = asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))
    assert res["status"] == "ok" and res["replaced"]["ip"] == IP
    assert [m["change"]["ip_id"] for m in hub._static_res_manual] == [7]
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert st["conflicts"] == [] and st["pending_replace"] == []


def test_a_replaced_row_the_rollback_cannot_use_is_an_error_not_a_crash():
    bad = dict(_replaced("other"))
    hub = _button_hub(lambda p: _report(p, replaced=[bad]))
    res = asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))
    assert res["status"] == "error" and "unusable" in res["error"]
    assert getattr(hub, "_static_res_manual", None) in (None, [])


def test_the_button_is_judged_only_by_a_sync_that_starts_after_its_write():
    import time

    def slow_write(p):
        # A DNS/DHCP sync starts while the spoke is still writing.
        hub._dhcp_delivered_at = time.time()
        return _report(p, replaced=[_replaced("m")])
    hub = _button_hub(slow_write)
    asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))
    [entry] = hub._static_res_manual
    assert entry["at"] >= hub._dhcp_delivered_at


def test_the_button_needs_a_conflict_the_tenant_was_shown():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    for tid, old, new in (("t-b", OLD, NEW), ("t-a", NEW, OLD),
                          ("t-a", OLD, "02:00:00:00:00:0c"), ("", OLD, NEW)):
        assert asyncio.run(use_new_mac(hub, tid, IP, old, new))["status"] == "error"
    assert hub.button_sent() == []


def test_the_button_acts_only_on_an_ip_reserved_for_another_mac():
    hub = _watched_hub(button_reply=lambda p: _report(p, replaced=[_replaced("m")]),
                       spoke_reply=lambda p: _report(p, conflicts=[
                           {**_conflict(), "reason": "netbox mac differs"}]))
    _run(hub, NOW)
    assert asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))["status"] == "error"
    assert hub.button_sent() == []


def test_the_button_on_an_older_spoke_is_unsupported():
    hub = _button_hub({"status": "ERROR",
                       "message": f"Unknown command: {REPLACE_COMMAND}"})
    assert asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))["status"] == "unsupported"


def test_the_button_is_off_with_the_feature():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    hub.state.system_state["global_config"]["static_ip_reservations"]["enabled"] = False
    assert asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW))["status"] == "error"
    assert hub.button_sent() == []


def test_a_button_replacement_rolls_back_only_after_a_later_sync_fails():
    def _reply(p):
        if "rollback" in p:
            return {"status": "SUCCESS", "rolled_back": p["rollback"]}
        return _report(p, pending_replace=[_pending()], conflicts=[_conflict()])
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    hub._spoke_reply = _reply
    asyncio.run(use_new_mac(hub, "t-a", IP, OLD, NEW, now=NOW + 60))
    # A sync that started before the button cannot judge it.
    hub._dhcp_delivered, hub._dhcp_delivered_at = set(), NOW + 30
    asyncio.run(roll_back_if_sync_failed(hub))
    assert not [p for p in hub.sent() if "rollback" in p]
    # One that started after it and did not deliver the tenant's scope does.
    hub._dhcp_delivered_at = NOW + 90
    st = asyncio.run(roll_back_if_sync_failed(hub))
    [rollback] = [p["rollback"] for p in hub.sent() if "rollback" in p]
    assert rollback[0]["ref"] == "m" and st["rolled_back"][0]["tenant"] == "t-a"
    assert hub._static_res_manual == []


def test_rollbacks_in_one_cycle_add_up_on_the_card():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    hub._spoke_reply = lambda p: {"status": "SUCCESS", "rolled_back": p["rollback"]}
    asyncio.run(_undo(hub, "netbox-1", {"0": "t-a"}, [_replaced("0")]))
    asyncio.run(_undo(hub, "netbox-1", {"m": "t-a"}, [{**_replaced("m"), "ip_id": 8}]))
    st = hub.dns_dhcp_sync_status["static_reservations"]
    assert [r["ip_id"] for r in st["rolled_back"]] == [7, 8]


# ── the route ───────────────────────────────────────────────────────────────

def _post(user, hub, body=None, tenant=None):
    """POST the button's route as ``user``."""
    from test_dhcp_tenant_routing import _build
    url = "/setup/static-reservations/use-new-mac" + (f"?tenant={tenant}" if tenant else "")
    return _build(user, hub).post(url, json=body if body is not None else
                                  {"ip": IP, "old_mac": OLD, "new_mac": NEW})


_ADMIN = {"user": {"is_admin": True, "permissions": {"admin": True}}}


def test_the_route_is_for_global_admins_only():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    r = _post({"user": {"is_admin": False, "tenant_id": "t-a"}}, hub)
    assert r.status_code == 403 and hub.button_sent() == []


def test_the_route_needs_a_tenant():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    assert _post(_ADMIN, hub).status_code == 400
    assert hub.button_sent() == []


def test_the_route_acts_only_inside_the_admins_tenant():
    hub = _button_hub(lambda p: _report(p, replaced=[_replaced("m")]))
    r = _post(_ADMIN, hub, tenant="t-b")
    assert r.status_code == 409 and "no such conflict" in r.json()["detail"]
    assert hub.button_sent() == []
    r = _post(_ADMIN, hub, tenant="t-a")
    assert r.status_code == 200 and r.json()["replaced"]["ip"] == IP


def test_the_route_rejects_a_bad_body_and_reports_a_refusal():
    hub = _button_hub({"status": "ERROR", "replaced": [],
                       "message": "cannot replace: old mac still seen"})
    assert _post(_ADMIN, hub, body={"ip": IP}, tenant="t-a").status_code == 400
    r = _post(_ADMIN, hub, tenant="t-a")
    assert r.status_code == 409 and r.json()["detail"] == "cannot replace: old mac still seen"
