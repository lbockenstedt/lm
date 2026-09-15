"""A reservation created in the WebUI must be written back to NetBox.

``core/src/dns_dhcp_sync.py`` rebuilds Kea's ENTIRE ``subnet4`` from NetBox
(``build_dhcp_payload`` mints a reservation only for an IP carrying
``custom_fields.mac_address``) and ``config-set``s the result. A reservation
added straight to Kea by ``POST /api/dhcp/reservation`` is therefore invisible
to that payload, and the next NetBox change silently DELETES it.

The loss is completely silent and arbitrarily delayed: the add returns
SUCCESS, the row appears in the merged Reservations list, and it vanishes
minutes-to-days later, whenever something unrelated in NetBox happens to move
the sync's payload hash. Observed in production — a 172.17.1.199 reservation
survived only for as long as its Kea cluster was unreachable, and disappeared
the moment the cluster became writable again and the next sync landed.

So these tests assert on the NetBox side-effect, not on the Kea reply: a Kea
reply that says SUCCESS is exactly what the bug looked like.
"""
from test_dhcp_tenant_routing import FakeHub, _build, _admin


class WritebackHub(FakeHub):
    """FakeHub that also fronts an ipam spoke holding a NetBox IP set."""

    def __init__(self, *a, ip_addresses=None, ipam="ipam-1",
                 ipam_error=None, **kw):
        super().__init__(*a, **kw)
        self._ipam = ipam
        self._ipam_error = ipam_error
        self.ip_addresses = ip_addresses if ip_addresses is not None else [
            {"id": 42, "address": "172.17.1.199/24",
             "dns_name": "mipbe-ssplm-winwks-lrb",
             "custom_fields": {"mac_address": ""}},
            {"id": 43, "address": "172.17.1.13/24", "custom_fields": {}},
        ]
        if ipam:
            self.active_connections.add(ipam)

    def get_spoke_by_type(self, module_type):
        if module_type == "ipam":
            return self._ipam
        return super().get_spoke_by_type(module_type)

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        if cmd in ("NETBOX_GET_IPS", "NETBOX_UPDATE_IP_ADDR"):
            self.forwarded.append((sid, cmd, payload))
            if self._ipam_error:
                raise RuntimeError(self._ipam_error)
            if cmd == "NETBOX_GET_IPS":
                return {"payload": {"data": {"ip_addresses": self.ip_addresses}}}
            return {"payload": {"data": {"status": "SUCCESS"}}}
        return await super().request_response(sid, cmd, payload, timeout)


def _hub(**kw):
    return WritebackHub(
        {"dhcp-a"},
        replies={"dhcp-a": {"DHCP_ADD_RES": {"status": "SUCCESS"},
                            "DHCP_UPDATE_RES": {"status": "SUCCESS"},
                            "DHCP_DEL_RES": {"status": "SUCCESS"}}},
        global_dhcp="dhcp-a",
        **kw,
    )


def _netbox_writes(hub):
    return [p for _, cmd, p in hub.forwarded if cmd == "NETBOX_UPDATE_IP_ADDR"]


# ── the core regression ──────────────────────────────────────────────────────

def test_adding_a_reservation_persists_the_mac_to_netbox():
    hub = _hub()
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    writes = _netbox_writes(hub)
    # Without the write-back this list is empty and the reservation exists
    # ONLY in Kea, where the next NetBox->Kea sync deletes it.
    assert writes == [{"ip_id": 42,
                       "custom_fields": {"mac_address": "bc:24:11:df:63:5e"}}]


def test_the_kea_write_still_happens_and_still_goes_first():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    cmds = [cmd for _, cmd, _ in hub.forwarded]
    assert cmds[0] == "DHCP_ADD_RES"
    assert "NETBOX_UPDATE_IP_ADDR" in cmds


def test_writeback_outcome_is_reported_to_the_caller():
    hub = _hub()
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    wb = r.json()["netbox_writeback"]
    assert wb["status"] == "ok" and wb["ip_id"] == 42


def test_existing_reply_keys_are_preserved():
    hub = _hub()
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.json()["status"] == "SUCCESS"


# ── delete / update keep NetBox in step ──────────────────────────────────────

def test_deleting_a_reservation_clears_the_netbox_mac():
    hub = _hub(ip_addresses=[
        {"id": 42, "address": "172.17.1.199/24",
         "custom_fields": {"mac_address": "bc:24:11:df:63:5e"}}])
    c = _build(_admin(), hub)
    r = c.request("DELETE", "/api/dhcp/reservation",
                  json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    # Leaving the mac behind means the very next sync recreates the
    # reservation the operator just deleted.
    assert _netbox_writes(hub) == [{"ip_id": 42,
                                    "custom_fields": {"mac_address": ""}}]


def test_readdressing_a_reservation_clears_the_old_ip_too():
    hub = _hub(ip_addresses=[
        {"id": 42, "address": "172.17.1.199/24", "custom_fields": {}},
        {"id": 43, "address": "172.17.1.13/24",
         "custom_fields": {"mac_address": "bc:24:11:df:63:5e"}}])
    c = _build(_admin(), hub)
    r = c.put("/api/dhcp/reservation",
              json={"ip": "172.17.1.199", "old_ip": "172.17.1.13",
                    "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    assert _netbox_writes(hub) == [
        {"ip_id": 43, "custom_fields": {"mac_address": ""}},
        {"ip_id": 42, "custom_fields": {"mac_address": "bc:24:11:df:63:5e"}},
    ]


def test_update_without_readdressing_touches_only_the_one_ip():
    hub = _hub()
    c = _build(_admin(), hub)
    c.put("/api/dhcp/reservation",
          json={"ip": "172.17.1.199", "old_ip": "172.17.1.199",
                "mac": "bc:24:11:df:63:5e"})
    assert _netbox_writes(hub) == [{"ip_id": 42,
                                    "custom_fields": {"mac_address": "bc:24:11:df:63:5e"}}]


# ── the write-back must never break an already-applied Kea write ─────────────

def test_unknown_address_is_flagged_not_fatal():
    hub = _hub(ip_addresses=[])
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "10.0.0.5", "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    assert r.json()["netbox_writeback"]["status"] == "not_found"
    assert not _netbox_writes(hub)


def test_no_ipam_spoke_is_skipped_not_fatal():
    hub = _hub(ipam=None)
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    assert r.json()["netbox_writeback"]["status"] == "skipped"


def test_netbox_failure_is_reported_not_raised():
    hub = _hub(ipam_error="netbox 500")
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    assert r.json()["netbox_writeback"]["status"] == "error"


def test_already_correct_mac_is_not_rewritten():
    hub = _hub(ip_addresses=[
        {"id": 42, "address": "172.17.1.199/24",
         "custom_fields": {"mac_address": "BC:24:11:DF:63:5E"}}])
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation",
               json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.json()["netbox_writeback"]["status"] == "unchanged"
    assert not _netbox_writes(hub)


def test_routing_keys_never_reach_the_ipam_spoke():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e",
                 "spoke_id": "dhcp-a", "_tenant": "t1"})
    for payload in _netbox_writes(hub):
        assert set(payload) == {"ip_id", "custom_fields"}
