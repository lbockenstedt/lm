"""A DHCP *write* must land on the Kea that owns the row it came from.

Every dhcp spoke fronts its own independent Kea (or Kea HA cluster). The
admin combined view merges leases/reservations from ALL of them
(_dhcp_merge_fanout), so a row shown in the UI may belong to any spoke.
The write routes used to resolve the target with _dhcp_spoke_for_request,
which for a no-tenant admin returns the FIRST connected dhcp spoke — so
reserving a lease that came from the second cluster silently wrote into
the first one's Kea. The reservation never appeared and the original lease
was never purged.

_dhcp_merge_fanout now tags every merged row with "_spoke", the WebUI hands
it back as "spoke_id", and _dhcp_write_spoke routes on it.
"""
from test_dhcp_tenant_routing import FakeHub, _build, _admin, _tenant_user


def _two_cluster_hub():
    return FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={
            "dhcp-a": {"DHCP_ADD_RES": {"status": "SUCCESS", "server": "A"},
                       "DHCP_DEL_LEASE": {"status": "SUCCESS", "server": "A"}},
            "dhcp-b": {"DHCP_ADD_RES": {"status": "SUCCESS", "server": "B"},
                       "DHCP_DEL_LEASE": {"status": "SUCCESS", "server": "B"}},
        },
        global_dhcp="dhcp-a",
    )


def test_reservation_write_follows_the_spoke_that_owns_the_row():
    hub = _two_cluster_hub()
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "aa:bb:cc:dd:ee:ff",
        "old_ip": "172.17.1.13", "spoke_id": "dhcp-b",
    })
    assert r.status_code == 200
    # Without the fix this went to the global fallback "dhcp-a".
    assert hub.forwarded[-1][0] == "dhcp-b"


def test_routing_keys_are_stripped_before_reaching_the_spoke():
    hub = _two_cluster_hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "aa:bb:cc:dd:ee:ff",
        "spoke_id": "dhcp-b", "_spoke": "dhcp-b", "_tenant": "t1",
    })
    sent = hub.forwarded[-1][2]
    for key in ("spoke_id", "_spoke", "_tenant"):
        assert key not in sent
    assert sent["ip"] == "172.17.1.199"


def test_underscore_spoke_tag_alone_is_enough_to_route():
    hub = _two_cluster_hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "aa:bb:cc:dd:ee:ff", "_spoke": "dhcp-b"})
    assert hub.forwarded[-1][0] == "dhcp-b"


def test_lease_delete_follows_the_owning_spoke():
    hub = _two_cluster_hub()
    c = _build(_admin(), hub)
    c.request("DELETE", "/api/dhcp/lease",
              json={"ip": "172.17.1.13", "spoke_id": "dhcp-b"})
    assert hub.forwarded[-1][0] == "dhcp-b"


def test_absent_spoke_id_keeps_legacy_resolution():
    hub = _two_cluster_hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "aa:bb:cc:dd:ee:ff"})
    assert hub.forwarded[-1][0] == "dhcp-a"


def test_unknown_spoke_id_is_rejected_not_silently_redirected():
    hub = _two_cluster_hub()
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "aa:bb:cc:dd:ee:ff", "spoke_id": "nope"})
    assert r.status_code == 400
    assert not hub.forwarded


def test_tenant_user_cannot_target_another_tenants_spoke():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={"dhcp-b": {"DHCP_ADD_RES": {"status": "SUCCESS"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "aa:bb:cc:dd:ee:ff", "spoke_id": "dhcp-b"})
    assert r.status_code == 403
    assert not hub.forwarded


def test_merged_rows_carry_the_spoke_tag_the_write_path_needs():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={
            "dhcp-a": {"DHCP_LIST_LEASES": {"status": "SUCCESS",
                                            "leases": [{"ip-address": "172.17.1.13"}]}},
            "dhcp-b": {"DHCP_LIST_LEASES": {"status": "SUCCESS",
                                            "leases": [{"ip-address": "172.17.1.14"}]}},
        },
    )
    c = _build(_admin(), hub)
    leases = c.get("/api/dhcp/leases").json()["leases"]
    assert len(leases) == 2
    assert {l["_spoke"] for l in leases} == {"dhcp-a", "dhcp-b"}
