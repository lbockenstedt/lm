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


def test_vrf_tenant_may_write_reservations_on_its_own_kea(monkeypatch):
    """A subnet a tenant has only in its own VRF is cut from shared writes,
    but a reservation landing on the tenant's OWN Kea is the tenant's
    whatever its address: every reservation route passes its target spoke."""
    import routes.net_services as ns

    async def out_of_shared_scope(hub, sess, record, fields, spoke_id=None):
        return False

    monkeypatch.setattr(ns.access, "record_in_tenant_scope", out_of_shared_scope)
    monkeypatch.setattr(ns.access, "spoke_owner_tenant",
                        lambda hub, sid: {"dhcp-a": "tenantA"}.get(sid))
    monkeypatch.setattr(ns.access, "_owned_spoke_writable",
                        lambda hub, sess, sid, owner: owner == sess["user"]["tenant_id"])
    hub = FakeHub({"dhcp-a", "dhcp-b"},
                  module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                                   "dhcp-b": {"tenant_id": "tenantB"}})
    body = {"ip": "10.9.0.5", "mac": "aa:bb:cc:dd:ee:ff"}

    c = _build(_tenant_user("tenantA"), hub)
    for method in ("POST", "PUT", "DELETE"):
        assert c.request(method, "/api/dhcp/reservation", json=body).status_code == 200
    assert [s for s, _c, _p in hub.forwarded] == ["dhcp-a"] * 3

    # The same write from a tenant with no Kea of its own is still refused.
    hub.forwarded.clear()
    c = _build(_tenant_user("tenantC"), hub)
    assert c.post("/api/dhcp/reservation", json=body).status_code in (403, 503)
    assert not hub.forwarded


def test_vrf_tenant_may_write_on_a_kea_it_owns_by_instance_record(monkeypatch):
    """A Kea the tenant configured itself (a ``dhcp_instances`` record) on a
    spoke with no tenant binding is still the tenant's own: the same records
    route its writes, so the shared-VRF cut must not refuse them."""
    import routes.net_services as ns

    async def out_of_shared_scope(hub, sess, record, fields, spoke_id=None):
        return False

    monkeypatch.setattr(ns.access, "record_in_tenant_scope", out_of_shared_scope)
    hub = FakeHub({"dhcp-a"},
                  dhcp_instances=[{"tenant_id": "tenantA", "spoke_id": "dhcp-a"}])
    body = {"ip": "10.9.0.5", "mac": "aa:bb:cc:dd:ee:ff"}

    c = _build(_tenant_user("tenantA"), hub)
    assert c.post("/api/dhcp/reservation", json=body).status_code == 200
    assert [s for s, _c, _p in hub.forwarded] == ["dhcp-a"]
