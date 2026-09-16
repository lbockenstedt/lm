"""A DHCP write with no ``_spoke`` tag must go to the spoke that OWNS the
target subnet, not to whichever dhcp spoke connected first.

test_dhcp_write_spoke_routing.py covers the easy half: a row from the admin
merged view carries ``_spoke``, so the write follows it back. The other half
is every write that has no such tag — a plain "Add Reservation", or a row
from a tenant-scoped (unmerged) list. Those fell through to
_dhcp_spoke_for_request, which for an admin with no tenant selected returns
the FIRST connected dhcp spoke.

Seen in production: a hub with two dhcp spokes, only one of which actually
fronts a Kea cluster. The reservation POST carried no spoke_id, the global
resolver handed it the Kea-less spoke, and the write died with a raw
"RuntimeError: Kea CA unreachable: HTTPConnectionPool(host='localhost',
port=8001)" returned to the browser as a 502. The same coin flip between two
*working* clusters is worse: it succeeds, silently, into the wrong Kea.

_dhcp_spoke_owning_target asks the spokes instead: exactly one of them lists
the target subnet.
"""
from test_dhcp_tenant_routing import FakeHub, _build, _admin, _tenant_user

_LIVE_SUBNETS = {"status": "SUCCESS", "subnets": [
    {"id": "55688444", "subnet": "172.17.1.0/24"},
]}
_OTHER_SUBNETS = {"status": "SUCCESS", "subnets": [
    {"id": "101", "subnet": "10.0.0.0/24"},
]}
_OK = {"status": "SUCCESS"}


def _hub(dead_replies=None, live_subnets=None):
    """Two dhcp spokes. "dhcp-dead" is the global first-connected fallback and
    owns nothing; "dhcp-live" owns 172.17.1.0/24."""
    return FakeHub(
        {"dhcp-dead", "dhcp-live"},
        replies={
            "dhcp-dead": dead_replies if dead_replies is not None else {
                "DHCP_LIST_SUBNETS": {"status": "SUCCESS", "subnets": []}},
            "dhcp-live": {
                "DHCP_LIST_SUBNETS": live_subnets or _LIVE_SUBNETS,
                "DHCP_ADD_RES": _OK, "DHCP_UPDATE_RES": _OK,
                "DHCP_DEL_RES": _OK, "DHCP_DEL_LEASE": _OK,
            },
        },
        global_dhcp="dhcp-dead",
    )


def _writes(hub):
    return [f for f in hub.forwarded if f[1] != "DHCP_LIST_SUBNETS"]


# ── the fix ─────────────────────────────────────────────────────────────────

def test_reservation_without_spoke_id_routes_by_subnet_id():
    hub = _hub()
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation", json={
        "subnet_id": "55688444", "ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert r.status_code == 200
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_reservation_without_subnet_id_routes_by_ip_containment():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_subnet_id_key_variants_are_matched():
    hub = _hub(live_subnets={"status": "SUCCESS",
                             "subnets": [{"subnet_id": "55688444", "subnet": ""}]})
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"subnet-id": "55688444", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_a_spoke_whose_kea_is_unreachable_owns_nothing():
    """The production case: the fallback spoke raises instead of listing
    subnets. It must not swallow the write."""
    hub = _hub(dead_replies={"DHCP_LIST_SUBNETS": {"status": "ERROR",
                                                   "message": "Kea CA unreachable"}})
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_lease_delete_routes_by_subnet_owner():
    hub = _hub()
    c = _build(_admin(), hub)
    c.request("DELETE", "/api/dhcp/lease", json={"ip": "172.17.1.13"})
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_reservation_update_routes_by_subnet_owner():
    hub = _hub()
    c = _build(_admin(), hub)
    c.put("/api/dhcp/reservation",
          json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_reservation_delete_routes_by_subnet_owner():
    hub = _hub()
    c = _build(_admin(), hub)
    c.request("DELETE", "/api/dhcp/reservation", json={"ip": "172.17.1.199"})
    assert _writes(hub)[-1][0] == "dhcp-live"


def test_old_ip_resolves_the_owner_when_the_new_ip_is_unknown():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation", json={
        "ip": "", "old_ip": "172.17.1.13", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-live"


# ── guard rails: never guess ────────────────────────────────────────────────

def test_explicit_spoke_id_still_wins_over_subnet_ownership():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e", "spoke_id": "dhcp-dead"})
    assert _writes(hub)[-1][0] == "dhcp-dead"
    # ...and the probe is skipped entirely when the caller already told us.
    assert all(f[1] != "DHCP_LIST_SUBNETS" for f in hub.forwarded)


def test_two_spokes_claiming_the_same_subnet_fall_back_rather_than_guess():
    hub = _hub(dead_replies={"DHCP_LIST_SUBNETS": _LIVE_SUBNETS})
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-dead"  # legacy resolver, unchanged


def test_no_owner_anywhere_falls_back_to_the_legacy_resolver():
    hub = _hub(live_subnets=_OTHER_SUBNETS)
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "192.168.99.5", "mac": "bc:24:11:df:63:5e"})
    assert _writes(hub)[-1][0] == "dhcp-dead"


def test_tenant_scoped_write_is_not_probed_at_all():
    """A tenant's spoke binding is already unambiguous — don't add a round
    trip, and don't let a subnet probe override tenant isolation."""
    hub = FakeHub(
        {"dhcp-dead", "dhcp-live"},
        replies={"dhcp-dead": {"DHCP_ADD_RES": _OK},
                 "dhcp-live": {"DHCP_LIST_SUBNETS": _LIVE_SUBNETS, "DHCP_ADD_RES": _OK}},
        module_metadata={"dhcp-dead": {"tenant_id": "tenantA"},
                         "dhcp-live": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert all(f[1] != "DHCP_LIST_SUBNETS" for f in hub.forwarded)
    # Whatever the shared-write guard decides, tenantB's spoke is never touched.
    assert all(f[0] != "dhcp-live" for f in hub.forwarded)


def test_single_dhcp_spoke_is_not_probed():
    hub = FakeHub({"dhcp-only"},
                  replies={"dhcp-only": {"DHCP_ADD_RES": _OK}},
                  global_dhcp="dhcp-only")
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation",
           json={"ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e"})
    assert all(f[1] != "DHCP_LIST_SUBNETS" for f in hub.forwarded)
    assert _writes(hub)[-1][0] == "dhcp-only"


def test_body_with_no_ip_or_subnet_is_not_probed():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation", json={"mac": "bc:24:11:df:63:5e"})
    assert all(f[1] != "DHCP_LIST_SUBNETS" for f in hub.forwarded)
    assert _writes(hub)[-1][0] == "dhcp-dead"


def test_routing_keys_never_reach_the_probed_spoke():
    hub = _hub()
    c = _build(_admin(), hub)
    c.post("/api/dhcp/reservation", json={
        "ip": "172.17.1.199", "mac": "bc:24:11:df:63:5e", "_tenant": "lrb"})
    sent = _writes(hub)[-1][2]
    assert "_tenant" not in sent and sent["ip"] == "172.17.1.199"
