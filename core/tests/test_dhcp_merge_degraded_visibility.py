"""A DHCP cluster that is DOWN must not look like a cluster that is EMPTY.

The admin combined view fans the subnet/lease/reservation list out to EVERY
connected dhcp spoke (``_dhcp_merge_fanout``) — each fronts its own independent
Kea. A spoke whose Kea Control Agent is unreachable used to be swallowed by a
bare ``except → return []``, so its rows just vanished from the merged list with
no signal anywhere in the API or the UI.

That made "one of my two Kea clusters is down" indistinguishable from "there are
no reservations", and cost real time chasing a phantom data-loss bug: the
operator saw an empty Reservations table while 126 reservations sat safely on a
cluster the hub couldn't reach.

The merge still never fails on one bad spoke — but it now reports the casualties
in ``_degraded`` so the WebUI can name the missing cluster
(``_dhcpDegradedBanner``).
"""
from test_dhcp_tenant_routing import FakeHub, _admin, _build


class _FlakyHub(FakeHub):
    """Two dhcp clusters; ``dead`` raises on every relay (unreachable Kea)."""

    def __init__(self, dead=("dhcp-b",), tenants=None, **kw):
        super().__init__({"dhcp-a", "dhcp-b"}, global_dhcp="dhcp-a", **kw)
        self._dead = set(dead)
        self._tenants = tenants or {"dhcp-a": "alpha", "dhcp-b": "bravo"}
        self.state.get_spoke_tenant = lambda sid: self._tenants.get(sid, "")

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        if sid in self._dead:
            raise RuntimeError("Kea Control Agent did not answer at http://localhost:8001")
        return {"payload": {"data": {
            "status": "SUCCESS",
            "reservations": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01"}],
            "leases": [{"ip-address": "10.0.0.9", "hw-address": "aa:bb:cc:dd:ee:02"}],
            "subnets": [{"subnet": "10.0.0.0/24"}],
        }}}


_PATHS = (("/api/dhcp/reservations", "reservations"),
          ("/api/dhcp/leases", "leases"),
          ("/api/dhcp/subnets", "subnets"))


def test_live_cluster_rows_still_returned_when_the_other_is_down():
    c = _build(_admin(), _FlakyHub())
    for path, key in _PATHS:
        body = c.get(path).json()
        assert len(body[key]) == 1, path
        assert body[key][0]["_spoke"] == "dhcp-a"


def test_dead_cluster_is_reported_not_silently_dropped():
    c = _build(_admin(), _FlakyHub())
    for path, _key in _PATHS:
        body = c.get(path).json()
        bad = body.get("_degraded")
        assert bad, f"{path} hid the unreachable cluster"
        assert len(bad) == 1
        assert bad[0]["spoke"] == "dhcp-b"
        # The tenant name is what the operator recognises in the UI.
        assert bad[0]["tenant"] == "bravo"
        assert "Control Agent" in bad[0]["error"]


def test_all_clusters_down_reports_every_one_with_an_empty_list():
    c = _build(_admin(), _FlakyHub(dead=("dhcp-a", "dhcp-b")))
    body = c.get("/api/dhcp/reservations").json()
    assert body["reservations"] == [] and body["total"] == 0
    assert {b["spoke"] for b in body["_degraded"]} == {"dhcp-a", "dhcp-b"}


def test_healthy_merge_carries_no_degraded_key():
    # No banner noise on a fully healthy fleet.
    c = _build(_admin(), _FlakyHub(dead=()))
    body = c.get("/api/dhcp/reservations").json()
    assert len(body["reservations"]) == 2
    assert "_degraded" not in body


def test_spoke_returning_a_malformed_payload_is_also_reported():
    class _Malformed(_FlakyHub):
        async def request_response(self, sid, cmd, payload=None, timeout=None):
            if sid == "dhcp-b":
                return {"payload": {"data": {"status": "SUCCESS"}}}   # no list
            return await _FlakyHub.request_response(self, sid, cmd, payload, timeout)

    c = _build(_admin(), _Malformed(dead=()))
    body = c.get("/api/dhcp/reservations").json()
    assert len(body["reservations"]) == 1
    assert body["_degraded"][0]["spoke"] == "dhcp-b"
    assert "reservations" in body["_degraded"][0]["error"]
