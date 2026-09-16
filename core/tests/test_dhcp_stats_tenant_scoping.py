"""The DHCP Overview tab must scope "Scope Utilization" to the caller's tenant.

/api/dhcp/subnets, /api/dhcp/leases and /api/dhcp/reservations all end in
``_filter_tenant(...)``; /api/dhcp/stats did not. The Overview tab renders
``stats.subnets``, so a tenant user saw EVERY tenant's scopes there while the
Subnets/Leases/Reservations tabs beside it were correctly scoped. (Reported
from production: an LRB-tenant login listing ADMIN scopes on Overview only.)
/api/dns/stats already filtered — DHCP stats was simply missed.

Filtering the list alone is not enough:

* ``global`` holds pool totals for the whole Kea instance, so one visible scope
  would sit under a fleet-wide utilization tile.
* ``members`` holds each HA node's RAW reply, including a complete unfiltered
  ``subnets`` list — the scopes leak back out through a field the UI never
  reads. Worst on the fail-closed path, where a tenant with no NetBox prefixes
  gets ``subnets: []`` and an intact ``members``.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from routes.net_services import register, _dhcp_rescope_stats

from test_dhcp_tenant_routing import FakeHub, _admin, _tenant_user


_STATS = {
    "status": "SUCCESS",
    "global": {"total_addresses": 1000, "assigned_addresses": 300,
               "declined_addresses": 10, "utilization_pct": 30.0,
               "pkt4_discover": 77, "pkt4_ack_sent": 55},
    "subnets": [
        {"subnet": "10.10.0.0/24", "total_addresses": 200,
         "assigned_addresses": 50, "declined_addresses": 1},
        {"subnet": "10.20.0.0/24", "total_addresses": 800,
         "assigned_addresses": 250, "declined_addresses": 9},
    ],
    "cluster": True,
    "members": {"node-1": {"status": "SUCCESS", "subnets": [
        {"subnet": "10.10.0.0/24"}, {"subnet": "10.20.0.0/24"}]}},
}


def _stats():
    import copy
    return copy.deepcopy(_STATS)


# ── _dhcp_rescope_stats (pure) ──────────────────────────────────────────────

def test_totals_are_rederived_from_the_visible_scopes():
    before = _stats()
    after = _stats()
    after["subnets"] = [after["subnets"][0]]

    out = _dhcp_rescope_stats(before, after)

    assert out["global"]["total_addresses"] == 200
    assert out["global"]["assigned_addresses"] == 50
    assert out["global"]["declined_addresses"] == 1
    assert out["global"]["utilization_pct"] == 25.0


def test_raw_member_replies_are_dropped_when_filtered():
    """`members` embeds an unfiltered copy of every subnet."""
    before = _stats()
    after = _stats()
    after["subnets"] = [after["subnets"][0]]

    out = _dhcp_rescope_stats(before, after)

    assert "members" not in out


def test_fail_closed_empty_scope_list_zeroes_the_tiles_and_drops_members():
    """A tenant with no NetBox prefixes: _filter_tenant empties `subnets` but
    leaves `members` intact — the leak this closes."""
    before = _stats()
    after = _stats()
    after["subnets"] = []

    out = _dhcp_rescope_stats(before, after)

    assert out["subnets"] == []
    assert "members" not in out
    assert out["global"]["total_addresses"] == 0
    assert out["global"]["assigned_addresses"] == 0
    assert out["global"]["utilization_pct"] == 0.0


def test_server_level_packet_counters_are_preserved():
    """pkt4_* cannot be attributed to a scope, so they are left alone."""
    before = _stats()
    after = _stats()
    after["subnets"] = [after["subnets"][0]]

    out = _dhcp_rescope_stats(before, after)

    assert out["global"]["pkt4_discover"] == 77
    assert out["global"]["pkt4_ack_sent"] == 55


def test_unfiltered_admin_view_is_returned_untouched():
    """The spoke de-duplicates HA nodes by averaging, not naive summing, so an
    admin must keep the spoke's own numbers rather than our re-derived ones."""
    before = _stats()
    after = _stats()

    out = _dhcp_rescope_stats(before, after)

    assert out is after
    assert out["global"]["total_addresses"] == 1000
    assert "members" in out


def test_non_stats_shapes_pass_through():
    assert _dhcp_rescope_stats({"status": "ERROR"}, {"status": "ERROR"}) == {"status": "ERROR"}
    assert _dhcp_rescope_stats(None, None) is None


# ── the route actually filters ──────────────────────────────────────────────

def _build_with_real_filter(sess, hub, allowed_prefix, calls):
    """Like test_dhcp_tenant_routing._build, but _filter_tenant records its
    arguments and really prunes, instead of passing through."""
    async def _filter(request, data, module, ip_fields, explicit_tenant=None):
        calls.append({"module": module, "ip_fields": ip_fields,
                      "tenant": explicit_tenant})
        is_admin = bool(sess and sess.get("user", {}).get("is_admin"))
        tid = explicit_tenant if is_admin else (sess or {}).get("user", {}).get("tenant_id")
        if not tid:
            return data
        out = dict(data)
        out["subnets"] = [s for s in data.get("subnets", [])
                          if s.get("subnet") == allowed_prefix]
        return out

    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
        _effective_tenant=lambda request, explicit=None: (
            explicit if (sess and sess.get("user", {}).get("is_admin"))
            else (sess or {}).get("user", {}).get("tenant_id")
        ),
        _filter_session=_filter,
        _filter_tenant=_filter,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


def _hub():
    return FakeHub({"dhcp-a"}, replies={"dhcp-a": {"DHCP_STATS": _stats()}},
                   module_metadata={"dhcp-a": {"tenant_id": "lrb"}},
                   global_dhcp="dhcp-a")


def test_tenant_user_sees_only_their_own_scopes_on_overview():
    """THE REGRESSION: an LRB user must not see the ADMIN scope."""
    calls = []
    client = _build_with_real_filter(_tenant_user("lrb"), _hub(),
                                     "10.10.0.0/24", calls)

    body = client.get("/api/dhcp/stats?tenant=lrb").json()

    assert [s["subnet"] for s in body["subnets"]] == ["10.10.0.0/24"]
    assert body["global"]["total_addresses"] == 200
    assert "members" not in body


def test_stats_is_filtered_with_the_same_key_as_the_subnets_tab():
    """/api/dhcp/subnets uses module "dhcp" and ip_fields ["subnet"]; Overview
    must match it or the two tabs disagree about what the tenant owns."""
    calls = []
    client = _build_with_real_filter(_tenant_user("lrb"), _hub(),
                                     "10.10.0.0/24", calls)

    client.get("/api/dhcp/stats?tenant=lrb")

    assert calls, "/api/dhcp/stats must call _filter_tenant"
    assert calls[0]["module"] == "dhcp"
    assert calls[0]["ip_fields"] == ["subnet"]


def test_admin_with_no_tenant_still_sees_every_scope():
    calls = []
    client = _build_with_real_filter(_admin(), _hub(), "10.10.0.0/24", calls)

    body = client.get("/api/dhcp/stats").json()

    assert [s["subnet"] for s in body["subnets"]] == ["10.10.0.0/24", "10.20.0.0/24"]
    assert body["global"]["total_addresses"] == 1000
