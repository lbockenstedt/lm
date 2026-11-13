"""Tenant scoping of the static-IP reservation pass and its status.

The pass is fleet-wide, so these check it never reads or writes outside a
tenant's own NetBox scope, and that its status shows each viewer only their
own tenant's rows (a global admin sees everything only before switching into
a tenant). All data is RFC 1918 example data.
"""

from static_ip_reservations import status_for_tenant
from test_static_ip_reservations import _Hub, _agent_static, _run

_STATUS = {"status": "ok", "tenants": 2, "skipped": 3,
           "reserved": [{"tenant": "t-a", "ip": "10.20.0.50"},
                        {"tenant": "t-b", "ip": "10.20.0.51"}],
           "conflicts": [{"tenant": "t-b", "ip": "10.20.0.52"}],
           "errors": [{"tenant": "t-a", "error": "no strict kea lease read"}]}


def test_global_admin_without_a_tenant_sees_every_tenant():
    assert status_for_tenant(_STATUS, None) == _STATUS


def test_tenant_view_sees_only_its_own_rows_and_no_fleet_counters():
    """Tenant users, tenant admins and a global admin switched into the
    tenant all resolve to the same effective tenant, so see the same rows."""
    view = status_for_tenant(_STATUS, "t-a")
    assert [r["ip"] for r in view["reserved"]] == ["10.20.0.50"]
    assert view["conflicts"] == [] and len(view["errors"]) == 1
    assert "tenants" not in view and "skipped" not in view


def test_a_user_with_no_tenant_sees_no_rows():
    view = status_for_tenant(_STATUS, "")
    assert view["reserved"] == view["conflicts"] == view["errors"] == []


def test_a_tenant_without_a_netbox_mapping_is_never_read_or_written():
    hub = _Hub(agent_addresses=_agent_static())
    hub.state._tenants["t-a"] = {}
    _run(hub)
    assert hub.writes() == []
    assert not [1 for _s, c, _p in hub.log if c.startswith("NETBOX_")]


def test_an_agent_only_touches_its_own_tenants_netbox_scope():
    hub = _Hub(agent_addresses=_agent_static())
    _run(hub)
    reads = {p.get("tenant") for _s, c, p in hub.log if c.startswith("NETBOX_GET")}
    assert reads == {"tenant-a"}


def _sync_status_rows(user):
    """GET /api/dns-dhcp/sync-status as ``user``; the static rows it returns."""
    from test_dhcp_tenant_routing import FakeHub, _build
    hub = FakeHub({"dhcp-a"})
    hub.state.system_state = {"global_config": {}}
    hub.dns_dhcp_sync_status = {"static_reservations": _STATUS}
    hub._dns_hook_desired = lambda: False
    hub._dhcp_hold_declined = lambda: False
    body = _build({"user": user}, hub).get("/api/dns-dhcp/sync-status").json()
    return body["status"]["static_reservations"]["reserved"]


def test_sync_status_route_needs_the_dhcp_right_to_show_rows():
    """The route sits outside the /api/dhcp/ gate, so it checks the right itself."""
    with_right = {"tenant_id": "t-a", "permissions": {"dhcp": True}}
    without = {"tenant_id": "t-a", "permissions": {"nw": True}}
    assert [r["ip"] for r in _sync_status_rows(with_right)] == ["10.20.0.50"]
    assert _sync_status_rows(without) == []
    assert len(_sync_status_rows({"is_admin": True, "permissions": {"admin": True}})) == 2
