"""Tenant scoping of the static-IP reservation pass and its status.

The pass is fleet-wide, so these check it never reads or writes outside a
tenant's own NetBox scope, and that its status shows each viewer only their
own tenant's rows (a global admin sees a tenant's rows only after switching
into it). All data is RFC 1918 example data.
"""

from static_ip_reservations import status_for_tenant
from test_static_ip_reservations import _Hub, _agent_static, _run

_STATUS = {"status": "error", "tenants": 2, "skipped": 3, "clean": ["t-b"],
           "skipped_reasons": {"no netbox ip": 3, "no kea subnet": 1},
           "skipped_by_tenant": [{"tenant": "t-a", "reasons": {"no netbox ip": 2}},
                                 {"tenant": "t-b", "reasons": {"no netbox ip": 1,
                                                               "no kea subnet": 1}}],
           "reserved": [{"tenant": "t-a", "ip": "10.20.0.50"},
                        {"tenant": "t-b", "ip": "10.20.0.51"}],
           "conflicts": [{"tenant": "t-b", "ip": "10.20.0.52"}],
           "errors": [{"tenant": "t-a", "error": "no strict kea lease read"}]}


def test_global_admin_without_a_tenant_sees_no_tenant_rows():
    view = status_for_tenant(_STATUS, None)
    assert view["reserved"] == view["conflicts"] == view["errors"] == []
    assert "tenants" not in view


def test_tenant_view_sees_only_its_own_rows_and_no_fleet_counters():
    """Tenant users, tenant admins and a global admin switched into the
    tenant all resolve to the same effective tenant, so see the same rows."""
    view = status_for_tenant(_STATUS, "t-a")
    assert [r["ip"] for r in view["reserved"]] == ["10.20.0.50"]
    assert view["conflicts"] == [] and len(view["errors"]) == 1
    assert "tenants" not in view and "skipped" not in view and "clean" not in view


def test_tenant_status_reflects_only_its_own_rows():
    """error beats conflicts beats ok (evaluated cleanly) beats skipped."""
    assert status_for_tenant(_STATUS, "t-a")["status"] == "error"
    assert status_for_tenant(_STATUS, "t-b")["status"] == "conflicts"
    assert status_for_tenant(dict(_STATUS, conflicts=[]), "t-b")["status"] == "ok"
    assert status_for_tenant(_STATUS, "t-c")["status"] == "skipped"


def test_a_user_with_no_tenant_sees_no_rows():
    view = status_for_tenant(_STATUS, "")
    assert view["reserved"] == view["conflicts"] == view["errors"] == []


def test_a_pass_wide_error_is_shown_to_every_tenant():
    """The netbox spoke unreachable or too old names no tenant."""
    status = dict(_STATUS, errors=[{"tenant": None, "error": "netbox spoke too old; update it"}],
                  status="unsupported")
    view = status_for_tenant(status, "t-b")
    assert view["status"] == "unsupported" and len(view["errors"]) == 1


def test_a_tenant_without_a_netbox_mapping_is_never_sent():
    hub = _Hub(agent_addresses=_agent_static())
    hub.state._tenants["t-a"] = {}
    _run(hub)
    assert hub.sent() == []


def test_an_agent_only_puts_its_own_tenants_netbox_scope_in_the_pass():
    hub = _Hub(agent_addresses=_agent_static())
    _run(hub)
    assert [t["filters"] for t in hub.sent()[0]["tenants"]] == [{"tenant": "tenant-a"}]


def _sync_status(user, stored=_STATUS):
    """GET /api/dns-dhcp/sync-status as ``user``; its static_reservations."""
    from test_dhcp_tenant_routing import FakeHub, _build
    hub = FakeHub({"dhcp-a"})
    hub.state.system_state = {"global_config": {}}
    hub.dns_dhcp_sync_status = {"static_reservations": stored} if stored is not None else {}
    hub._dns_hook_desired = lambda: False
    hub._dhcp_hold_declined = lambda: False
    body = _build({"user": user}, hub).get("/api/dns-dhcp/sync-status").json()
    return body["status"]["static_reservations"]


_WITH_RIGHT = {"tenant_id": "t-a", "permissions": {"dhcp": True}}


def test_sync_status_route_needs_the_dhcp_right_to_show_rows():
    """The route sits outside the /api/dhcp/ gate, so it checks the right itself."""
    assert [r["ip"] for r in _sync_status(_WITH_RIGHT)["reserved"]] == ["10.20.0.50"]
    without = {"tenant_id": "t-a", "permissions": {"nw": True}}
    assert _sync_status(without) == {"visibility_reason": "no_permission"}


def test_sync_status_route_says_why_rows_are_hidden_or_missing():
    assert _sync_status(_WITH_RIGHT)["visibility_reason"] == "tenant"
    admin = {"is_admin": True, "permissions": {"admin": True}}
    assert _sync_status(admin) == {"status": "error", "visibility_reason": "no_tenant"}
    # A tenant sees only its own skip counts, never the pass-wide ones.
    view = _sync_status(_WITH_RIGHT)
    assert view["skipped_reasons"] == {"no netbox ip": 2} and "skipped_by_tenant" not in view
    # Never ran: no status word, but still a reason.
    assert _sync_status(_WITH_RIGHT, stored=None) == {"visibility_reason": "tenant"}
