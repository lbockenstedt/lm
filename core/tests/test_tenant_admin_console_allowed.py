"""Unit tests for access.tenant_admin_console_allowed — the operator opt-in that
lets a Tenant Admin console/control VMs on a shared/unbound (or own) hypervisor
when Setup → Hypervisors enables it (tenant_console_enabled or host_shell_enabled)."""
import asyncio

import access
from _fakes import FakeHub, FakeState


class _FakeStore:
    def __init__(self, by_tenant):
        self._by_tenant = by_tenant

    async def get_hypervisors_config(self, tenant_id):
        return dict(self._by_tenant.get(tenant_id or "", {}))


def _hub(spoke_tenants=None, hv_by_tenant=None):
    hub = FakeHub(FakeState(spoke_tenants=spoke_tenants or {}))
    hub.simulations_store = _FakeStore(hv_by_tenant or {})
    return hub


def _sess(role="tenant_admin", tenants=("t1",)):
    return {"user": {"permissions": {"role": role},
                     "tenants": list(tenants), "tenant_id": (tenants[0] if tenants else "")}}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_non_tenant_admin_denied():
    hub = _hub(hv_by_tenant={"": {"tenant_console_enabled": True}})
    # A plain write-user (not tenant_admin) never gets whole-host access.
    assert _run(access.tenant_admin_console_allowed(hub, _sess(role="user"), "spoke")) is False


def test_unbound_hypervisor_opt_in_allows():
    hub = _hub(spoke_tenants={}, hv_by_tenant={"": {"tenant_console_enabled": True}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(), "spoke")) is True


def test_unbound_hypervisor_no_opt_in_denied():
    hub = _hub(spoke_tenants={}, hv_by_tenant={"": {}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(), "spoke")) is False


def test_host_shell_enabled_implies_console():
    hub = _hub(spoke_tenants={}, hv_by_tenant={"": {"host_shell_enabled": True}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(), "spoke")) is True


def test_bound_to_own_tenant_with_opt_in_allows():
    hub = _hub(spoke_tenants={"spoke": "t1"},
               hv_by_tenant={"t1": {"tenant_console_enabled": True}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(tenants=("t1",)), "spoke")) is True


def test_bound_to_other_tenant_denied_even_with_opt_in():
    # A hypervisor bound to a DIFFERENT tenant is never opened this way, even if
    # that tenant enabled the flag — no cross-tenant leak.
    hub = _hub(spoke_tenants={"spoke": "t2"},
               hv_by_tenant={"t2": {"tenant_console_enabled": True}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(tenants=("t1",)), "spoke")) is False


def test_admin_not_special_cased_here():
    # Global admins are allowed by the CALLERS (bypass); this helper only judges
    # the tenant-admin opt-in, so a non-tenant_admin role returns False.
    hub = _hub(hv_by_tenant={"": {"tenant_console_enabled": True}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(role="admin"), "spoke")) is False


def test_empty_spoke_unbound_treated_as_shared():
    hub = _hub(spoke_tenants={}, hv_by_tenant={"": {"tenant_console_enabled": True}})
    assert _run(access.tenant_admin_console_allowed(hub, _sess(), "")) is True
