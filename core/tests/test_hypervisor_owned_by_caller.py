"""Guard for ``access.hypervisor_owned_by_caller`` — whole-host ownership for the
VM console/control gates.

THE bug: a tenant admin who owns a hypervisor (its spoke is BOUND to their
tenant) could open the host SHELL (gated on spoke binding) but was DENIED a
VM's console ("not authorized for this VM's tenant"), because that gate
attributed a VM only by its Proxmox tag or a live IP∈prefix — a STOPPED or
guest-agentless VM exposes no IP, and many fleets never tag VMs. Whole-host
ownership closes the gap: a tenant bound to the hypervisor owns every VM on it.

STRICT: a shared/unbound host is NOT owned (falls through to per-VM tag/subnet
attribution), preserving multi-tenant isolation on a shared hypervisor.
"""
import access
from _fakes import FakeHub, FakeState


def _hub(spoke_tenants):
    return FakeHub(FakeState(spoke_tenants=spoke_tenants))


def _sess(tenants, tenant_id=None):
    return {"user": {"permissions": {"role": "tenant_admin"},
                     "tenants": tenants,
                     "tenant_id": tenant_id if tenant_id is not None
                     else (tenants[0] if tenants else None)}}


def test_admin_always_owns():
    hub = _hub({"pxmx-1": "acme"})
    assert access.hypervisor_owned_by_caller(hub, {"user": {"permissions": {"admin": True}}}, "pxmx-1") is True


def test_bound_hypervisor_owned_by_its_tenant():
    hub = _hub({"pxmx-acme": "acme"})
    assert access.hypervisor_owned_by_caller(hub, _sess(["acme"]), "pxmx-acme") is True


def test_bound_hypervisor_owned_by_multi_tenant_admin_non_primary():
    hub = _hub({"pxmx-globex": "globex"})
    # Primary tenant is acme; the hypervisor is bound to globex (also assigned).
    assert access.hypervisor_owned_by_caller(hub, _sess(["acme", "globex"]), "pxmx-globex") is True


def test_foreign_bound_hypervisor_not_owned():
    hub = _hub({"pxmx-initech": "initech"})
    assert access.hypervisor_owned_by_caller(hub, _sess(["acme"]), "pxmx-initech") is False


def test_unbound_hypervisor_not_owned():
    # No binding → shared/global host → NOT whole-host owned (per-VM attribution
    # must still decide; a tenant can't grab a shared host's VMs wholesale).
    hub = _hub({})
    assert access.hypervisor_owned_by_caller(hub, _sess(["acme"]), "pxmx-shared") is False


def test_no_spoke_id_not_owned():
    hub = _hub({"pxmx-acme": "acme"})
    assert access.hypervisor_owned_by_caller(hub, _sess(["acme"]), "") is False


def test_no_tenants_not_owned():
    hub = _hub({"pxmx-acme": "acme"})
    assert access.hypervisor_owned_by_caller(hub, _sess([]), "pxmx-acme") is False


def test_legacy_tenant_id_fallback():
    hub = _hub({"pxmx-acme": "acme"})
    sess = {"user": {"permissions": {"role": "tenant_admin"}, "tenant_id": "acme"}}
    assert access.hypervisor_owned_by_caller(hub, sess, "pxmx-acme") is True
