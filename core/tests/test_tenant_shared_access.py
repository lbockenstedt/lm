"""Per-tenant "Access to shared tenant" setting (auto / allow / deny)."""

import access
from access import scoped_spoke_of_type, tenant_left_shared, tenant_shared_access
from hub_spoke_registry import SpokeRegistryMixin
from _fakes import FakeHub, FakeState


class _Hub(SpokeRegistryMixin, FakeHub):
    """acme owns nac-acme; the shared tenant owns nac-shared."""

    def __init__(self, mode=None, acme_owns=True):
        acme = {"name": "acme"}
        if mode:
            acme["shared_access"] = mode
        spokes = {"nac-shared": "lab"}
        if acme_owns:
            spokes["nac-acme"] = "acme"
        super().__init__(FakeState(
            system_state={"module_metadata": {sid: {"tenant_id": t, "module_type": "nac"}
                                              for sid, t in spokes.items()}},
            tenants={"lab": {"shared": True}, "acme": acme},
            spoke_tenants=spokes))
        self.spoke_module_types = {sid: "nac" for sid in spokes}
        access.refresh_shared_tenant(self)

    def get_cppm_spoke_for_tenant(self, tenant_id=None):
        return next((sid for sid, t in self.state._spoke_tenants.items() if t == tenant_id), None)

    def get_spoke_by_type(self, module_type):
        return "nac-shared"


def test_mode_defaults_to_auto_and_ignores_junk():
    assert tenant_shared_access(_Hub(), "acme") == "auto"
    assert tenant_shared_access(_Hub("bogus"), "ACME") == "auto"
    assert tenant_shared_access(_Hub("deny"), "ACME") == "deny"


def test_auto_follows_own_spoke():
    assert tenant_left_shared(_Hub(), "acme", "nac") is True
    assert tenant_left_shared(_Hub(acme_owns=False), "acme", "nac") is False


def test_allow_keeps_shared_even_with_own_spoke():
    hub = _Hub("allow")
    assert tenant_left_shared(hub, "acme", "nac") is False
    assert hub.get_cppm_spokes_for_tenant("acme") == ["nac-acme", "nac-shared"]


def test_deny_hides_shared_without_own_spoke():
    hub = _Hub("deny", acme_owns=False)
    assert tenant_left_shared(hub, "acme", "nac") is True
    assert hub.get_cppm_spokes_for_tenant("acme") == []
    assert scoped_spoke_of_type(hub, "acme", "nac") is None


def test_shared_tenant_and_admin_never_left_shared():
    hub = _Hub("deny")
    assert tenant_left_shared(hub, "lab", "nac") is False
    assert tenant_left_shared(hub, "default", "nac") is False
