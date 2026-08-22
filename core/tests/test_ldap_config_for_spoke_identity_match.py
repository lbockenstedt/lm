"""Regression: _ldap_config_for_spoke's ldap_instances matching must survive
either identity generation (legacy name or guid-primary, see hub_identity.py's
spoke_id_alias) and must never fall back to "the first instance in the list"
— mirrors the NAC/IPAM/nw fixes for the same live incident (two tenants' spoke
bindings both went silently unmatched once their identity migration armed).
"""
from main import LabManagerHub


class _FakeHub:
    def __init__(self, gc, alias=None):
        self._gc = gc
        self._alias = alias or {}
        self.state = type("S", (), {
            "get_global_config": lambda self, _g=gc: _g,
        })()

    def _primary_key(self, spoke_id):
        return self._alias.get(spoke_id, spoke_id)


def test_matches_own_instance_by_legacy_name():
    hub = _FakeHub({"ldap_instances": [
        {"spoke_id": "ldap-a", "server_url": "ldap://a"},
        {"spoke_id": "ldap-b", "server_url": "ldap://b"},
    ]})
    cfg = LabManagerHub._ldap_config_for_spoke(hub, "ldap-a")
    assert cfg["LDAP_SERVER_URL"] == "ldap://a"


def test_matches_across_identity_generations():
    """Instance saved under the legacy name; this spoke now connects as its
    guid-primary identity."""
    hub = _FakeHub({"ldap_instances": [
        {"spoke_id": "ldap-a", "server_url": "ldap://a"},
    ]}, alias={"ldap-a": "guid-ldap-a"})
    cfg = LabManagerHub._ldap_config_for_spoke(hub, "guid-ldap-a")
    assert cfg["LDAP_SERVER_URL"] == "ldap://a"


def test_unrelated_spoke_never_receives_another_spokes_instance():
    """The core regression: no instances[0] fallback — an unrelated spoke
    with no bound instance and no gldap config gets nothing at all."""
    hub = _FakeHub({"ldap_instances": [
        {"spoke_id": "ldap-a", "server_url": "ldap://a"},
        {"spoke_id": "ldap-b", "server_url": "ldap://b"},
    ]})
    cfg = LabManagerHub._ldap_config_for_spoke(hub, "ldap-c")
    assert cfg is None


def test_unrelated_spoke_with_global_ldap_config_gets_that_not_an_instance():
    """gldap (Setup → Directory global config) is a safe fallback — it's the
    admin's own canonical config, not a specific other spoke's secret."""
    hub = _FakeHub({
        "ldap_instances": [{"spoke_id": "ldap-a", "server_url": "ldap://a"}],
        "ldap": {"server_url": "ldap://global"},
    })
    cfg = LabManagerHub._ldap_config_for_spoke(hub, "ldap-c")
    assert cfg["LDAP_SERVER_URL"] == "ldap://global"


def test_unbound_instance_still_fills_single_product_deployment():
    hub = _FakeHub({"ldap_instances": [{"server_url": "ldap://only"}]})
    cfg = LabManagerHub._ldap_config_for_spoke(hub, "ldap-any")
    assert cfg["LDAP_SERVER_URL"] == "ldap://only"
