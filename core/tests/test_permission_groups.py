"""RBAC permission-group resolution tests.

Covers resolve_effective_permissions (group ∪ per-user, admin normalisation,
OR semantics, legacy/no-group fallback) and the LDAP-group → hub-group mapping.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from access import (  # noqa: E402
    ENFORCED_RIGHTS,
    groups_for_ldap_membership,
    resolve_effective_permissions,
)


class _FakeState:
    def __init__(self, groups):
        self.system_state = {"permission_groups": groups}


class _FakeHub:
    def __init__(self, groups):
        self.state = _FakeState(groups)


def _hub():
    return _FakeHub({
        "noc":   {"name": "NOC", "permissions": {"nw": True, "ipam": True}},
        "certs": {"name": "Certs", "permissions": {"le": True},
                  "ldap_group": "cn=cert-admins,ou=groups"},
        "super": {"name": "Super", "permissions": {"admin": True, "role": "admin"}},
    })


def test_union_of_groups():
    eff = resolve_effective_permissions(_hub(), {"groups": ["noc", "certs"]})
    assert eff.get("nw") and eff.get("ipam") and eff.get("le")
    assert "admin" not in eff


def test_per_user_override_adds_on_top():
    eff = resolve_effective_permissions(
        _hub(), {"groups": ["noc"], "permissions": {"cs": True}})
    assert eff.get("nw") and eff.get("cs")


def test_admin_group_normalises_both_forms():
    eff = resolve_effective_permissions(_hub(), {"groups": ["super"]})
    assert eff.get("admin") is True and eff.get("role") == "admin"


def test_legacy_per_user_only():
    eff = resolve_effective_permissions(
        _hub(), {"permissions": {"nw": True, "admin": True}})
    assert eff.get("nw") and eff.get("admin") and eff.get("role") == "admin"


def test_or_semantics_false_never_revokes():
    eff = resolve_effective_permissions(
        _hub(), {"groups": ["noc"], "permissions": {"nw": False}})
    assert eff.get("nw") is True


def test_ldap_membership_maps_case_insensitively():
    gids = groups_for_ldap_membership(
        _hub(), ["CN=Cert-Admins,OU=Groups", "cn=other"])
    assert gids == ["certs"]


def test_missing_group_id_ignored():
    assert resolve_effective_permissions(_hub(), {"groups": ["ghost"]}) == {}


def test_no_hub_state_falls_back_to_per_user():
    class _NoState:
        pass
    eff = resolve_effective_permissions(_NoState(), {"permissions": {"cs": True}})
    assert eff.get("cs")


def test_enforced_rights_are_stable():
    # The group editor + resolver share this list; guard against accidental drift.
    assert set(ENFORCED_RIGHTS) == {"cs", "nw", "ipam", "le", "console", "console_write"}
