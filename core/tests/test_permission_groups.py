"""RBAC permission-group resolution tests.

Covers resolve_effective_permissions (group ∪ per-user, admin normalisation,
OR semantics, legacy/no-group fallback) and the LDAP-group → hub-group mapping.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from access import (  # noqa: E402
    ENFORCED_RIGHTS,
    groups_and_tenants_for_membership,
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


# A hub whose groups also carry granted ``tenants`` (Entra group → tenant scope).
def _hub_with_tenants():
    return _FakeHub({
        "noc":   {"name": "NOC", "permissions": {"nw": True},
                  "ldap_group": "11111111-1111-1111-1111-111111111111",
                  "tenants": ["t-tenant-a"]},
        "certs": {"name": "Certs", "permissions": {"le": True},
                  "ldap_group": "22222222-2222-2222-2222-222222222222",
                  "tenants": ["t-tenant-b", "t-tenant-a"]},
        "no-ten": {"name": "NoTen", "permissions": {"dns": True},
                   "ldap_group": "33333333-3333-3333-3333-333333333333"},
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


# ── groups_and_tenants_for_membership (Entra group → RBAC + tenant scope) ────

def test_membership_returns_groups_and_tenants_union():
    # Two matching Entra groups → union of group ids + union of their tenants.
    gids, tids = groups_and_tenants_for_membership(_hub_with_tenants(), [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ])
    assert set(gids) == {"noc", "certs"}
    assert set(tids) == {"t-tenant-a", "t-tenant-b"}


def test_membership_entra_object_id_case_insensitive():
    # Entra object IDs are lowercase GUIDs; matching is case-insensitive exact.
    gids, tids = groups_and_tenants_for_membership(
        _hub_with_tenants(), ["11111111-1111-1111-1111-111111111111"])
    assert gids == ["noc"]
    assert tids == ["t-tenant-a"]


def test_membership_group_without_tenants_grants_no_tenants():
    # A matching group with no ``tenants`` field → group id but no tenants.
    gids, tids = groups_and_tenants_for_membership(
        _hub_with_tenants(), ["33333333-3333-3333-3333-333333333333"])
    assert gids == ["no-ten"]
    assert tids == []


def test_membership_no_match_returns_empty():
    gids, tids = groups_and_tenants_for_membership(
        _hub_with_tenants(), ["deadbeef-0000-0000-0000-000000000000"])
    assert gids == [] and tids == []


def test_membership_empty_input_returns_empty():
    gids, tids = groups_and_tenants_for_membership(_hub_with_tenants(), [])
    assert gids == [] and tids == []
    assert groups_and_tenants_for_membership(_hub_with_tenants(), None) == ([], [])


def test_groups_for_ldap_membership_is_wrapper_returning_groups_only():
    # Backward-compat wrapper: returns just the group ids (no tenants).
    gids = groups_for_ldap_membership(
        _hub_with_tenants(), ["11111111-1111-1111-1111-111111111111"])
    assert gids == ["noc"]


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
