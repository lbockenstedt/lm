"""Directory (LDAP/Entra) hub-side authz + tenant-identity tests.

Covers the SECURITY BOUNDARY (a tenant-admin cannot cross tenants — even by
case-folding the slug) and the shared tenant→OU slug derivation + group mapping
that the Directory routes and RBAC wiring depend on. All pure — no hub sockets."""

import access
from _fakes import FakeHub, FakeState


# ── resolve_directory_tenant: the cross-tenant guard ─────────────────────────

def test_global_admin_may_pick_any_tenant():
    tid, status, _ = access.resolve_directory_tenant(True, [], "any-tenant")
    assert (tid, status) == ("any-tenant", None)


def test_global_admin_must_name_a_tenant():
    tid, status, _ = access.resolve_directory_tenant(True, [], "")
    assert tid is None and status == 400


def test_tenant_admin_own_tenant_ok():
    tid, status, _ = access.resolve_directory_tenant(False, ["lrb"], "lrb")
    assert (tid, status) == ("lrb", None)


def test_tenant_admin_case_insensitive_match_returns_own_stored_case():
    # session tenant "lrb" may act on OU "LRB" (any case) — and we return the
    # caller's OWN stored form, never the client-supplied casing.
    tid, status, _ = access.resolve_directory_tenant(False, ["lrb"], "LRB")
    assert (tid, status) == ("lrb", None)
    tid, status, _ = access.resolve_directory_tenant(False, ["LRB"], "lrb")
    assert (tid, status) == ("LRB", None)
    tid, status, _ = access.resolve_directory_tenant(False, ["Lrb"], "lRB")
    assert (tid, status) == ("Lrb", None)


def test_tenant_admin_cannot_cross_tenant_regardless_of_case():
    # THE guard: a tenant-admin owning "lrb" is rejected for another tenant, and
    # case cannot be used to smuggle a foreign slug past the check.
    for foreign in ("other", "OTHER", "Other", "lrbx", "l"):
        tid, status, _ = access.resolve_directory_tenant(False, ["lrb"], foreign)
        assert tid is None and status == 403, foreign


def test_tenant_admin_single_tenant_defaults():
    tid, status, _ = access.resolve_directory_tenant(False, ["solo"], "")
    assert (tid, status) == ("solo", None)


def test_tenant_admin_multi_tenant_requires_selection():
    tid, status, _ = access.resolve_directory_tenant(False, ["a", "b"], "")
    assert tid is None and status == 400


def test_no_tenant_assigned_is_denied():
    tid, status, _ = access.resolve_directory_tenant(False, [], "")
    assert tid is None and status == 403


# ── tenant_slug_matches: the one normalization ──────────────────────────────

def test_tenant_slug_matches_case_insensitive():
    assert access.tenant_slug_matches("LRB", "lrb")
    assert access.tenant_slug_matches(" Lrb ", "lRB")
    assert not access.tenant_slug_matches("lrb", "lrbx")
    assert not access.tenant_slug_matches("", "lrb")


# ── ldap_tenant_slug: shared OU derivation ──────────────────────────────────

def test_ldap_tenant_slug_prefers_netbox_slug_then_id():
    hub = FakeHub(FakeState(tenants={
        "lrb": {"netbox_tenant_slug": "LRB"},
        "plain": {},
    }))
    assert access.ldap_tenant_slug(hub, "lrb") == "LRB"      # display case preserved
    assert access.ldap_tenant_slug(hub, "plain") == "plain"  # falls back to id
    assert access.ldap_tenant_slug(hub, "") == ""


# ── groups_for_ldap_membership: RBAC group mapping ──────────────────────────

def _hub_with_groups():
    return FakeHub(FakeState(system_state={"permission_groups": {
        "grp-net": {"ldap_group": "cn=neteng,ou=lrb,dc=x", "tenants": ["lrb"],
                    "permissions": {"nw": True}},
        "grp-entra": {"ldap_group": "11111111-2222-3333-4444-555555555555",
                      "permissions": {"ipam": True}},
        "grp-none": {"ldap_group": "", "permissions": {"cs": True}},
    }}))


def test_group_mapping_matches_ldap_dn_case_insensitively():
    hub = _hub_with_groups()
    # membership DN differs only in case → still maps to the permission group.
    gids = access.groups_for_ldap_membership(hub, ["CN=NetEng,OU=LRB,DC=X"])
    assert gids == ["grp-net"]


def test_group_mapping_matches_entra_object_id():
    hub = _hub_with_groups()
    gids = access.groups_for_ldap_membership(
        hub, ["11111111-2222-3333-4444-555555555555"])
    assert gids == ["grp-entra"]


def test_group_mapping_unmatched_membership_maps_to_nothing():
    hub = _hub_with_groups()
    assert access.groups_for_ldap_membership(hub, ["cn=unknown,dc=x"]) == []
    assert access.groups_for_ldap_membership(hub, []) == []
