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

def test_ldap_tenant_slug_prefers_netbox_slug_then_id_lowercased():
    hub = FakeHub(FakeState(tenants={
        "lrb": {"netbox_tenant_slug": "LRB"},
        "Plain": {},
    }))
    # Canonical stored form is lower-case (matches the server's ou=lrb RDN).
    assert access.ldap_tenant_slug(hub, "lrb") == "lrb"
    assert access.ldap_tenant_slug(hub, "Plain") == "plain"  # falls back to id, lowered
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


# ── LDAPAuthProvider.get_user_groups: raw membership → hub permission groups ──

def test_provider_maps_directory_groups_to_permission_groups(monkeypatch):
    import security.auth_manager as am
    hub = _hub_with_groups()
    prov = am.LDAPAuthProvider({"server": "ldap://x", "hub": hub})
    # Stand in for the spoke relay: return raw directory groups (case differs).
    monkeypatch.setattr(prov, "get_directory_groups",
                        lambda uid, tenant_slug=None: ["CN=NetEng,OU=LRB,DC=X"])
    assert prov.get_user_groups("alice") == ["grp-net"]


def test_provider_no_hub_returns_empty():
    import security.auth_manager as am
    prov = am.LDAPAuthProvider({"server": "ldap://x"})  # no hub
    assert prov.hub is None
    assert prov.get_user_groups("bob") == []
    assert prov.get_directory_groups("bob") == []


def test_provider_no_directory_spoke_degrades_gracefully():
    import security.auth_manager as am
    hub = _hub_with_groups()  # FakeHub.get_spoke_by_type → None
    prov = am.LDAPAuthProvider({"server": "ldap://x", "hub": hub})
    assert prov.get_directory_groups("carol") == []
    assert prov.get_user_groups("carol") == []


# ── read_scope / write_scope: the layered tier gate (routes/ldap.py
#    _directory_resolve calls resolve_directory_tenant THEN read_scope/write_scope) ─

def _sess(tenants, **perms):
    return {"user": {"tenants": list(tenants), "permissions": dict(perms)}}


def test_admin_full_read_and_write_for_any_tenant():
    """Global Admin is unconfined — may read AND write ANY tenant's OU (the
    all-OU admin view the Directory tenant-scoping preserves)."""
    adm = _sess([], admin=True)
    for tid in ("lrb", "acme", "other"):
        assert access.read_scope(adm, tid) == "full"
        assert access.write_scope(adm, tid) == "full"


def test_tenant_admin_full_read_and_write_for_own_tenant():
    """A tenant-admin managing their OWN tenant OU: full read + full write."""
    ta = _sess(["lrb"], role="tenant_admin")
    assert access.read_scope(ta, "lrb") == "full"
    assert access.write_scope(ta, "lrb") == "full"


def test_view_user_own_tenant_read_full_write_deny():
    """A view user (``ldap`` right, no ``edit``) owning the tenant: reads are
    allowed (full — it's their own dedicated tenant), but WRITES are denied —
    the tier re-check ``_directory_resolve`` adds on top of
    ``resolve_directory_tenant`` (which allowed because it's their tenant)."""
    viewer = _sess(["lrb"], ldap=True)
    assert access.read_scope(viewer, "lrb") == "full"
    assert access.write_scope(viewer, "lrb") == "deny"


def test_write_user_own_tenant_read_and_write_full():
    """A non-admin write user (global ``edit`` right) owning the tenant: full
    read + full write on their own dedicated OU."""
    writer = _sess(["lrb"], edit=True, ldap=True)
    assert access.read_scope(writer, "lrb") == "full"
    assert access.write_scope(writer, "lrb") == "full"


def test_foreign_tenant_read_and_write_deny_for_non_admin():
    """A non-admin reaches for a tenant they DON'T own: read + write both deny.
    (``resolve_directory_tenant`` 403s first in the handler; this confirms the
    scope classifier agrees — defense-in-depth.)"""
    ta = _sess(["lrb"], role="tenant_admin")
    assert access.read_scope(ta, "acme") == "deny"
    assert access.write_scope(ta, "acme") == "deny"
    viewer = _sess(["lrb"], ldap=True)
    assert access.read_scope(viewer, "acme") == "deny"
    assert access.write_scope(viewer, "acme") == "deny"


def test_shared_ou_not_granted_to_non_owner(monkeypatch):
    """Own-tenant-only invariant: a non-admin who does NOT own the shared tenant
    is NOT granted shared-OU access. ``resolve_directory_tenant`` 403s a foreign
    tenant BEFORE ``read_scope`` is reached; and even if it were reached, the
    shared-tenant branch requires ``can_edit_shared`` (tenant-admin/admin) for a
    write and returns only ``filtered`` for a read — never ``full`` for a non-owner."""
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "shared-tenant")
    # A view user owning lrb (NOT the shared tenant) asks for the shared OU.
    viewer = _sess(["lrb"], ldap=True)
    tid, status, _ = access.resolve_directory_tenant(False, ["lrb"], "shared-tenant")
    assert tid is None and status == 403  # the guard rejects first
    # And the scope classifier would not grant full to a non-owner either.
    assert access.read_scope(viewer, "shared-tenant") == "filtered"
    assert access.write_scope(viewer, "shared-tenant") == "deny"


def test_tenant_admin_shared_ou_write_constrained(monkeypatch):
    """A tenant-admin may CHANGE shared infra but only CONSTRAINED to their
    slice (write_scope); reads are filtered. (Own-tenant-only decision: shared
    OU visibility is not added for non-owners, but a tenant-admin's shared
    write stays constrained, not full — matches the other modules.)"""
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "shared-tenant")
    ta = _sess(["lrb"], role="tenant_admin")
    assert access.read_scope(ta, "shared-tenant") == "filtered"
    assert access.write_scope(ta, "shared-tenant") == "constrained"
