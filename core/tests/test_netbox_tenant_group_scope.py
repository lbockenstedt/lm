"""Unit tests for ``access.netbox_tenant_scope`` / ``tenant_netbox_slugs`` — the
NetBox tenant-GROUP scope resolver.

A NetBox tenant group is stored as its own hub tenant keyed ``group:<slug>`` and
flagged ``is_tenant_group``. Selecting it must resolve to NetBox's tree-aware
``?tenant_group=`` filter (the union of its members) rather than to a single
tenant slug. Pure helpers over a fake hub.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import access  # noqa: E402


class _State:
    def __init__(self, tenants, active="default"):
        self._tenants = tenants
        self.system_state = {"active_tenant": active}
        self.tenant_state = {"tenants": tenants}

    def get_tenant(self, tid):
        return self._tenants.get(tid)


class _Hub:
    def __init__(self, tenants, active="default"):
        self.state = _State(tenants, active)


TENANTS = {
    "ra": {"name": "RA", "netbox_tenant_slug": "ra", "netbox_id": 2,
           "tenant_group_slug": "solution-tme"},
    "central": {"name": "CENTRAL", "netbox_tenant_slug": "central", "netbox_id": 9,
                "tenant_group_slug": "solution-tme"},
    "lrb": {"name": "LRB", "netbox_tenant_slug": "lrb", "netbox_id": 1},
    "group:solution-tme": {
        "name": "SOLUTION TME", "is_tenant_group": True,
        "netbox_tenant_group_slug": "solution-tme",
        "netbox_tenant_slug": "",
        "member_tenant_slugs": ["central", "ra"],
        "netbox_id": 1,
    },
}


def _hub():
    return _Hub(TENANTS)


# ─── plain tenants keep the existing contract ────────────────────────────────

def test_plain_tenant_sends_tenant_filter():
    s = access.netbox_tenant_scope(_hub(), "ra")
    assert s["tenant"] == "ra"
    assert s["tenant_group"] is None
    assert s["is_group"] is False
    assert s["slugs"] == ["ra"]
    assert s["key"] == "ra"


def test_unknown_tenant_is_unscoped():
    s = access.netbox_tenant_scope(_hub(), "does-not-exist")
    assert s["tenant"] is None and s["tenant_group"] is None
    assert s["slugs"] == []
    assert s["key"] == "_all_"


# ─── groups resolve to the tenant_group filter ───────────────────────────────

def test_group_sends_tenant_group_filter_not_a_tenant():
    s = access.netbox_tenant_scope(_hub(), "group:solution-tme")
    assert s["is_group"] is True
    assert s["tenant_group"] == "solution-tme"
    # Critical: a group must NOT be sent as a tenant slug — no NetBox tenant
    # named "solution-tme" exists, and NetBox 400s on an unknown slug.
    assert s["tenant"] is None
    assert s["slugs"] == ["central", "ra"]


def test_group_cache_key_cannot_collide_with_a_tenant():
    """A tenant literally named "solution-tme" must not share the group's key."""
    tenants = dict(TENANTS)
    tenants["solution-tme"] = {"name": "decoy", "netbox_tenant_slug": "solution-tme"}
    hub = _Hub(tenants)
    assert (access.netbox_tenant_scope(hub, "group:solution-tme")["key"]
            != access.netbox_tenant_scope(hub, "solution-tme")["key"])


def test_group_slug_falls_back_to_the_tenant_id_prefix():
    tenants = {"group:solution-tme": {"name": "G", "is_tenant_group": True,
                                      "member_tenant_slugs": ["ra"]}}
    s = access.netbox_tenant_scope(_Hub(tenants), "group:solution-tme")
    assert s["tenant_group"] == "solution-tme"


def test_unusable_group_degrades_to_unscoped_instead_of_raising():
    """is_tenant_group with no derivable group slug must not 500 the request."""
    tenants = {"weird": {"name": "W", "is_tenant_group": True}}
    s = access.netbox_tenant_scope(_Hub(tenants), "weird")
    assert s["is_group"] is False
    assert s["tenant"] is None and s["tenant_group"] is None
    assert s["key"] == "_all_"


def test_member_list_is_sanitised():
    tenants = {"group:g": {"name": "G", "is_tenant_group": True,
                           "netbox_tenant_group_slug": "g",
                           "member_tenant_slugs": ["  ra ", None, "", "ra", "central"]}}
    s = access.netbox_tenant_scope(_Hub(tenants), "group:g")
    assert s["slugs"] == ["central", "ra"]


def test_missing_member_list_is_empty_not_none():
    tenants = {"group:g": {"name": "G", "is_tenant_group": True,
                           "netbox_tenant_group_slug": "g",
                           "member_tenant_slugs": None}}
    assert access.netbox_tenant_scope(_Hub(tenants), "group:g")["slugs"] == []


# ─── write authorisation ─────────────────────────────────────────────────────

def test_tenant_netbox_slugs_expands_a_group_for_write_guards():
    """A group-assigned user may create into any MEMBER tenant."""
    assert access.tenant_netbox_slugs(_hub(), "group:solution-tme") == ["central", "ra"]
    assert access.tenant_netbox_slugs(_hub(), "ra") == ["ra"]
    # A non-member must not be reachable via the group.
    assert "lrb" not in access.tenant_netbox_slugs(_hub(), "group:solution-tme")
