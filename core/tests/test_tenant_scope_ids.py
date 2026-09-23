"""Shared tenant-picker scoping helpers (access.tenant_scope_ids / in_tenant_scope).

``default`` is the built-in ADMIN tenant (routes/tenants_users.py renders it as
"ADMIN"), NOT an "All tenants" view. The rule routes/nw.py names "ADMIN(default)
must not accumulate across tenants": the ADMIN scope covers UNASSIGNED resources
and resources explicitly bound to ``default``, plus shared infra — never another
tenant's dedicated resources.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import access  # noqa: E402


def _set_shared(monkeypatch, value):
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", value, raising=False)


def test_absent_selection_is_unscoped(monkeypatch):
    _set_shared(monkeypatch, None)
    # None/blank == a programmatic call with no ?tenant= at all → no filtering.
    assert access.tenant_scope_ids(None) is None
    assert access.tenant_scope_ids("") is None
    assert access.tenant_scope_ids("   ") is None
    assert access.in_tenant_scope("lrb", None) is True


def test_admin_default_scope_is_unassigned_plus_default(monkeypatch):
    _set_shared(monkeypatch, None)
    assert access.tenant_scope_ids("default") == {"", "default"}


def test_admin_default_scope_includes_shared(monkeypatch):
    _set_shared(monkeypatch, "sharedtenant")
    assert access.tenant_scope_ids("default") == {"", "default", "sharedtenant"}


def test_real_tenant_scope_is_itself_plus_shared(monkeypatch):
    _set_shared(monkeypatch, "sharedtenant")
    assert access.tenant_scope_ids("lrb") == {"lrb", "sharedtenant"}
    assert access.tenant_scope_ids("  lrb  ") == {"lrb", "sharedtenant"}


def test_admin_default_excludes_other_tenants(monkeypatch):
    # THE reported bug: ADMIN/Default must not accumulate every tenant.
    _set_shared(monkeypatch, "sharedtenant")
    scope = access.tenant_scope_ids("default")
    assert access.in_tenant_scope("lrb", scope) is False
    assert access.in_tenant_scope("acme", scope) is False


def test_admin_default_includes_unassigned_default_and_shared(monkeypatch):
    _set_shared(monkeypatch, "sharedtenant")
    scope = access.tenant_scope_ids("default")
    assert access.in_tenant_scope("", scope) is True
    assert access.in_tenant_scope(None, scope) is True     # None == UNASSIGNED
    assert access.in_tenant_scope("   ", scope) is True
    assert access.in_tenant_scope("default", scope) is True
    assert access.in_tenant_scope("sharedtenant", scope) is True


def test_real_tenant_scope_excludes_unassigned_and_others(monkeypatch):
    _set_shared(monkeypatch, "sharedtenant")
    scope = access.tenant_scope_ids("lrb")
    assert access.in_tenant_scope("lrb", scope) is True
    assert access.in_tenant_scope("sharedtenant", scope) is True
    assert access.in_tenant_scope("acme", scope) is False
    assert access.in_tenant_scope(None, scope) is False
    assert access.in_tenant_scope("", scope) is False


def test_literal_shared_tenant_always_in_scope(monkeypatch):
    # access.tenant_is_shared also honours the literal id "shared".
    _set_shared(monkeypatch, None)
    assert access.in_tenant_scope("shared", access.tenant_scope_ids("lrb")) is True
    assert access.in_tenant_scope("shared", access.tenant_scope_ids("default")) is True


def test_admin_tenant_id_constant():
    assert access.ADMIN_TENANT_ID == "default"


# ── Capitalisation must never decide visibility ──────────────────────────────
# tenant_scope_ids used to lowercase only to DETECT the admin tenant, then put
# the caller's raw spelling in the set, while in_tenant_scope compared the
# resource side exactly. A tenant recorded as "Default" therefore matched
# neither {"", "default"} nor {"Default"} -- its own resources were invisible
# to it under either picker spelling. Flagged on lm#1026.

def test_admin_scope_is_case_insensitive_on_the_picker_side(monkeypatch):
    _set_shared(monkeypatch, None)
    for spelling in ("Default", "DEFAULT", "  DeFaUlT  "):
        assert access.tenant_scope_ids(spelling) == {"", "default"}, spelling


def test_admin_scope_matches_a_capitalised_resource_tenant(monkeypatch):
    _set_shared(monkeypatch, None)
    scope = access.tenant_scope_ids("default")
    # The exact case that used to disappear from the ADMIN view.
    assert access.in_tenant_scope("Default", scope) is True
    assert access.in_tenant_scope("DEFAULT", scope) is True


def test_regular_tenant_scope_is_case_insensitive_both_ways(monkeypatch):
    _set_shared(monkeypatch, None)
    assert access.tenant_scope_ids("LRB") == {"lrb"}
    scope = access.tenant_scope_ids("LRB")
    assert access.in_tenant_scope("lrb", scope) is True
    assert access.in_tenant_scope("Lrb", scope) is True
    # Still never another tenant's resources.
    assert access.in_tenant_scope("Acme", scope) is False


def test_shared_tenant_matches_regardless_of_case(monkeypatch):
    _set_shared(monkeypatch, "SharedTenant")
    assert access.tenant_scope_ids("lrb") == {"lrb", "sharedtenant"}
    assert access.tenant_is_shared("SHAREDTENANT") is True
    assert access.tenant_is_shared("sharedtenant") is True
    assert access.in_tenant_scope("SharedTenant", access.tenant_scope_ids("default")) is True
    assert access.tenant_is_shared("Shared") is True


def test_blank_and_none_still_canonicalise_to_unassigned(monkeypatch):
    _set_shared(monkeypatch, None)
    assert access._norm_tenant_id(None) == ""
    assert access._norm_tenant_id("   ") == ""
    assert access.tenant_is_shared(None) is False
    assert access.tenant_is_shared("") is False


# ── spoke_is_unbound: gates every "fall back to the global spoke" call site ──
class _Hub:
    def __init__(self, md):
        self.state = type("_S", (), {"system_state": {"module_metadata": md}})()


def test_unbound_spoke_with_no_metadata_entry_at_all(monkeypatch):
    # The ordinary UNASSIGNED case: the spoke simply isn't in module_metadata.
    _set_shared(monkeypatch, None)
    assert access.spoke_is_unbound(_Hub({}), "s1") is True


def test_unbound_spoke_with_blank_binding(monkeypatch):
    _set_shared(monkeypatch, None)
    hub = _Hub({"s1": {}, "s2": {"tenant_id": None}, "s3": {"tenant_id": "  "}})
    assert access.spoke_is_unbound(hub, "s1") is True
    assert access.spoke_is_unbound(hub, "s2") is True
    assert access.spoke_is_unbound(hub, "s3") is True


def test_shared_and_admin_bound_spokes_are_unbound(monkeypatch):
    # Shared infra is visible to every tenant AND to the global admin.
    _set_shared(monkeypatch, "sharedtenant")
    hub = _Hub({"s_shared": {"tenant_id": "sharedtenant"},
                "s_admin": {"tenant_id": "default"}})
    assert access.spoke_is_unbound(hub, "s_shared") is True
    assert access.spoke_is_unbound(hub, "s_admin") is True


def test_real_tenant_bound_spoke_is_not_unbound(monkeypatch):
    # THE leak vector: falling back to "the global spoke" when it actually
    # belongs to a tenant surfaced that tenant's data in the ADMIN view.
    _set_shared(monkeypatch, "sharedtenant")
    assert access.spoke_is_unbound(_Hub({"s1": {"tenant_id": "lrb"}}), "s1") is False


def test_falsy_spoke_id_and_unreadable_state_fail_closed(monkeypatch):
    _set_shared(monkeypatch, None)
    assert access.spoke_is_unbound(_Hub({}), None) is False
    assert access.spoke_is_unbound(_Hub({}), "") is False

    class _Boom:
        @property
        def state(self):
            raise RuntimeError("state unavailable")

    assert access.spoke_is_unbound(_Boom(), "s1") is False


def test_call_sites_gate_the_global_spoke_fallback():
    """dashboard + search_index must not re-introduce an ungated fallback."""
    import os
    base = os.path.join(os.path.dirname(__file__), "..", "src")
    dash = open(os.path.join(base, "routes", "dashboard.py")).read()
    idx = open(os.path.join(base, "search_index.py")).read()
    assert dash.count("access.spoke_is_unbound(hub,") >= 3
    assert "access.spoke_is_unbound(self, _gs)" in idx
    # The hand-rolled module_metadata check it replaced is gone.
    assert 'if not (_md.get(_gs, {}) or {}).get("tenant_id"):' not in dash
