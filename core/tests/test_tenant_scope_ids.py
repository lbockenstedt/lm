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
