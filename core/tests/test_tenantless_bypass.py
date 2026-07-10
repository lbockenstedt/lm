"""Regression tests for the tenantless non-admin bypass (deny-by-default).

``check_tenant_access`` previously returned ``not allowed or tenant_id in
allowed`` — a non-admin with an empty/missing ``tenants`` list (e.g. a user
created without a tenant_id; login derives ``tenant_id = tenants[0]`` so the two
are 1:1) passed the ``?tenant=`` gate for ANY tenant. ``filter_session``
compounded it: a tenantless non-admin has no prefixes, so ``if not prefixes:
return data`` returned the unfiltered fleet-wide set.

Both now deny by default (matching ``effective_tenant``'s existing strict
posture). Admins still see everything; configured single/multi-tenant users
are unaffected.
"""
import pytest

from access import check_tenant_access, is_admin


def _sess(*, admin=False, tenants=None, tenant_id=None):
    user = {"tenants": tenants or [], "tenant_id": tenant_id}
    if admin:
        user["permissions"] = {"role": "admin", "admin": True}
    return {"user": user}


def test_admin_sees_all_tenants():
    sess = _sess(admin=True)
    assert check_tenant_access(sess, "acme") is True
    assert check_tenant_access(sess, "other") is True


def test_single_tenant_user_sees_only_own():
    sess = _sess(tenants=["acme"], tenant_id="acme")
    assert check_tenant_access(sess, "acme") is True
    assert check_tenant_access(sess, "other") is False


def test_multi_tenant_user_sees_assigned():
    sess = _sess(tenants=["acme", "beta"], tenant_id="acme")
    assert check_tenant_access(sess, "acme") is True
    assert check_tenant_access(sess, "beta") is True
    assert check_tenant_access(sess, "gamma") is False


def test_tenantless_non_admin_denied_for_every_tenant():
    """The bypass: empty tenants must NOT mean 'sees all tenants'."""
    sess = _sess(tenants=[], tenant_id=None)
    assert check_tenant_access(sess, "acme") is False
    assert check_tenant_access(sess, "other") is False
    assert check_tenant_access(sess, "") is False


def test_missing_tenants_key_denied():
    """A user record with no `tenants` key at all (omission) is denied."""
    sess = {"user": {"tenant_id": None}}
    assert check_tenant_access(sess, "acme") is False


def test_no_session_denied():
    assert check_tenant_access(None, "acme") is False
    assert check_tenant_access({}, "acme") is False


def test_is_admin_consistency():
    assert is_admin(_sess(admin=True)) is True
    assert is_admin(_sess(tenants=["acme"], tenant_id="acme")) is False