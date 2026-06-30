"""Permission gates for the module-access rights (``cs`` / ``nw`` / ``ipam``).

``has_module_access`` is the shared gate behind ``has_cs_access`` /
``has_nw_access`` / ``has_ipam_access``: admins always pass; otherwise the
session user's permissions must carry the explicit right (set in User
Management). Mirrors the frontend ``canSeeModule`` gate so nav-hiding and API
access agree.
"""
from access import (has_module_access, has_cs_access, has_nw_access,
                    has_ipam_access, is_admin)


def _sess(perms):
    return {"user": {"permissions": perms}}


def test_admin_passes_every_gate():
    s = _sess({"admin": True, "role": "admin"})
    assert is_admin(s) is True
    assert has_cs_access(s) is True
    assert has_nw_access(s) is True
    assert has_ipam_access(s) is True
    # A role-only admin (no boolean flag) is still an admin → passes.
    s2 = _sess({"role": "admin"})
    assert has_nw_access(s2) is True
    assert has_ipam_access(s2) is True


def test_non_admin_needs_explicit_right():
    s = _sess({"nw": True})
    assert is_admin(s) is False
    assert has_nw_access(s) is True
    assert has_ipam_access(s) is False
    assert has_cs_access(s) is False


def test_non_admin_ipam_only():
    s = _sess({"ipam": True})
    assert has_ipam_access(s) is True
    assert has_nw_access(s) is False


def test_no_rights_denies_all():
    s = _sess({})
    assert has_cs_access(s) is False
    assert has_nw_access(s) is False
    assert has_ipam_access(s) is False


def test_empty_session_denies_all():
    assert has_cs_access(None) is False
    assert has_nw_access({}) is False
    assert has_ipam_access({}) is False


def test_has_module_access_generic():
    s = _sess({"custom": True})
    assert has_module_access(s, "custom") is True
    assert has_module_access(s, "other") is False