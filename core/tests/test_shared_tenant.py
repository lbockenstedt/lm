"""Shared-tenant visibility gate (access.py).

A tenant flagged ``shared`` is visible to every user (objects still subnet-
scoped elsewhere); an unassigned spoke (no tenant) is admin-only (NOT global
anymore); a spoke bound to a normal tenant is private to that tenant. Exactly
one tenant may be shared.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import access  # noqa: E402


class _FakeState:
    def __init__(self, tenants):
        self.tenant_state = {"tenants": tenants}
        self.system_state = {}

    def get_tenant(self, tenant_id):
        return self.tenant_state.get("tenants", {}).get(tenant_id, {})


class _FakeHub:
    def __init__(self, tenants):
        self.state = _FakeState(tenants)


def _admin():
    return {"user": {"permissions": {"admin": True}}}


def _user(tenants):
    return {"user": {"permissions": {}, "tenants": tenants}}


def test_refresh_finds_single_shared():
    hub = _FakeHub({"shared-lab": {"shared": True}, "acme": {}, "default": {}})
    assert access.refresh_shared_tenant(hub) == "shared-lab"
    assert access.shared_tenant_id() == "shared-lab"
    assert access.tenant_is_shared("shared-lab")
    assert not access.tenant_is_shared("acme")


def test_visibility_matrix():
    access.refresh_shared_tenant(_FakeHub({"shared-lab": {"shared": True}, "acme": {}}))
    # Admin sees everything, including unassigned.
    assert access.spoke_visible_to_session(_admin(), "acme")
    assert access.spoke_visible_to_session(_admin(), "")
    assert access.spoke_visible_to_session(_admin(), "shared-lab")
    # Shared tenant → visible to any user.
    assert access.spoke_visible_to_session(_user(["acme"]), "shared-lab")
    # Own tenant → visible; other tenant → hidden.
    assert access.spoke_visible_to_session(_user(["acme"]), "acme")
    assert not access.spoke_visible_to_session(_user(["acme"]), "other")
    # Unassigned → admin-only (the behavior change).
    assert not access.spoke_visible_to_session(_user(["acme"]), "")


def test_no_shared_tenant_defaults_none():
    access.refresh_shared_tenant(_FakeHub({"acme": {}, "default": {}}))
    assert access.shared_tenant_id() is None
    assert not access.tenant_is_shared("acme")
    # Unassigned still admin-only; own tenant still visible.
    assert not access.spoke_visible_to_session(_user(["acme"]), "")
    assert access.spoke_visible_to_session(_user(["acme"]), "acme")


import pytest


@pytest.mark.asyncio
async def test_filter_tenant_shared_tenant_keeps_unscoped_data():
    hub = _FakeHub({"shared": {"shared": True}, "acme": {}})
    access.refresh_shared_tenant(hub)

    class _FakeReq:
        cookies = {"lm_session": "adm_token"}
        client = None

    sessions = {"adm_token": {"user": {"permissions": {"admin": True}}, "expires": 9999999999}}
    raw_data = {"leases": [{"ip-address": "172.17.0.50", "hw-address": "00:11:22:33:44:55"}]}

    # When explicit_tenant is 'shared' or 'SHARED' and no NetBox prefixes exist for it,
    # shared infrastructure data is preserved rather than blanked.
    res_lower = await access.filter_tenant(hub, sessions, _FakeReq(), raw_data, "dhcp", ["ip", "address", "ip-address", "ip_address"], explicit_tenant="shared")
    assert res_lower == raw_data

    res_upper = await access.filter_tenant(hub, sessions, _FakeReq(), raw_data, "dhcp", ["ip", "address", "ip-address", "ip_address"], explicit_tenant="SHARED")
    assert res_upper == raw_data

