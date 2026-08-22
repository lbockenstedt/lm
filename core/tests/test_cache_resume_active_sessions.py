"""Restart-resume of per-tenant collection.

Login starts a tenant's cache-refresh loop; ``_load_sessions`` rehydrates logins
across a hub restart WITHOUT their loops. ``_active_session_tenant_ids`` is the
selector the startup resume uses to restart collection for exactly the tenants
that still have a live session — and nothing for logged-out / expired ones
(poll-as-needed), matching the logout teardown.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api  # noqa: E402


def _seed(sessions):
    api._sessions.clear()
    api._sessions.update(sessions)


def test_picks_only_tenants_with_a_live_session():
    now = time.time()
    _seed({
        "tok-a": {"user": {"tenant_id": "tenantA"}, "expires": now + 3600},
        "tok-b": {"user": {"tenant_id": "tenantB"}, "expires": now + 3600},
        "tok-a2": {"user": {"tenant_id": "tenantA"}, "expires": now + 60},  # dup tenant
    })
    assert api._active_session_tenant_ids(now) == {"tenantA", "tenantB"}


def test_expired_sessions_are_excluded():
    now = time.time()
    _seed({
        "tok-live": {"user": {"tenant_id": "tenantA"}, "expires": now + 10},
        "tok-dead": {"user": {"tenant_id": "tenantB"}, "expires": now - 10},
    })
    assert api._active_session_tenant_ids(now) == {"tenantA"}


def test_tenantless_and_admin_sessions_are_excluded():
    now = time.time()
    _seed({
        "tok-admin": {"user": {"is_admin": True}, "expires": now + 3600},      # no tenant_id
        "tok-empty": {"user": {"tenant_id": ""}, "expires": now + 3600},       # falsy tenant
        "tok-tenant": {"user": {"tenant_id": "tenantC"}, "expires": now + 3600},
    })
    assert api._active_session_tenant_ids(now) == {"tenantC"}


def test_no_sessions_is_empty():
    _seed({})
    assert api._active_session_tenant_ids(time.time()) == set()
