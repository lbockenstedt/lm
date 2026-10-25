"""Which cache scopes count as "active" (refreshed every 60s) and what a login
refreshes immediately.

The hub data cache refreshes a scope on the fast cycle while a live session
that can see it was used in the last 10 minutes, and on the slow (5min) cycle
otherwise. A login kicks an immediate refresh of everything the new session
can see. Scopes: a hub tenant id, ``"*"`` (admin-wide data) and
``"default"``. These replace the old per-tenant refresh loops and the
restart-resume selector.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api  # noqa: E402


def _seed(sessions):
    api._sessions.clear()
    api._sessions.update(sessions)


def _live(user, seen_ago=0):
    now = time.time()
    return {"user": user, "expires": now + 3600, "last_seen": now - seen_ago}


# ── _session_cache_scopes ────────────────────────────────────────────────────

def test_tenant_user_sees_only_their_tenant():
    assert api._session_cache_scopes({"user": {"tenant_id": "tA"}}) == {"tA"}


def test_multi_tenant_user_sees_all_their_tenants():
    sess = {"user": {"tenant_id": "tA", "tenants": ["tA", "tB", ""]}}
    assert api._session_cache_scopes(sess) == {"tA", "tB"}


def test_admin_adds_admin_wide_and_default():
    sess = {"user": {"permissions": {"admin": True}, "tenant_id": "tA"}}
    assert api._session_cache_scopes(sess) == {"tA", "*", "default"}


def test_tenantless_account_gets_admin_wide_and_default():
    assert api._session_cache_scopes({"user": {}}) == {"*", "default"}
    assert api._session_cache_scopes(None) == {"*", "default"}


# ── _cache_active_scopes ─────────────────────────────────────────────────────

def test_recently_used_live_sessions_are_active():
    _seed({"a": _live({"tenant_id": "tA"}), "b": _live({"tenant_id": "tB"}, 60)})
    assert api._cache_active_scopes() == {"tA", "tB"}


def test_expired_session_is_not_active():
    s = _live({"tenant_id": "tA"})
    s["expires"] = time.time() - 1
    _seed({"a": s})
    assert api._cache_active_scopes() == set()


def test_idle_session_beyond_window_is_not_active():
    _seed({"a": _live({"tenant_id": "tA"}, api._CACHE_ACTIVE_WINDOW_S + 5),
           "b": _live({"tenant_id": "tB"}, api._CACHE_ACTIVE_WINDOW_S - 5)})
    assert api._cache_active_scopes() == {"tB"}


def test_session_with_no_last_seen_is_not_active():
    _seed({"a": {"user": {"tenant_id": "tA"}, "expires": time.time() + 3600}})
    assert api._cache_active_scopes() == set()


def test_admin_session_activates_admin_scope():
    _seed({"a": _live({"permissions": {"role": "admin"}})})
    assert api._cache_active_scopes() == {"*", "default"}


def test_malformed_session_is_skipped():
    _seed({"bad": {"user": {"tenant_id": "tX"}, "expires": "never"},
           "ok": _live({"tenant_id": "tA"})})
    assert api._cache_active_scopes() == {"tA"}


def test_no_sessions_is_empty():
    _seed({})
    assert api._cache_active_scopes() == set()


# ── cache_kick_login ─────────────────────────────────────────────────────────

class _Hub:
    def __init__(self):
        self.kicked = []

    def cache_kick_tenant(self, scope):
        self.kicked.append(scope)


def test_tenant_login_kicks_only_its_tenant():
    hub = _Hub()
    api.cache_kick_login(hub, {"tenant_id": "tA"})
    assert hub.kicked == ["tA"]


def test_admin_login_kicks_admin_wide_and_default_not_every_tenant():
    hub = _Hub()
    api.cache_kick_login(hub, {"permissions": {"admin": True}, "tenant_id": "tA"})
    # "*" (admin-wide data) is kicked as None.
    assert sorted(hub.kicked, key=str) == sorted([None, "default", "tA"], key=str)


def test_login_kick_never_raises():
    class _Boom:
        def cache_kick_tenant(self, scope):
            raise RuntimeError("down")
    api.cache_kick_login(_Boom(), {"tenant_id": "tA"})     # no exception
    api.cache_kick_login(object(), {"tenant_id": "tA"})    # hub without a cache
