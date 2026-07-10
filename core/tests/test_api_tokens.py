"""Tests for api_tokens — Bearer access + refresh-token rotation.

Covers: issue → bearer resolve, seamless rotation (old access dies, new works),
single-use refresh with family-revoke on reuse, list/revoke, and per-user
invalidation. Uses a throwaway hub whose state.data_dir is a tmp path.
"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import api_tokens  # noqa: E402


class _State:
    def __init__(self, d):
        self.data_dir = d


class _Hub:
    def __init__(self, d):
        self.state = _State(d)


def _fresh(tmp_path):
    """Clear the module-global stores (shared across tests) + a tmp hub."""
    api_tokens._access.clear()
    api_tokens._refresh.clear()
    return _Hub(str(tmp_path))


def _req(token):
    return types.SimpleNamespace(headers={"Authorization": f"Bearer {token}"})


def test_issue_and_bearer_resolve(tmp_path):
    hub = _fresh(tmp_path)
    access, refresh, ttl = api_tokens.issue_pair(
        hub, "alice", {"user_id": "alice", "permissions": {"admin": True}}, "test")
    assert ttl == api_tokens.ACCESS_TTL_S
    sess = api_tokens.bearer_session(_req(access))
    assert sess and sess["user_id"] == "alice" and sess["api_token"] is True
    # permissions travel with the token
    assert sess["user"]["permissions"] == {"admin": True}
    # a bogus token resolves to nothing
    assert api_tokens.bearer_session(_req("nope")) is None
    assert api_tokens.bearer_session(types.SimpleNamespace(headers={})) is None


def test_secret_fields_stripped_from_snapshot(tmp_path):
    hub = _fresh(tmp_path)
    access, _r, _t = api_tokens.issue_pair(
        hub, "dave", {"user_id": "dave", "password_hash": "SECRET", "permissions": {}}, "t")
    sess = api_tokens.bearer_session(_req(access))
    assert "password_hash" not in sess["user"]  # never persisted into a token


def test_refresh_rotation(tmp_path):
    hub = _fresh(tmp_path)
    access, refresh, _ = api_tokens.issue_pair(hub, "bob", {"user_id": "bob"}, "t")
    pair = api_tokens.refresh(hub, refresh)
    assert pair
    new_access, new_refresh, _ = pair
    # old access is invalidated by the rotation; new access works
    assert api_tokens.bearer_session(_req(access)) is None
    assert api_tokens.bearer_session(_req(new_access)) is not None
    assert new_refresh != refresh


def test_refresh_reuse_revokes_family(tmp_path):
    hub = _fresh(tmp_path)
    _a, refresh, _ = api_tokens.issue_pair(hub, "bob", {"user_id": "bob"}, "t")
    new_access, _new_refresh, _ = api_tokens.refresh(hub, refresh)
    assert api_tokens.bearer_session(_req(new_access)) is not None
    # Reusing the ALREADY-rotated refresh token is a theft signal → whole family
    # revoked (the just-issued access token dies too).
    assert api_tokens.refresh(hub, refresh) is None
    assert api_tokens.bearer_session(_req(new_access)) is None


def test_list_and_revoke(tmp_path):
    hub = _fresh(tmp_path)
    access, _r, _t = api_tokens.issue_pair(hub, "carol", {"user_id": "carol"}, "mytoken")
    toks = api_tokens.list_tokens("carol")
    assert len(toks) == 1 and toks[0]["name"] == "mytoken"
    assert api_tokens.revoke(hub, "carol", toks[0]["id"]) is True
    assert api_tokens.list_tokens("carol") == []
    assert api_tokens.bearer_session(_req(access)) is None  # dead after revoke
    # revoking someone else's / a missing id → False
    assert api_tokens.revoke(hub, "carol", "does-not-exist") is False


def test_invalidate_user(tmp_path):
    hub = _fresh(tmp_path)
    a1, _r1, _ = api_tokens.issue_pair(hub, "erin", {"user_id": "erin"}, "one")
    a2, _r2, _ = api_tokens.issue_pair(hub, "erin", {"user_id": "erin"}, "two")
    a_other, _ro, _ = api_tokens.issue_pair(hub, "frank", {"user_id": "frank"}, "x")
    assert api_tokens.invalidate_user(hub, "erin") == 2
    assert api_tokens.bearer_session(_req(a1)) is None
    assert api_tokens.bearer_session(_req(a2)) is None
    assert api_tokens.bearer_session(_req(a_other)) is not None  # other user untouched


def test_persist_and_load(tmp_path):
    hub = _fresh(tmp_path)
    access, refresh, _ = api_tokens.issue_pair(hub, "gina", {"user_id": "gina"}, "t")
    # wipe in-memory, reload from disk → tokens still resolve
    api_tokens._access.clear()
    api_tokens._refresh.clear()
    api_tokens.load(hub)
    assert api_tokens.bearer_session(_req(access)) is not None
    assert api_tokens.refresh(hub, refresh) is not None
