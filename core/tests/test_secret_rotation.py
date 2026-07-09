"""Session-secret rotation / revocation (item 9a/9b/9c).

9a: the zero-touch bootstrap first-secret's 1h ``expires_at`` is now HONORED by
    ``get_keys_due_for_rotation`` (it was a dead field before — rotation was
    created_at/30d only).
9b: on-demand in-place rotation (``rotate_spoke_secret_now`` +
    ``rotate_all_spoke_secrets_now``) — non-disruptive, pushes the new secret
    signed with the pre-rotation secret; the old secret stays valid via history.
9c: non-destructive revocation (``revoke_spoke``) — close WS, drop approval,
    wipe the key so the old secret stops verifying, keep the registration record.
"""
import os
import time
import asyncio

import pytest
import main  # noqa: E402  (core/src on sys.path via conftest)
from security.key_manager import KeyManager, ManagedKey  # noqa: E402


# ── KeyManager tmp-storage helper (mirrors test_signature_rotation_window) ────

def _make_km():
    km = KeyManager("keys_rot_test.json", "hub_secret_rot_test.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_rot_test.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_rot_test.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_rot_test.json", "hub_secret_rot_test.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


def _key(kid, secret):
    return ManagedKey(key_id=kid, secret=secret, created_at=time.time(),
                     expires_at=time.time() + 3600)


# ── 9a: first-secret expires_at is honored ────────────────────────────────────

def test_fresh_first_secret_not_due_for_rotation():
    km = _make_km()
    km.generate_first_secret("s1")  # expires_at = now + 3600
    assert "s1" not in km.get_keys_due_for_rotation(days=30)


def test_expired_first_secret_is_due():
    """The 1h bootstrap expiry now fires: a first secret whose expires_at passed
    is returned by get_keys_due_for_rotation even though created_at < 30d."""
    km = _make_km()
    km.generate_first_secret("s1")
    km.keys["s1"].expires_at = time.time() - 1  # expired
    assert "s1" in km.get_keys_due_for_rotation(days=30)


def test_30day_old_key_is_due_via_created_at():
    km = _make_km()
    km.generate_first_secret("s2")
    km.keys["s2"].created_at = time.time() - (31 * 24 * 3600)
    assert "s2" in km.get_keys_due_for_rotation(days=30)


def test_rotated_key_not_due_until_30d():
    """A just-rotated key (expires_at = created_at + 30d) is NOT due immediately
    — no double-rotation, and the two clauses agree for full keys."""
    km = _make_km()
    km.generate_first_secret("s3")
    km.rotate_key("s3")  # new key: created_at=now, expires_at=now+30d
    assert "s3" not in km.get_keys_due_for_rotation(days=30)


# ── 10c: the LM_DEV_MODE auth backdoor is GONE — regression guard ─────────────

def test_dev_mode_backdoor_removed_no_bypass_for_keyless_spoke(monkeypatch):
    """The dev-mode fallback (LM_DEV_MODE=1 + LM_DEV_SECRET) used to let a spoke
    authenticate with a shared dev secret when no real keys existed — a backdoor
    that bypassed PSK/approval onboarding. It is removed entirely. Even with both
    env vars set, a keyless spoke presenting the dev secret gets None (no auto-
    key creation), so the only auth path is a real per-spoke key (current or
    history). This test pins the removal so it can't be reintroduced."""
    monkeypatch.setenv("LM_DEV_MODE", "1")
    monkeypatch.setenv("LM_DEV_SECRET", "dev-backdoor-secret")
    km = _make_km()
    # No real key for "s1" — the old bypass would have minted a dev-key here.
    assert km.get_valid_key("s1", "dev-backdoor-secret") is None
    assert "s1" not in km.keys  # no auto-created dev-key


def test_dev_mode_backdoor_removed_no_bypass_for_keyed_spoke(monkeypatch):
    """Even with dev-mode env set, a keyed spoke must authenticate ONLY via its
    real current/history secret — the dev secret is not accepted."""
    monkeypatch.setenv("LM_DEV_MODE", "1")
    monkeypatch.setenv("LM_DEV_SECRET", "dev-backdoor-secret")
    km = _make_km()
    real = km.generate_first_secret("s2")
    assert km.get_valid_key("s2", real) is not None       # real secret works
    assert km.get_valid_key("s2", "dev-backdoor-secret") is None  # dev secret rejected
    assert km.get_valid_key("s2", "totally-wrong") is None        # wrong secret rejected


# ── 9b/9c: a LabManagerHub subclass with stubbed deps ─────────────────────────

class _FakeWS:
    def __init__(self):
        self.closed = False
        self.close_code = None
    async def close(self, code, reason):
        self.closed = True
        self.close_code = code


class _FakeState:
    def __init__(self):
        self.approved = {}
        self.saved = 0
    def register_module(self, spoke_id, approved=False):
        self.approved[spoke_id] = approved
    def save_state(self):
        self.saved += 1


class _FakeMailbox:
    def __init__(self):
        self.cleared = []
    async def clear_spoke(self, spoke_id):
        self.cleared.append(spoke_id)


def _fake_hub():
    class _FakeHub(main.LabManagerHub):
        def __init__(self):
            self.key_manager = _make_km()
            self.active_connections = {}
            self.approved_modules = {}
            self.state = _FakeState()
            self.mailbox = _FakeMailbox()
            self.events = []
            self.sent = []  # (msg, signing_secret)

        async def send_to_spoke(self, msg, signing_secret=None):
            self.sent.append((msg, signing_secret))

        def record_spoke_event(self, spoke_id, event_type, detail=""):
            self.events.append((spoke_id, event_type, detail))
    return _FakeHub()


# ── 9b: rotate_spoke_secret_now ───────────────────────────────────────────────

async def test_rotate_now_pushes_new_secret_when_connected():
    hub = _fake_hub()
    hub.key_manager.generate_first_secret("s1")
    prev = hub.key_manager.current_session_secret("s1")
    hub.active_connections["s1"] = _FakeWS()
    hub.approved_modules["s1"] = True

    r = await hub.rotate_spoke_secret_now("s1")
    assert r["status"] == "SUCCESS"
    assert r["connected"] is True
    assert r["pushed"] is True
    # Key actually rotated (new secret != prev).
    assert hub.key_manager.current_session_secret("s1") != prev
    # Push happened, signed with the PRE-rotation secret (non-disruptive delivery).
    assert len(hub.sent) == 1
    msg, signing_secret = hub.sent[0]
    assert signing_secret == prev
    assert msg.payload.type == "SPOKE_UPDATE_SESSION_KEY"
    # Event recorded.
    assert any(ev[1] == "secret_rotated" for ev in hub.events)


async def test_rotate_now_rotates_even_when_not_connected():
    """A disconnected spoke is still rotated; the new secret takes effect on next
    connect (pushed=False because there's no live WS to push to)."""
    hub = _fake_hub()
    hub.key_manager.generate_first_secret("s2")
    prev = hub.key_manager.current_session_secret("s2")
    r = await hub.rotate_spoke_secret_now("s2")
    assert r["status"] == "SUCCESS"
    assert r["connected"] is False
    assert r["pushed"] is False
    assert hub.key_manager.current_session_secret("s2") != prev
    assert hub.sent == []  # no push (not connected)


async def test_rotate_now_error_when_no_key():
    hub = _fake_hub()
    r = await hub.rotate_spoke_secret_now("never-seen")
    assert r["status"] == "ERROR"
    assert "nothing to rotate" in r["message"]


async def test_rotate_all_rotates_every_approved_spoke_with_key():
    hub = _fake_hub()
    for sid in ("a", "b", "c"):
        hub.key_manager.generate_first_secret(sid)
        hub.approved_modules[sid] = True
        hub.active_connections[sid] = _FakeWS()
    # An approved spoke with NO key is skipped, not errored into the batch.
    hub.approved_modules["keyless"] = True
    r = await hub.rotate_all_spoke_secrets_now()
    assert r["status"] == "SUCCESS"
    assert sorted(r["rotated"]) == ["a", "b", "c"]
    assert r["failed"] == []
    assert "keyless" not in r["rotated"]
    assert len(hub.sent) == 3  # one push per connected spoke


# ── 9c: revoke_spoke ──────────────────────────────────────────────────────────

async def test_revoke_closes_ws_drops_approval_wipes_key_keeps_record():
    hub = _fake_hub()
    hub.key_manager.generate_first_secret("s1")
    hub.approved_modules["s1"] = True
    hub.state.approved["s1"] = True
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    r = await hub.revoke_spoke("s1")
    assert r["status"] == "SUCCESS"
    assert r["was_connected"] is True
    # Live WS closed with 1008.
    assert ws.closed is True
    assert ws.close_code == 1008
    # Approval dropped (re-approval required to return).
    assert hub.approved_modules["s1"] is False
    assert hub.state.approved["s1"] is False
    # Crypto material wiped → the old secret no longer verifies.
    assert "s1" not in hub.key_manager.keys
    assert "s1" not in hub.key_manager.history
    # Mail cleared (keyless spoke can't verify signed frames).
    assert "s1" in hub.mailbox.cleared
    # Event recorded.
    assert any(ev[1] == "revoked" for ev in hub.events)


async def test_revoke_on_disconnected_spoke_reports_was_connected_false():
    hub = _fake_hub()
    hub.key_manager.generate_first_secret("s2")
    hub.approved_modules["s2"] = True
    r = await hub.revoke_spoke("s2")
    assert r["status"] == "SUCCESS"
    assert r["was_connected"] is False
    assert "s2" not in hub.key_manager.keys
    assert hub.approved_modules["s2"] is False


async def test_revoked_secret_no_longer_verifies():
    """The point of revocation: after revoke_spoke, the spoke's old secret can't
    authenticate anymore (get_valid_key returns None)."""
    hub = _fake_hub()
    secret = hub.key_manager.generate_first_secret("s1")
    hub.approved_modules["s1"] = True
    # Before revoke, the secret authenticates.
    assert hub.key_manager.get_valid_key("s1", secret) is not None
    await hub.revoke_spoke("s1")
    # After revoke, the same secret is dead.
    assert hub.key_manager.get_valid_key("s1", secret) is None