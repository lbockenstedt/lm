"""Durable recovery PSK — the self-heal for a spoke stranded past the hub's
root-secret rotation window.

Incident this pins: cs-svr-01..04 went offline ~1 week, missed enough hub root
rotations that none of their stored ``hub_secrets`` could verify the hub's
challenge, and with ``LM_HUB_TLS_VERIFY=0`` and no onboarding PSK they took the
"refusing unverified hub (possible MITM)" branch — forever. 77k log lines, and
only a physical reinstall cleared it. Deleting and re-adding the spoke hub-side
could not help, because the refusal is spoke-side.

The fix is a per-spoke PSK derived from a hub root that NEVER rotates, pushed on
every approved connect. Two properties have to hold together, and the tests below
pin both, because fixing one by breaking the other is the obvious wrong turn:

  1. A spoke holding the recovery PSK heals itself with TLS verify OFF.
  2. A spoke that does NOT hold one still refuses an unverifiable hub, exactly
     as before. The MITM guard is not softened — it is given a key.
"""
import asyncio
import hashlib
import hmac
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from messaging.control_plane import BaseControlPlane  # noqa: E402
from security.key_manager import KeyManager  # noqa: E402


# --------------------------------------------------------------------------
# Hub side: derivation + signing
# --------------------------------------------------------------------------

@pytest.fixture()
def km(tmp_path, monkeypatch):
    """A KeyManager with its stores redirected into tmp_path."""
    monkeypatch.chdir(tmp_path)
    return _km_at(tmp_path)


def _km_at(tmp_path):
    """KeyManager with every store repointed into tmp_path, then reloaded so the
    in-memory root matches what is on disk THERE (not in the real data dir)."""
    m = KeyManager()
    m.storage_path = str(tmp_path / "keys.json")
    m.hub_secret_path = str(tmp_path / "hub_secret.json")
    m.recovery_root_path = str(tmp_path / "hub_recovery_root.json")
    m.hub_secrets = m._load_or_generate_hub_secrets()
    m._recovery_root = m._load_or_generate_recovery_root()
    return m


def test_recovery_psk_is_stable_across_root_rotations(km):
    """The whole point: rotating the root secret must NOT change the PSK."""
    before = km.recovery_psk_for("cs-svr-01")
    for _ in range(10):
        km.rotate_hub_secret()
    assert km.recovery_psk_for("cs-svr-01") == before


def test_recovery_psk_is_per_spoke(km):
    """A rogue spoke must not be able to impersonate the hub to its peers."""
    assert km.recovery_psk_for("cs-svr-01") != km.recovery_psk_for("cs-svr-02")


def test_recovery_root_survives_restart(km, tmp_path):
    """Persisted, not regenerated — a hub restart must not strand the fleet."""
    psk = km.recovery_psk_for("cs-svr-01")
    assert _km_at(tmp_path).recovery_psk_for("cs-svr-01") == psk


def test_signature_verifies_under_the_spokes_psk(km):
    challenge = "c0ffee"
    sig = km.sign_hub_challenge_recovery(challenge.encode(), "cs-svr-01")
    expected = hmac.new(km.recovery_psk_for("cs-svr-01").encode(),
                        challenge.encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, expected)


# --------------------------------------------------------------------------
# Spoke side: the self-heal decision
# --------------------------------------------------------------------------

class _Spoke(BaseControlPlane):
    """BaseControlPlane with persistence neutralized (see loadtest_spokes.py)."""

    def __init__(self, **kw):
        # Set before super(): __init__ persists INSTALL_UUID on the way through.
        self.persisted = {}
        super().__init__(**kw)
        self.persisted.clear()

    def _persist_secret_to_env(self, key, value):
        self.persisted[key] = value

    def _touch_healthy_marker(self):
        pass


def _spoke(monkeypatch, *, recovery_psk="", hub_secret="stale-secret"):
    monkeypatch.delenv("LM_RECOVERY_PSK", raising=False)
    monkeypatch.delenv("LM_ONBOARDING_PSK", raising=False)
    monkeypatch.delenv("LM_TENANT_ID_HINT", raising=False)
    if recovery_psk:
        monkeypatch.setenv("LM_RECOVERY_PSK", recovery_psk)
    return _Spoke(spoke_id="cs-svr-01", hub_url="wss://hub:443",
                  hub_secret=hub_secret)


def test_recovery_psk_is_stored_and_persisted(monkeypatch):
    """SPOKE_SET_RECOVERY_PSK must persist — it has to outlive the downtime."""
    s = _spoke(monkeypatch)
    res = asyncio.run(s.handle_system_command(
        "SPOKE_SET_RECOVERY_PSK", {"recovery_psk": "psk-abc"}))
    assert res["status"] == "SUCCESS"
    assert s.recovery_psk == "psk-abc"
    assert s.persisted["LM_RECOVERY_PSK"] == "psk-abc"


def test_recovery_psk_push_is_idempotent(monkeypatch):
    """Re-pushed on every connect; an unchanged value must not rewrite .env."""
    s = _spoke(monkeypatch, recovery_psk="psk-abc")
    asyncio.run(s.handle_system_command(
        "SPOKE_SET_RECOVERY_PSK", {"recovery_psk": "psk-abc"}))
    assert "LM_RECOVERY_PSK" not in s.persisted


def test_stranded_spoke_heals_with_recovery_psk(monkeypatch, km):
    """THE regression test. Stale hub_secret + TLS verify OFF + recovery PSK
    == verified, secrets dropped, ready for the hub to re-provision."""
    psk = km.recovery_psk_for("cs-svr-01")
    s = _spoke(monkeypatch, recovery_psk=psk)
    s._tls_verify = False

    challenge = "deadbeef"
    # The hub has rotated far past anything this spoke holds.
    for _ in range(5):
        km.rotate_hub_secret()

    verified, _idx = s._verify_hub_challenge(
        challenge, km.sign_hub_challenge(challenge.encode()),
        km.sign_hub_challenge_all(challenge.encode()))
    assert verified is False, "precondition: no stored hub_secret can verify"

    rec_sig = km.sign_hub_challenge_recovery(challenge.encode(), "cs-svr-01")
    assert s._recovery_psk_verifies(challenge, rec_sig), (
        "the stranded spoke must still be able to verify the hub")


def test_spoke_without_recovery_psk_still_refuses_unverified_hub(monkeypatch, km):
    """The MITM guard must NOT be softened. No recovery PSK == no recovery."""
    s = _spoke(monkeypatch, recovery_psk="")
    s._tls_verify = False
    assert s.recovery_psk == ""

    challenge = "deadbeef"
    rec_sig = km.sign_hub_challenge_recovery(challenge.encode(), "cs-svr-01")
    # The hub offered a perfectly genuine proof; with no stored PSK the spoke
    # still has no way to check it, so it must fall through to the refusal.
    assert s._recovery_psk_verifies(challenge, rec_sig) is False


def test_wrong_recovery_psk_does_not_verify(monkeypatch, km):
    """An attacker's signature must not pass under the real PSK."""
    s = _spoke(monkeypatch, recovery_psk=km.recovery_psk_for("cs-svr-01"))
    challenge = "deadbeef"
    attacker_sig = hmac.new(b"attacker-root", challenge.encode(),
                            hashlib.sha256).hexdigest()
    assert s._recovery_psk_verifies(challenge, attacker_sig) is False
    # Fail-closed on malformed/absent proofs too.
    assert s._recovery_psk_verifies(challenge, None) is False
    assert s._recovery_psk_verifies(challenge, "") is False
    assert s._recovery_psk_verifies(challenge, {"sig": attacker_sig}) is False


def test_peer_spokes_psk_does_not_verify(monkeypatch, km):
    """Holding cs-svr-02's PSK must not let anyone impersonate the hub to
    cs-svr-01 — the derivation is per-spoke for exactly this reason."""
    s = _spoke(monkeypatch, recovery_psk=km.recovery_psk_for("cs-svr-01"))
    challenge = "deadbeef"
    peer_sig = km.sign_hub_challenge_recovery(challenge.encode(), "cs-svr-02")
    assert s._recovery_psk_verifies(challenge, peer_sig) is False
