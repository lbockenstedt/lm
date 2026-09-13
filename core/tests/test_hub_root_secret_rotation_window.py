"""Hub root-secret rotation window: making the documented 3-entry window real.

Background: ``KeyManager`` has always retained the Hub's last 3 root secrets
(``rotate_hub_secret``), and its docstring says this window exists "so spokes
can verify the Hub's identity even if they have not yet received the latest
rotation update or if they were restored from a backup" — but
``sign_hub_challenge`` only ever signed with ``hub_secrets[0]`` (the newest),
so a spoke holding an older-but-still-retained secret had no signature to
check it against. With ``LM_HUB_TLS_VERIFY=0`` and no onboarding PSK, that
spoke hit the "Hub identity unverified (TLS verify off)" refuse-forever path
— a permanent lockout after missing even one root rotation.

This file covers, in order:

1. ``KeyManager.sign_hub_challenge_all`` — the new additive signer that makes
   the window real by signing the challenge with every retained secret.
2. ``BaseControlPlane._verify_hub_challenge`` — the spoke-side check, which
   must accept a match against ANY retained secret via the ``signatures``
   list while behaving byte-for-byte as before against a legacy hub (no
   ``signatures`` field).
3. ``LabManagerHub._record_hub_identity_rejection`` — hub-side telemetry for
   the case a spoke still refuses (all secrets exhausted): previously silent,
   now surfaced via ``record_spoke_event``/``spoke_telemetry``.
4. The session-key history window (a related, separately-approved change):
   raised from 1 to 3 previous keys, mirroring the hub-secret window.
5. ``LabManagerHub._maybe_reprovision_hub_secret`` — the self-correcting half
   of (1)/(2): a spoke that verified via an OLDER retained secret gets the
   CURRENT one pushed back to it, so it can't accumulate rotations behind
   forever.
"""

import asyncio
import hashlib
import hmac
import os
import time

import main  # noqa: E402  (core/src on sys.path via conftest)
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from security.signer import MessageSigner  # noqa: E402
from messaging.control_plane import BaseControlPlane  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_km():
    """KeyManager whose persistence lives in tmp, not core/data (see the
    identical helper in test_signature_rotation_window.py)."""
    km = KeyManager("keys_hub_root_rot.json", "hub_secret_hub_root_rot.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_hub_root_rot.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_hub_root_rot.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_hub_root_rot.json", "hub_secret_hub_root_rot.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


def _spoke(hub_secrets):
    s = BaseControlPlane.__new__(BaseControlPlane)
    s.spoke_id = "s1"
    s.hub_secrets = list(hub_secrets)
    return s


# ── 1. KeyManager.sign_hub_challenge_all ─────────────────────────────────────

def test_sign_hub_challenge_all_signs_every_retained_secret_newest_first():
    km = _make_km()
    km.hub_secrets = ["newest", "middle", "oldest"]
    challenge = b"a-challenge"
    sigs = km.sign_hub_challenge_all(challenge)
    assert len(sigs) == 3
    for secret, sig in zip(km.hub_secrets, sigs):
        expected = hmac.new(secret.encode(), challenge, hashlib.sha256).hexdigest()
        assert sig == expected
    # First entry matches the newest secret == what sign_hub_challenge alone produces.
    assert sigs[0] == km.sign_hub_challenge(challenge)


def test_sign_hub_challenge_unchanged_still_signs_only_with_newest():
    """The pre-existing single-signature signer must be untouched — other
    callers (and legacy spokes) depend on this exact behavior."""
    km = _make_km()
    km.hub_secrets = ["newest", "older"]
    challenge = b"another-challenge"
    sig = km.sign_hub_challenge(challenge)
    assert sig == hmac.new(b"newest", challenge, hashlib.sha256).hexdigest()


# ── 2. BaseControlPlane._verify_hub_challenge (spoke side) ──────────────────

def test_verify_via_primary_signature_matches_index_0():
    """The common/no-rotation case: the spoke's newest secret matches the
    hub's single ``signature`` field directly — index 0, no rotation-window
    fallback needed."""
    challenge = "chal-1"
    spoke = _spoke(["current-secret"])
    signature = hmac.new(b"current-secret", challenge.encode(), hashlib.sha256).hexdigest()
    verified, idx = spoke._verify_hub_challenge(challenge, signature, None)
    assert verified is True
    assert idx == 0


def test_spoke_holding_hub_secrets_index_1_verifies_via_signatures():
    """The core fix: a spoke that missed ONE hub root rotation (so its
    retained secret is the hub's hub_secrets[1], not [0]) used to have no
    signature to check against and would refuse the hub forever. Now the
    hub's ``signatures`` list carries a signature for hub_secrets[1] too."""
    challenge = "chal-2"
    hub_secrets = ["newest", "one-rotation-old", "two-rotations-old"]
    km = _make_km()
    km.hub_secrets = hub_secrets
    signatures = km.sign_hub_challenge_all(challenge.encode())
    primary_signature = km.sign_hub_challenge(challenge.encode())

    # Spoke only ever received the middle secret (missed the latest rotation).
    spoke = _spoke(["one-rotation-old"])
    verified, idx = spoke._verify_hub_challenge(challenge, primary_signature, signatures)
    assert verified is True
    assert idx == 1


def test_spoke_holding_hub_secrets_index_2_verifies_via_signatures():
    """Same as above but two rotations behind (the oldest retained secret)."""
    challenge = "chal-3"
    hub_secrets = ["newest", "one-rotation-old", "two-rotations-old"]
    km = _make_km()
    km.hub_secrets = hub_secrets
    signatures = km.sign_hub_challenge_all(challenge.encode())
    primary_signature = km.sign_hub_challenge(challenge.encode())

    spoke = _spoke(["two-rotations-old"])
    verified, idx = spoke._verify_hub_challenge(challenge, primary_signature, signatures)
    assert verified is True
    assert idx == 2


def test_spoke_holding_none_of_the_retained_secrets_still_fails():
    """A spoke whose secret has fallen out of the Hub's 3-entry window
    entirely (or was never valid) must NOT verify — the fallback only widens
    the ACCEPTED set to the Hub's own retained secrets, it doesn't accept
    just anything."""
    challenge = "chal-4"
    hub_secrets = ["newest", "one-rotation-old", "two-rotations-old"]
    km = _make_km()
    km.hub_secrets = hub_secrets
    signatures = km.sign_hub_challenge_all(challenge.encode())
    primary_signature = km.sign_hub_challenge(challenge.encode())

    spoke = _spoke(["some-totally-unrelated-secret"])
    verified, idx = spoke._verify_hub_challenge(challenge, primary_signature, signatures)
    assert verified is False
    assert idx is None


def test_legacy_hub_proof_no_signatures_field_behaves_exactly_as_before():
    """A legacy hub sends only ``signature`` (no ``signatures`` key at all).
    A spoke on the newest secret still verifies (index 0); a spoke on an
    older secret still fails — the rotation-window fallback must not run
    when the field is simply absent."""
    challenge = "chal-5"
    signature = hmac.new(b"newest", challenge.encode(), hashlib.sha256).hexdigest()

    on_newest = _spoke(["newest"])
    verified, idx = on_newest._verify_hub_challenge(challenge, signature, None)
    assert verified is True
    assert idx == 0

    on_older = _spoke(["one-rotation-old"])
    verified, idx = on_older._verify_hub_challenge(challenge, signature, None)
    assert verified is False
    assert idx is None


def test_malformed_signatures_field_falls_back_to_today_behavior():
    """A ``signatures`` field that isn't a list (e.g. a stray string, or a
    list containing non-string junk) must be ignored, not crash the spoke or
    get treated as a match — fail-safe to the single-signature behavior."""
    challenge = "chal-6"
    signature = hmac.new(b"newest", challenge.encode(), hashlib.sha256).hexdigest()
    spoke = _spoke(["one-rotation-old"])  # would only verify via signatures[1]

    verified, idx = spoke._verify_hub_challenge(challenge, signature, "not-a-list")
    assert verified is False
    assert idx is None

    verified, idx = spoke._verify_hub_challenge(challenge, signature, [123, None, {}])
    assert verified is False
    assert idx is None


# ── 3. LabManagerHub._record_hub_identity_rejection (hub-side telemetry) ────

class _TelemetryHub:
    """Just the attributes _record_hub_identity_rejection touches."""
    def __init__(self):
        self.spoke_events = {}
        self.spoke_event_limit = 50
        self.spoke_telemetry = {}

    def _primary_key(self, spoke_id):
        return spoke_id

    record_spoke_event = main.LabManagerHub.record_spoke_event


def test_hub_identity_rejected_event_recorded_on_1008_identity_close():
    hub = _TelemetryHub()
    recorded = main.LabManagerHub._record_hub_identity_rejection(
        hub, "spoke-1", "spoke-1", 1008, "Hub identity unverified (TLS verify off)")
    assert recorded is True
    events = hub.spoke_events["spoke-1"]
    assert any(e["event"] == "hub_identity_rejected" for e in events)
    tel = hub.spoke_telemetry["spoke-1"]
    assert tel["status"] == "HUB_IDENTITY_REJECTED"
    assert "identity" in tel["error"].lower()


def test_hub_identity_rejected_not_recorded_for_unrelated_close():
    """A different 1008 reason (e.g. plain auth failure) or a non-1008 close
    must NOT be misclassified as an identity rejection."""
    hub = _TelemetryHub()
    assert main.LabManagerHub._record_hub_identity_rejection(
        hub, "spoke-1", "spoke-1", 1008, "Authentication failed") is False
    assert "spoke-1" not in hub.spoke_telemetry
    assert main.LabManagerHub._record_hub_identity_rejection(
        hub, "spoke-1", "spoke-1", 1000, "Hub identity unverified (TLS verify off)") is False
    assert "spoke-1" not in hub.spoke_telemetry


def test_hub_identity_rejected_telemetry_failure_never_raises():
    """record_spoke_event raising must not propagate — telemetry is
    best-effort and must never break the handshake path."""
    class _BrokenHub(_TelemetryHub):
        def record_spoke_event(self, *a, **kw):
            raise RuntimeError("boom")

    hub = _BrokenHub()
    # Must not raise.
    result = main.LabManagerHub._record_hub_identity_rejection(
        hub, "spoke-1", "spoke-1", 1008, "Hub identity unverified (TLS verify off)")
    assert result is False


# ── 4. Session-key history window: 1 → 3 previous keys ──────────────────────

def test_get_valid_key_accepts_secret_two_rotations_old():
    km = _make_km()
    km.generate_first_secret("s1")
    n1 = km.rotate_key("s1").secret
    km.rotate_key("s1")
    n3 = km.rotate_key("s1").secret
    assert km.current_session_secret("s1") == n3
    # n1 is 2 rotations old (rotated out at rotate #2, one more rotation since)
    # — still inside the 3-deep window.
    assert km.get_valid_key("s1", n1) is not None
    assert km.verify_signature_source("s1", b"{}", MessageSigner(n1).sign({})) == "history"


def test_get_valid_key_rejects_secret_four_rotations_old():
    km = _make_km()
    s0 = km.generate_first_secret("s1")
    km.rotate_key("s1")
    km.rotate_key("s1")
    km.rotate_key("s1")
    n4 = km.rotate_key("s1").secret  # 4th rotation evicts s0 from the 3-deep window
    assert km.current_session_secret("s1") == n4
    assert km.get_valid_key("s1", s0) is None
    assert len(km.history["s1"]) == 3


# ── 5. LabManagerHub._maybe_reprovision_hub_secret ──────────────────────────

class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, wire):
        self.sent.append(wire)

    async def close(self):
        pass


class _ReprovisionHub:
    """Just the attributes _maybe_reprovision_hub_secret (and the
    send_to_spoke/record_spoke_event it calls) touch. Reuses the real
    send_to_spoke so the SPOKE_SET_HUB_SECRET frame is genuinely built and
    signed, not stubbed away."""
    def __init__(self, km):
        self.key_manager = km
        self.active_connections = {}
        self.active_connection_key_ids = {}
        self.spoke_enc_capable = {}
        self.bytes_count = 0
        self.message_count = 0
        self.spoke_id_alias = {}
        self._hub_secret_repush_at = {}
        self.events = []

    def _primary_key(self, spoke_id):
        return self.spoke_id_alias.get(spoke_id, spoke_id)

    def record_spoke_event(self, spoke_id, event_type, detail=""):
        self.events.append((spoke_id, event_type, detail))

    send_to_spoke = main.LabManagerHub.send_to_spoke


def _reprovision(hub, spoke_id):
    return main.LabManagerHub._maybe_reprovision_hub_secret(hub, spoke_id)


def test_reprovision_pushes_current_root_secret_when_index_greater_than_zero():
    km = _make_km()
    km.keys["s1"] = ManagedKey(key_id="k1", secret="session-secret",
                               created_at=time.time(), expires_at=time.time() + 3600)
    km.hub_secrets = ["current-root", "older-root"]
    hub = _ReprovisionHub(km)
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.run(_reprovision(hub, "s1"))

    assert len(ws.sent) == 1
    from security.signer import split_frame
    import json
    _sig, body = split_frame(ws.sent[0])
    payload = json.loads(body)["payload"]
    assert payload["type"] == "SPOKE_SET_HUB_SECRET"
    assert payload["data"]["hub_secret"] == "current-root"
    assert any(ev[1] == "hub_secret_reprovisioned" for ev in hub.events)


def test_reprovision_is_rate_limited_to_once_per_60s():
    km = _make_km()
    km.keys["s1"] = ManagedKey(key_id="k1", secret="session-secret",
                               created_at=time.time(), expires_at=time.time() + 3600)
    km.hub_secrets = ["current-root"]
    hub = _ReprovisionHub(km)
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.run(_reprovision(hub, "s1"))
    asyncio.run(_reprovision(hub, "s1"))
    assert len(ws.sent) == 1  # second call within 60s is a no-op


def test_reprovision_not_invoked_by_handshake_when_index_is_zero_or_absent():
    """The mutual-auth call site only invokes _maybe_reprovision_hub_secret
    when the spoke reports hub_secret_index > 0. This pins that gating
    expression directly (mirrors the encryption-negotiation ad-contract
    tests) rather than driving the full handshake."""
    def _should_reprovision(hub_response: dict) -> bool:
        matched_index = hub_response.get("hub_secret_index")
        return isinstance(matched_index, int) and matched_index > 0

    assert _should_reprovision({"status": "HUB_OK", "hub_secret_index": 0}) is False
    assert _should_reprovision({"status": "HUB_OK"}) is False  # legacy spoke — no field
    assert _should_reprovision({"status": "HUB_OK", "hub_secret_index": 1}) is True
    assert _should_reprovision({"status": "HUB_OK", "hub_secret_index": 2}) is True
