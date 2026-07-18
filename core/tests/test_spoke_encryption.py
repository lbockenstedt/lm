"""H4 spoke side: AEAD-encrypt outbound secret frames and decrypt inbound ones.

Drives the REAL ``BaseControlPlane._encode_frame`` and ``_decode_frame`` on a
minimal harness (the pattern from ``test_agent_hosting_frame_decode.py`` —
bypass the heavy ``__init__`` and set only the attributes the methods touch).

Covers: ``CS_TOKEN_RESULT`` nested inside ``AGENT_RELAY_UP`` is encrypted at
the inner payload when ``hub_enc_capable`` (outer routing fields stay
plaintext); skipped when the hub isn't capable / no secret / kill switch;
inbound ``SPOKE_UPDATE_SESSION_KEY`` rotation decrypts with ``self.secret``
(the PRE-rotation key at decode time) then dispatch installs the new key;
inbound ``INSTALL_CERT`` decrypts; a tampered inbound frame is dropped; the
kill switch disables advertising + encrypting.
"""

import asyncio  # noqa: F401
import json
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.control_plane import BaseControlPlane  # noqa: E402
from core.src.security.signer import MessageSigner, encode_frame, split_frame  # noqa: E402
from core.src.security import frame_crypto as fc  # noqa: E402

SECRET = "spoke-session-secret-1234567890"


class _Spoke:
    """Minimal stand-in for the attributes _encode_frame/_decode_frame touch."""

    def __init__(self, secret=SECRET):
        self.spoke_id = "s1"
        self.secret = secret
        self.signer = MessageSigner(secret) if secret else None
        self.hub_enc_capable = False


# ── outbound _encode_frame: nested CS_TOKEN_RESULT (refinement #2) ────────────

def _relay_msg(inner_type, inner_data):
    return {"header": {"sender_id": "s1", "destination_id": "hub"},
            "payload": {"type": "AGENT_RELAY_UP", "data": {
                "agent_id": "a1", "install_uuid": "u1", "hostname": "h1",
                "original_payload": {"payload": {"type": inner_type,
                                                   "data": inner_data}}}}}


def _sent_payload(wire):
    _sig, body = split_frame(wire)
    return json.loads(body)["payload"]


def test_encode_encrypts_nested_cs_token_result_when_capable():
    spoke = _Spoke()
    spoke.hub_enc_capable = True
    wire = BaseControlPlane._encode_frame(spoke, _relay_msg("CS_TOKEN_RESULT", {"token": "TOK"}))
    payload = _sent_payload(wire)
    # Outer envelope stays plaintext (hub reads routing fields).
    assert payload["type"] == "AGENT_RELAY_UP"
    assert not fc.is_encrypted(payload)
    outer_data = payload["data"]
    assert outer_data["agent_id"] == "a1"
    assert outer_data["hostname"] == "h1"
    # Inner payload is encrypted.
    inner = outer_data["original_payload"]["payload"]
    assert fc.is_encrypted(inner) is True
    assert inner["type"] == "CS_TOKEN_RESULT"
    assert isinstance(inner["data"], str)
    assert "TOK" not in inner["data"]
    # Decrypts with the spoke's session secret.
    assert fc.decrypt_payload_data(SECRET, inner["data"]) == {"token": "TOK"}


def test_encode_skips_nested_encryption_when_hub_not_capable():
    spoke = _Spoke()
    spoke.hub_enc_capable = False  # legacy hub
    wire = BaseControlPlane._encode_frame(spoke, _relay_msg("CS_TOKEN_RESULT", {"token": "TOK"}))
    payload = _sent_payload(wire)
    inner = payload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)
    assert inner["data"] == {"token": "TOK"}  # plaintext


def test_encode_skips_nested_encryption_when_no_secret():
    """Pre-key bootstrap: no secret → no encrypt (the hub can't decrypt yet)."""
    spoke = _Spoke(secret=None)
    spoke.hub_enc_capable = True  # capable, but no key
    wire = BaseControlPlane._encode_frame(spoke, _relay_msg("CS_TOKEN_RESULT", {"token": "TOK"}))
    payload = _sent_payload(wire)
    inner = payload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)
    assert inner["data"] == {"token": "TOK"}


def test_encode_kill_switch_disables_nested_encryption(monkeypatch):
    monkeypatch.setenv("LM_APP_ENCRYPTION", "0")
    spoke = _Spoke()
    spoke.hub_enc_capable = True
    wire = BaseControlPlane._encode_frame(spoke, _relay_msg("CS_TOKEN_RESULT", {"token": "TOK"}))
    payload = _sent_payload(wire)
    inner = payload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)
    assert inner["data"] == {"token": "TOK"}


def test_encode_keeps_non_secret_relay_plaintext():
    """An AGENT_RELAY_UP carrying a non-secret inner type (AGENT_HEARTBEAT) is
    not encrypted even when capable — only ENCRYPTED_TYPES get wrapped."""
    spoke = _Spoke()
    spoke.hub_enc_capable = True
    wire = BaseControlPlane._encode_frame(spoke, _relay_msg("AGENT_HEARTBEAT", {"ok": 1}))
    payload = _sent_payload(wire)
    inner = payload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)
    assert inner["data"] == {"ok": 1}


def test_encode_top_level_secret_type_wrapped_when_capable():
    """A top-level (non-nested) secret type also wraps when capable — covers the
    symmetric top-level gate (the spoke→hub direction doesn't currently emit
    these at top level, but the gate must be correct)."""
    spoke = _Spoke()
    spoke.hub_enc_capable = True
    msg = {"header": {"sender_id": "s1"}, "payload": {"type": "SET_PASSWORD",
                                                       "data": {"password": "pw"}}}
    wire = BaseControlPlane._encode_frame(spoke, msg)
    payload = _sent_payload(wire)
    assert fc.is_encrypted(payload)
    assert fc.decrypt_payload_data(SECRET, payload["data"]) == {"password": "pw"}


# ── inbound _decode_frame ────────────────────────────────────────────────────

def _wire_from_hub(secret, ptype, data, encrypt=False):
    """Build a <sig>.<body> wire the spoke decodes (signed with the secret the
    spoke holds). If encrypt, wrap data first (as the hub's send_to_spoke does)."""
    body = {"header": {"sender_id": "hub", "destination_id": "s1"},
            "payload": {"type": ptype, "data": data}}
    if encrypt:
        fc.wrap(secret, body["payload"])
    return encode_frame(MessageSigner(secret), body)


def test_decode_decrypts_rotation_with_prev_secret():
    """SPOKE_UPDATE_SESSION_KEY rotation: the hub signs+encrypts with the
    PRE-rotation secret the spoke still holds. At decode time self.secret is
    still prev; the frame decrypts; dispatch later installs the new key."""
    prev = SECRET
    new_secret = "rotated-new-secret-9876543210"
    spoke = _Spoke(secret=prev)  # still holds prev
    wire = _wire_from_hub(prev, "SPOKE_UPDATE_SESSION_KEY", {"secret": new_secret},
                          encrypt=True)
    msg, ok = BaseControlPlane._decode_frame(spoke, wire)
    assert ok is True
    assert msg["payload"]["type"] == "SPOKE_UPDATE_SESSION_KEY"
    assert msg["payload"]["data"] == {"secret": new_secret}  # decrypted
    # Simulate dispatch installing the new key — a subsequent frame
    # signed+encrypted with the NEW key decodes on the re-keyed spoke.
    spoke.secret = new_secret
    spoke.signer = MessageSigner(new_secret)
    wire2 = _wire_from_hub(new_secret, "INSTALL_CERT", {"privkey": "PEM"}, encrypt=True)
    msg2, ok2 = BaseControlPlane._decode_frame(spoke, wire2)
    assert ok2 is True
    assert msg2["payload"]["data"] == {"privkey": "PEM"}


def test_decode_decrypts_install_cert():
    spoke = _Spoke()
    wire = _wire_from_hub(SECRET, "INSTALL_CERT", {"privkey": "PEM-SECRET"}, encrypt=True)
    msg, ok = BaseControlPlane._decode_frame(spoke, wire)
    assert ok is True
    assert msg["payload"]["data"] == {"privkey": "PEM-SECRET"}


def test_decode_drops_tampered_encrypted():
    spoke = _Spoke()
    wire = _wire_from_hub(SECRET, "INSTALL_CERT", {"privkey": "PEM"}, encrypt=True)
    # Corrupt one byte of the body (after the sig '.') — flip a char in the b64
    # ciphertext. Find the data field and corrupt it via the wire string.
    sig, body = split_frame(wire)
    # Corrupt a char well inside the body (not the signature).
    idx = body.find('"data":"') + len('"data":"')
    body_chars = list(body)
    body_chars[idx + 5] = "X" if body_chars[idx + 5] != "X" else "Y"
    corrupted = sig + "." + "".join(body_chars)
    msg, ok = BaseControlPlane._decode_frame(spoke, corrupted)
    assert ok is False  # dropped (either HMAC or AEAD failure)


def test_decode_plaintext_frame_still_works():
    """A plaintext (non-encrypted) inbound frame decodes normally."""
    spoke = _Spoke()
    wire = _wire_from_hub(SECRET, "GET_VERSION", {"want": "v"}, encrypt=False)
    msg, ok = BaseControlPlane._decode_frame(spoke, wire)
    assert ok is True
    assert msg["payload"]["data"] == {"want": "v"}


def test_decode_encrypted_frame_with_no_secret_dropped():
    """A never-keyed spoke receives an encrypted frame — but a real hub never
    sends one to a never-keyed spoke (refinement #1). If it did, the spoke
    has no secret to decrypt with → drop (defensive)."""
    spoke = _Spoke(secret=None)
    spoke.signer = None
    # Build an encrypted frame signed with some secret; the spoke has no key,
    # so has_key=False → it parses without verifying (bootstrap path) but then
    # hits the encrypted-with-no-secret drop.
    wire = _wire_from_hub("other-secret", "INSTALL_CERT", {"privkey": "PEM"}, encrypt=True)
    msg, ok = BaseControlPlane._decode_frame(spoke, wire)
    assert ok is False


# ── kill switch on advertise ─────────────────────────────────────────────────

def test_kill_switch_disables_advertising(monkeypatch):
    """When LM_APP_ENCRYPTION=0, encryption_enabled() is False — the spoke must
    not advertise enc nor encrypt. (We assert the gate function directly; the
    auth-frame ad is added in connect() and gated on encryption_enabled().)"""
    monkeypatch.setenv("LM_APP_ENCRYPTION", "0")
    assert fc.encryption_enabled() is False
    # _encode_frame with kill switch off → no encryption even if capable.
    spoke = _Spoke()
    spoke.hub_enc_capable = True
    wire = BaseControlPlane._encode_frame(spoke, _relay_msg("CS_TOKEN_RESULT", {"token": "TOK"}))
    payload = _sent_payload(wire)
    inner = payload["data"]["original_payload"]["payload"]
    assert not fc.is_encrypted(inner)
    assert inner["data"] == {"token": "TOK"}