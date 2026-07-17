"""H4 hub outbound: ``LabManagerHub.send_to_spoke`` AEAD-encrypts secret-bearing
frames to encryption-capable spokes, and leaves them plaintext otherwise.

Drives the REAL ``send_to_spoke`` (unbound from the class, called on a minimal
stand-in that holds only the attributes the method touches — same pattern as
``test_signature_rotation_window.py``). A ``_FakeWS`` captures the wire so the
test can split + parse + decrypt the body and assert what actually went out.

Covers: encrypts a secret frame to a capable spoke (decrypts with the current
key); skips for a non-capable spoke; skips for non-secret types; the
``SPOKE_UPDATE_SESSION_KEY`` first-ever push (``signing_secret=None``) stays
PLAINTTEXT (refinement #1 — the never-keyed spoke has no key to decrypt with);
a rotation push is encrypted with the PRE-rotation secret; the
``LM_APP_ENCRYPTION=0`` kill switch → plaintext.
"""

import asyncio
import json
import os
import time

import main  # noqa: E402
from security.key_manager import KeyManager, ManagedKey  # noqa: E402
from security.signer import split_frame  # noqa: E402
from security import frame_crypto as fc  # noqa: E402


# ── harness ─────────────────────────────────────────────────────────────────

def _make_km():
    km = KeyManager("keys_h4_out.json", "hub_secret_h4_out.json")
    km.storage_path = os.path.join("/tmp", "lm_keys_h4_out.json")
    km.hub_secret_path = os.path.join("/tmp", "lm_hub_secret_h4_out.json")
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    for name in ("keys_h4_out.json", "hub_secret_h4_out.json"):
        try:
            os.remove(os.path.join(data_dir, name))
        except OSError:
            pass
    return km


def _key(secret):
    return ManagedKey(key_id="k-" + secret[:6], secret=secret,
                      created_at=time.time(), expires_at=time.time() + 3600)


class _FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, wire):
        self.sent.append(wire)

    async def close(self):
        pass


class _Hub:
    """Minimal stand-in holding only what ``send_to_spoke`` touches."""

    def __init__(self, km):
        self.key_manager = km
        self.active_connections = {}
        self.active_connection_key_ids = {}
        self.spoke_enc_capable = {}
        self.bytes_count = 0
        self.message_count = 0


def _msg(ptype, data, dest):
    from main import Message, MessageHeader, MessagePayload
    return Message(
        header=MessageHeader(message_id="m1", timestamp=time.time(),
                             sender_id="hub", destination_id=dest),
        payload=MessagePayload(type=ptype, data=data))


def _send(hub, message, signing_secret=None):
    return main.LabManagerHub.send_to_spoke(hub, message, signing_secret=signing_secret)


def _parse_wire(ws):
    """Return (sig, body_str, body_dict, payload_dict) for the single sent
    frame — the raw body string is needed to re-verify the HMAC."""
    assert len(ws.sent) == 1, f"expected 1 frame, got {len(ws.sent)}"
    sig, body = split_frame(ws.sent[0])
    body_dict = json.loads(body)
    return sig, body, body_dict, body_dict["payload"]


# ── encryption on for capable spoke ─────────────────────────────────────────

def test_encrypts_secret_frame_to_capable_spoke():
    km = _make_km()
    km.keys["s1"] = _key("current-secret-abc")
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.new_event_loop().run_until_complete(
        _send(hub, _msg("INSTALL_CERT", {"privkey": "PEM-SECRET"}, "s1")))

    sig, body, _body_dict, payload = _parse_wire(ws)
    # HMAC was over the ENCRYPTED body (verify with the current secret).
    from security.signer import MessageSigner
    assert MessageSigner("current-secret-abc").verify_bytes(body.encode(), sig)
    # data is now a b64 ciphertext string + enc marker.
    assert fc.is_encrypted(payload) is True
    assert isinstance(payload["data"], str)
    assert "PEM-SECRET" not in payload["data"]
    # Decrypts with the current session key.
    plain = fc.decrypt_payload_data("current-secret-abc", payload["data"])
    assert plain == {"privkey": "PEM-SECRET"}


def test_skips_encryption_for_non_capable_spoke():
    """A legacy spoke (or one that didn't advertise enc) gets plaintext."""
    km = _make_km()
    km.keys["s1"] = _key("current-secret-abc")
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = False  # not capable
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.new_event_loop().run_until_complete(
        _send(hub, _msg("INSTALL_CERT", {"privkey": "PEM-SECRET"}, "s1")))

    _sig, _bstr, _bd, payload = _parse_wire(ws)
    assert fc.is_encrypted(payload) is False
    assert payload["data"] == {"privkey": "PEM-SECRET"}  # plaintext


def test_skips_encryption_for_non_secret_type():
    """Heartbeats / commands / replies stay plaintext (hot path not encrypted)."""
    km = _make_km()
    km.keys["s1"] = _key("current-secret-abc")
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.new_event_loop().run_until_complete(
        _send(hub, _msg("GET_VERSION", {"want": "v"}, "s1")))

    _sig, _bstr, _bd, payload = _parse_wire(ws)
    assert fc.is_encrypted(payload) is False
    assert payload["data"] == {"want": "v"}


# ── refinement #1: SPOKE_UPDATE_SESSION_KEY ──────────────────────────────────

def test_first_ever_key_push_stays_plaintext():
    """Never-keyed spoke: signing_secret=None → skip encryption (refinement #1).
    The spoke has no key to decrypt with, so the bootstrap push is plaintext."""
    km = _make_km()
    # generate_first_secret mints the new key (the spoke will install it).
    new_secret = km.generate_first_secret("s1")
    assert km.current_session_secret("s1") == new_secret
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    # prev_secret for a never-keyed spoke is None → signing_secret=None.
    asyncio.new_event_loop().run_until_complete(
        _send(hub, _msg("SPOKE_UPDATE_SESSION_KEY", {"secret": new_secret}, "s1"),
              signing_secret=None))

    _sig, _bstr, _bd, payload = _parse_wire(ws)
    assert fc.is_encrypted(payload) is False
    assert payload["data"] == {"secret": new_secret}  # plaintext bootstrap


def test_rotation_key_push_is_encrypted_with_prev_secret():
    """A spoke that already holds a key gets the rotation encrypted with the
    PRE-rotation secret it still has (refinement #1)."""
    km = _make_km()
    old = km.generate_first_secret("s1")            # the secret the spoke holds
    new_key = km.rotate_key("s1")                    # hub flips to a new key
    new_secret = new_key.secret
    assert new_secret != old
    prev = old  # the secret the spoke still holds = previous_session_secret
    assert km.previous_session_secret("s1") == prev

    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.new_event_loop().run_until_complete(
        _send(hub, _msg("SPOKE_UPDATE_SESSION_KEY", {"secret": new_secret}, "s1"),
              signing_secret=prev))

    sig, body, _bd, payload = _parse_wire(ws)
    # Signed with the prev secret (encode_frame_with_secret).
    from security.signer import MessageSigner
    assert MessageSigner(prev).verify_bytes(body.encode(), sig)
    assert fc.is_encrypted(payload) is True
    # Decrypts with the PRE-rotation secret (what the spoke still holds).
    plain = fc.decrypt_payload_data(prev, payload["data"])
    assert plain == {"secret": new_secret}
    # And does NOT decrypt with the new secret (the spoke doesn't have it yet).
    from cryptography.exceptions import InvalidTag
    try:
        fc.decrypt_payload_data(new_secret, payload["data"])
        assert False, "should have raised InvalidTag"
    except InvalidTag:
        pass


# ── kill switch ──────────────────────────────────────────────────────────────

def test_kill_switch_makes_capable_spoke_get_plaintext(monkeypatch):
    """LM_APP_ENCRYPTION=0 → a capable spoke still gets plaintext (rollback)."""
    monkeypatch.setenv("LM_APP_ENCRYPTION", "0")
    km = _make_km()
    km.keys["s1"] = _key("current-secret-abc")
    hub = _Hub(km)
    hub.spoke_enc_capable["s1"] = True  # capable, but kill switch off
    ws = _FakeWS()
    hub.active_connections["s1"] = ws

    asyncio.new_event_loop().run_until_complete(
        _send(hub, _msg("INSTALL_CERT", {"privkey": "PEM-SECRET"}, "s1")))

    _sig, _bstr, _bd, payload = _parse_wire(ws)
    assert fc.is_encrypted(payload) is False
    assert payload["data"] == {"privkey": "PEM-SECRET"}