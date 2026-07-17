"""Unit tests for :mod:`security.frame_crypto` — the pure AEAD helper (H4).

No hub, no spoke, no sockets — just the HKDF/AES-GCM primitives, the marker
gate, and the kill switch. These are the contract the hub/spoke edits rely on.
"""

import os
import json

import pytest
from cryptography.exceptions import InvalidTag

from security import frame_crypto as fc


# ── derive_aead_key ─────────────────────────────────────────────────────────

def test_derive_key_is_deterministic():
    """Same secret → same key (both sides hold the same signing secret)."""
    assert fc.derive_aead_key("samesecret") == fc.derive_aead_key("samesecret")


def test_derive_key_differs_for_distinct_secrets():
    a = fc.derive_aead_key("secret-a")
    b = fc.derive_aead_key("secret-b")
    assert a != b
    assert len(a) == 32  # AES-256


def test_derive_key_handles_unicode_token_urlsafe_secret():
    """Real secrets are ``secrets.token_urlsafe(32)`` — may contain ``-``/``_``
    and span the full base64url alphabet; HKDF must accept any bytes."""
    import secrets
    s = secrets.token_urlsafe(32)
    assert len(fc.derive_aead_key(s)) == 32
    assert fc.derive_aead_key(s) == fc.derive_aead_key(s)


# ── encrypt / decrypt round-trip ────────────────────────────────────────────

def test_encrypt_decrypt_round_trip_deep_equality():
    data = {"secret": "supersecret", "nested": {"a": [1, 2, 3]}, "n": 7}
    b64 = fc.encrypt_payload_data("k", data)
    assert isinstance(b64, str)
    assert fc.decrypt_payload_data("k", b64) == data


def test_encrypt_yields_distinct_ciphertexts_for_same_data():
    """Fresh random nonce per call → two encryptions of the same data differ
    (AEAD nonce reuse under one key is catastrophic, so the nonce is never
    reused/derived)."""
    data = {"secret": "x"}
    a = fc.encrypt_payload_data("k", data)
    b = fc.encrypt_payload_data("k", data)
    assert a != b
    assert fc.decrypt_payload_data("k", a) == data
    assert fc.decrypt_payload_data("k", b) == data


def test_decrypt_wrong_key_raises_invalid_tag():
    b64 = fc.encrypt_payload_data("right-key", {"secret": "x"})
    with pytest.raises(InvalidTag):
        fc.decrypt_payload_data("wrong-key", b64)


def test_decrypt_tampered_ciphertext_raises_invalid_tag():
    b64 = fc.encrypt_payload_data("k", {"secret": "x"})
    # Flip the last char of the b64 blob (corrupts tag/ciphertext).
    tampered = b64[:-1] + ("A" if b64[-1] != "A" else "B")
    with pytest.raises(InvalidTag):
        fc.decrypt_payload_data("k", tampered)


def test_encrypt_decrypt_preserves_types():
    """AEAD carries JSON, so the round-trip preserves nested structure/types."""
    data = {"none": None, "bool": True, "float": 1.5, "list": [1, "two", None]}
    assert fc.decrypt_payload_data("k", fc.encrypt_payload_data("k", data)) == data


# ── is_encrypted / marker gate ──────────────────────────────────────────────

def test_is_encrypted_true_for_marker():
    assert fc.is_encrypted({"enc": "v1", "data": "x", "type": "T"}) is True


def test_is_encrypted_false_without_marker():
    assert fc.is_encrypted({"data": {"x": 1}, "type": "T"}) is False


def test_is_encrypted_false_for_wrong_marker_value():
    assert fc.is_encrypted({"enc": "v2", "data": "x"}) is False
    assert fc.is_encrypted({"enc": "", "data": "x"}) is False


# ── wrap / unwrap ───────────────────────────────────────────────────────────

def test_wrap_encrypts_data_and_marks():
    p = {"type": "INSTALL_CERT", "data": {"privkey": "PEM..."}}
    fc.wrap("k", p)
    assert fc.is_encrypted(p) is True
    assert isinstance(p["data"], str)
    assert "privkey" not in p["data"]  # not plaintext


def test_unwrap_restores_data_and_drops_marker():
    original = {"privkey": "PEM...", "cert": "C"}
    p = {"type": "INSTALL_CERT", "data": original}
    fc.wrap("k", p)
    fc.unwrap("k", p)
    assert p["data"] == original
    assert "enc" not in p
    assert fc.is_encrypted(p) is False


def test_wrap_then_unwrap_round_trip():
    original = {"a": 1, "b": [2, 3]}
    p = {"type": "T", "data": original}
    fc.wrap("k", p)
    fc.unwrap("k", p)
    assert p["data"] == original
    assert p["type"] == "T"


def test_wrap_is_idempotent():
    """Double-wrap must NOT re-encrypt (would wrap the already-b64 blob)."""
    p = {"type": "T", "data": {"secret": "x"}}
    fc.wrap("k", p)
    first_data = p["data"]
    fc.wrap("k", p)  # second call
    assert p["data"] == first_data  # unchanged
    fc.unwrap("k", p)
    assert p["data"] == {"secret": "x"}


def test_wrap_preserves_non_data_keys():
    """Reply frames carry ``correlation_id`` at the payload top level — it
    must survive wrapping (only ``data`` is encrypted)."""
    p = {"type": "RESPONSE", "data": {"secret": "x"}, "correlation_id": "abc-123"}
    fc.wrap("k", p)
    assert p["correlation_id"] == "abc-123"
    assert p["type"] == "RESPONSE"
    fc.unwrap("k", p)
    assert p["correlation_id"] == "abc-123"


def test_unwrap_is_noop_on_unmarked_payload():
    """Symmetric with wrap idempotence: a plaintext payload passes through."""
    p = {"type": "T", "data": {"x": 1}}
    fc.unwrap("k", p)
    assert p == {"type": "T", "data": {"x": 1}}


def test_unwrap_tampered_raises():
    p = {"type": "T", "data": {"secret": "x"}}
    fc.wrap("k", p)
    p["data"] = p["data"][:-1] + ("A" if p["data"][-1] != "A" else "B")
    with pytest.raises(InvalidTag):
        fc.unwrap("k", p)


def test_unwrap_wrong_key_raises():
    p = {"type": "T", "data": {"secret": "x"}}
    fc.wrap("k1", p)
    with pytest.raises(InvalidTag):
        fc.unwrap("k2", p)


def test_wrap_with_no_data_key_is_noop():
    """Defensive: a payload without ``data`` (shouldn't happen in practice)
    is left untouched rather than KeyError."""
    p = {"type": "T"}
    fc.wrap("k", p)
    assert p == {"type": "T"}


# ── encryption_enabled kill switch ───────────────────────────────────────────

@pytest.mark.parametrize("val,expected", [
    ("1", True),
    ("", True),      # unset/empty → default ON (the get default is "1")
    ("0", False),
    ("false", False),
    ("no", False),
    ("FALSE", False),
    ("  0  ", False),
    ("yes", True),
])
def test_encryption_enabled_kill_switch(monkeypatch, val, expected):
    monkeypatch.setenv("LM_APP_ENCRYPTION", val)
    assert fc.encryption_enabled() is expected


def test_encryption_enabled_default_on_when_unset(monkeypatch):
    monkeypatch.delenv("LM_APP_ENCRYPTION", raising=False)
    assert fc.encryption_enabled() is True


# ── ENCRYPTED_TYPES contract ─────────────────────────────────────────────────

def test_secret_bearing_types_are_in_set():
    expected = {
        "SPOKE_UPDATE_SESSION_KEY", "INSTALL_CERT", "SPOKE_SET_MTLS_MATERIALS",
        "SPOKE_SET_HUB_SECRET", "NETBOX_APPLY_SSO", "SET_PASSWORD",
        "SET_USER_PASSWORD", "RESET_PASSWORD", "NETBOX_RESET_ADMIN_PASSWORD",
        "CONSOLE_PUSH_CONFIG", "UPDATE_CONFIG", "CS_STORE_PROXMOX_TOKEN",
        "CS_TOKEN_RESULT",
    }
    assert expected.issubset(fc.ENCRYPTED_TYPES)


def test_non_secret_types_are_not_in_set():
    for t in ("HEARTBEAT", "TELEMETRY", "ACK", "RESPONSE", "VOUCH_SUBSPOKE",
              "GET_AVAILABLE_ROLES", "AGENT_RELAY_UP"):
        assert t not in fc.ENCRYPTED_TYPES


def test_encrypted_marker_constant():
    assert fc.ENC_MARKER == "v1"