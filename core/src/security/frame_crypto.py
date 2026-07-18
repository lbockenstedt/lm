"""App-layer AEAD encryption of secret-bearing Hub↔spoke frames (H4).

The spoke↔hub wire frame is ``<sig>.<body>`` where the body is compact JSON
HMAC-signed for **integrity** but **never encrypted**. On a plaintext
``ws://`` loopback link (co-located spokes, or an advertise-TLS proxy→hub hop)
a co-located sniffer reads secret fields in cleartext: the session secret in
``SPOKE_UPDATE_SESSION_KEY``, cert private keys, the hub root secret, and
credentials in config pushes. The HMAC protects integrity, not
confidentiality — this module adds confidentiality on top of the existing
HMAC, without touching the signing path.

**Key reuse, don't build new key material:** the AEAD key is derived from the
*same secret that already HMAC-signs the frame* (HKDF-SHA256 → AES-256-GCM,
info ``b"lm-app-layer-enc-v1"``, 32 bytes). Both sides always have it — no new
key exchange, no new crypto lifecycle. ``cryptography>=42`` is already a dep;
``AESGCM``/``HKDF`` are simply unused until now (``Fernet``/``PBKDF2HMAC`` were
the only imported primitives).

**Wire form when encrypted:**
``payload = {"type": <type>, "data": "<base64(nonce||ct||tag)>", "enc": "v1"}``
Non-``data`` payload keys (e.g. ``correlation_id`` on reply frames) are
preserved. The receiver: if ``payload["enc"] == "v1"`` → ``data`` is a b64
string → decrypt → restore ``data`` to the plaintext dict, drop ``enc``. The
marker's presence/absence drives behavior — no per-type branching on the
receive side. ``wrap``/``unwrap`` are in-place and idempotent on the payload
dict so callers can operate on the live frame object.

**Fail-safe + no fleet break:** the ``enc:"v1"`` marker is purely additive;
every version combo degrades to today's plaintext (mixed → plaintext, legacy
unchanged). ``LM_APP_ENCRYPTION=0`` makes a new hub/spoke behave as legacy
(don't advertise, don't encrypt) — operator rollback without redeploy. This
module is intentionally stateless — it holds no secrets; the secret is
supplied per call by the hub (:mod:`security.key_manager`) or the spoke
(``self.secret``).
"""

import os
import base64
import logging
from typing import Any, Dict, FrozenSet, Optional

logger = logging.getLogger("FrameCrypto")

# cryptography is a core dep, but a spoke venv that hasn't installed it yet
# (older install / core-req drift) must NOT crash-loop on import — this module
# is fail-safe by design (every version combo degrades to plaintext). When the
# lib is absent we disable app-layer encryption: the spoke doesn't advertise
# the capability, so the hub degrades to plaintext for it (mixed → plaintext).
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only on a dep-short venv
    _CRYPTO_AVAILABLE = False

    class InvalidTag(Exception):  # fallback so callers can still `except InvalidTag`
        pass

    logger.warning(
        "cryptography not installed — app-layer frame encryption DISABLED "
        "(plaintext, HMAC-signed as before). Install 'cryptography>=42' to enable."
    )

#: Env var that toggles app-layer encryption. Default ON (``"1"``); set to
#: ``0``/``false``/``no`` to make a new hub/spoke behave as legacy (don't
#: advertise, don't encrypt) — operator rollback without redeploy.
_ENV_VAR = "LM_APP_ENCRYPTION"

#: HKDF ``info`` label — domain-separates this key from any other use of the
#: same signing secret (the HMAC key is the *raw* secret; the AEAD key is the
#: HKDF-derived one, so a compromise of one primitive's output doesn't bleed
#: into the other's key).
_INFO = b"lm-app-layer-enc-v1"
_KEY_LEN = 32  # AES-256
_NONCE_LEN = 12  # AES-GCM standard

#: Frame types whose ``payload.data`` carries a secret worth hiding. The
#: gate is ``type in ENCRYPTED_TYPES and peer-capable and key-available and
#: enabled`` — non-secret frames (heartbeats, telemetry, commands, replies)
#: hit only a cheap type-check and stay unchanged on the wire.
ENCRYPTED_TYPES: FrozenSet[str] = frozenset({
    "SPOKE_UPDATE_SESSION_KEY",
    "INSTALL_CERT",
    "SPOKE_SET_MTLS_MATERIALS",
    "SPOKE_SET_HUB_SECRET",
    "NETBOX_APPLY_SSO",
    "SET_PASSWORD",
    "SET_USER_PASSWORD",
    "RESET_PASSWORD",
    "NETBOX_RESET_ADMIN_PASSWORD",
    "CONSOLE_PUSH_CONFIG",
    "UPDATE_CONFIG",
    "CS_STORE_PROXMOX_TOKEN",
    "CS_TOKEN_RESULT",
})

#: The marker value placed in ``payload["enc"]`` to signal an encrypted
#: ``data`` field. Receivers check equality with this constant.
ENC_MARKER = "v1"


def encryption_enabled() -> bool:
    """Whether app-layer frame encryption is active. Default ON (``"1"``);
    ``0``/``false``/``no`` (case-insensitive, whitespace-trimmed) → off. Always
    off when the ``cryptography`` lib is unavailable (fail-safe → plaintext)."""
    if not _CRYPTO_AVAILABLE:
        return False
    return os.environ.get(_ENV_VAR, "1").strip().lower() not in ("0", "false", "no")


def derive_aead_key(secret: str) -> bytes:
    """Derive the 32-byte AES-256-GCM key from ``secret`` via HKDF-SHA256.

    Deterministic: the same secret always yields the same key (so both sides,
    holding the same signing secret, derive the same AEAD key). Distinct
    secrets yield distinct keys (HKDF is a PRF). The signing secret is used
    DIRECTLY as the HKDF input — it already has ~32 bytes of entropy
    (``secrets.token_urlsafe(32)``) so a salt is unnecessary; the ``info``
    label alone domain-separates this key from the raw HMAC key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=None,
        info=_INFO,
    )
    return hkdf.derive(secret.encode())


def encrypt_payload_data(secret: str, data: Any) -> str:
    """Encrypt ``data`` (JSON-serializable) → ``base64(nonce||ct||tag)`` str.

    AES-256-GCM with a fresh 12-byte random nonce per call (AEAD nonce reuse
    under the same key is catastrophic, so the nonce is NEVER derived/reused —
    a fresh ``os.urandom`` draw per frame). The nonce is prepended to the
    ciphertext for the receiver. Returns a base64 str so the encrypted
    ``data`` stays JSON-encodable in the wire payload (``json.dumps`` of the
    outer body handles it like any other string field).
    """
    import json  # local: keeps the module importable without json at top cost
    key = derive_aead_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_LEN)
    plaintext = json.dumps(data, separators=(',', ':')).encode()
    ct = aesgcm.encrypt(nonce, plaintext, None)  # ct || tag
    return base64.b64encode(nonce + ct).decode()


def decrypt_payload_data(secret: str, b64: str) -> Any:
    """Inverse of :func:`encrypt_payload_data`. Raises :class:`InvalidTag` on
    tamper or wrong key (caller logs + drops the frame)."""
    import json
    key = derive_aead_key(secret)
    aesgcm = AESGCM(key)
    raw = base64.b64decode(b64)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return json.loads(plaintext)


def is_encrypted(payload: Dict[str, Any]) -> bool:
    """Whether ``payload``'s ``data`` is an encrypted b64 blob (marker
    present). The single receive-side gate — no per-type branching."""
    return isinstance(payload, dict) and payload.get("enc") == ENC_MARKER


def wrap(secret: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt ``payload["data"]`` in place, marking it ``enc="v1"``.

    Idempotent: a payload already marked encrypted is returned untouched
    (defends against a double-encrypt if a caller re-enters the outbound path,
    e.g. a redelivery). Non-``data`` keys (e.g. ``correlation_id`` on reply
    frames, ``type``) are preserved. Returns ``payload`` for chaining."""
    if not isinstance(payload, dict):
        return payload
    if not _CRYPTO_AVAILABLE:
        return payload  # no crypto lib → never encrypt (fail-safe plaintext)
    if payload.get("enc") == ENC_MARKER:
        return payload  # already wrapped — idempotent
    if "data" not in payload:
        return payload  # nothing to encrypt (defensive)
    payload["data"] = encrypt_payload_data(secret, payload["data"])
    payload["enc"] = ENC_MARKER
    return payload


def unwrap(secret: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypt ``payload["data"]`` in place, dropping the ``enc`` marker.

    Raises :class:`InvalidTag` on tamper or wrong key — the caller catches it
    and drops the frame (a frame that won't AEAD-decrypt under the key that
    HMAC-verified it is a corrupted or hostile frame; never dispatch it).
    Does nothing (and never raises) on an unmarked payload — symmetric with
    :func:`wrap`'s idempotence and the legacy/plaintext path."""
    if not isinstance(payload, dict):
        return payload
    if payload.get("enc") != ENC_MARKER:
        return payload  # plaintext — pass through (legacy / non-secret path)
    if not _CRYPTO_AVAILABLE:
        # An encrypted frame arrived but we can't decrypt (shouldn't happen — we
        # don't advertise the capability without crypto). Drop it, don't dispatch.
        raise InvalidTag("cryptography unavailable — cannot decrypt frame")
    payload["data"] = decrypt_payload_data(secret, payload["data"])
    del payload["enc"]
    return payload