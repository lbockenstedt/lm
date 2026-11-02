"""Browser-side encryption of the local login password.

TLS already protects the password on the wire, but the browser's developer
tools show the request body in clear text. The login page therefore fetches a
one-time key from ``GET /auth/login/key`` and sends the password RSA-OAEP
(SHA-256) encrypted together with that key's nonce. Each nonce is single use
and expires after ``NONCE_TTL`` seconds, so a payload copied out of devtools
cannot be replayed.

The RSA key pair lives only in process memory and rotates every
``KEY_ROTATE`` seconds; outstanding nonces keep a reference to the key they
were issued with, so a rotation never breaks a login already in flight.
"""
import base64
import json
import secrets
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

NONCE_TTL = 300
KEY_ROTATE = 3600
MAX_PENDING = 2000

_lock = threading.Lock()
_key = None
_key_born = 0.0
_pending = {}  # key_id -> (private_key, nonce, expires_at)


def _current_key(now):
    global _key, _key_born
    if _key is None or now - _key_born > KEY_ROTATE:
        _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _key_born = now
    return _key


def _prune(now):
    for kid in [k for k, v in _pending.items() if v[2] <= now]:
        _pending.pop(kid, None)
    # Unauthenticated callers can mint keys; cap memory by dropping the oldest.
    while len(_pending) >= MAX_PENDING:
        _pending.pop(next(iter(_pending)))


def issue():
    """A fresh one-time key: ``{key_id, nonce, alg, spki, expires_in}``."""
    now = time.time()
    with _lock:
        _prune(now)
        priv = _current_key(now)
        kid = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        _pending[kid] = (priv, nonce, now + NONCE_TTL)
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"key_id": kid, "nonce": nonce, "alg": "RSA-OAEP-256",
            "spki": base64.b64encode(spki).decode(), "expires_in": NONCE_TTL}


def decrypt(key_id, ciphertext_b64):
    """Return the password from an encrypted login, consuming the key.

    Raises ``ValueError`` for an unknown, expired or already-used key, a bad
    ciphertext, or a nonce mismatch."""
    with _lock:
        entry = _pending.pop(str(key_id or ""), None)
    if not entry or entry[2] <= time.time():
        raise ValueError("login key expired or already used")
    priv, nonce, _exp = entry
    try:
        raw = priv.decrypt(
            base64.b64decode(ciphertext_b64 or ""),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        body = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("login payload could not be decrypted") from exc
    if not isinstance(body, dict) or not secrets.compare_digest(str(body.get("n", "")), nonce):
        raise ValueError("login nonce mismatch")
    return str(body.get("p", ""))
