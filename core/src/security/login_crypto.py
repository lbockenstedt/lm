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
# base64 turns the binary public key and ciphertext into browser-friendly text.
import base64
# json parses the decrypted {"p": password, "n": nonce} payload.
import json
# secrets makes unguessable key ids/nonces and does constant-time comparisons.
import secrets
# A lock keeps the shared key/nonce state consistent across request threads.
import threading
# time.time() drives nonce expiry and key rotation.
import time

# cryptography primitives: RSA key generation, OAEP padding, SHA-256 and key export.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# A login key must be used within 5 minutes of being handed to the browser.
NONCE_TTL = 300
# Generate a new RSA key pair every hour to limit how long any one key is in use.
KEY_ROTATE = 3600
# Upper bound on outstanding one-time keys so anonymous callers cannot exhaust memory.
MAX_PENDING = 2000

# Guards every read/write of the module-level state below.
_lock = threading.Lock()
# The current RSA private key and the time it was generated (0 = never).
_key = None
_key_born = 0.0
# Outstanding one-time keys waiting to be used by a login submission.
_pending = {}  # key_id -> (private_key, nonce, expires_at)


def _current_key(now):
    """Return the active RSA private key, generating a new one if missing or too old."""
    # The key and its birth time are module-level state shared by all requests.
    global _key, _key_born
    # Rotate when there is no key yet or the current one has outlived KEY_ROTATE.
    if _key is None or now - _key_born > KEY_ROTATE:
        # 2048-bit RSA with the standard public exponent is what WebCrypto RSA-OAEP expects.
        _key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _key_born = now
    return _key


def _prune(now):
    """Remove expired one-time keys and enforce the MAX_PENDING memory cap."""
    # Drop every entry whose expiry time has passed (list() first: we mutate while looping).
    for kid in [k for k, v in _pending.items() if v[2] <= now]:
        _pending.pop(kid, None)
    # Unauthenticated callers can mint keys; cap memory by dropping the oldest.
    # Dicts keep insertion order, so the first key is the oldest one.
    while len(_pending) >= MAX_PENDING:
        _pending.pop(next(iter(_pending)))


def issue():
    """A fresh one-time key: ``{key_id, nonce, alg, spki, expires_in}``."""
    # Read the clock once so every value below uses the same "now".
    now = time.time()
    # Hold the lock while touching the shared key/pending state.
    with _lock:
        # Clean out stale entries before adding a new one.
        _prune(now)
        # Get (or rotate) the RSA key and mint a random key id and nonce for this login.
        priv = _current_key(now)
        kid = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        # Remember which key and nonce this id refers to, and when it stops being valid.
        _pending[kid] = (priv, nonce, now + NONCE_TTL)
    # Export the public key as DER SubjectPublicKeyInfo, the format WebCrypto importKey uses.
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    # Everything the login page needs to encrypt the password for this one attempt.
    return {"key_id": kid, "nonce": nonce, "alg": "RSA-OAEP-256",
            "spki": base64.b64encode(spki).decode(), "expires_in": NONCE_TTL}


def decrypt(key_id, ciphertext_b64):
    """Return the password from an encrypted login, consuming the key.

    Raises ``ValueError`` for an unknown, expired or already-used key, a bad
    ciphertext, or a nonce mismatch."""
    # pop() makes the key single-use: once looked up it can never be used again.
    with _lock:
        entry = _pending.pop(str(key_id or ""), None)
    # Unknown, already-used or expired key ids are rejected.
    if not entry or entry[2] <= time.time():
        raise ValueError("login key expired or already used")
    # Unpack the stored private key and the nonce it was issued with.
    priv, nonce, _exp = entry
    # Base64-decode and RSA-OAEP(SHA-256) decrypt, then parse the JSON body. Any failure
    # (bad base64, wrong key, bad padding, bad JSON) becomes one generic ValueError.
    try:
        raw = priv.decrypt(
            base64.b64decode(ciphertext_b64 or ""),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        body = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("login payload could not be decrypted") from exc
    # The payload must echo the nonce issued with this key (constant-time compare) to
    # prove it was produced for this login attempt and is not a replay.
    if not isinstance(body, dict) or not secrets.compare_digest(str(body.get("n", "")), nonce):
        raise ValueError("login nonce mismatch")
    # The decrypted password.
    return str(body.get("p", ""))
