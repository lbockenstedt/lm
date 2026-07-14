"""Azure Entra ID (OIDC) login provider for the LM hub.

Authorization-Code flow with PKCE for a **confidential client** that
authenticates to Entra with a **certificate** (a JWT ``client_assertion``
signed RS256 by the cert's private key — no client secret). The id-token is
verified against the Entra JWKS, MFA is **hard-enforced** via the ``amr``
claim, and the user's Entra group memberships drive BOTH RBAC permissions AND
tenant scope (``access.groups_and_tenants_for_membership``).

Design notes
------------
* Hand-rolled with ``httpx`` + ``pyjwt`` (matches the existing Aruba Central
  OAuth client in ``simulations/aruba.py``; no ``msal`` dependency).
* OIDC discovery (``/.well-known/openid-configuration``) is fetched + cached
  so JWKS key rotation is automatic.
* The HTTP-touching entry points (``discover``, ``exchange_code``,
  ``fetch_jwks``) accept an optional ``httpx.AsyncClient`` so tests inject a
  ``MockTransport``; production uses a short-lived client.
* ``verify_id_token`` accepts the JWKS keys directly (or fetches them) so the
  MFA / nonce / claim extraction logic is unit-testable without a network.

This module is stateless except for the discovery-cache; it holds no secrets.
The client private key is read from ``key_path`` — never stored in
``global_config`` — and resolved through ``security.credential_store`` so it
may be a filesystem path OR a Key Vault reference (``kv:<secret-name>``).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from urllib.parse import quote as _url_quote

import httpx
import jwt
from cryptography.hazmat.primitives import serialization

from access import groups_and_tenants_for_membership, resolve_effective_permissions

logger = logging.getLogger("Hub")

# ── config ──────────────────────────────────────────────────────────────────

_DEFAULT_SCOPE = "openid profile email offline_access"
_STATE_TTL_S = 300  # the OIDC round-trip must complete within 5 minutes

# Default on-host location for the Entra client cert + key — used when the admin
# hasn't set a path (auto-detect) and as the target of "Generate certificate"
# (auto-create). It MUST be writable by the hub's service user, which does NOT
# own /etc/lm, so the default is derived from the hub's own (write-tested) state
# data_dir — see ``default_oidc_dir``. LM_OIDC_DIR overrides everything. The
# module-level ``_OIDC_DIR`` is only the no-hub fallback (tests / bare imports).
_OIDC_DIR = (os.environ.get("LM_OIDC_DIR") or "/var/lib/lm/oidc").strip() or "/var/lib/lm/oidc"


def default_oidc_dir(hub=None) -> str:
    """Resolve the writable directory for the OIDC cert/key.

    Precedence: ``LM_OIDC_DIR`` env → ``<hub state data_dir>/oidc`` (guaranteed
    writable — the state manager write-tests it with a home-dir fallback) →
    ``_OIDC_DIR``. Deriving from ``data_dir`` is what keeps "Generate certificate"
    from hitting EACCES on ``/etc/lm`` for a non-root hub."""
    env = (os.environ.get("LM_OIDC_DIR") or "").strip()
    if env:
        return env
    try:
        dd = getattr(getattr(hub, "state", None), "data_dir", "") or ""
        if dd:
            return os.path.join(dd, "oidc")
    except Exception:  # noqa: BLE001
        pass
    return _OIDC_DIR


class OidcError(Exception):
    """Raised for any OIDC-flow failure the callback should surface as 401/400.

    The message is safe to return to the browser (no secret material); the
    hub log gets the full context via ``logger.exception`` at the call site."""


class OidcConfig:
    """Resolved OIDC configuration (``global_config["oidc"]`` + env overrides).

    Env overrides (``LM_OIDC_*``) win over stored config so an operator can
    re-point the hub at a different tenant without the WebUI. ``enabled``
    requires ``tenant_id`` + ``client_id`` + ``key_path`` to be truthy."""

    def __init__(self, stored: dict | None = None, default_dir: str | None = None):
        stored = stored or {}
        env = os.environ
        _dir = (default_dir or _OIDC_DIR)
        _def_key = os.path.join(_dir, "client-key.pem")
        _def_cert = os.path.join(_dir, "client-cert.pem")
        self.tenant_id = (env.get("LM_OIDC_TENANT_ID") or stored.get("tenant_id") or "").strip()
        self.client_id = (env.get("LM_OIDC_CLIENT_ID") or stored.get("client_id") or "").strip()
        self.redirect_uri = (env.get("LM_OIDC_REDIRECT_URI") or stored.get("redirect_uri") or "").strip()
        # Paths default to the conventional /etc/lm/oidc location so an admin who
        # runs "Generate certificate" (or drops the files there) never has to type
        # a path — auto-detected. An explicit env/stored value still wins.
        self.cert_path = (env.get("LM_OIDC_CLIENT_CERT") or stored.get("cert_path")
                          or "").strip() or _def_cert
        self.key_path = (env.get("LM_OIDC_CLIENT_KEY") or stored.get("key_path")
                         or "").strip() or _def_key
        self.allowed_group = (env.get("LM_OIDC_ALLOWED_GROUP") or stored.get("allowed_group") or "").strip()
        self.require_mfa = _bool_env(env.get("LM_OIDC_REQUIRE_MFA"),
                                     stored.get("require_mfa", True))
        self.enabled = _bool_env(env.get("LM_OIDC_ENABLED"), stored.get("enabled", False))

    @property
    def ready(self) -> bool:
        """True when enough is configured to attempt a login (Entra-side cert
        upload + redirect URI are also required, but we can't see those here)."""
        return bool(self.tenant_id and self.client_id and self.key_path)

    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    def discovery_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid-configuration"


def _bool_env(val, default: bool) -> bool:
    if val is None:
        return bool(default)
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def get_oidc_config(hub) -> OidcConfig:
    """Read the stored OIDC config from ``global_config`` (admin-set via
    ``/setup/oidc-config``) and build an :class:`OidcConfig`."""
    stored = {}
    try:
        stored = hub.state.system_state.get("global_config", {}).get("oidc", {}) or {}
    except Exception:  # noqa: BLE001 — hub without state (tests)
        stored = {}
    return OidcConfig(stored, default_dir=default_oidc_dir(hub))


# ── PKCE + state cookie ─────────────────────────────────────────────────────

def _state_secret(hub) -> bytes:
    """HMAC key for the OIDC state cookie. Prefers a dedicated env, then the
    hub's current root secret (rotates with it; the state cookie is consumed
    within _STATE_TTL_S so a mid-round-trip rotation is covered by verifying
    against the full hub_secrets list), then the Fernet key, then a constant
    (only when nothing else is configured — logged as a weakness)."""
    sec = os.environ.get("LM_OIDC_STATE_SECRET", "").strip()
    if sec:
        return sec.encode()
    try:
        secrets_list = hub.key_manager.hub_secrets
        if secrets_list:
            return secrets_list[0].encode()
    except Exception:  # noqa: BLE001
        pass
    fk = os.environ.get("LM_FERNET_KEY", "").strip()
    if fk:
        return fk.encode()
    logger.warning("OIDC state cookie has no dedicated secret — using weak fallback")
    return b"lm-oidc-state-weak-fallback"


def sign_state_cookie(hub, state: str, nonce: str, code_verifier: str) -> str:
    """Build the ``lm_oidc_state`` cookie value: ``state:nonce:verifier:ts`` +
    HMAC. Verified by :func:`verify_state_cookie`."""
    ts = int(time.time())
    payload = f"{state}:{nonce}:{code_verifier}:{ts}"
    sig = hmac.new(_state_secret(hub), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_state_cookie(hub, cookie: str) -> tuple | None:
    """Return ``(state, nonce, code_verifier)`` if the cookie's HMAC is valid
    and fresh (within ``_STATE_TTL_S``); else ``None``. Accepts any key in the
    hub_secrets history so a rotation mid-round-trip doesn't drop the login."""
    if not cookie or "." not in cookie:
        return None
    payload, _, sig = cookie.rpartition(".")
    expected_off = payload.rfind(":")  # ts is the last colon-separated field
    if expected_off < 0:
        return None
    keys = []
    try:
        keys = [s.encode() for s in hub.key_manager.hub_secrets]
    except Exception:  # noqa: BLE001
        pass
    env_sec = os.environ.get("LM_OIDC_STATE_SECRET", "").strip()
    if env_sec:
        keys.append(env_sec.encode())
    fk = os.environ.get("LM_FERNET_KEY", "").strip()
    if fk:
        keys.append(fk.encode())
    if not keys:
        keys.append(b"lm-oidc-state-weak-fallback")
    for k in keys:
        if hmac.new(k, payload.encode(), hashlib.sha256).hexdigest() == sig:
            parts = payload.split(":")
            if len(parts) != 4:
                return None
            state, nonce, verifier, ts_s = parts
            try:
                ts = int(ts_s)
            except ValueError:
                return None
            if abs(time.time() - ts) > _STATE_TTL_S:
                return None
            return state, nonce, verifier
    return None


# ── discovery + authorize URL ───────────────────────────────────────────────

_discovery_cache: dict = {}  # tenant_id -> (fetched_at, doc)


async def discover(cfg: OidcConfig, http: httpx.AsyncClient | None = None) -> dict:
    """Fetch + cache the OIDC discovery doc for ``cfg.tenant_id`` (5 min TTL
    so JWKS rotation is picked up without a hub restart). Returns the doc with
    at least ``authorization_endpoint`` / ``token_endpoint`` / ``jwks_uri`` /
    ``issuer``."""
    now = time.time()
    cached = _discovery_cache.get(cfg.tenant_id)
    if cached and now - cached[0] < 300:
        return cached[1]
    async with (http or httpx.AsyncClient(timeout=15.0)) as client:
        resp = await client.get(cfg.discovery_url())
        resp.raise_for_status()
        doc = resp.json()
    _discovery_cache[cfg.tenant_id] = (now, doc)
    return doc


def authorize_url(cfg: OidcConfig, discovery_doc: dict,
                  state: str, nonce: str, code_challenge: str) -> str:
    """Build the Entra authorize URL (Authorization Code + PKCE)."""
    endpoint = discovery_doc.get("authorization_endpoint") or \
        f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/authorize"
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": _DEFAULT_SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return endpoint + "?" + "&".join(f"{k}={_url_quote(str(v), safe='')}"
                                     for k, v in params.items())


# ── client assertion (cert-based confidential client) ───────────────────────

def cert_thumbprint_x5t(cert_pem: bytes) -> str:
    """``x5t`` header value Entra requires: base64url( SHA-1( DER(cert) ) ).

    Entra maps a ``client_assertion`` to the uploaded certificate by this
    thumbprint; omit it and Entra rejects the assertion (AADSTS700027)."""
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha1(der).digest()).rstrip(b"=").decode()


def _write_file(path: str, data: bytes, mode: int) -> None:
    """Write ``data`` to ``path`` with ``mode`` perms, creating parent dirs."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def generate_client_cert(key_path: str | None = None, cert_path: str | None = None,
                         subject: str = "lm-hub-oidc", days: int = 730,
                         force: bool = False) -> dict:
    """Auto-create the Entra client cert: a fresh RSA-2048 keypair + self-signed
    certificate written to ``key_path`` (unencrypted PEM, 0600) and ``cert_path``
    (public PEM, 0644). Returns ``{key_path, cert_path, cert_pem, thumbprint}`` —
    the caller uploads ``cert_pem`` to the Entra app registration (Certificates &
    secrets → Certificates). Refuses to clobber an existing key unless ``force``
    (so a live credential isn't silently replaced)."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
    key_path = key_path or os.path.join(_OIDC_DIR, "client-key.pem")
    cert_path = cert_path or os.path.join(_OIDC_DIR, "client-cert.pem")
    if os.path.exists(key_path) and not force:
        raise OidcError(f"a private key already exists at {key_path}; "
                        f"pass force=true to overwrite it")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=days))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    _write_file(key_path, key_pem, 0o600)
    _write_file(cert_path, cert_pem, 0o644)
    logger.info("generated OIDC client cert: key=%s cert=%s (valid %dd)",
                key_path, cert_path, days)
    return {"key_path": key_path, "cert_path": cert_path,
            "cert_pem": cert_pem.decode(), "thumbprint": cert_thumbprint_x5t(cert_pem)}


def _load_private_key(key_path: str):
    """Load the PEM-encoded RSA/EC private key used to sign the client
    assertion. Accepts an unencrypted PEM (the key file's perms / Key Vault
    ACL are the secret boundary, per the cert-auth model).

    ``key_path`` may be a filesystem path (historical behaviour) OR a
    ``kv:<secret-name>`` reference / bare secret name resolved through the
    credential store (so the private key can live in Azure Key Vault). See
    ``security.credential_store.resolve_private_key_material``."""
    from .credential_store import resolve_private_key_material
    pem = resolve_private_key_material(key_path)
    if pem is None:
        raise OidcError("could not load OIDC client private key from %r" % key_path)
    return serialization.load_pem_private_key(pem, password=None)


def build_client_assertion(cfg: OidcConfig, token_endpoint: str) -> str:
    """Build a RS256 JWT ``client_assertion`` signed by the cert's private key.

    Entra accepts this in place of a client secret for a confidential client
    (``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer``).
    The JWT's ``aud`` is the token endpoint URI; ``iss==sub==client_id``."""
    import secrets as _s
    key = _load_private_key(cfg.key_path)
    now = int(time.time())
    payload = {
        "iss": cfg.client_id,
        "sub": cfg.client_id,
        "aud": token_endpoint,
        "jti": _s.token_urlsafe(16),
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }
    # Entra REQUIRES the cert thumbprint in the JWT header (``x5t``) so it can map
    # this assertion to the uploaded certificate — without it the token request is
    # rejected (AADSTS700027). Load the public cert (path or Key Vault ref) to
    # compute it. Fail loudly if we can't: a silently-omitted x5t is a confusing
    # server-side reject.
    from .credential_store import resolve_private_key_material
    cert_pem = resolve_private_key_material(cfg.cert_path) if cfg.cert_path else None
    if not cert_pem:
        raise OidcError("could not load OIDC client certificate from %r "
                        "(needed for the Entra x5t header)" % cfg.cert_path)
    headers = {"x5t": cert_thumbprint_x5t(cert_pem)}
    # PyJWT picks RS256 from a cryptography RSA/EC private key automatically.
    return jwt.encode(payload, key, algorithm="RS256", headers=headers)


# ── code exchange ───────────────────────────────────────────────────────────

async def exchange_code(cfg: OidcConfig, discovery_doc: dict,
                        code: str, code_verifier: str,
                        http: httpx.AsyncClient | None = None) -> dict:
    """Exchange an authorization code for tokens. Authenticates the hub to Entra
    with the cert-signed ``client_assertion`` (no client secret). Returns the
    token response JSON (``id_token`` + ``access_token`` + ``expires_in``)."""
    token_endpoint = discovery_doc.get("token_endpoint") or \
        f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token"
    assertion = build_client_assertion(cfg, token_endpoint)
    data = {
        "grant_type": "authorization_code",
        "client_id": cfg.client_id,
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": code_verifier,
        "scope": _DEFAULT_SCOPE,
        "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    async with (http or httpx.AsyncClient(timeout=15.0)) as client:
        resp = await client.post(token_endpoint, data=data)
    if resp.status_code != 200:
        raise OidcError(f"token exchange failed: HTTP {resp.status_code}"
                        f"{_entra_error_detail(resp)}")
    return resp.json()


def _entra_error_detail(resp) -> str:
    """Extract Entra's ``error`` / ``error_description`` (the AADSTS code) from a
    failed token response so the callback surfaces WHY instead of a bare status.
    The AADSTS text is Entra's own diagnostic (no secret material) — safe to show.
    Returns ``" — <detail>"`` or ``""``."""
    try:
        j = resp.json()
        detail = j.get("error_description") or j.get("error") or ""
        # AADSTS descriptions are multi-line (code, then a stack); keep line 1.
        detail = str(detail).replace("\r", "\n").split("\n")[0].strip()[:300]
        return f" — {detail}" if detail else ""
    except Exception:  # noqa: BLE001
        txt = (getattr(resp, "text", "") or "")[:200].strip()
        return f" — {txt}" if txt else ""


# ── id-token verification + MFA enforcement ─────────────────────────────────

async def fetch_jwks(jwks_uri: str, http: httpx.AsyncClient | None = None) -> list:
    """Fetch the JWKS keys (cached implicitly by the caller via discovery)."""
    async with (http or httpx.AsyncClient(timeout=15.0)) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        return resp.json().get("keys", [])


def _jwk_to_key(jwk: dict):
    """Convert a JWK (RSA) to a cryptography key object for PyJWT verify."""
    from cryptography.hazmat.primitives.asymmetric import ec
    kty = jwk.get("kty")
    if kty == "RSA":
        return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    if kty == "EC":
        return jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
    raise OidcError(f"unsupported JWKS kty: {kty!r}")


def verify_id_token(cfg: OidcConfig, id_token: str, nonce: str,
                    jwks_keys: list) -> dict:
    """Verify an Entra id-token and enforce MFA. Returns the decoded claims.

    Validates the signature against the JWKS, the issuer (Entra v2.0 endpoint
    for the configured tenant), the audience (this app's ``client_id``), and
    the ``nonce`` (binds the token to this browser round-trip — replay to a
    different session fails). **MFA is hard-enforced**: when ``require_mfa``
    is set (default), the ``amr`` claim MUST contain ``mfa`` or login is
    refused — Entra conditional access enforces it at the IdP, but the hub does
    not trust the network path to have done so."""
    try:
        unverified_header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as e:
        raise OidcError(f"malformed id_token: {e}") from e
    kid = unverified_header.get("kid")
    keys = [_jwk_to_key(k) for k in jwks_keys if k.get("kid") == kid] or \
           [_jwk_to_key(k) for k in jwks_keys]
    if not keys:
        raise OidcError("no matching JWKS key for id_token kid")
    last_err: Exception | None = None
    claims = None
    for key in keys:
        try:
            claims = jwt.decode(
                id_token, key=key, algorithms=["RS256"],
                audience=cfg.client_id, issuer=cfg.issuer(),
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
            break
        except jwt.PyJWTError as e:
            last_err = e
    if claims is None:
        raise OidcError(f"id_token verification failed: {last_err}")
    # Nonce binds the token to this round-trip.
    if claims.get("nonce") != nonce:
        raise OidcError("nonce mismatch — id_token replay suspected")
    # MFA hard-enforcement. Entra reports the auth methods in ``amr`` (e.g.
    # ["pwd","mfa"]). "mfa" is the classic value, but phishing-resistant /
    # passwordless factors — which ARE multi-factor — surface under different
    # amr values: "ngcmfa" (Windows Hello / passkey), "fido" (FIDO2 key), "otp"
    # (TOTP / one-time passcode). Accept any of those so a stronger sign-in isn't
    # rejected as "no MFA". "pwd" alone never counts.
    if cfg.require_mfa:
        amr = claims.get("amr") or []
        if not isinstance(amr, list):
            amr = [amr]
        amr_l = {str(a).strip().lower() for a in amr}
        if not (amr_l & _MFA_AMR_VALUES):
            raise OidcError(
                "MFA required — this sign-in did not perform multi-factor "
                f"authentication (amr={sorted(amr_l) or '[]'}). Having MFA on the "
                "account isn't enough; a Conditional Access policy (or security "
                "defaults) must FORCE MFA for this app so Entra actually challenges "
                "it. Check the Entra sign-in log's 'Authentication requirement', or "
                "turn off 'Require MFA' in Setup → SSO if you rely on Entra to "
                "enforce it.")
    return claims


# amr values that indicate a genuine second / phishing-resistant factor was used:
# "mfa" (classic multi-factor), "ngcmfa" (Windows Hello / passkey), "fido" (FIDO2
# key), "otp" (one-time passcode). "pwd"/"wia" (password / Kerberos) are
# single-factor and deliberately EXCLUDED so they never satisfy the requirement.
_MFA_AMR_VALUES = {"mfa", "ngcmfa", "fido", "otp"}


def extract_member_groups(claims: dict) -> list:
    """The Entra ``groups`` claim (group object IDs). Entra OMITS ``groups``
    when the user is in >200 groups (the overflow case) and emits a
    ``_claim_names``/``_claim_sources`` pointer to a Graph endpoint instead.
    The lab is small so ``groups`` is present; the Graph fallback is a
    real-but-edge path handled by :func:`fetch_member_groups_via_graph`."""
    g = claims.get("groups")
    if isinstance(g, list):
        return [str(x) for x in g]
    return []


async def fetch_member_groups_via_graph(access_token: str,
                                        http: httpx.AsyncClient | None = None) -> list:
    """Fall back to Microsoft Graph ``/me/transitiveMemberOf`` when the
    ``groups`` claim overflows (>200 groups). Returns group object IDs."""
    async with (http or httpx.AsyncClient(timeout=15.0)) as client:
        resp = await client.get(
            "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$select=id",
            headers={"Authorization": f"Bearer {access_token}"})
        if resp.status_code != 200:
            raise OidcError(f"Graph groups fetch failed: HTTP {resp.status_code}")
        return [v["id"] for v in resp.json().get("value", []) if "id" in v]


async def fetch_app_token(cfg: OidcConfig, scope: str,
                          http: httpx.AsyncClient | None = None) -> str:
    """Mint an app-only (client-credentials) token for the HUB'S OWN APP, signed
    with the cert ``client_assertion`` — for ANY resource the app has rights to.
    ``scope`` is the resource's ``.default`` scope, e.g.
    ``https://graph.microsoft.com/.default`` (directory reads) or
    ``https://management.azure.com/.default`` (Azure Resource Manager / NSG).
    The app registration must hold the matching permission/RBAC role."""
    token_endpoint = f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": cfg.client_id,
        "scope": scope,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": build_client_assertion(cfg, token_endpoint),
    }
    async with (http or httpx.AsyncClient(timeout=15.0)) as client:
        resp = await client.post(token_endpoint, data=data)
    if resp.status_code != 200:
        raise OidcError(f"app-token failed ({scope}): HTTP {resp.status_code} — "
                        f"{resp.text[:200]}")
    tok = resp.json().get("access_token")
    if not tok:
        raise OidcError("app-token response had no access_token")
    return tok


async def fetch_app_graph_token(cfg: OidcConfig,
                                http: httpx.AsyncClient | None = None) -> str:
    """Microsoft Graph app-only token (see :func:`fetch_app_token`). Requires the
    app to hold a Graph **application** permission (e.g. ``Group.Read.All``)."""
    return await fetch_app_token(cfg, "https://graph.microsoft.com/.default", http=http)


async def fetch_directory_groups(cfg: OidcConfig,
                                 http: httpx.AsyncClient | None = None,
                                 limit: int = 2000) -> list:
    """List the tenant's Entra groups as ``[{id, displayName}]`` for the admin
    group→tenant mapping picker. Uses an app token (see
    :func:`fetch_app_graph_token`) and pages through ``@odata.nextLink`` up to
    ``limit``. Object IDs here are exactly what a permission group's
    ``ldap_group`` field matches at login."""
    token = await fetch_app_graph_token(cfg, http=http)
    out: list = []
    url = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName&$top=999"
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        while url:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                raise OidcError(f"Graph groups list failed: HTTP {resp.status_code} — "
                                f"{resp.text[:200]}")
            body = resp.json()
            for v in body.get("value", []):
                gid = v.get("id")
                if gid:
                    out.append({"id": gid, "displayName": v.get("displayName") or gid})
                    if len(out) >= limit:
                        return out
            url = body.get("@odata.nextLink")
    return out


async def fetch_user_groups_via_app(cfg: OidcConfig, oid: str,
                                    http: httpx.AsyncClient | None = None) -> list:
    """A user's transitive group object IDs via the hub's APP token
    (``Group.Read.All``/``GroupMember.Read.All`` application permission).

    This is the reliable membership source when the id_token carries NO ``groups``
    claim — which is Entra's DEFAULT until an admin adds the groups claim in the
    app's Token Configuration. Unlike ``/me/transitiveMemberOf`` it doesn't depend
    on the user's token holding a group scope. Pages ``@odata.nextLink``."""
    token = await fetch_app_graph_token(cfg, http=http)
    out: list = []
    url = (f"https://graph.microsoft.com/v1.0/users/{oid}"
           f"/transitiveMemberOf/microsoft.graph.group?$select=id&$top=999")
    async with (http or httpx.AsyncClient(timeout=15.0)) as client:
        while url:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                raise OidcError(f"Graph user-groups fetch failed: HTTP {resp.status_code} — "
                                f"{resp.text[:200]}")
            body = resp.json()
            out.extend(str(v["id"]) for v in body.get("value", []) if v.get("id"))
            url = body.get("@odata.nextLink")
    return out


# ── user provisioning + re-sync ─────────────────────────────────────────────

def provision_or_sync_entra_user(hub, oid: str, email: str, name: str,
                                 member_of: list, allowed_group: str = "") -> dict:
    """Auto-provision (first Entra login) or re-sync (every login) the LM user
    record from Entra group membership.

    * ``user_id`` is the Entra ``oid`` (stable; the email can change). Stored
      on the record alongside ``email``/``name`` for display.
    * ``groups``+``tenants`` are re-derived from the directory membership each
      login via :func:`access.groups_and_tenants_for_membership` — the source
      of truth for an Entra-provisioned user.
    * When the derived set changed since last login, the record is updated +
      persisted + the user's live sessions invalidated (so a dropped group /
      tenant takes effect immediately, not at the 8h session TTL).
    * ``allowed_group`` (if set) restricts who may log in: a user not a member
      is refused (:class:`OidcError`) before any record is written.

    Returns the (possibly updated) user record. Never touches the protected
    admin (``ensure_admin_lockout`` keeps it tenantless/local; an Entra user
    can't collide with it because the admin's id is a chosen username, not an
    Entra ``oid``)."""
    # allowed_group gate — refuse before provisioning.
    if allowed_group and allowed_group not in (member_of or []):
        raise OidcError("Entra user is not a member of the allowed group")

    group_ids, tenant_ids = groups_and_tenants_for_membership(hub, member_of)
    users = hub.state.system_state.setdefault("users", {})
    now = time.time()
    existing = users.get(oid)
    if existing is None:
        # Auto-provision: no password_hash (Entra users can't local-login),
        # no per-user perms (groups drive RBAC), not protected.
        record = {
            "auth_type": "entra",
            "groups": group_ids,
            "tenants": tenant_ids,
            "permissions": {},
            "protected": False,
            "email": email,
            "name": name,
            "updated_at": now,
        }
        users[oid] = record
        hub.state.save_state()
        logger.info("Entra auto-provisioned user %s (groups=%s tenants=%s)",
                    oid, group_ids, tenant_ids)
        return record
    # Re-sync: replace the directory-derived sets if they changed.
    changed = (existing.get("groups", []) != group_ids
               or existing.get("tenants", []) != tenant_ids)
    existing["groups"] = group_ids
    existing["tenants"] = tenant_ids
    existing["email"] = email or existing.get("email", "")
    existing["name"] = name or existing.get("name", "")
    existing["auth_type"] = "entra"
    existing["updated_at"] = now
    if changed:
        hub.state.save_state()
        # Reuse the hub's session-invalidation helper so a dropped group/tenant
        # takes effect immediately (matches every other perm/tenant change).
        try:
            from api import _invalidate_user_sessions
            _invalidate_user_sessions(hub, oid)
        except Exception:  # noqa: BLE001 — tests without api import
            pass
        logger.info("Entra re-synced user %s (groups=%s tenants=%s)",
                    oid, group_ids, tenant_ids)
    return existing


def build_user_data(hub, user_record: dict, user_id: str) -> dict:
    """Build the 7-key ``user_data`` dict the session machinery expects (the
    same shape ``routes/auth.local_login`` builds for a local user). Entra
    users are never protected and never carry a tenant_id beyond their
    derived set."""
    perms = resolve_effective_permissions(hub, user_record)
    tenants = list(user_record.get("tenants", []) or [])
    name = str(user_record.get("name") or "")
    email = str(user_record.get("email") or "")
    return {
        "user_id": user_id,           # the Entra oid GUID (stable key)
        "auth_type": "entra",
        "name": name,
        "email": email,
        "display_name": name or email or user_id,   # what the UI shows
        "permissions": perms,
        "tenants": tenants,
        "tenant_id": tenants[0] if tenants else None,
        "protected": False,
    }