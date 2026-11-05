"""Lab Manager Entra ID SSO backend + group-sync pipeline step for NetBox.

The generic agent copies this file VERBATIM into a netbox-server host's NetBox
project dir as ``lm_sso_backend.py`` (see ``GenericAgent._apply_netbox_sso``),
where ``configuration.py``'s LM SSO block references it. It is never imported by
the agent itself — only by NetBox (plus the agent unit tests).

It lets NetBox log in through the LM hub's OWN Entra app registration, using the
same certificate the hub uses (no client secret):

* :class:`EntraCertOIDCAuth` — social-core's ``OpenIdConnectAuth`` (backend name
  stays ``oidc`` so ``/oauth/login/oidc/`` + ``/oauth/complete/oidc/`` are
  unchanged) that authenticates the code exchange with a cert-signed JWT
  ``client_assertion`` (private_key_jwt) when ``SOCIAL_AUTH_OIDC_CLIENT_KEY_FILE``
  is set; falls back to the stock client-secret flow otherwise.
* :func:`sync_entra_groups` — pipeline step: allowed-group gate, Entra group →
  NetBox group sync, and Entra group → NetBox superuser.

Settings are read from ``SOCIAL_AUTH_*`` names on purpose: NetBox only copies
``SOCIAL_AUTH_*`` (and its known parameters) from ``configuration.py`` into
Django settings, so any other custom name would silently never arrive.

Django model imports are deferred: this module is imported while NetBox's
settings load, before the apps registry is ready.
"""
from __future__ import annotations

# base64: URL-safe base64 for JWT parts and the cert thumbprint.
import base64
# hashlib: SHA-1 of the certificate to build the x5t thumbprint.
import hashlib
# json: decode JWT payloads and Graph/token HTTP responses.
import json
# logging: report SSO decisions and failures in NetBox's logs.
import logging
# re: split comma/space-separated group id lists.
import re
# secrets: random unique "jti" id for each client assertion.
import secrets
# time: issued-at / expiry timestamps in the JWT.
import time
# urllib: plain HTTP calls to Entra's token endpoint and Microsoft Graph (no extra deps).
import urllib.parse
import urllib.request

# social-core provides the OIDC backend we extend; it is only present inside NetBox.
try:
    from social_core.backends.open_id_connect import OpenIdConnectAuth
except Exception:  # noqa: BLE001 — importable without social-core (unit tests)
    # Without social-core (unit tests) fall back to a plain base class so the module still imports.
    OpenIdConnectAuth = object  # type: ignore[assignment,misc]

# Logger name used in NetBox logs for every message from this module.
logger = logging.getLogger("lm_sso")

# Standard OAuth value saying "client_assertion is a JWT bearer token" (RFC 7523).
_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Microsoft Graph v1.0 API base URL, used for group membership lookups.
_GRAPH = "https://graph.microsoft.com/v1.0"


def _read(path):
    """Return the raw bytes of the file at path."""
    with open(path, "rb") as f:
        return f.read()


def cert_thumbprint_x5t(cert_pem):
    """``x5t`` = base64url(SHA-1(DER(cert))) — how Entra maps the assertion to
    the uploaded certificate (same as the hub's ``security.oidc``)."""
    # cryptography is imported lazily so the module loads even where it is not needed.
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    # Convert the PEM cert to DER bytes, hash with SHA-1, and base64url-encode without padding.
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha1(der).digest()).rstrip(b"=").decode()


def build_client_assertion(client_id, token_endpoint, key_pem, cert_pem):
    """RS256 JWT client assertion (iss == sub == client_id, aud == token URL)."""
    # PyJWT and cryptography imported lazily; only needed when cert auth is used.
    import jwt
    from cryptography.hazmat.primitives import serialization
    # Parse the PEM private key (it is stored unencrypted on disk).
    key = serialization.load_pem_private_key(key_pem, password=None)
    # Claims: issuer/subject are our app id, audience is the token URL, unique jti, valid for
    # 5 minutes from now.
    now = int(time.time())
    payload = {"iss": client_id, "sub": client_id, "aud": token_endpoint,
               "jti": secrets.token_urlsafe(16), "iat": now, "nbf": now, "exp": now + 300}
    # Sign with the private key; the x5t header tells Entra which uploaded cert to verify with.
    return jwt.encode(payload, key, algorithm="RS256",
                      headers={"x5t": cert_thumbprint_x5t(cert_pem)})


class EntraCertOIDCAuth(OpenIdConnectAuth):
    """Entra OIDC with certificate (private_key_jwt) client authentication."""

    # Keep the stock backend name so NetBox's existing /oauth/.../oidc/ URLs keep working.
    name = "oidc"

    def _cert_files(self):
        """Return (key_file, cert_file) when cert auth is configured, else None."""
        # Read SOCIAL_AUTH_OIDC_CLIENT_KEY_FILE / _CLIENT_CERT_FILE; missing values become "".
        key = self.setting("CLIENT_KEY_FILE", "") or ""
        cert = self.setting("CLIENT_CERT_FILE", "") or ""
        # Both files are required for cert auth.
        return (key, cert) if key and cert else None

    def use_basic_auth(self):
        """Disable HTTP Basic client auth when cert auth is on; otherwise keep the default."""
        if self._cert_files():
            return False
        return super().use_basic_auth()

    def auth_complete_credentials(self):
        """Return None in cert mode so no client secret is sent; otherwise use the default."""
        if self._cert_files():
            return None
        return super().auth_complete_credentials()

    def client_assertion(self):
        """Build the signed JWT that proves our identity to Entra's token endpoint."""
        # Load both PEM files and sign an assertion addressed to the token URL.
        key_file, cert_file = self._cert_files()
        client_id, _ = self.get_key_and_secret()
        return build_client_assertion(client_id, self.access_token_url(),
                                      _read(key_file), _read(cert_file))

    def auth_complete_params(self, state=None):
        """Return token-exchange form fields, swapping the secret for a cert assertion if set."""
        # Start from social-core's normal parameters (code, redirect_uri, etc.).
        params = super().auth_complete_params(state)
        # Cert mode: drop any secret and add client_id plus the signed client_assertion instead.
        if self._cert_files():
            params.pop("client_secret", None)
            client_id, _ = self.get_key_and_secret()
            params["client_id"] = client_id
            params["client_assertion_type"] = _ASSERTION_TYPE
            params["client_assertion"] = self.client_assertion()
        return params


# ── group membership ─────────────────────────────────────────────────────────

def _decode_id_token_claims(id_token):
    """Read a JWT's claims WITHOUT re-verifying (social-core already verified the
    id_token against the Entra JWKS before the pipeline runs)."""
    # Anything that is not a three-part "header.payload.signature" string has no claims to read.
    if not id_token or not isinstance(id_token, str) or id_token.count(".") != 2:
        return {}
    # Malformed base64/JSON is logged and treated as "no claims".
    try:
        # Take the middle (payload) part of the JWT.
        payload = id_token.split(".")[1]
        # JWTs strip base64 padding; add back "=" characters to a multiple of 4.
        pad = "=" * (-len(payload) % 4)
        # Decode the payload and parse it as JSON; an empty result becomes {}.
        return json.loads(base64.urlsafe_b64decode(payload + pad).decode("utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("lm_sso: could not decode id_token claims: %s", exc)
        return {}


def _graph_ids(url, token):
    """Return all "id" values from a Graph list endpoint, following pagination links."""
    # Collected object ids across all pages.
    out = []
    # Keep fetching while Graph gives us a next-page link.
    while url:
        # Call Graph with the bearer token and parse the JSON body.
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
        # Keep only entries that actually have an id.
        out.extend(str(v["id"]) for v in body.get("value", []) if v.get("id"))
        # Graph's next page URL, or None on the last page (ends the loop).
        url = body.get("@odata.nextLink")
    return out


def _app_graph_token(backend):
    """App-only Graph token minted with the cert (the hub's
    ``fetch_app_graph_token``). Needs Group.Read.All (application) on the app."""
    # Credentials and token endpoint come from the configured backend.
    key_file, cert_file = backend._cert_files()
    client_id, _ = backend.get_key_and_secret()
    token_url = backend.access_token_url()
    # Client-credentials grant for Graph's default scope, authenticated with the cert assertion.
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_assertion_type": _ASSERTION_TYPE,
        "client_assertion": build_client_assertion(client_id, token_url,
                                                   _read(key_file), _read(cert_file)),
    }).encode()
    # POST the form and return the access token ("" if Entra did not return one).
    with urllib.request.urlopen(urllib.request.Request(token_url, data=data), timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}").get("access_token") or ""


def member_groups(backend, claims, access_token):
    """The user's Entra group object IDs.

    1. id_token ``groups`` claim when present (even empty = in no groups);
    2. else, with the cert, the app-token ``/users/{oid}/transitiveMemberOf``
       (reliable whatever the token configuration — the hub's primary fallback);
    3. else the delegated ``/me/transitiveMemberOf`` for a ``groups`` overflow.
    """
    # 1) Groups claim present in the id_token: use it directly.
    g = claims.get("groups")
    if isinstance(g, list):
        return [str(x) for x in g]
    # Entra user object id, needed for the app-token Graph lookup.
    oid = claims.get("oid") or ""
    # Only real EntraCertOIDCAuth backends have _cert_files; others skip step 2.
    cert_files = getattr(backend, "_cert_files", None)
    # 2) Cert configured: look up transitive group membership with an app-only token.
    if oid and callable(cert_files) and cert_files():
        try:
            tok = _app_graph_token(backend)
            if tok:
                return _graph_ids(f"{_GRAPH}/users/{oid}/transitiveMemberOf/"
                                  "microsoft.graph.group?$select=id&$top=999", tok)
        except Exception as exc:  # noqa: BLE001 — never crash login
            logger.warning("lm_sso: Graph app-token group lookup failed: %s", exc)
    # 3) "groups" overflow: Entra put a pointer in _claim_names instead of the list, so ask
    # /me with the user's delegated access token.
    names = claims.get("_claim_names")
    if isinstance(names, dict) and "groups" in names and access_token:
        try:
            return _graph_ids(f"{_GRAPH}/me/transitiveMemberOf?$select=id", access_token)
        except Exception as exc:  # noqa: BLE001
            logger.warning("lm_sso: Graph /me/transitiveMemberOf failed: %s", exc)
    # No way to determine groups: treat the user as in no groups.
    return []


def _id_list(value):
    """Normalise a list or a comma/space-separated string into a list of non-empty id strings."""
    # Already a collection: stringify, trim, and drop blanks.
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    # A string (or None): split on commas/whitespace and drop empty pieces.
    return [g for g in re.split(r"[\s,]+", str(value or "")) if g]


def sync_entra_groups(backend, user, response, *args, **kwargs):
    """Pipeline step (end of ``SOCIAL_AUTH_PIPELINE``).

    * ``SOCIAL_AUTH_LM_ALLOWED_GROUP`` (object id or comma/space list): refuse
      login (AuthForbidden) unless the user is in ANY of them.
    * ``SOCIAL_AUTH_LM_GROUP_MAP`` ``{entra-obj-id: netbox-group}``: set the
      user's NetBox groups to EXACTLY the mapped set (Entra is the source of truth).
    * ``SOCIAL_AUTH_LM_SUPERUSER_GROUPS`` (list): members become NetBox
      superusers; non-members lose it (only for SSO-provisioned logins).
    """
    # Django settings hold the SOCIAL_AUTH_* values copied from configuration.py.
    from django.conf import settings
    # AuthForbidden makes social-core show "access denied"; fall back to PermissionError in tests.
    try:
        from social_core.exceptions import AuthForbidden
    except Exception:  # noqa: BLE001
        AuthForbidden = PermissionError

    # Entra group id -> NetBox group name; the older NETBOX_SSO_* name is accepted as a fallback.
    group_map = getattr(settings, "SOCIAL_AUTH_LM_GROUP_MAP", None)
    if group_map is None:
        group_map = getattr(settings, "NETBOX_SSO_GROUP_MAP", {})
    # Make keys and values strings so lookups by group id are consistent.
    group_map = {str(k): str(v) for k, v in (group_map or {}).items()}
    # Allowed group ids (new name first, legacy name as fallback).
    allowed = _id_list(getattr(settings, "SOCIAL_AUTH_LM_ALLOWED_GROUP", None)
                       or getattr(settings, "NETBOX_SSO_ALLOWED_GROUP", ""))
    # Entra groups whose members become NetBox superusers.
    su_groups = set(_id_list(getattr(settings, "SOCIAL_AUTH_LM_SUPERUSER_GROUPS", [])))
    # Whether to create NetBox groups that do not exist yet (NetBox's own remote-auth setting).
    auto_create = bool(getattr(settings, "REMOTE_AUTH_AUTO_CREATE_GROUPS", False))

    # Read the id_token claims from the token response (or the backend) and work out groups.
    resp = response or {}
    claims = _decode_id_token_claims(resp.get("id_token") or getattr(backend, "id_token", "") or "")
    member_of = member_groups(backend, claims, resp.get("access_token") or "")

    # Gate: if an allowed list is set, the user must be in at least one of those groups.
    if allowed and not (set(member_of) & set(allowed)):
        logger.info("lm_sso: refusing login for %r — not in allowed Entra group(s) %s "
                    "(read %d group(s))", getattr(user, "username", None), allowed, len(member_of))
        raise AuthForbidden(backend)
    # No user object (e.g. login refused earlier in the pipeline): nothing to sync.
    if user is None:
        return

    # Translate Entra group ids to NetBox group names, without duplicates, keeping order.
    names = []
    for gid in member_of:
        name = group_map.get(gid)
        if name and name not in names:
            names.append(name)
    # The Group model class used by this user's groups relation (Django's auth Group).
    GroupModel = user.groups.model
    # Find (or optionally create) each mapped NetBox group.
    target = []
    for name in names:
        grp = GroupModel.objects.filter(name=name).first()
        if grp is None and auto_create:
            # Creation failures are logged and that group is skipped; login still proceeds.
            try:
                grp, _ = GroupModel.objects.get_or_create(name=name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("lm_sso: could not create NetBox group %r: %s", name, exc)
        # Only add groups that exist.
        if grp is not None:
            target.append(grp)
    # Replace the user's groups with exactly the mapped set; Entra is the source of truth.
    user.groups.set(target)

    # Superuser sync only when superuser groups are configured.
    if su_groups:
        # Should this user be a superuser? Yes if they are in any superuser group.
        want = bool(su_groups & set(member_of))
        # Save only when the flag actually changes.
        if bool(getattr(user, "is_superuser", False)) != want:
            user.is_superuser = want
            user.save(update_fields=["is_superuser"])
    # Record the final result for auditing.
    logger.info("lm_sso: synced %r -> groups=%s superuser=%s",
                getattr(user, "username", None), sorted(g.name for g in target),
                getattr(user, "is_superuser", None))
