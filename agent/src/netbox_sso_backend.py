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

import base64
import hashlib
import json
import logging
import re
import secrets
import time
import urllib.parse
import urllib.request

try:
    from social_core.backends.open_id_connect import OpenIdConnectAuth
except Exception:  # noqa: BLE001 — importable without social-core (unit tests)
    OpenIdConnectAuth = object  # type: ignore[assignment,misc]

logger = logging.getLogger("lm_sso")

_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_GRAPH = "https://graph.microsoft.com/v1.0"


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def cert_thumbprint_x5t(cert_pem):
    """``x5t`` = base64url(SHA-1(DER(cert))) — how Entra maps the assertion to
    the uploaded certificate (same as the hub's ``security.oidc``)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha1(der).digest()).rstrip(b"=").decode()


def build_client_assertion(client_id, token_endpoint, key_pem, cert_pem):
    """RS256 JWT client assertion (iss == sub == client_id, aud == token URL)."""
    import jwt
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(key_pem, password=None)
    now = int(time.time())
    payload = {"iss": client_id, "sub": client_id, "aud": token_endpoint,
               "jti": secrets.token_urlsafe(16), "iat": now, "nbf": now, "exp": now + 300}
    return jwt.encode(payload, key, algorithm="RS256",
                      headers={"x5t": cert_thumbprint_x5t(cert_pem)})


class EntraCertOIDCAuth(OpenIdConnectAuth):
    """Entra OIDC with certificate (private_key_jwt) client authentication."""

    name = "oidc"

    def _cert_files(self):
        key = self.setting("CLIENT_KEY_FILE", "") or ""
        cert = self.setting("CLIENT_CERT_FILE", "") or ""
        return (key, cert) if key and cert else None

    def use_basic_auth(self):
        if self._cert_files():
            return False
        return super().use_basic_auth()

    def auth_complete_credentials(self):
        if self._cert_files():
            return None
        return super().auth_complete_credentials()

    def client_assertion(self):
        key_file, cert_file = self._cert_files()
        client_id, _ = self.get_key_and_secret()
        return build_client_assertion(client_id, self.access_token_url(),
                                      _read(key_file), _read(cert_file))

    def auth_complete_params(self, state=None):
        params = super().auth_complete_params(state)
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
    if not id_token or not isinstance(id_token, str) or id_token.count(".") != 2:
        return {}
    try:
        payload = id_token.split(".")[1]
        pad = "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload + pad).decode("utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("lm_sso: could not decode id_token claims: %s", exc)
        return {}


def _graph_ids(url, token):
    out = []
    while url:
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8") or "{}")
        out.extend(str(v["id"]) for v in body.get("value", []) if v.get("id"))
        url = body.get("@odata.nextLink")
    return out


def _app_graph_token(backend):
    """App-only Graph token minted with the cert (the hub's
    ``fetch_app_graph_token``). Needs Group.Read.All (application) on the app."""
    key_file, cert_file = backend._cert_files()
    client_id, _ = backend.get_key_and_secret()
    token_url = backend.access_token_url()
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_assertion_type": _ASSERTION_TYPE,
        "client_assertion": build_client_assertion(client_id, token_url,
                                                   _read(key_file), _read(cert_file)),
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(token_url, data=data), timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}").get("access_token") or ""


def member_groups(backend, claims, access_token):
    """The user's Entra group object IDs.

    1. id_token ``groups`` claim when present (even empty = in no groups);
    2. else, with the cert, the app-token ``/users/{oid}/transitiveMemberOf``
       (reliable whatever the token configuration — the hub's primary fallback);
    3. else the delegated ``/me/transitiveMemberOf`` for a ``groups`` overflow.
    """
    g = claims.get("groups")
    if isinstance(g, list):
        return [str(x) for x in g]
    oid = claims.get("oid") or ""
    cert_files = getattr(backend, "_cert_files", None)
    if oid and callable(cert_files) and cert_files():
        try:
            tok = _app_graph_token(backend)
            if tok:
                return _graph_ids(f"{_GRAPH}/users/{oid}/transitiveMemberOf/"
                                  "microsoft.graph.group?$select=id&$top=999", tok)
        except Exception as exc:  # noqa: BLE001 — never crash login
            logger.warning("lm_sso: Graph app-token group lookup failed: %s", exc)
    names = claims.get("_claim_names")
    if isinstance(names, dict) and "groups" in names and access_token:
        try:
            return _graph_ids(f"{_GRAPH}/me/transitiveMemberOf?$select=id", access_token)
        except Exception as exc:  # noqa: BLE001
            logger.warning("lm_sso: Graph /me/transitiveMemberOf failed: %s", exc)
    return []


def _id_list(value):
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
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
    from django.conf import settings
    try:
        from social_core.exceptions import AuthForbidden
    except Exception:  # noqa: BLE001
        AuthForbidden = PermissionError

    group_map = getattr(settings, "SOCIAL_AUTH_LM_GROUP_MAP", None)
    if group_map is None:
        group_map = getattr(settings, "NETBOX_SSO_GROUP_MAP", {})
    group_map = {str(k): str(v) for k, v in (group_map or {}).items()}
    allowed = _id_list(getattr(settings, "SOCIAL_AUTH_LM_ALLOWED_GROUP", None)
                       or getattr(settings, "NETBOX_SSO_ALLOWED_GROUP", ""))
    su_groups = set(_id_list(getattr(settings, "SOCIAL_AUTH_LM_SUPERUSER_GROUPS", [])))
    auto_create = bool(getattr(settings, "REMOTE_AUTH_AUTO_CREATE_GROUPS", False))

    resp = response or {}
    claims = _decode_id_token_claims(resp.get("id_token") or getattr(backend, "id_token", "") or "")
    member_of = member_groups(backend, claims, resp.get("access_token") or "")

    if allowed and not (set(member_of) & set(allowed)):
        logger.info("lm_sso: refusing login for %r — not in allowed Entra group(s) %s "
                    "(read %d group(s))", getattr(user, "username", None), allowed, len(member_of))
        raise AuthForbidden(backend)
    if user is None:
        return

    names = []
    for gid in member_of:
        name = group_map.get(gid)
        if name and name not in names:
            names.append(name)
    GroupModel = user.groups.model
    target = []
    for name in names:
        grp = GroupModel.objects.filter(name=name).first()
        if grp is None and auto_create:
            try:
                grp, _ = GroupModel.objects.get_or_create(name=name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("lm_sso: could not create NetBox group %r: %s", name, exc)
        if grp is not None:
            target.append(grp)
    user.groups.set(target)

    if su_groups:
        want = bool(su_groups & set(member_of))
        if bool(getattr(user, "is_superuser", False)) != want:
            user.is_superuser = want
            user.save(update_fields=["is_superuser"])
    logger.info("lm_sso: synced %r -> groups=%s superuser=%s",
                getattr(user, "username", None), sorted(g.name for g in target),
                getattr(user, "is_superuser", None))
