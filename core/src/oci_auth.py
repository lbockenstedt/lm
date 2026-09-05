"""Shared Oracle Cloud Infrastructure (OCI) API request-signing primitives.

Factored out of ``oci_nsg.py`` so a second OCI integration (``oci_vault.py`` —
the Vault/Secrets credential-store parity feature) doesn't duplicate the
Signature Version 1 signing logic. Each OCI feature module still owns its OWN
:class:`OciAuthConfig`-shaped auth block in ``global_config`` (e.g.
``oci_nsg`` vs ``oci_vault``) — a customer may reasonably want a different,
narrower-scoped OCI user/API key per integration — only the crypto/HTTP
plumbing is shared here.

See https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from email.utils import formatdate
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from security.credential_store import resolve_private_key_material

logger = logging.getLogger("OciAuth")


class OciAuthError(Exception):
    """Raised for any OCI request-signing/auth failure."""


class OciAuthConfig:
    """Resolved OCI API-signing-key auth (tenancy/user/fingerprint/key/region).

    Every OCI feature module builds one of these from its own
    ``global_config`` block (fields are identically named/shaped across all
    of them so the admin UI stays consistent)."""

    def __init__(self, stored: Optional[dict] = None):
        stored = stored or {}
        self.tenancy_ocid = str(stored.get("tenancy_ocid") or "").strip()
        self.user_ocid = str(stored.get("user_ocid") or "").strip()
        self.fingerprint = str(stored.get("fingerprint") or "").strip()
        # Resolved via credential_store: kv:<name> / filesystem path / bare
        # secret name — same shape as the Entra OIDC client-key path.
        self.key_path = str(stored.get("key_path") or "").strip()
        self.region = str(stored.get("region") or "").strip()

    @property
    def key_id(self) -> str:
        return f"{self.tenancy_ocid}/{self.user_ocid}/{self.fingerprint}"

    @property
    def ready(self) -> bool:
        return bool(self.tenancy_ocid and self.user_ocid and self.fingerprint
                    and self.key_path and self.region)


# ── request signing (Signature Version 1) ───────────────────────────────────
# Only the subset needed here: plain GET / POST with a JSON body, no
# query-string params, no on-behalf-of token.

_key_cache: Dict[str, Any] = {}  # key_path -> loaded RSAPrivateKey


def _load_private_key(key_path: str):
    key = _key_cache.get(key_path)
    if key is not None:
        return key
    pem = resolve_private_key_material(key_path)
    if not pem:
        raise OciAuthError(f"could not resolve OCI API private key {key_path!r}")
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as e:  # noqa: BLE001
        raise OciAuthError(f"could not parse OCI API private key {key_path!r}: {e}")
    _key_cache[key_path] = key
    return key


def signed_headers(cfg: OciAuthConfig, method: str, url: str,
                   body: Optional[bytes]) -> Dict[str, str]:
    """Build the ``Authorization`` header (+ every header it covers) for one
    signed OCI API request."""
    if not cfg.ready:
        raise OciAuthError("OCI auth incomplete: tenancy_ocid/user_ocid/"
                           "fingerprint/key_path/region are all required")
    parsed = urlsplit(url)
    method_lc = method.lower()
    request_target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    headers: Dict[str, str] = {
        "date": formatdate(usegmt=True),
        "host": parsed.netloc,
        "(request-target)": f"{method_lc} {request_target}",
    }
    signed = ["(request-target)", "date", "host"]
    if body is not None:
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        headers["content-length"] = str(len(body))
        headers["content-type"] = "application/json"
        headers["x-content-sha256"] = digest
        signed += ["content-length", "content-type", "x-content-sha256"]
    signing_string = "\n".join(f"{h}: {headers[h]}" for h in signed)
    key = _load_private_key(cfg.key_path)
    signature = key.sign(signing_string.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(signature).decode("ascii")
    auth = (f'Signature version="1",headers="{" ".join(signed)}",'
           f'keyId="{cfg.key_id}",algorithm="rsa-sha256",signature="{sig_b64}"')
    out = {k: v for k, v in headers.items() if k != "(request-target)"}
    out["Authorization"] = auth
    return out


async def oci_request(cfg: OciAuthConfig, client: httpx.AsyncClient, method: str, url: str, *,
                      json_body: Optional[dict] = None) -> httpx.Response:
    """Issue ONE signed request on an already-open ASYNC client. Callers own
    the client's lifecycle (opened once per public entry point) — this must
    NOT close it, since a multi-request operation reuses the same client
    across several calls."""
    body = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
    headers = signed_headers(cfg, method, url, body)
    return await client.request(method, url, headers=headers, content=body)


def oci_request_sync(cfg: OciAuthConfig, client: httpx.Client, method: str, url: str, *,
                     json_body: Optional[dict] = None) -> httpx.Response:
    """Issue ONE signed request on an already-open SYNC client. Used by the
    ``security.credential_store`` provider, whose ``get_secret`` interface is
    synchronous (called from both sync and async call sites across the hub)."""
    body = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else None
    headers = signed_headers(cfg, method, url, body)
    return client.request(method, url, headers=headers, content=body)
