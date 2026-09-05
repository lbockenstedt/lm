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
import os
from email.utils import formatdate
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from security.credential_store import resolve_private_key_material

logger = logging.getLogger("OciAuth")

# Generous cap for an uploaded OCI API signing key PEM (~1.7 KB typical).
MAX_KEY_UPLOAD_BYTES = 64 * 1024


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


# Curated list of OCI commercial ("OC1" realm) region identifiers + a
# human-friendly label, so the WebUI can offer a dropdown instead of a
# freeform text field (a mistyped/mis-cased region silently produces a
# hostname that can't resolve — e.g. "iaas.US-Ashburn-1.oraclecloud.com" —
# which surfaces as an opaque DNS error far from the actual mistake). There is
# no unauthenticated OCI API to fetch this list (ListRegions requires a
# working signing key + a bootstrap region — chicken-and-egg for a NEW
# integration), so it is hand-maintained here; government/sovereign-realm
# regions are out of scope. Shared by ``routes/oci_nsg.py`` and
# ``routes/oci_vault.py`` (one dropdown source for both integrations).
# Source: https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
OCI_REGIONS = [
    ("us-ashburn-1", "US East (Ashburn)"),
    ("us-phoenix-1", "US West (Phoenix)"),
    ("us-sanjose-1", "US West (San Jose)"),
    ("us-chicago-1", "US Midwest (Chicago)"),
    ("ca-toronto-1", "Canada Southeast (Toronto)"),
    ("ca-montreal-1", "Canada Southeast (Montreal)"),
    ("mx-queretaro-1", "Mexico Central (Queretaro)"),
    ("mx-monterrey-1", "Mexico Northeast (Monterrey)"),
    ("sa-saopaulo-1", "Brazil East (Sao Paulo)"),
    ("sa-vinhedo-1", "Brazil Southeast (Vinhedo)"),
    ("sa-santiago-1", "Chile Central (Santiago)"),
    ("sa-valparaiso-1", "Chile West (Valparaiso)"),
    ("sa-bogota-1", "Colombia Central (Bogota)"),
    ("uk-london-1", "UK South (London)"),
    ("uk-cardiff-1", "UK West (Cardiff/Newport)"),
    ("eu-frankfurt-1", "Germany Central (Frankfurt)"),
    ("eu-milan-1", "Italy Northwest (Milan)"),
    ("eu-paris-1", "France Central (Paris)"),
    ("eu-marseille-1", "France South (Marseille)"),
    ("eu-zurich-1", "Switzerland North (Zurich)"),
    ("eu-amsterdam-1", "Netherlands Northwest (Amsterdam)"),
    ("eu-madrid-1", "Spain Central (Madrid)"),
    ("eu-stockholm-1", "Sweden Central (Stockholm)"),
    ("eu-jovanovac-1", "Serbia Central (Jovanovac)"),
    ("il-jerusalem-1", "Israel Central (Jerusalem)"),
    ("me-riyadh-1", "Saudi Arabia Central (Riyadh)"),
    ("me-jeddah-1", "Saudi Arabia West (Jeddah)"),
    ("me-abudhabi-1", "UAE Central (Abu Dhabi)"),
    ("me-dubai-1", "UAE East (Dubai)"),
    ("af-johannesburg-1", "South Africa Central (Johannesburg)"),
    ("ap-hyderabad-1", "India South (Hyderabad)"),
    ("ap-mumbai-1", "India West (Mumbai)"),
    ("ap-tokyo-1", "Japan East (Tokyo)"),
    ("ap-osaka-1", "Japan Central (Osaka)"),
    ("ap-seoul-1", "South Korea Central (Seoul)"),
    ("ap-chuncheon-1", "South Korea North (Chuncheon)"),
    ("ap-sydney-1", "Australia East (Sydney)"),
    ("ap-melbourne-1", "Australia Southeast (Melbourne)"),
    ("ap-singapore-1", "Singapore"),
    ("ap-singapore-2", "Singapore West"),
    ("ap-batam-1", "Indonesia (Batam)"),
]


def list_regions() -> list:
    """The curated OCI region catalog as ``[{id, label}, ...]`` for the WebUI
    dropdown, sorted by label for a stable, readable picker."""
    return sorted(
        ({"id": rid, "label": f"{label} ({rid})"} for rid, label in OCI_REGIONS),
        key=lambda r: r["label"],
    )


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


def write_uploaded_private_key(hub, subdir: str, filename: str, data: bytes) -> str:
    """Validate an uploaded OCI API signing key (unencrypted PEM) and write it
    to ``<hub data_dir>/<subdir>/<filename>`` (0600), returning the path.

    Shared by ``routes/oci_nsg.py`` and ``routes/oci_vault.py`` so an admin
    can upload the private key via the WebUI instead of hand-copying it onto
    the hub / typing a path into ``key_path``. Not vault-backed: the OCI
    Vault credential-store backend needs its OWN resolvable private key just
    to authenticate to OCI in the first place, so it can't be the bootstrap
    target for this key without a chicken-and-egg problem — a plain,
    tightly-permissioned file is what ``key_path`` already supports via
    ``resolve_private_key_material``'s filesystem-path branch.

    Raises :class:`OciAuthError` on validation or write failure; never
    partially writes (validated fully before anything touches disk)."""
    if not data:
        raise OciAuthError("empty upload")
    if len(data) > MAX_KEY_UPLOAD_BYTES:
        raise OciAuthError("key upload exceeds 64 KB limit")
    try:
        serialization.load_pem_private_key(data, password=None)
    except Exception as e:  # noqa: BLE001
        raise OciAuthError(f"not a valid, unencrypted PEM private key: {e}")
    path = os.path.join(hub.state.data_dir, subdir, filename)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as e:
        raise OciAuthError(f"could not write key file: {e}")
    return path


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
