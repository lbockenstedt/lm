"""Oracle Cloud Infrastructure (OCI) Vault credential-store hook for the LM hub.

The OCI parity feature for ``key_vault.py`` — lets a hub authenticate secret
storage against OCI's **Vault + Secrets** service instead of (or as well as —
see exclusivity below) Azure Key Vault. Used through ``cloud_vault.py``, the
generic dispatcher every other part of the hub should call: it resolves
``kv:<name>`` references and stores/reads named secrets WITHOUT the caller
ever knowing (or needing to know) which cloud vault backend is active.

Auth is the same OCI **API signing key** shape as ``oci_nsg.py`` (tenancy OCID
+ user OCID + key fingerprint + RSA private key), signed via the shared
``oci_auth`` module — but configured as its OWN, separate
``global_config['oci_vault']`` block (a customer may reasonably want a
narrower-scoped OCI user/API key for Vault access than for NSG management).

OCI Vault + Secrets is actually TWO service surfaces, on two DIFFERENT hosts —
both of which carry an ``.oci.`` label that the plain OCI Core (iaas) endpoints
do NOT have:
  * the **Vaults** control plane (``vaults.<region>.oci.oraclecloud.com``) —
    create/update/list secrets (management operations, need
    ``compartment_id`` + ``vault_id`` + a KMS ``key_id`` to encrypt with when
    CREATING a brand-new secret);
  * the **Secrets** retrieval plane
    (``secrets.vaults.<region>.oci.oraclecloud.com``) — read a secret's current
    value by name (no compartment needed).

Only one of {Azure Key Vault, OCI Vault} can be ``enabled`` at a time (see
``cloud_vault.py``) — enforced by ``routes/key_vault.py`` /
``routes/oci_vault.py`` at save time.

Scope note: unlike ``key_vault.py``, this module does NOT implement the
Azure-only disaster-recovery automation (break-glass admin password rotation,
scheduled min-backup bundles) — that's a separate, much larger feature that
wasn't asked for. This module covers the credential-storage primitives
(get/set/test) that ``cloud_vault.py`` needs to make Vault choice transparent
to the rest of the hub.

Everything is best-effort + explicit: functions raise ``OciVaultError`` with
the OCI response body so the route/UI can show the real reason.
"""
from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

import oci_auth as _oci_auth
from oci_auth import OciAuthConfig as OciConfig  # re-exported: same fields/shape

logger = logging.getLogger("OciVault")

# "OCI Vault" is three separate services on three hostnames with two different
# API versions, and using the wrong combination returns 404
# NotAuthorizedOrNotFound — indistinguishable from a missing resource or a
# policy denial. Verified against live endpoints (an unauthenticated request to
# a real route answers 401 NotAuthenticated; a bad route answers 404):
#
#   KMS vault mgmt   kms.<region>.oraclecloud.com                /20180608/vaults…
#   secret mgmt      vaults.<region>.oci.oraclecloud.com         /20180608/secrets…
#   secret retrieval secrets.vaults.<region>.oci.oraclecloud.com /20190301/secretbundles…
#
# Note the ``.oci.`` label appears on the two secrets hosts but NOT on kms.
_KMS_API_VERSION = "20180608"      # KMS vault management
_VAULTS_API_VERSION = "20180608"   # secret management (create/list/update/delete)
_SECRETS_API_VERSION = "20190301"  # secret retrieval (secret bundles)


class OciVaultError(Exception):
    """Raised for any OCI Vault/Secrets API failure; message is safe to surface."""


def _not_found_help(cfg: OciConfig, vcfg: Optional[Dict[str, Any]]) -> str:
    """Explain a 404 NotAuthorizedOrNotFound, which OCI makes deliberately
    ambiguous: it means "doesn't exist, OR is in another region, OR your policy
    doesn't let you see it" — collapsed into one response so the API can't be
    used to probe for resources you lack access to. Nothing in the response
    body narrows it down, so we narrow it locally."""
    region = getattr(cfg, "region", "") or ""
    problems = []
    if vcfg:
        problems += _oci_auth.diagnose_resource_ocid(
            str(vcfg.get("vault_id") or ""), "vault", "Vault OCID", region)
        problems += _oci_auth.diagnose_resource_ocid(
            str(vcfg.get("compartment_id") or ""), "compartment",
            "Compartment OCID", region)
        key_id = str(vcfg.get("key_id") or "")
        if key_id:
            problems += _oci_auth.diagnose_resource_ocid(
                key_id, "key", "Encryption key OCID", region)

    out = ""
    if problems:
        out += "\n\nDetected:\n" + "\n".join(f"  • {p}" for p in problems)
        return out

    # Nothing provably wrong in the OCIDs — point at the two remaining causes.
    out += ("\n\nOCI returns this same 404 for three different situations and "
            "will not say which:\n"
            "  • The resource is in a different region than "
            f"'{region or '(unset)'}'.\n"
            "  • The vault was deleted (a deleted vault stays visible in the "
            "console for a while).\n"
            "  • Your policy doesn't grant access. The API user needs, in the "
            "vault's compartment, something like:\n"
            "      allow group <your-group> to manage secret-family in "
            "compartment <name>\n"
            "      allow group <your-group> to read vaults in compartment "
            "<name>\n"
            "      allow group <your-group> to use keys in compartment <name>\n"
            "Note that a compartment OCID equal to the tenancy OCID is normal "
            "— the root compartment IS the tenancy — so that by itself is not "
            "the problem.")
    return out


def _http_error(cfg: OciConfig, what: str, resp: httpx.Response,
                vcfg: Optional[Dict[str, Any]] = None) -> OciVaultError:
    """Build the error for a non-success OCI HTTP response.

    OCI answers a bad signing credential with a bare "NotAuthenticated" that
    names no field, so the locally-verifiable diagnosis (OCID shapes, and
    whether the private key actually matches the configured fingerprint) is
    appended on 401/403. A 404 is equally vague and gets its own diagnosis."""
    msg = f"{what} failed: HTTP {resp.status_code} — {resp.text[:300]}"
    try:
        if resp.status_code in (401, 403):
            msg += _oci_auth.auth_failure_help(cfg)
        elif resp.status_code == 404:
            msg += _not_found_help(cfg, vcfg)
    except Exception:  # diagnosis must never mask the original failure
        pass
    return OciVaultError(msg)


def get_oci_config(hub) -> OciConfig:
    """Read the stored OCI Vault auth config from ``global_config`` (admin-set
    via ``/setup/oci-vault``) and build an :class:`OciConfig`."""
    stored = {}
    try:
        stored = hub.state.system_state.get("global_config", {}).get("oci_vault", {}) or {}
    except Exception:  # noqa: BLE001 — hub without state (tests)
        stored = {}
    return OciConfig(stored)


def _require(vcfg: Dict[str, Any]) -> None:
    if not str(vcfg.get("vault_id") or "").strip():
        raise OciVaultError("OCI Vault config incomplete: 'vault_id' is required")
    if not str(vcfg.get("compartment_id") or "").strip():
        raise OciVaultError("OCI Vault config incomplete: 'compartment_id' is required")


def _vault_region(cfg: OciConfig) -> str:
    """Validated region id shared by both Vault endpoint builders. Catches a
    typo'd region here rather than letting it become a bare DNS failure."""
    if not cfg.region:
        raise OciVaultError("OCI Vault config incomplete: 'region' is required")
    try:
        return _oci_auth.validate_region(cfg.region)
    except _oci_auth.OciAuthError as e:
        raise OciVaultError(str(e)) from e


def _kms_base(cfg: OciConfig) -> str:
    """KMS vault MANAGEMENT — GetVault/ListVaults/CreateVault.

    A different service from the secrets endpoints below, on a host with **no**
    ``.oci.`` label. ``GET /vaults/{id}`` does not exist on
    ``vaults.<region>.oci.oraclecloud.com`` at all; sending it there returns
    404 NotAuthorizedOrNotFound, which reads exactly like a missing vault or a
    policy problem and sends you hunting for the wrong thing."""
    return f"https://kms.{_vault_region(cfg)}.oraclecloud.com/{_KMS_API_VERSION}"


def _vaults_base(cfg: OciConfig) -> str:
    """Secret MANAGEMENT (control plane) — create/update/list/delete secrets.

    Note the ``.oci.`` label: the Vault service endpoints are
    ``vaults.<region>.oci.oraclecloud.com``, NOT
    ``vaults.<region>.oraclecloud.com`` (which does not resolve at all). Getting
    this wrong surfaces only as a DNS ``Name or service not known``."""
    return f"https://vaults.{_vault_region(cfg)}.oci.oraclecloud.com/{_VAULTS_API_VERSION}"


def _secrets_base(cfg: OciConfig) -> str:
    """Secret RETRIEVAL (data plane) — fetch a secret's actual value.

    A separate host from the management plane, and note it is
    ``secrets.vaults.<region>.oci.oraclecloud.com`` — the ``vaults.`` label is
    part of the retrieval host too. It is also the one endpoint on a different
    API version (20190301)."""
    return f"https://secrets.vaults.{_vault_region(cfg)}.oci.oraclecloud.com/{_SECRETS_API_VERSION}"


async def _request(cfg: OciConfig, client: httpx.AsyncClient, method: str, url: str, *,
                   json_body: Optional[dict] = None) -> httpx.Response:
    try:
        return await _oci_auth.oci_request(cfg, client, method, url, json_body=json_body)
    except _oci_auth.OciAuthError as e:
        raise OciVaultError(str(e)) from e


def _request_sync(cfg: OciConfig, client: httpx.Client, method: str, url: str, *,
                  json_body: Optional[dict] = None) -> httpx.Response:
    try:
        return _oci_auth.oci_request_sync(cfg, client, method, url, json_body=json_body)
    except _oci_auth.OciAuthError as e:
        raise OciVaultError(str(e)) from e


# ── read ─────────────────────────────────────────────────────────────────────

async def get_secret(cfg: OciConfig, vcfg: Dict[str, Any], name: str,
                     http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Fetch a secret's current value by name. ``None`` if it doesn't exist."""
    if not name:
        return None
    vault_id = str(vcfg.get("vault_id") or "").strip()
    # GetSecretBundleByName is a POST whose arguments are QUERY parameters and
    # whose body is empty — a GET on this path 404s.
    url = (f"{_secrets_base(cfg)}/secretbundles/actions/getByName"
           f"?secretName={quote(name, safe='')}&vaultId={quote(vault_id, safe='')}")
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        resp = await _request(cfg, client, "POST", url)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise _http_error(cfg, "OCI GetSecretBundleByName", resp, vcfg)
    body = resp.json()
    content = ((body.get("secretBundleContent") or {}).get("content") or "")
    if not content:
        return None
    try:
        return base64.b64decode(content).decode("utf-8")
    except Exception as e:  # noqa: BLE001
        raise OciVaultError(f"could not decode secret bundle content: {e}")


def get_secret_sync(cfg: OciConfig, vcfg: Dict[str, Any], name: str,
                    http: Optional[httpx.Client] = None) -> Optional[str]:
    """Synchronous variant of :func:`get_secret` — used by
    ``security.credential_store``'s ``get_secret`` interface, which is
    synchronous (called from both sync and async call sites across the hub).
    Never raises: any failure logs a warning and returns ``None`` (matching
    ``KeyVaultCredentialProvider``'s best-effort contract)."""
    if not name:
        return None
    try:
        _require(vcfg)
        vault_id = str(vcfg.get("vault_id") or "").strip()
        url = (f"{_secrets_base(cfg)}/secretbundles/actions/getByName"
               f"?secretName={quote(name, safe='')}&vaultId={quote(vault_id, safe='')}")
        with (http or httpx.Client(timeout=20.0)) as client:
            resp = _request_sync(cfg, client, "POST", url)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            logger.warning("OCI Vault fetch of %r failed: HTTP %s — %s", name, resp.status_code, resp.text[:200])
            return None
        content = ((resp.json().get("secretBundleContent") or {}).get("content") or "")
        return base64.b64decode(content).decode("utf-8") if content else None
    except Exception as e:  # noqa: BLE001 — never raise from a credential provider
        logger.warning("OCI Vault fetch of %r failed: %s", name, e)
        return None


# ── write (create-or-update) ─────────────────────────────────────────────────

async def _find_secret_id(cfg: OciConfig, vcfg: Dict[str, Any], name: str,
                          client: httpx.AsyncClient) -> Optional[str]:
    url = (f"{_vaults_base(cfg)}/secrets?compartmentId={vcfg['compartment_id']}"
          f"&vaultId={vcfg['vault_id']}&name={name}")
    resp = await _request(cfg, client, "GET", url)
    if resp.status_code != 200:
        raise _http_error(cfg, "OCI ListSecrets", resp, vcfg)
    for item in (resp.json() or []):
        if item.get("secretName") == name and item.get("lifecycleState") not in ("DELETED", "SCHEDULING_DELETION"):
            return item.get("id")
    return None


async def _wait_secret_active(cfg: OciConfig, vcfg: Dict[str, Any], secret_id: str,
                              client: httpx.AsyncClient, *,
                              attempts: int = 10, delay: float = 2.0) -> bool:
    """Block until a newly created secret reaches ACTIVE, or give up.

    OCI CreateSecret returns 200 with the secret in ``CREATING``; the secret
    BUNDLE (the actual value) is not retrievable until it goes ``ACTIVE``, which
    typically takes a few seconds. Without this wait, storing a credential and
    immediately reading it back — exactly what "save the token, then fetch"
    does — races and the read 404s.

    Best-effort: returns False on timeout rather than raising, so a slow vault
    degrades to the caller's existing error path instead of losing the write
    (the secret IS created either way)."""
    for i in range(attempts):
        resp = await _request(cfg, client, "GET", f"{_vaults_base(cfg)}/secrets/{secret_id}")
        if resp.status_code == 200 and (resp.json() or {}).get("lifecycleState") == "ACTIVE":
            return True
        if i < attempts - 1:
            await asyncio.sleep(delay)
    logger.warning("OCI vault: secret %s not ACTIVE after %.0fs — reads may 404 briefly",
                   secret_id, attempts * delay)
    return False


async def set_secret(cfg: OciConfig, vcfg: Dict[str, Any], name: str, value: str,
                     http: Optional[httpx.AsyncClient] = None) -> str:
    """Create the secret if it doesn't exist yet, else push a new version.
    Returns the secret's OCID."""
    _require(vcfg)
    if not name:
        raise OciVaultError("secret name is required")
    content_b64 = base64.b64encode((value or "").encode("utf-8")).decode("ascii")
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        secret_id = await _find_secret_id(cfg, vcfg, name, client)
        if secret_id:
            resp = await _request(
                cfg, client, "PUT", f"{_vaults_base(cfg)}/secrets/{secret_id}",
                json_body={"secretContent": {"contentType": "BASE64", "content": content_b64, "stage": "CURRENT"}})
            if resp.status_code not in (200, 202):
                raise _http_error(cfg, "OCI UpdateSecret", resp, vcfg)
            return secret_id
        key_id = str(vcfg.get("key_id") or "").strip()
        if not key_id:
            raise OciVaultError("OCI Vault config incomplete: 'key_id' (KMS master key OCID) "
                               "is required to create a NEW secret")
        resp = await _request(
            cfg, client, "POST", f"{_vaults_base(cfg)}/secrets",
            json_body={
                "compartmentId": vcfg["compartment_id"], "vaultId": vcfg["vault_id"], "keyId": key_id,
                "secretName": name,
                "secretContent": {"contentType": "BASE64", "content": content_b64, "stage": "CURRENT"},
            })
        if resp.status_code not in (200, 201):
            raise _http_error(cfg, "OCI CreateSecret", resp, vcfg)
        new_id = resp.json().get("id", "")
        # A freshly created secret is CREATING; its value can't be read back
        # until ACTIVE. Wait here so the caller's next read doesn't 404.
        if new_id:
            await _wait_secret_active(cfg, vcfg, new_id, client)
        return new_id


# ── delete ───────────────────────────────────────────────────────────────────

async def delete_secret(cfg: OciConfig, vcfg: Dict[str, Any], name: str,
                        http: Optional[httpx.AsyncClient] = None) -> bool:
    """Delete a secret by name (idempotent — a missing secret is not an
    error, mirroring ``key_vault.delete_secret``'s 404-tolerant contract).

    OCI has no INSTANT delete for Vault secrets — deletion is always a
    scheduled action (``ScheduleSecretDeletion``), analogous to Azure Key
    Vault's soft-delete-then-purge. We schedule with no explicit
    ``timeOfDeletion`` so OCI applies its default (minimum allowed) retention
    window; the secret becomes unreadable to ``get_secret``/``resolve_ref``
    well before that window elapses (OCI's ``GetSecretBundle`` already
    refuses ``PENDING_DELETION`` secrets), so callers see the same "gone"
    behavior as an instant delete."""
    _require(vcfg)
    if not name:
        return True
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        secret_id = await _find_secret_id(cfg, vcfg, name, client)
        if not secret_id:
            return True  # already absent/deleted — nothing to schedule
        resp = await _request(
            cfg, client, "POST", f"{_vaults_base(cfg)}/secrets/{secret_id}/actions/scheduleDeletion",
            json_body={})
        if resp.status_code not in (200, 202, 404):
            raise _http_error(cfg, "OCI ScheduleSecretDeletion", resp, vcfg)
    return True


# ── connectivity test ────────────────────────────────────────────────────────

async def test_connection(cfg: OciConfig, vcfg: Dict[str, Any],
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET the vault to confirm the signing key + IAM policy + OCID resolve."""
    _require(vcfg)
    url = f"{_kms_base(cfg)}/vaults/{vcfg['vault_id']}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        resp = await _request(cfg, client, "GET", url)
    if resp.status_code != 200:
        raise _http_error(cfg, "OCI GET vault", resp, vcfg)
    body = resp.json()
    return {"lifecycle_state": body.get("lifecycleState"), "vault_id": body.get("id"),
            "management_endpoint": body.get("managementEndpoint")}


# ── kv:<name> reference resolution (mirrors key_vault.resolve_ref) ──────────

async def resolve_ref(hub, ref: Optional[str],
                      http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Resolve a secret *reference* to its value, OCI-Vault-optionally.

    ``kv:<name>`` -> fetch secret ``<name>`` from the hub's configured OCI
    vault (returns ``None`` when not configured/enabled or the secret is
    absent). Any other non-empty string is treated as an inline literal and
    returned unchanged. Never raises."""
    if not ref:
        return None
    ref = str(ref)
    if not ref.startswith("kv:"):
        return ref
    name = ref[len("kv:"):].strip()
    if not name:
        return None
    try:
        vcfg = (hub.state.system_state.get("global_config", {}) or {}).get("oci_vault", {}) or {}
        if not vcfg.get("enabled") or not vcfg.get("vault_id"):
            return None
        return await get_secret(get_oci_config(hub), vcfg, name, http=http)
    except Exception as e:  # noqa: BLE001
        logger.warning("OCI Vault: resolve_ref(%s) failed: %s", name, e)
        return None
