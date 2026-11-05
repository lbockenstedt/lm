"""Hub email notifications — multi-provider SMTP + Azure ACS REST API.

A platform-level alert channel for the hub. Today the hub has no email-sending
path at all (the only SMTP config in the repo is per-tenant and *forwarded* to
the remote cs spoke, which does the actual send). This module lets the hub send
its own alerts — starting with spoke out-of-contact (``spoke_alert_sync.py``).

Provider dropdown (``global_config["notifications"]``):

  * ``azure_acs`` — Azure Communication Services Email. Sender creds come from
    one of two sources (``acs_source``):
      - ``arm`` (default) — the hub auto-pulls the connection string from Azure
        via the ``communicationServices/{name}/listKeys`` ARM action using the
        SSO app cert (the same ARM access the NSG hook uses). Nothing is stored
        in Key Vault; a key rotation is picked up within the cache TTL. The app
        needs a role with ``listKeys`` on the ACS resource (Contributor on it
        or its resource group).
      - ``keyvault`` — a Key Vault secret holds the ACS connection string
        ``endpoint=https://<name>.communication.azure.com;accesskey=<key>``.
    Two transports:
      - ``api`` (default) — pure REST: POST ``{endpoint}/emails:send`` signed
        with the ACS access key (HMAC-SHA256). No smtplib, no blocking, no
        Entra app permission — the access key comes from the same Key Vault
        connection string.
      - ``smtp`` — ``smtp.azurecomm.net:587`` STARTTLS, user = ACS resource
        name, password = access key (parsed from the same connection string).
  * ``gmail`` / ``yahoo`` / ``office365`` / ``generic`` — SMTP with manually
    entered creds; the password is Fernet-encrypted at rest
    (``security.encryption.hub_encryption``), never returned to the UI.

Mirrors the ``key_vault.py`` module shape (leaf; config under
``global_config["notifications"]``; ``CFG_FIELDS`` / ``DEFAULTS`` /
``get_config`` / ``save_config``). Pure REST + stdlib smtplib — no Azure SDK.
"""
from __future__ import annotations

# asyncio runs the blocking smtplib send on a worker thread so the event loop never stalls.
import asyncio
# base64/hashlib/hmac build the HMAC-SHA256 signature the ACS REST API requires.
import base64
import hashlib
import hmac
# json serializes the ACS email request body.
import json
# Standard logging for send results and failures.
import logging
# smtplib/ssl implement the SMTP (STARTTLS) transport for non-ACS providers.
import smtplib
import ssl
# EmailMessage builds the MIME message; formatdate makes the RFC1123 date ACS signs.
from email.message import EmailMessage
from email.utils import formatdate
# Type hints only; they document the shapes of values passed around.
from typing import Any, Dict, List, Optional, Tuple
# urlsplit pulls the path/query/host out of the ACS URL for the signature string.
from urllib.parse import urlsplit

# httpx is the async HTTP client type used for ARM and ACS REST calls.
import httpx

# shared_client reuses a caller-supplied client or opens a short-lived one.
from http_client import shared_client

# hub_encryption decrypts stored SMTP passwords; the oidc helpers mint the app token used
# for Azure ARM calls; key_vault reads/writes the optional ACS connection-string secret.
from security.encryption import hub_encryption
from security.oidc import fetch_app_token, get_oidc_config
import key_vault

# One named logger so every notifications message can be filtered together.
logger = logging.getLogger("Notifications")

# ACS Email data-plane (emails:send). Use the GA version — the 2023-07-01-preview
# it was on has been retired by Azure ("UnsupportedApiVersion"). The GA payload
# (senderAddress / recipients.to[].address / content.subject/plainText) matches
# what _acs_api_send already builds, so this is a drop-in bump.
_ACS_API_VERSION = "2023-03-31"
# ACS SMTP relay host and port (587 = STARTTLS submission port).
_ACS_SMTP_HOST = "smtp.azurecomm.net"
_ACS_SMTP_PORT = 587
# ARM API version for the Microsoft.Communication resource provider calls.
_ACS_ARM_API = "2023-04-01"
# OAuth scope that grants an Azure Resource Manager (management plane) token.
_ARM_SCOPE = "https://management.azure.com/.default"
# Short TTL cache for the ARM-fetched connection string so a burst of alerts
# doesn't hammer listKeys, but a key rotation is picked up within the TTL.
_ACS_ARM_CACHE: Dict[str, Tuple[float, str]] = {}
# Cache entries older than 600 seconds (10 minutes) are refetched from ARM.
_ACS_ARM_CACHE_TTL = 600.0

# Per-provider SMTP defaults (host, port, STARTTLS) plus the label shown in the UI dropdown.
PROVIDER_PRESETS: Dict[str, Dict[str, Any]] = {
    "azure_acs": {"host": _ACS_SMTP_HOST, "port": _ACS_SMTP_PORT, "starttls": True,
                  "label": "Azure ACS (Key Vault-managed)"},
    "gmail":     {"host": "smtp.gmail.com",      "port": 587, "starttls": True, "label": "Gmail"},
    "yahoo":     {"host": "smtp.mail.yahoo.com", "port": 587, "starttls": True, "label": "Yahoo"},
    "office365": {"host": "smtp.office365.com",  "port": 587, "starttls": True, "label": "Office 365"},
    "generic":   {"host": "",                    "port": 587, "starttls": True, "label": "Generic SMTP"},
}


class NotificationsError(Exception):
    """Raised for any notification send/config failure; message is safe to surface."""


# ---------------------------------------------------------------------------
# config helpers (mirror key_vault.CFG_FIELDS / DEFAULTS / get_config / save_config)
# ---------------------------------------------------------------------------

# Every key the notifications config may hold; routes use it to whitelist posted fields.
CFG_FIELDS = ("enabled", "provider", "transport", "acs_source",
              "azure_subscription_id", "azure_resource_group", "acs_resource_name",
              "smtp_host", "smtp_port", "smtp_user", "smtp_password_enc",
              "acs_kv_secret_name", "vault_url", "from_email", "to_emails")
# Default value for each config key, used when a key has never been saved.
DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "provider": "azure_acs",
    "transport": "api",          # only meaningful for azure_acs; others are SMTP
    "acs_source": "arm",         # azure_acs cred source: arm (auto listKeys) or keyvault
    "azure_subscription_id": "",
    "azure_resource_group": "",
    "acs_resource_name": "",
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password_enc": "",     # Fernet ciphertext (base64); empty for ACS
    "acs_kv_secret_name": "acs-email-connstr",
    "vault_url": "",             # empty -> reuse key_vault config's vault_url
    "from_email": "",
    "to_emails": [],
}


def get_config(hub) -> Dict[str, Any]:
    """Return the saved notifications config merged over DEFAULTS so every key is present."""
    # Start from the defaults, then overlay whatever has been saved in global_config.
    c = dict(DEFAULTS)
    c.update((hub.state.system_state.get("global_config", {}) or {})
             .get("notifications", {}) or {})
    # Hand back the merged config dict.
    return c


def _vault_url(hub, cfg: Dict[str, Any]) -> str:
    """The notifications vault URL, falling back to the DR Key Vault URL when
    blank so a one-vault deployment doesn't need a second entry."""
    # Prefer an explicitly configured notifications vault URL.
    v = str(cfg.get("vault_url") or "").strip()
    if v:
        return v
    # Otherwise reuse the Key Vault module's URL; any failure there just means no URL.
    try:
        return str(key_vault.get_config(hub).get("vault_url") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def save_config(hub, cfg: Dict[str, Any]) -> None:
    """Persist the notifications config into global_config and mark hub state dirty."""
    # Read global_config, replace its notifications block, and write it back.
    gc = hub.state.system_state.get("global_config", {})
    gc["notifications"] = cfg
    hub.state.system_state["global_config"] = gc
    # Flag state as changed so the hub saves it to disk.
    hub.state._mark_dirty()


# ---------------------------------------------------------------------------
# ACS connection-string parsing + credential/endpoint resolution
# ---------------------------------------------------------------------------

def _parse_acs_connstr(connstr: str) -> Tuple[str, str, str]:
    """Parse ``endpoint=https://<name>.communication.azure.com;accesskey=<key>``
    into ``(endpoint, resourcename, accesskey)``. ``resourcename`` is the first
    label of the endpoint host (the ACS SMTP auth user). Raises
    ``NotificationsError`` if malformed."""
    # Split the "k=v;k=v" string into a dict with lower-cased keys.
    parts = {}
    # Each ';'-separated segment is one key=value pair.
    for seg in str(connstr or "").split(";"):
        seg = seg.strip()
        # Ignore segments with no '='; split only on the first '=' since values may contain '='.
        if "=" in seg:
            k, _, v = seg.partition("=")
            parts[k.strip().lower()] = v.strip()
    # Pull the two required pieces out of the parsed pairs.
    endpoint = parts.get("endpoint", "")
    accesskey = parts.get("accesskey", "")
    # Both endpoint and access key are mandatory; fail with a hint of the expected format.
    if not endpoint or not accesskey:
        raise NotificationsError(
            "ACS connection string is malformed — expected "
            "'endpoint=https://<name>.communication.azure.com;accesskey=<key>'")
    # resource name = first label of the endpoint host
    host = endpoint.split("://", 1)[-1].split("/", 1)[0]
    resourcename = host.split(".", 1)[0]
    # An empty first label means the endpoint was unusable.
    if not resourcename:
        raise NotificationsError("could not derive ACS resource name from endpoint")
    # Strip a trailing slash so callers can append paths safely.
    return endpoint.rstrip("/"), resourcename, accesskey


async def _acs_connstr_kv(hub, cfg: Dict[str, Any],
                          http: Optional[httpx.AsyncClient] = None) -> str:
    """Pull the ACS connection string from Key Vault (optional cred source)."""
    # Work out which vault to read; without one there is nowhere to look.
    vault_url = _vault_url(hub, cfg)
    if not vault_url:
        raise NotificationsError("Key Vault URL not configured (set it in Key Vault or Notifications)")
    # Secret name defaults to the conventional "acs-email-connstr".
    secret_name = str(cfg.get("acs_kv_secret_name") or "acs-email-connstr")
    # Read the secret using the SSO app's OIDC credentials.
    oidc_cfg = get_oidc_config(hub)
    connstr = await key_vault.get_secret(oidc_cfg, vault_url, secret_name, http=http)
    # A missing/empty secret is a configuration error worth reporting clearly.
    if not connstr:
        raise NotificationsError(
            f"ACS connection string not found in Key Vault secret '{secret_name}'")
    # Return the raw connection string for the caller to parse.
    return connstr


async def _acs_connstr_arm(hub, cfg: Dict[str, Any],
                           http: Optional[httpx.AsyncClient] = None) -> str:
    """Auto-pull the ACS connection string from Azure via the
    ``communicationServices/{name}/listKeys`` ARM action (no Key Vault needed).
    The SSO app must hold a role with ``listKeys`` on the ACS resource
    (Contributor on the resource or its resource group covers it). Short TTL
    cache so a burst doesn't repeat the call but a key rotation is picked up."""
    # Read the three ARM coordinates that identify the ACS resource.
    sub = str(cfg.get("azure_subscription_id") or "").strip()
    rg = str(cfg.get("azure_resource_group") or "").strip()
    name = str(cfg.get("acs_resource_name") or "").strip()
    # All three are needed to build the listKeys URL.
    if not (sub and rg and name):
        raise NotificationsError(
            "ACS resource not configured — set subscription id, resource group, "
            "and the Communication Services resource name (or switch to the "
            "Key Vault cred source)")
    # Cache key identifies the ACS resource uniquely across subscriptions.
    cache_key = f"{sub}/{rg}/{name}"
    # time is imported locally to timestamp cache entries.
    import time as _t
    # Serve a cached connection string while it is younger than the TTL.
    cached = _ACS_ARM_CACHE.get(cache_key)
    if cached and (_t.time() - cached[0] < _ACS_ARM_CACHE_TTL):
        return cached[1]
    # Get an ARM token for the SSO app, then build the listKeys action URL.
    oidc_cfg = get_oidc_config(hub)
    token = await fetch_app_token(oidc_cfg, _ARM_SCOPE, http=http)
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.Communication/communicationServices/{name}"
           f"/listKeys?api-version={_ACS_ARM_API}")
    # listKeys is a POST action on the ACS resource.
    async with shared_client(http, 20.0) as c:
        resp = await c.post(url, headers={"Authorization": f"Bearer {token}"})
    # Anything but 200 (e.g. 403 missing role) is surfaced with the response text.
    if resp.status_code != 200:
        raise NotificationsError(
            f"ACS listKeys failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # Prefer the ready-made primary connection string from the response.
    body = resp.json()
    connstr = body.get("primaryConnectionString") or ""
    if not connstr:
        # Some API versions return only primaryKey; reconstruct from endpoint.
        pk = body.get("primaryKey") or ""
        if pk:
            connstr = f"endpoint=https://{name}.communication.azure.com;accesskey={pk}"
    # Neither form was returned, so there is nothing usable to send with.
    if not connstr:
        raise NotificationsError("ACS listKeys returned no connection string or key")
    # Remember the result with the current time so later calls within the TTL skip ARM.
    _ACS_ARM_CACHE[cache_key] = (_t.time(), connstr)
    return connstr


async def _acs_connstr(hub, cfg: Dict[str, Any],
                       http: Optional[httpx.AsyncClient] = None) -> str:
    """Resolve the ACS connection string per the configured cred source
    (ARM auto-pull by default; Key Vault optional)."""
    # Key Vault is only used when explicitly selected; ARM listKeys is the default.
    if str(cfg.get("acs_source") or "arm") == "keyvault":
        return await _acs_connstr_kv(hub, cfg, http=http)
    return await _acs_connstr_arm(hub, cfg, http=http)


async def list_azure_subscriptions(hub, http: Optional[httpx.AsyncClient] = None
                                   ) -> List[Dict[str, str]]:
    """List the Azure subscriptions the SSO app can see, via ARM (reuses the
    same ARM token as the NSG hook / listKeys path). Returns ``[{id, name}]``
    sorted by name — lets the Notifications tile pre-fill the subscription id
    instead of typing it. Empty list (not an error) if the app has no
    subscription-level read."""
    # Mint an ARM token and list every subscription the app can read.
    oidc_cfg = get_oidc_config(hub)
    token = await fetch_app_token(oidc_cfg, _ARM_SCOPE, http=http)
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    # GET the subscription list with the bearer token.
    async with shared_client(http, 20.0) as c:
        resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
    # Non-200 means the app lacks rights or ARM failed; report it.
    if resp.status_code != 200:
        raise NotificationsError(
            f"Azure subscription list failed: HTTP {resp.status_code} — "
            f"{resp.text[:300]}")
    # ARM returns subscriptions under "value"; tolerate a null body.
    subs = (resp.json() or {}).get("value", []) or []
    out = []
    # Keep only entries with an id, using the display name as the label.
    for s in subs:
        sid = str(s.get("subscriptionId") or "").strip()
        if not sid:
            continue
        out.append({"id": sid,
                    "name": str(s.get("displayName") or sid)})
    # Sort alphabetically (case-insensitive) for the dropdown.
    out.sort(key=lambda e: e["name"].lower())
    return out


async def list_azure_resource_groups(hub, subscription_id: str,
                                     http: Optional[httpx.AsyncClient] = None
                                     ) -> List[Dict[str, str]]:
    """List resource groups in ``subscription_id`` via ARM (same token as the
    NSG hook / listKeys path). Returns ``[{id, name}]`` sorted by name — drives
    the RG dropdown in the Notifications tile once a subscription is chosen, so
    the admin picks from what the SSO app can see instead of typing."""
    # A subscription id is required to scope the resource-group query.
    sub = (subscription_id or "").strip()
    if not sub:
        raise NotificationsError("Select a subscription before pulling resource groups.")
    # Mint an ARM token and build the resource-groups list URL.
    oidc_cfg = get_oidc_config(hub)
    token = await fetch_app_token(oidc_cfg, _ARM_SCOPE, http=http)
    url = (f"https://management.azure.com/subscriptions/{sub}"
           f"/resourceGroups?api-version=2021-04-01")
    # GET the resource groups with the bearer token.
    async with shared_client(http, 20.0) as c:
        resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
    # Non-200 means missing rights or an ARM failure; report it.
    if resp.status_code != 200:
        raise NotificationsError(
            f"Azure resource group list failed: HTTP {resp.status_code} — "
            f"{resp.text[:300]}")
    # Build {id, name} entries, skipping any group without a name.
    rgs = (resp.json() or {}).get("value", []) or []
    out = [{"id": str(r.get("id") or ""),
            "name": str(r.get("name") or "")}
           for r in rgs if r.get("name")]
    # Sort alphabetically (case-insensitive) for the dropdown.
    out.sort(key=lambda e: e["name"].lower())
    return out


async def list_acs_resources(hub, subscription_id: str, resource_group: str,
                             http: Optional[httpx.AsyncClient] = None
                             ) -> List[Dict[str, str]]:
    """List ``Microsoft.Communication/communicationServices`` resources in
    ``subscription_id`` / ``resource_group`` via ARM (same token as listKeys).
    Returns ``[{name, location, provisioningState, dataLocation, endpoint,
    fromEmail}]`` sorted by name — drives the ACS resource dropdown so the
    admin picks the exact resource ``listKeys`` will target, instead of typing
    the name. ``endpoint`` and ``fromEmail`` are derived from the resource
    name (the ACS data-plane endpoint is ``https://{name}.communication.
    azure.com`` and the default AzureManaged MailFrom domain is
    ``DoNotReply@{name}.azurecomm.net``) so the tile can auto-populate the
    sender field."""
    # Both subscription and resource group are needed to scope the query.
    sub = (subscription_id or "").strip()
    rg = (resource_group or "").strip()
    if not sub or not rg:
        raise NotificationsError(
            "Select a subscription and resource group before pulling ACS resources.")
    # Mint an ARM token and build the communicationServices list URL.
    oidc_cfg = get_oidc_config(hub)
    token = await fetch_app_token(oidc_cfg, _ARM_SCOPE, http=http)
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.Communication/communicationServices"
           f"?api-version={_ACS_ARM_API}")
    # GET the ACS resources with the bearer token.
    async with shared_client(http, 20.0) as c:
        resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
    # Non-200 means missing rights or an ARM failure; report it.
    if resp.status_code != 200:
        raise NotificationsError(
            f"ACS resource list failed: HTTP {resp.status_code} — "
            f"{resp.text[:300]}")
    # ARM returns the resources under "value"; tolerate a null body.
    items = (resp.json() or {}).get("value", []) or []
    out = []
    # Build one dropdown entry per named resource, deriving endpoint and default sender.
    for i in items:
        name = str(i.get("name") or "")
        if not name:
            continue
        props = i.get("properties") or {}
        out.append({
            "name": name,
            "location": str(i.get("location") or ""),
            "provisioningState": str(props.get("provisioningState") or ""),
            "dataLocation": str(props.get("dataLocation") or ""),
            "endpoint": f"https://{name}.communication.azure.com",
            "fromEmail": f"DoNotReply@{name}.azurecomm.net",
        })
    # Sort alphabetically (case-insensitive) for the dropdown.
    out.sort(key=lambda e: e["name"].lower())
    return out


async def list_acs_sender_domains(hub, subscription_id: str, resource_group: str,
                                  acs_name: str,
                                  http: Optional[httpx.AsyncClient] = None
                                  ) -> List[Dict[str, str]]:
    """Sender MailFrom addresses for the email domains actually LINKED to the
    given Communication Services resource. GETs the ACS resource and reads
    ``properties.linkedDomains`` (email-domain resource IDs), deriving
    ``DoNotReply@<domain>`` from each. An EMPTY list is the ``DomainNotLinked``
    cause: the ACS resource has no CONNECTED domain, so nothing can send from it
    until one is linked (Azure → Communication Services → Email → Domains →
    Connect domain). Only needs resource READ (not listKeys)."""
    # Normalize the three identifiers; all are required to address the resource.
    sub = (subscription_id or "").strip()
    rg = (resource_group or "").strip()
    name = (acs_name or "").strip()
    if not (sub and rg and name):
        raise NotificationsError("subscription, resource group, and ACS resource are required")
    # Mint an ARM token and build the GET URL for this one ACS resource.
    oidc_cfg = get_oidc_config(hub)
    token = await fetch_app_token(oidc_cfg, _ARM_SCOPE, http=http)
    url = (f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
           f"/providers/Microsoft.Communication/communicationServices/{name}"
           f"?api-version={_ACS_ARM_API}")
    # GET the resource definition (read access is enough).
    async with shared_client(http, 20.0) as c:
        resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
    # Non-200 means missing rights or the resource was not found; report it.
    if resp.status_code != 200:
        raise NotificationsError(
            f"ACS resource GET failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # linkedDomains lists the email-domain resource ids connected to this ACS resource.
    props = (resp.json() or {}).get("properties", {}) or {}
    linked = props.get("linkedDomains") or []
    out = []
    # Turn each linked domain resource id into a DoNotReply@<domain> sender suggestion.
    for dom_id in linked:
        # resource id: .../emailServices/<email>/domains/<domain> — the last
        # segment is the domain name (a GUID .azurecomm.net or a custom domain).
        domain = str(dom_id or "").rstrip("/").split("/")[-1].strip()
        # Skip ids that produced an empty domain.
        if domain:
            out.append({"domain": domain, "sender": f"DoNotReply@{domain}"})
    # Sort by domain name for a stable dropdown order.
    out.sort(key=lambda e: e["domain"].lower())
    return out


async def _resolve(hub, cfg: Dict[str, Any],
                   http: Optional[httpx.AsyncClient] = None
                   ) -> Tuple[str, Any]:
    """Resolve how to send for this config.

    Returns ``(mode, payload)``:
      - ``("acs_api", (endpoint, resourcename, accesskey))`` — caller signs the
        request with the access key (HMAC-SHA256) and POSTs the ACS email
        endpoint.
      - ``("smtp", (host, port, user, password, starttls))`` — caller does
        smtplib STARTTLS.
    """
    # Azure ACS needs its connection string; every other provider is plain SMTP.
    provider = cfg.get("provider", "azure_acs")
    if provider == "azure_acs":
        # Fetch and parse the connection string into endpoint, resource name, and key.
        connstr = await _acs_connstr(hub, cfg, http=http)
        endpoint, resourcename, accesskey = _parse_acs_connstr(connstr)
        # ACS SMTP transport: user is the resource name and the password is the access key.
        if cfg.get("transport", "api") == "smtp":
            return "smtp", (_ACS_SMTP_HOST, _ACS_SMTP_PORT, resourcename, accesskey, True)
        # Default ACS transport is the signed REST API.
        return "acs_api", (endpoint, resourcename, accesskey)

    # SMTP providers (gmail / yahoo / office365 / generic)
    # Fall back to the generic preset for unknown providers; a saved host overrides the preset.
    preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["generic"])
    host = str(cfg.get("smtp_host") or "").strip() or preset["host"]
    # SMTP cannot work without a host.
    if not host:
        raise NotificationsError(f"SMTP host not configured for provider '{provider}'")
    # Use the saved port; a non-numeric value falls back to the preset port.
    try:
        port = int(cfg.get("smtp_port") or preset["port"])
    except (TypeError, ValueError):
        port = int(preset["port"])
    # Saved username plus the encrypted password (if any).
    user = str(cfg.get("smtp_user") or "")
    enc = str(cfg.get("smtp_password_enc") or "")
    # Decrypt the stored Fernet ciphertext to get the real password.
    if enc:
        password = hub_encryption.decrypt(enc.encode())
    else:
        # Plaintext fallback (a posted-but-unsaved form value from the Test
        # button); never persisted — the route encrypts before storing.
        password = str(cfg.get("smtp_password") or "")
    # Every SMTP provider here requires a password.
    if not password:
        raise NotificationsError(f"SMTP password not set for provider '{provider}'")
    # Return SMTP settings, with STARTTLS taken from the provider preset.
    return "smtp", (host, port, user, password, bool(preset["starttls"]))


# ---------------------------------------------------------------------------
# recipient normalization
# ---------------------------------------------------------------------------

def _normalize_recipients(val: Any) -> List[str]:
    """Accept a list or a comma/whitespace-separated string → flat list of
    trimmed addresses."""
    # A list/tuple is used as-is; anything else is treated as a separated string.
    if isinstance(val, (list, tuple)):
        raw = val
    else:
        raw = str(val or "").replace(",", " ").split()
    # Trim each address and drop blanks.
    out = [str(x).strip() for x in raw if str(x).strip()]
    return out


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------

def _smtp_send(host: str, port: int, user: str, password: str,
               starttls: bool, msg: EmailMessage) -> None:
    """Send one message over SMTP, upgrading to TLS first when starttls is set.

    Blocking; callers run it via asyncio.to_thread.
    """
    # Open the SMTP connection with a 20s timeout so a dead server cannot hang a thread.
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.ehlo()
        # Upgrade to TLS and re-greet, since the server's capabilities change after STARTTLS.
        if starttls:
            s.starttls(context=ssl.create_default_context())
            s.ehlo()
        # Authenticate only when a username is configured (some relays are open).
        if user:
            s.login(user, password)
        # Hand the full MIME message to the server.
        s.send_message(msg)


async def _acs_api_send(endpoint: str, accesskey: str, sender: str,
                        recipients: List[str], subject: str, body: str,
                        html: str = "",
                        http: Optional[httpx.AsyncClient] = None) -> None:
    """POST {endpoint}/emails:send signed with the ACS access key
    (HMAC-SHA256). No Entra token/permission needed — the key is parsed from
    the same Key Vault connection string. ``html`` (optional) adds an HTML body
    alongside the plain-text one (used by the scheduled report / alert emails)."""
    # ACS send endpoint, plus the subject/plain-text content block.
    url = f"{endpoint}/emails:send?api-version={_ACS_API_VERSION}"
    content = {"subject": subject, "plainText": body}
    # Include an HTML body only when one was supplied.
    if html:
        content["html"] = html
    # GA ACS payload: sender, list of recipient addresses, and the content.
    payload = {
        "senderAddress": sender,
        "recipients": {"to": [{"address": a} for a in recipients]},
        "content": content,
    }
    # Serialize once; the exact same bytes are hashed and sent.
    body_bytes = json.dumps(payload).encode()
    # Split the URL to get the path+query and host that go into the signature.
    parts = urlsplit(url)
    path_and_query = parts.path + (("?" + parts.query) if parts.query else "")
    host = parts.hostname or ""
    # Base64 SHA-256 of the body, required as x-ms-content-sha256.
    content_hash = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode()
    date = formatdate(timeval=None, usegmt=True)  # RFC1123, e.g. "Mon, 01 Jan 2024 12:00:00 GMT"
    # ACS string-to-sign: verb, path+query, then "date;host;content-hash".
    string_to_sign = f"POST\n{path_and_query}\n{date};{host};{content_hash}"
    # The access key is base64; decode it to raw bytes for HMAC (bad keys give a clear error).
    try:
        key_bytes = base64.b64decode(accesskey)
    except Exception as e:  # noqa: BLE001
        raise NotificationsError(f"ACS access key is not valid base64: {e}")
    # Sign the string with HMAC-SHA256 and base64-encode the result.
    sig = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode(), hashlib.sha256).digest()).decode()
    # Headers ACS checks: the signed date, body hash, and HMAC Authorization header.
    headers = {
        "x-ms-date": date,
        "x-ms-content-sha256": content_hash,
        "Authorization": (f"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256"
                          f"&Signature={sig}"),
        "Content-Type": "application/json",
    }
    # POST the signed request.
    async with shared_client(http, 20.0) as c:
        resp = await c.post(url, headers=headers, content=body_bytes)
    # ACS replies 202 Accepted normally; anything outside 200-202 is a failure.
    if resp.status_code not in (200, 201, 202):
        raise NotificationsError(
            f"ACS email send failed: HTTP {resp.status_code} — {resp.text[:300]}")


async def push_acs_secret(hub, connstr: str,
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """One-time: write the ACS connection string into the Key Vault secret
    using the SSO app (which has Set). Lets an admin provision the secret from
    the Notifications tile without personal data-plane access to the vault."""
    # Load config and find the target vault; without one there is nowhere to write.
    cfg = get_config(hub)
    vault_url = _vault_url(hub, cfg)
    if not vault_url:
        raise NotificationsError("Key Vault URL not configured (set it in Key Vault or Notifications)")
    # Secret name defaults to the conventional "acs-email-connstr".
    secret_name = str(cfg.get("acs_kv_secret_name") or "acs-email-connstr")
    # Basic sanity check so an obviously wrong value is never stored.
    connstr = str(connstr or "").strip()
    if "accesskey=" not in connstr or "endpoint=" not in connstr:
        raise NotificationsError(
            "connection string looks malformed — expected "
            "'endpoint=https://<name>.communication.azure.com;accesskey=<key>'")
    # Write the secret using the SSO app's credentials.
    sid = await key_vault.set_secret(get_oidc_config(hub), vault_url, secret_name,
                                     connstr, http=http)
    # Log the secret name only (never the value) and report what was written.
    logger.info("notifications: pushed ACS connection string to Key Vault secret '%s'", secret_name)
    return {"secret": secret_name, "id": sid}


async def _tenant_recipients(hub, spoke_id: str) -> List[str]:
    """Resolve a spoke's alert recipients from the per-tenant notifications
    config — the cs tenant Notifications card stores ``to_emails`` in the
    simulations store (``hub.simulations_store.get_notifications``), keyed by
    the tenant the spoke is bound to (``state.get_spoke_tenant``). Returns
    ``[]`` if the spoke isn't tenant-bound or the tenant hasn't configured
    recipients; the caller then falls back to the hub's global list.

    Import-free on purpose: this is a leaf module, so the store and the
    tenant binding are reached through the ``hub`` object (no back-import)."""
    # Look up which tenant this spoke belongs to; any failure means no tenant recipients.
    try:
        tenant_id = hub.state.get_spoke_tenant(spoke_id)
    except Exception:  # noqa: BLE001
        return []
    # Unbound spokes have no tenant recipient list.
    if not tenant_id:
        return []
    # The simulations store holds tenant notification settings; it may not exist.
    store = getattr(hub, "simulations_store", None)
    if store is None:
        return []
    # Read the tenant's notification settings; a failure means fall back to global recipients.
    try:
        ncfg = await store.get_notifications(tenant_id)
    except Exception:  # noqa: BLE001
        return []
    # Normalize the tenant's to_emails into a clean list.
    return _normalize_recipients((ncfg or {}).get("to_emails"))


async def send_email(hub, subject: str, body: str,
                     to_emails: Any = None,
                     spoke_id: Optional[str] = None,
                     html: str = "",
                     http: Optional[httpx.AsyncClient] = None) -> bool:
    """Send one email using the hub's notifications config. Returns False (and
    logs) when notifications are disabled or there are no recipients — never
    raises from the alert-loop call site's perspective; callers that need the
    error (the Test button) call ``send_test`` instead.

    Recipient resolution order: an explicit ``to_emails`` list wins; else, if
    ``spoke_id`` is given, the per-tenant recipients from the cs tenant
    Notifications card are used (falling back to the hub's global list when the
    tenant hasn't configured any, so an unconfigured tenant's alerts still go
    somewhere); else the hub's global ``to_emails``."""
    # Do nothing when the channel is switched off.
    cfg = get_config(hub)
    if not cfg.get("enabled", False):
        logger.debug("notifications: disabled — skipping send")
        return False
    # Explicit recipients win over everything else.
    if to_emails is not None:
        recipients = _normalize_recipients(to_emails)
    # Otherwise use the spoke's tenant recipients, falling back to the global list.
    elif spoke_id:
        recipients = await _tenant_recipients(hub, spoke_id)
        if not recipients:
            recipients = _normalize_recipients(cfg.get("to_emails"))
    # No spoke context: use the global recipient list.
    else:
        recipients = _normalize_recipients(cfg.get("to_emails"))
    # Without recipients there is nobody to send to.
    if not recipients:
        logger.warning("notifications: no recipients — skipping send")
        return False
    # A sender address is mandatory for both ACS and SMTP.
    sender = str(cfg.get("from_email") or "").strip()
    if not sender:
        logger.warning("notifications: no from_email configured — skipping send")
        return False
    # Any send failure is logged and swallowed so alert loops keep running.
    try:
        # Work out the transport and credentials for the current config.
        mode, payload = await _resolve(hub, cfg, http=http)
        # ACS REST transport.
        if mode == "acs_api":
            endpoint, _resourcename, accesskey = payload
            await _acs_api_send(endpoint, accesskey, sender,
                                recipients, subject, body, html=html, http=http)
        # SMTP transport: build a MIME message with plain text (and HTML if given).
        else:
            host, port, user, password, starttls = payload
            msg = EmailMessage()
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            msg.set_content(body)
            if html:
                msg.add_alternative(html, subtype="html")
            # Run the blocking SMTP send on a worker thread.
            await asyncio.to_thread(_smtp_send, host, port, user, password,
                                    starttls, msg)
        # Log success with the subject and recipient count.
        logger.info("notifications: sent '%s' to %d recipient(s) via %s",
                    subject, len(recipients), cfg.get("provider"))
        return True
    except Exception as e:  # noqa: BLE001
        # error-level so it lands in the Error Log feed (matches collect_error_logs)
        logger.error("notifications: send failed: %s", e)
        return False


async def send_test(hub, cfg_override: Optional[Dict[str, Any]] = None,
                    http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Send a test email. Does NOT short-circuit on ``enabled`` (the Test button
    works while the toggle is off, mirroring ``key_vault.test_connection``).
    ``cfg_override`` (the posted form, merged over saved config) lets the Test
    button validate unsaved edits without persisting. Returns a status dict;
    raises ``NotificationsError`` on failure."""
    # Start from saved config, overlaid with any unsaved form values.
    cfg = get_config(hub)
    if cfg_override:
        cfg = {**cfg, **cfg_override}
    # Recipients and sender are required; raise so the UI shows the reason.
    recipients = _normalize_recipients(cfg.get("to_emails"))
    if not recipients:
        raise NotificationsError("no recipients configured (set 'To Emails' first)")
    sender = str(cfg.get("from_email") or "").strip()
    if not sender:
        raise NotificationsError("no from_email configured")
    # Resolve transport/credentials (raises on bad config so the Test button reports it).
    mode, payload = await _resolve(hub, cfg, http=http)
    # Fixed subject and a body describing the provider/transport being tested.
    subject = "[LM Hub] notifications test"
    body = (f"This is a test email from the LM Hub notifications channel.\n"
            f"Provider: {cfg.get('provider')}\n"
            f"Transport: {cfg.get('transport') if cfg.get('provider') == 'azure_acs' else 'smtp'}\n"
            f"From: {sender}\n")
    # ACS REST transport: send and describe the endpoint used.
    if mode == "acs_api":
        endpoint, resourcename, accesskey = payload
        await _acs_api_send(endpoint, accesskey, sender, recipients,
                            subject, body, http=http)
        host_info = f"{endpoint} (ACS API, resource {resourcename})"
    # SMTP transport: build the message and send it on a worker thread.
    else:
        host, port, user, password, starttls = payload
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg.set_content(body)
        await asyncio.to_thread(_smtp_send, host, port, user, password,
                                starttls, msg)
        host_info = f"{host}:{port} (SMTP)"
    # Report success and which path was used.
    return {"status": "ok", "provider": cfg.get("provider"),
            "host": host_info, "recipients": len(recipients)}