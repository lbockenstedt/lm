"""Hub email notifications — multi-provider SMTP + Azure ACS REST API.

A platform-level alert channel for the hub. Today the hub has no email-sending
path at all (the only SMTP config in the repo is per-tenant and *forwarded* to
the remote cs spoke, which does the actual send). This module lets the hub send
its own alerts — starting with spoke out-of-contact (``spoke_alert_sync.py``).

Provider dropdown (``global_config["notifications"]``):

  * ``azure_acs`` — Azure Communication Services Email. Sender creds are
    **auto-pulled from Key Vault** (the "automatic" path): a secret holds the
    ACS connection string ``endpoint=https://<name>.communication.azure.com;
    accesskey=<key>``. Two transports:
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

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from security.encryption import hub_encryption
from security.oidc import get_oidc_config
import key_vault

logger = logging.getLogger("Notifications")

_ACS_API_VERSION = "2023-07-01-preview"
_ACS_SMTP_HOST = "smtp.azurecomm.net"
_ACS_SMTP_PORT = 587

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

CFG_FIELDS = ("enabled", "provider", "transport", "smtp_host", "smtp_port",
              "smtp_user", "smtp_password_enc", "acs_kv_secret_name",
              "vault_url", "from_email", "to_emails")
DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "provider": "azure_acs",
    "transport": "api",          # only meaningful for azure_acs; others are SMTP
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
    c = dict(DEFAULTS)
    c.update((hub.state.system_state.get("global_config", {}) or {})
             .get("notifications", {}) or {})
    return c


def _vault_url(hub, cfg: Dict[str, Any]) -> str:
    """The notifications vault URL, falling back to the DR Key Vault URL when
    blank so a one-vault deployment doesn't need a second entry."""
    v = str(cfg.get("vault_url") or "").strip()
    if v:
        return v
    try:
        return str(key_vault.get_config(hub).get("vault_url") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def save_config(hub, cfg: Dict[str, Any]) -> None:
    gc = hub.state.system_state.get("global_config", {})
    gc["notifications"] = cfg
    hub.state.system_state["global_config"] = gc
    hub.state.save_state()


# ---------------------------------------------------------------------------
# ACS connection-string parsing + credential/endpoint resolution
# ---------------------------------------------------------------------------

def _parse_acs_connstr(connstr: str) -> Tuple[str, str, str]:
    """Parse ``endpoint=https://<name>.communication.azure.com;accesskey=<key>``
    into ``(endpoint, resourcename, accesskey)``. ``resourcename`` is the first
    label of the endpoint host (the ACS SMTP auth user). Raises
    ``NotificationsError`` if malformed."""
    parts = {}
    for seg in str(connstr or "").split(";"):
        seg = seg.strip()
        if "=" in seg:
            k, _, v = seg.partition("=")
            parts[k.strip().lower()] = v.strip()
    endpoint = parts.get("endpoint", "")
    accesskey = parts.get("accesskey", "")
    if not endpoint or not accesskey:
        raise NotificationsError(
            "ACS connection string is malformed — expected "
            "'endpoint=https://<name>.communication.azure.com;accesskey=<key>'")
    # resource name = first label of the endpoint host
    host = endpoint.split("://", 1)[-1].split("/", 1)[0]
    resourcename = host.split(".", 1)[0]
    if not resourcename:
        raise NotificationsError("could not derive ACS resource name from endpoint")
    return endpoint.rstrip("/"), resourcename, accesskey


async def _acs_connstr(hub, cfg: Dict[str, Any],
                       http: Optional[httpx.AsyncClient] = None) -> str:
    """Pull the ACS connection string from Key Vault (auto-managed creds)."""
    vault_url = _vault_url(hub, cfg)
    if not vault_url:
        raise NotificationsError("Key Vault URL not configured (set it in Key Vault or Notifications)")
    secret_name = str(cfg.get("acs_kv_secret_name") or "acs-email-connstr")
    oidc_cfg = get_oidc_config(hub)
    connstr = await key_vault.get_secret(oidc_cfg, vault_url, secret_name, http=http)
    if not connstr:
        raise NotificationsError(
            f"ACS connection string not found in Key Vault secret '{secret_name}'")
    return connstr


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
    provider = cfg.get("provider", "azure_acs")
    if provider == "azure_acs":
        connstr = await _acs_connstr(hub, cfg, http=http)
        endpoint, resourcename, accesskey = _parse_acs_connstr(connstr)
        if cfg.get("transport", "api") == "smtp":
            return "smtp", (_ACS_SMTP_HOST, _ACS_SMTP_PORT, resourcename, accesskey, True)
        return "acs_api", (endpoint, resourcename, accesskey)

    # SMTP providers (gmail / yahoo / office365 / generic)
    preset = PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["generic"])
    host = str(cfg.get("smtp_host") or "").strip() or preset["host"]
    if not host:
        raise NotificationsError(f"SMTP host not configured for provider '{provider}'")
    try:
        port = int(cfg.get("smtp_port") or preset["port"])
    except (TypeError, ValueError):
        port = int(preset["port"])
    user = str(cfg.get("smtp_user") or "")
    enc = str(cfg.get("smtp_password_enc") or "")
    if enc:
        password = hub_encryption.decrypt(enc.encode())
    else:
        # Plaintext fallback (a posted-but-unsaved form value from the Test
        # button); never persisted — the route encrypts before storing.
        password = str(cfg.get("smtp_password") or "")
    if not password:
        raise NotificationsError(f"SMTP password not set for provider '{provider}'")
    return "smtp", (host, port, user, password, bool(preset["starttls"]))


# ---------------------------------------------------------------------------
# recipient normalization
# ---------------------------------------------------------------------------

def _normalize_recipients(val: Any) -> List[str]:
    """Accept a list or a comma/whitespace-separated string → flat list of
    trimmed addresses."""
    if isinstance(val, (list, tuple)):
        raw = val
    else:
        raw = str(val or "").replace(",", " ").split()
    out = [str(x).strip() for x in raw if str(x).strip()]
    return out


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------

def _smtp_send(host: str, port: int, user: str, password: str,
               starttls: bool, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.ehlo()
        if starttls:
            s.starttls(context=ssl.create_default_context())
            s.ehlo()
        if user:
            s.login(user, password)
        s.send_message(msg)


async def _acs_api_send(endpoint: str, accesskey: str, sender: str,
                        recipients: List[str], subject: str, body: str,
                        http: Optional[httpx.AsyncClient] = None) -> None:
    """POST {endpoint}/emails:send signed with the ACS access key
    (HMAC-SHA256). No Entra token/permission needed — the key is parsed from
    the same Key Vault connection string."""
    url = f"{endpoint}/emails:send?api-version={_ACS_API_VERSION}"
    payload = {
        "senderAddress": sender,
        "recipients": {"to": [{"address": a} for a in recipients]},
        "content": {"subject": subject, "plainText": body},
    }
    body_bytes = json.dumps(payload).encode()
    parts = urlsplit(url)
    path_and_query = parts.path + (("?" + parts.query) if parts.query else "")
    host = parts.hostname or ""
    content_hash = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode()
    date = formatdate(timeval=None, usegmt=True)  # RFC1123, e.g. "Mon, 01 Jan 2024 12:00:00 GMT"
    string_to_sign = f"POST\n{path_and_query}\n{date};{host};{content_hash}"
    try:
        key_bytes = base64.b64decode(accesskey)
    except Exception as e:  # noqa: BLE001
        raise NotificationsError(f"ACS access key is not valid base64: {e}")
    sig = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode(), hashlib.sha256).digest()).decode()
    headers = {
        "x-ms-date": date,
        "x-ms-content-sha256": content_hash,
        "Authorization": (f"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256"
                          f"&Signature={sig}"),
        "Content-Type": "application/json",
    }
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.post(url, headers=headers, content=body_bytes)
    if resp.status_code not in (200, 201, 202):
        raise NotificationsError(
            f"ACS email send failed: HTTP {resp.status_code} — {resp.text[:300]}")


async def push_acs_secret(hub, connstr: str,
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """One-time: write the ACS connection string into the Key Vault secret
    using the SSO app (which has Set). Lets an admin provision the secret from
    the Notifications tile without personal data-plane access to the vault."""
    cfg = get_config(hub)
    vault_url = _vault_url(hub, cfg)
    if not vault_url:
        raise NotificationsError("Key Vault URL not configured (set it in Key Vault or Notifications)")
    secret_name = str(cfg.get("acs_kv_secret_name") or "acs-email-connstr")
    connstr = str(connstr or "").strip()
    if "accesskey=" not in connstr or "endpoint=" not in connstr:
        raise NotificationsError(
            "connection string looks malformed — expected "
            "'endpoint=https://<name>.communication.azure.com;accesskey=<key>'")
    sid = await key_vault.set_secret(get_oidc_config(hub), vault_url, secret_name,
                                     connstr, http=http)
    logger.info("notifications: pushed ACS connection string to Key Vault secret '%s'", secret_name)
    return {"secret": secret_name, "id": sid}


async def send_email(hub, subject: str, body: str,
                     to_emails: Any = None,
                     http: Optional[httpx.AsyncClient] = None) -> bool:
    """Send one email using the hub's notifications config. Returns False (and
    logs) when notifications are disabled or there are no recipients — never
    raises from the alert-loop call site's perspective; callers that need the
    error (the Test button) call ``send_test`` instead."""
    cfg = get_config(hub)
    if not cfg.get("enabled", False):
        logger.debug("notifications: disabled — skipping send")
        return False
    recipients = _normalize_recipients(to_emails if to_emails is not None else cfg.get("to_emails"))
    if not recipients:
        logger.warning("notifications: no recipients — skipping send")
        return False
    sender = str(cfg.get("from_email") or "").strip()
    if not sender:
        logger.warning("notifications: no from_email configured — skipping send")
        return False
    try:
        mode, payload = await _resolve(hub, cfg, http=http)
        if mode == "acs_api":
            endpoint, _resourcename, accesskey = payload
            await _acs_api_send(endpoint, accesskey, sender,
                                recipients, subject, body, http=http)
        else:
            host, port, user, password, starttls = payload
            msg = EmailMessage()
            msg["From"] = sender
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = subject
            msg.set_content(body)
            await asyncio.to_thread(_smtp_send, host, port, user, password,
                                    starttls, msg)
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
    cfg = get_config(hub)
    if cfg_override:
        cfg = {**cfg, **cfg_override}
    recipients = _normalize_recipients(cfg.get("to_emails"))
    if not recipients:
        raise NotificationsError("no recipients configured (set 'To Emails' first)")
    sender = str(cfg.get("from_email") or "").strip()
    if not sender:
        raise NotificationsError("no from_email configured")
    mode, payload = await _resolve(hub, cfg, http=http)
    subject = "[LM Hub] notifications test"
    body = (f"This is a test email from the LM Hub notifications channel.\n"
            f"Provider: {cfg.get('provider')}\n"
            f"Transport: {cfg.get('transport') if cfg.get('provider') == 'azure_acs' else 'smtp'}\n"
            f"From: {sender}\n")
    if mode == "acs_api":
        endpoint, resourcename, accesskey = payload
        await _acs_api_send(endpoint, accesskey, sender, recipients,
                            subject, body, http=http)
        host_info = f"{endpoint} (ACS API, resource {resourcename})"
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
    return {"status": "ok", "provider": cfg.get("provider"),
            "host": host_info, "recipients": len(recipients)}