"""Cloud NAC — JIT Entra account provisioning (hub broker).

When the cs SimQuotaEngine moves a client onto a 1X SSID, the spoke asks the HUB
(which holds the Entra app cert) to JIT-create that user's Entra account and hand
back a random password; the spoke delivers it to the client as its
``dot1x_password`` override. Accounts idle for ``idle_days`` (no Entra sign-in)
are swept + deleted.

Auth reuses the SSO app cert (``security.oidc.fetch_app_token``, Graph scope). The
app registration needs these Graph **application** permissions (admin-consented):
  * ``User.ReadWrite.All`` — create / reset / delete the accounts;
  * ``AuditLog.Read.All`` — read ``signInActivity`` for the idle sweep (Entra ID P1).

Errors carry the Graph body so the route/UI can show the real reason.
"""
from __future__ import annotations

import logging
import secrets
import string
from typing import Any, Dict, List, Optional

import httpx

from security.oidc import OidcConfig, fetch_app_token

logger = logging.getLogger("CloudNac")

_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class CloudNacError(Exception):
    """Raised for any Graph/provisioning failure; message is safe to surface."""


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_config(system_state: dict) -> dict:
    """The tenant-independent Cloud NAC config (global_config['cloud_nac']) with
    defaults. Hub state is Fernet-encrypted at rest, so the recorded passwords
    (stored alongside under 'cloud_nac_accounts') are protected."""
    c = dict((system_state.get("global_config", {}) or {}).get("cloud_nac", {}) or {})
    c.setdefault("enabled", False)
    c.setdefault("domain", "")
    c.setdefault("idle_days", 7)
    return c


def record_account(system_state: dict, result: Dict[str, Any]) -> dict:
    """Persist a provisioned account (incl. its password) into the hub state's
    'cloud_nac_accounts' map, keyed by username. Returns the stored record."""
    accts = system_state.setdefault("cloud_nac_accounts", {})
    u = result["username"]
    prev = accts.get(u, {}) if isinstance(accts.get(u), dict) else {}
    rec = {
        "username": u, "upn": result["upn"], "oid": result.get("oid"),
        "password": result["password"],
        "created_at": prev.get("created_at") or _now_iso(),
        "provisioned_at": _now_iso(),
    }
    accts[u] = rec
    return rec


def forget_account(system_state: dict, username: str) -> Optional[dict]:
    """Drop a username from the local store (after Entra delete). Returns the
    removed record or None."""
    accts = system_state.get("cloud_nac_accounts", {}) or {}
    return accts.pop(str(username), None)


def gen_password(n: int = 20) -> str:
    """A random password meeting Entra complexity (>=3 of 4 classes) — we include
    all four and shuffle. Length ``n`` (>=8)."""
    lo, up, dg = string.ascii_lowercase, string.ascii_uppercase, string.digits
    sy = "!@#$%^&*()-_=+"
    n = max(8, n)
    pw = [secrets.choice(lo), secrets.choice(up), secrets.choice(dg), secrets.choice(sy)]
    allc = lo + up + dg + sy
    pw += [secrets.choice(allc) for _ in range(n - 4)]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


async def _graph(method: str, path: str, token: str, *, json=None, params=None,
                 http: Optional[httpx.AsyncClient] = None):
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        return await c.request(
            method, f"{_GRAPH}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=json, params=params)


async def get_user(token: str, ident: str, http: Optional[httpx.AsyncClient] = None) -> Optional[dict]:
    """GET a user by UPN or objectId; None if not found."""
    resp = await _graph("GET", f"/users/{ident}", token,
                        params={"$select": "id,userPrincipalName,accountEnabled"}, http=http)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise CloudNacError(f"Graph GET user {ident} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return resp.json()


async def provision_user(cfg: OidcConfig, domain: str, username: str,
                         http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Create the Entra account for ``username`` (or reset its password if it
    exists), non-interactive (``forceChangePasswordNextSignIn=false`` so a
    headless MSCHAPv2 client can auth). Returns
    ``{username, upn, oid, password, created}``. The caller records the password."""
    username = str(username or "").strip().lower()
    if not username:
        raise CloudNacError("empty username")
    domain = str(domain or "").strip()
    if not domain:
        raise CloudNacError("UPN domain not configured")
    upn = f"{username}@{domain}"
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    password = gen_password()
    existing = await get_user(token, upn, http=http)
    if existing:
        oid = existing["id"]
        resp = await _graph("PATCH", f"/users/{oid}", token, json={
            "accountEnabled": True,
            "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
        }, http=http)
        if resp.status_code not in (200, 204):
            raise CloudNacError(f"Graph reset password {upn} failed: HTTP {resp.status_code} — {resp.text[:200]}")
        logger.info("Cloud NAC reset password for existing Entra user %s", upn)
        return {"username": username, "upn": upn, "oid": oid, "password": password, "created": False}
    body = {
        "accountEnabled": True,
        "displayName": username,
        "mailNickname": username,
        "userPrincipalName": upn,
        "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
    }
    resp = await _graph("POST", "/users", token, json=body, http=http)
    if resp.status_code not in (200, 201):
        raise CloudNacError(f"Graph create user {upn} failed: HTTP {resp.status_code} — {resp.text[:300]}")
    oid = resp.json().get("id")
    logger.info("Cloud NAC provisioned Entra user %s (oid=%s)", upn, oid)
    return {"username": username, "upn": upn, "oid": oid, "password": password, "created": True}


async def delete_user(cfg: OidcConfig, ident: str,
                      http: Optional[httpx.AsyncClient] = None) -> bool:
    """Delete the Entra account (by UPN or oid). 404 is treated as success."""
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    resp = await _graph("DELETE", f"/users/{ident}", token, http=http)
    if resp.status_code not in (200, 204, 404):
        raise CloudNacError(f"Graph delete {ident} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


async def last_signin(cfg: OidcConfig, ident: str,
                      http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Most recent Entra sign-in (interactive or non-interactive) ISO timestamp,
    or None if never / no data. Needs AuditLog.Read.All + Entra ID P1."""
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    resp = await _graph("GET", f"/users/{ident}", token,
                        params={"$select": "id,signInActivity"}, http=http)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise CloudNacError(f"Graph signInActivity {ident} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    sa = resp.json().get("signInActivity") or {}
    times = [t for t in (sa.get("lastSignInDateTime"),
                         sa.get("lastNonInteractiveSignInDateTime")) if t]
    return max(times) if times else None
