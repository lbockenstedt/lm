"""Cloud NAC — JIT Entra account provisioning (hub broker).

Graph primitives for the Entra backend of the JIT 802.1X broker
(``dot1x_jit``): when the cs SimQuotaEngine moves a client onto a 1X SSID cell
whose account location is ``entra``, the hub creates the user's Entra account
with a random password and delivers it to the client as its ``dot1x_password``
override. The ``/setup/cloud-nac`` routes keep the manual admin tools (and
``idle_days`` sweep) for accounts provisioned by hand.

Auth reuses the SSO app cert (``security.oidc.fetch_app_token``, Graph scope). The
app registration needs these Graph **application** permissions (admin-consented):
  * ``User.ReadWrite.All`` — create / reset / delete the accounts;
  * ``AuditLog.Read.All`` — read ``signInActivity`` for the idle sweep (Entra ID P1).

Errors carry the Graph body so the route/UI can show the real reason.
"""
# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio.sleep is used to wait between retries while Entra replicates a new user.
import asyncio
# Standard-library logging for provisioning messages.
import logging
# secrets picks cryptographically strong random password characters.
import secrets
# string supplies the letter/digit character classes for passwords.
import string
# Type hints only.
from typing import Any, Dict, List, Optional

# httpx is the async HTTP client used for Microsoft Graph calls.
import httpx

# Helper that reuses a caller's HTTP client or creates (and closes) its own.
from http_client import shared_client

# OIDC config type and the helper that gets an app-only Graph access token.
from security.oidc import OidcConfig, fetch_app_token

# One named logger so Cloud NAC messages can be filtered together.
logger = logging.getLogger("CloudNac")

# Base URL of the Microsoft Graph v1.0 REST API.
_GRAPH = "https://graph.microsoft.com/v1.0"
# OAuth scope meaning "all Graph application permissions granted to this app".
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class CloudNacError(Exception):
    """Raised for any Graph/provisioning failure; message is safe to surface."""


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    # Imported lazily; only needed for this helper.
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def get_config(system_state: dict) -> dict:
    """The tenant-independent Cloud NAC config (global_config['cloud_nac']) with
    defaults. Hub state is Fernet-encrypted at rest, so the recorded passwords
    (stored alongside under 'cloud_nac_accounts') are protected."""
    # Copy the stored cloud_nac settings (never mutate state); "or {}" guards against None.
    c = dict((system_state.get("global_config", {}) or {}).get("cloud_nac", {}) or {})
    # Fill in defaults: disabled, no UPN domain, and a 7-day idle-account sweep.
    c.setdefault("enabled", False)
    c.setdefault("domain", "")
    c.setdefault("idle_days", 7)
    # Return the merged config.
    return c


def record_account(system_state: dict, result: Dict[str, Any]) -> dict:
    """Persist a provisioned account (incl. its password) into the hub state's
    'cloud_nac_accounts' map, keyed by username. Returns the stored record."""
    # Get (creating if needed) the username -> account record map in hub state.
    accts = system_state.setdefault("cloud_nac_accounts", {})
    # Username is the key.
    u = result["username"]
    # Previous record for this user, if a valid one exists, so the original creation date is kept.
    prev = accts.get(u, {}) if isinstance(accts.get(u), dict) else {}
    # Build the new record including the password the client will use.
    rec = {
        "username": u, "upn": result["upn"], "oid": result.get("oid"),
        "password": result["password"],
        "created_at": prev.get("created_at") or _now_iso(),
        "provisioned_at": _now_iso(),
    }
    # Store it (overwriting any previous record) and return it.
    accts[u] = rec
    return rec


def forget_account(system_state: dict, username: str) -> Optional[dict]:
    """Drop a username from the local store (after Entra delete). Returns the
    removed record or None."""
    # Look up the stored accounts map (empty if missing).
    accts = system_state.get("cloud_nac_accounts", {}) or {}
    # Remove the user and return what was removed (or None).
    return accts.pop(str(username), None)


def gen_password(n: int = 20) -> str:
    """A random password meeting Entra complexity (>=3 of 4 classes) — we include
    all four and shuffle. Length ``n`` (>=8)."""
    # Character classes: lowercase, uppercase, digits...
    lo, up, dg = string.ascii_lowercase, string.ascii_uppercase, string.digits
    # ...and symbols allowed in Entra passwords.
    sy = "!@#$%^&*()-_=+"
    # Never generate fewer than 8 characters.
    n = max(8, n)
    # Guarantee one character from each class so complexity rules are always met.
    pw = [secrets.choice(lo), secrets.choice(up), secrets.choice(dg), secrets.choice(sy)]
    # Fill the rest from all classes combined.
    allc = lo + up + dg + sy
    pw += [secrets.choice(allc) for _ in range(n - 4)]
    # Shuffle with a secure RNG so the guaranteed characters are not always first.
    secrets.SystemRandom().shuffle(pw)
    # Join the characters into the final password string.
    return "".join(pw)


async def _graph(method: str, path: str, token: str, *, json=None, params=None,
                 http: Optional[httpx.AsyncClient] = None):
    """Send one authenticated request to Microsoft Graph and return the raw response."""
    # Reuse the caller's client if given, else open a short-lived one with a 20 s timeout.
    async with shared_client(http, 20.0) as c:
        # Bearer-token auth plus JSON body/query parameters as requested.
        return await c.request(
            method, f"{_GRAPH}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=json, params=params)


async def get_user(token: str, ident: str, http: Optional[httpx.AsyncClient] = None) -> Optional[dict]:
    """GET a user by UPN or objectId; None if not found."""
    # Ask Graph for just the fields we need about this user.
    resp = await _graph("GET", f"/users/{ident}", token,
                        params={"$select": "id,userPrincipalName,accountEnabled"}, http=http)
    # 404 means the user does not exist.
    if resp.status_code == 404:
        return None
    # Any other non-200 is a real error; include Graph's reply so the UI shows the cause.
    if resp.status_code != 200:
        raise CloudNacError(f"Graph GET user {ident} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    # Return the user object.
    return resp.json()


async def _reset_password(token: str, oid: str, upn: str, password: str,
                          http: Optional[httpx.AsyncClient] = None,
                          retries: int = 5, delay_s: float = 2.0) -> None:
    """Enable the user and set a non-expiring-on-login password. Retries a
    404 briefly: a freshly created user can take a few seconds to replicate."""
    # Enable the account and set a password that does not have to be changed at first login.
    body = {"accountEnabled": True,
            "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False}}
    # Retry loop to ride out Graph replication lag on just-created users.
    for attempt in range(retries):
        resp = await _graph("PATCH", f"/users/{oid}", token, json=body, http=http)
        # Success: done.
        if resp.status_code in (200, 204):
            logger.info("Cloud NAC reset password for Entra user %s", upn)
            return
        # Stop retrying on non-404 errors or when out of attempts.
        if resp.status_code != 404 or attempt == retries - 1:
            break
        # 404 on a new user: wait and try again.
        await asyncio.sleep(delay_s)
    # All attempts failed; raise with Graph's reply.
    raise CloudNacError(f"Graph reset password {upn} failed: HTTP {resp.status_code} — {resp.text[:200]}")


async def provision_user(cfg: OidcConfig, domain: str, username: str,
                         http: Optional[httpx.AsyncClient] = None,
                         password: Optional[str] = None,
                         oid: Optional[str] = None) -> Dict[str, Any]:
    """Create the Entra account for ``username`` (or reset its password if it
    exists), non-interactive (``forceChangePasswordNextSignIn=false`` so a
    headless MSCHAPv2 client can auth). Returns
    ``{username, upn, oid, password, created}``. The caller records the password.
    ``password`` lets the caller (dot1x_jit) choose it; default is random."""
    # Normalise the username (lower-case, trimmed); it must not be empty.
    username = str(username or "").strip().lower()
    if not username:
        raise CloudNacError("empty username")
    # The UPN domain must be configured.
    domain = str(domain or "").strip()
    if not domain:
        raise CloudNacError("UPN domain not configured")
    # Full Entra sign-in name, e.g. user@contoso.com.
    upn = f"{username}@{domain}"
    # App-only Graph token from the SSO app's certificate.
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    # Use the caller's chosen password or generate a random one.
    password = password or gen_password()
    # Object id already known: just reset the password.
    if oid:
        # Caller already knows the object (a rotate). Patch it directly: a
        # UPN lookup can miss a just-created user (Graph replication lag).
        await _reset_password(token, oid, upn, password, http)
        return {"username": username, "upn": upn, "oid": oid, "password": password, "created": False}
    # Look the user up by UPN; if it exists, reset its password rather than create it.
    existing = await get_user(token, upn, http=http)
    if existing:
        oid = existing["id"]
        await _reset_password(token, oid, upn, password, http)
        return {"username": username, "upn": upn, "oid": oid, "password": password, "created": False}
    # User does not exist yet: build the create-user request.
    body = {
        "accountEnabled": True,
        "displayName": username,
        "mailNickname": username,
        "userPrincipalName": upn,
        "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False},
    }
    # Create the user.
    resp = await _graph("POST", "/users", token, json=body, http=http)
    # Creation failed; raise with Graph's reply.
    if resp.status_code not in (200, 201):
        raise CloudNacError(f"Graph create user {upn} failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # Graph returns the new user's object id.
    oid = resp.json().get("id")
    logger.info("Cloud NAC provisioned Entra user %s (oid=%s)", upn, oid)
    # Report the new account details back to the caller, who stores the password.
    return {"username": username, "upn": upn, "oid": oid, "password": password, "created": True}


async def add_user_to_group(cfg: OidcConfig, group_id: str, oid: str,
                            http: Optional[httpx.AsyncClient] = None) -> bool:
    """Add the user (objectId) to an Entra group. Idempotent — an already-member
    400 is treated as success. Needs Graph ``GroupMember.ReadWrite.All`` (App).
    Used so JIT'd Cloud NAC accounts land in a group you can target with a CA
    MFA-exclusion / Cloud Auth policy (and the LM group→tenant mapping)."""
    # Nothing to do without both a group and a user.
    if not group_id or not oid:
        return False
    # App-only Graph token.
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    # Graph's "add member" call takes a reference URL to the directory object.
    body = {"@odata.id": f"{_GRAPH}/directoryObjects/{oid}"}
    # Add the user to the group.
    resp = await _graph("POST", f"/groups/{group_id}/members/$ref", token, json=body, http=http)
    # Added successfully.
    if resp.status_code in (200, 201, 204):
        return True
    # Graph reports an already-present member as a 400; treat it as success (idempotent).
    if resp.status_code == 400 and "already exist" in (resp.text or "").lower():
        return True  # already a member
    # Any other failure is a real error.
    raise CloudNacError(f"Graph add-to-group failed: HTTP {resp.status_code} — {resp.text[:200]}")


async def delete_user(cfg: OidcConfig, ident: str,
                      http: Optional[httpx.AsyncClient] = None) -> bool:
    """Delete the Entra account (by UPN or oid). 404 is treated as success."""
    # App-only Graph token.
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    # Delete the account.
    resp = await _graph("DELETE", f"/users/{ident}", token, http=http)
    # 404 means it is already gone, which is the desired end state.
    if resp.status_code not in (200, 204, 404):
        raise CloudNacError(f"Graph delete {ident} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


async def last_signin(cfg: OidcConfig, ident: str,
                      http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Most recent Entra sign-in (interactive or non-interactive) ISO timestamp,
    or None if never / no data. Needs AuditLog.Read.All + Entra ID P1."""
    # App-only Graph token.
    token = await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)
    # Ask only for the sign-in activity block.
    resp = await _graph("GET", f"/users/{ident}", token,
                        params={"$select": "id,signInActivity"}, http=http)
    # User not found: no sign-in data.
    if resp.status_code == 404:
        return None
    # Any other error is raised with Graph's reply.
    if resp.status_code != 200:
        raise CloudNacError(f"Graph signInActivity {ident} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    # Extract the sign-in activity (may be absent without an Entra ID P1 licence).
    sa = resp.json().get("signInActivity") or {}
    # Collect whichever of the two last-sign-in timestamps are present.
    times = [t for t in (sa.get("lastSignInDateTime"),
                         sa.get("lastNonInteractiveSignInDateTime")) if t]
    # ISO timestamps compare correctly as strings, so max() gives the latest.
    return max(times) if times else None
