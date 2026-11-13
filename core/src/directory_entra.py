"""Directory → Entra: per-tenant Entra accounts and groups (Microsoft Graph).

Entra has no notion of an LM tenant, so each tenant gets its own Entra groups,
recorded on the tenant record under ``directory_entra_groups``:

  * the **base group** ``LM-<tenant>-Users`` (``base: True``), created the first
    time the tenant needs one. Every Entra account created in the Directory
    joins it, and its members ARE "this tenant's Entra accounts";
  * **tenant groups** ``LM-<tenant>-<name>`` that a tenant admin creates and
    fills with the tenant's Entra accounts.

These are separate from the Permission Groups (``ldap_group`` + ``tenants``),
which decide who may manage LM and are never used to list accounts.

Only groups registered on the tenant are touched, an account is managed only
while it is a DIRECT member of the tenant's base group (never through a group
nested in it), and only object ids (GUIDs) go into Graph paths, so one tenant
can never act on another tenant's (or the organisation's own) Entra objects.

Auth reuses the SSO app cert (``cloud_nac`` Graph helpers). The app
registration needs the Graph **application** permissions ``User.ReadWrite.All``
and ``Group.ReadWrite.All`` (admin-consented).
"""
# Postpone evaluation of type hints.
from __future__ import annotations

# Random suffix that keeps each group's mailNickname unique.
import secrets
# UPN and name validation.
import re
# Type hints only.
from typing import List, Optional

# Async HTTP client type (the caller may share one).
import httpx

# Graph request helper, scope, error type, user lookup and password generator.
from cloud_nac import (_GRAPH, _GRAPH_SCOPE, CloudNacError, _graph, gen_password,
                       get_user)
# OIDC config type and the app-only token helper.
from security.oidc import OidcConfig, fetch_app_token

# Tenant-record key holding the tenant's registered Entra groups.
TENANT_KEY = "directory_entra_groups"
# Name part of the base group (LM-<tenant>-Users); reserved for it.
BASE_NAME = "Users"

# Group name a tenant admin may pick: a letter or digit, then letters, digits,
# space, dot, dash or underscore (Entra display names allow far more; this
# keeps them readable and safe in a mailNickname).
_GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
# A user principal name: local part @ a dotted domain.
_UPN_RE = re.compile(r"^[A-Za-z0-9._'+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
# Fields read for every Entra account.
_USER_SELECT = "id,userPrincipalName,displayName,accountEnabled"
# An Entra object id (a GUID). Only these go into a Graph path: anything else
# ("../users/x#") could point the call at another object.
_OID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class EntraConflict(CloudNacError):
    """The account already exists in Entra (a create never takes one over)."""


def registered_groups(tenant: Optional[dict]) -> List[dict]:
    """The tenant's registered Entra groups (``[{id, name, base}]``), valid
    entries only. Read-only: never mutates the tenant record."""
    groups = (tenant or {}).get(TENANT_KEY) or []
    return [g for g in groups if isinstance(g, dict) and g.get("id")]


def base_group(tenant: Optional[dict]) -> Optional[dict]:
    """The tenant's base group record, or None before it is created."""
    return next((g for g in registered_groups(tenant) if g.get("base")), None)


def group_name_arg(name) -> str:
    """Validate a tenant-group name; raise ValueError with a readable reason."""
    name = str(name or "").strip()
    if not _GROUP_NAME_RE.match(name):
        raise ValueError("Group name: 1-40 letters, digits, spaces, '.', '-' or '_', "
                         "starting with a letter or digit")
    # The base group's name is reserved so a tenant group can't look like it.
    if name.lower() == BASE_NAME.lower():
        raise ValueError(f"'{BASE_NAME}' is reserved for the tenant's base group")
    return name


def upn_arg(upn) -> str:
    """Validate a user principal name (user@domain); raise ValueError if not."""
    upn = str(upn or "").strip()
    if not _UPN_RE.match(upn):
        raise ValueError("Enter the sign-in name as user@domain")
    return upn


def object_id_arg(value) -> str:
    """Validate an Entra object id (a GUID); raise ValueError if not."""
    value = str(value or "").strip()
    if not _OID_RE.match(value):
        raise ValueError("Not an Entra object id")
    return value


def _oid(value) -> str:
    """An object id that is safe to put in a Graph path, or CloudNacError
    (a second guard behind the routes' own check)."""
    try:
        return object_id_arg(value)
    except ValueError:
        raise CloudNacError(f"refused a Graph call for a malformed object id {str(value)[:40]!r}")


def display_name(tenant_name: str, name: str) -> str:
    """Entra display name for a tenant group: ``LM-<tenant>-<name>``."""
    return f"LM-{tenant_name}-{name}"


def _nickname(display: str) -> str:
    """A mailNickname for a group: ASCII letters/digits/dashes from the display
    name plus a random suffix (Graph needs one, unique, even for a non-mail
    security group)."""
    base = re.sub(r"[^A-Za-z0-9-]", "", display.replace(" ", "-"))[:48] or "lm-group"
    return f"{base}-{secrets.token_hex(3)}"


def _fail(what: str, resp) -> CloudNacError:
    """A CloudNacError carrying Graph's status and reply, for the UI."""
    return CloudNacError(f"Graph {what} failed: HTTP {resp.status_code} — {resp.text[:200]}")


async def _token(cfg: OidcConfig, http=None) -> str:
    """App-only Graph token from the SSO app cert."""
    return await fetch_app_token(cfg, _GRAPH_SCOPE, http=http)


async def create_group(cfg: OidcConfig, display: str,
                       http: Optional[httpx.AsyncClient] = None) -> dict:
    """Create a security group in Entra; return ``{id, name}``."""
    token = await _token(cfg, http)
    body = {"displayName": display, "mailEnabled": False, "securityEnabled": True,
            "mailNickname": _nickname(display),
            "description": "Lab Manager directory group"}
    resp = await _graph("POST", "/groups", token, json=body, http=http)
    if resp.status_code not in (200, 201):
        raise _fail(f"create group {display}", resp)
    return {"id": _oid(resp.json().get("id")), "name": display}


async def delete_group(cfg: OidcConfig, group_id: str,
                       http: Optional[httpx.AsyncClient] = None) -> None:
    """Delete a group in Entra. Already gone (404) is the wanted end state."""
    token = await _token(cfg, http)
    resp = await _graph("DELETE", f"/groups/{_oid(group_id)}", token, http=http)
    if resp.status_code not in (200, 204, 404):
        raise _fail("delete group", resp)


async def list_group_users(cfg: OidcConfig, group_id: str,
                           http: Optional[httpx.AsyncClient] = None) -> List[dict]:
    """The group's direct user members as ``[{id, upn, name, enabled}]``.
    Direct only: users of a group nested inside (perhaps a big organisation
    group) are not the tenant's accounts and must never become manageable
    through it. A missing group is an error, not an empty list: "the group
    was deleted in Entra" must not read as "no accounts"."""
    token = await _token(cfg, http)
    path = f"/groups/{_oid(group_id)}/members/microsoft.graph.user"
    params = {"$select": _USER_SELECT, "$top": "999"}
    users = []
    # Follow Graph's paging links until the last page.
    while path:
        resp = await _graph("GET", path, token, params=params, http=http)
        if resp.status_code != 200:
            raise _fail("list group members", resp)
        body = resp.json()
        users += [{"id": u.get("id"), "upn": u.get("userPrincipalName") or "",
                   "name": u.get("displayName") or "",
                   "enabled": u.get("accountEnabled") is not False}
                  for u in body.get("value") or [] if u.get("id")]
        # nextLink is a full URL that already carries the query.
        nxt = body.get("@odata.nextLink") or ""
        path = nxt[len(_GRAPH):] if nxt.startswith(_GRAPH) else ""
        params = None
    return users


async def is_member(cfg: OidcConfig, group_id: str, user_id: str,
                    http: Optional[httpx.AsyncClient] = None) -> bool:
    """Is the user a DIRECT member of the group? (Graph's membership checks
    are transitive, so read the direct member list instead; see
    :func:`list_group_users`.)"""
    user_id = _oid(user_id)
    return any(u["id"] == user_id for u in await list_group_users(cfg, group_id, http=http))


async def add_member(cfg: OidcConfig, group_id: str, user_id: str,
                     http: Optional[httpx.AsyncClient] = None) -> None:
    """Add a user to a group. Already a member counts as success."""
    token = await _token(cfg, http)
    body = {"@odata.id": f"{_GRAPH}/directoryObjects/{_oid(user_id)}"}
    resp = await _graph("POST", f"/groups/{_oid(group_id)}/members/$ref", token, json=body,
                        http=http)
    if resp.status_code in (200, 201, 204):
        return
    if resp.status_code == 400 and "already exist" in (resp.text or "").lower():
        return
    raise _fail("add group member", resp)


async def remove_member(cfg: OidcConfig, group_id: str, user_id: str,
                        http: Optional[httpx.AsyncClient] = None) -> None:
    """Remove a user from a group. Not a member (404) is the wanted end state."""
    token = await _token(cfg, http)
    resp = await _graph("DELETE", f"/groups/{_oid(group_id)}/members/{_oid(user_id)}/$ref",
                        token, http=http)
    if resp.status_code not in (200, 204, 404):
        raise _fail("remove group member", resp)


async def create_user(cfg: OidcConfig, upn: str, name: str = "",
                      password: str = "",
                      http: Optional[httpx.AsyncClient] = None) -> dict:
    """Create an Entra account; never takes over an existing one.

    Returns ``{id, upn, name, password, generated}``. ``password`` is the one
    the admin typed, or a generated one (``generated: True``) that the caller
    shows once and does not store. The sign-in does not force a change, so a
    linked LDAP login (which checks the password with Entra directly) works
    from the start."""
    token = await _token(cfg, http)
    # Refuse an existing account: a create must never reset someone's password.
    if await get_user(token, upn, http=http):
        raise EntraConflict(f"{upn} already exists in Entra")
    generated = not password
    password = password or gen_password()
    local = upn.split("@", 1)[0]
    body = {"accountEnabled": True, "displayName": name or local,
            "mailNickname": re.sub(r"[^A-Za-z0-9._-]", "", local) or "user",
            "userPrincipalName": upn,
            "passwordProfile": {"password": password,
                                "forceChangePasswordNextSignIn": False}}
    resp = await _graph("POST", "/users", token, json=body, http=http)
    if resp.status_code not in (200, 201):
        # Created between the lookup and now: still a conflict, not a failure.
        if "already exists" in (resp.text or "").lower():
            raise EntraConflict(f"{upn} already exists in Entra")
        raise _fail(f"create user {upn}", resp)
    return {"id": _oid(resp.json().get("id")), "upn": upn, "name": body["displayName"],
            "password": password, "generated": generated}


async def delete_user(cfg: OidcConfig, user_id: str,
                      http: Optional[httpx.AsyncClient] = None) -> None:
    """Delete an Entra account. Already gone (404) is the wanted end state."""
    token = await _token(cfg, http)
    resp = await _graph("DELETE", f"/users/{_oid(user_id)}", token, http=http)
    if resp.status_code not in (200, 204, 404):
        raise _fail("delete user", resp)
