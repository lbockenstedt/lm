"""LM Hub authentication providers — local + LDAP.

The Hub authenticates users through a pluggable ``AuthProvider``. Local users
(hashed passwords in ``state.system_state["users"]``) are verified by the
``/auth/login`` handler in ``api.py``; LDAP users bind against a configured
LDAP server through ``LDAPAuthProvider``. ``AuthManager`` is the thin facade
the Hub holds, delegating ``login``/``get_groups`` to the configured provider.
Audience: Hub developers; see ``docs/security.md`` for the zero-trust model.
"""

# Standard-library logging for auth attempts and failures.
import logging
# Type hints only; describe user dicts and configuration.
from typing import Optional, Dict, Any

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("Auth")

class AuthProvider:
    """Base class for identity management providers."""
    def authenticate(self, username, password) -> Optional[Dict]:
        """Check the credentials; return a user dict on success or None on failure."""
        raise NotImplementedError()

    def get_user_groups(self, username) -> list[str]:
        """Return the hub permission-group ids the user belongs to."""
        raise NotImplementedError()

def _relay_sync(hub, cmd: str, data: dict, timeout: float = 10.0) -> Any:
    """Best-effort SYNCHRONOUS relay of a directory command to the ``directory``
    spoke, bridging the hub's async ``request_response`` into this sync provider.

    Only attempts the relay from a plain (non-async) context — ``asyncio.run``
    can't drive a coroutine while an event loop is already running on this
    thread, and the hub's request/response futures are bound to the hub's loop,
    so cross-loop driving isn't safe. When called from within a running loop this
    returns ``None`` (the caller degrades gracefully: auth still succeeds, RBAC
    just adds no directory-derived groups). Returns the unwrapped ``data`` dict
    or ``None``."""
    # No hub wired in means there is nobody to relay to.
    if hub is None:
        return None
    # Find the connected directory spoke; any lookup error is treated as "none".
    try:
        spoke_id = hub.get_spoke_by_type("directory")
    except Exception:  # noqa: BLE001
        spoke_id = None
    # Without a directory spoke the relay is impossible.
    if not spoke_id:
        return None
    # Imported lazily because only this relay path needs it.
    import asyncio
    # Detect whether this thread already runs an event loop (asyncio.run would fail there).
    try:
        asyncio.get_running_loop()
        return None  # inside a running loop — can't safely drive the coroutine
    except RuntimeError:
        pass  # no running loop — safe to asyncio.run
    # Drive the hub's async request/response to completion on a fresh event loop.
    try:
        result = asyncio.run(hub.request_response(spoke_id, cmd, data, timeout=timeout))
    # Relay failures are logged and reported as "no data" so login still works.
    except Exception as e:  # noqa: BLE001
        logger.warning("directory relay %s failed: %s", cmd, e)
        return None
    # Unwrap the response's "data" field when present; otherwise return it as-is.
    return result.get("data", result) if isinstance(result, dict) else result


class LDAPAuthProvider(AuthProvider):
    """LDAP authentication — real bind performed when server is configured.

    When a ``hub`` is supplied in ``config`` the provider also resolves a user's
    RBAC permission-group membership: it relays ``LDAP_GET_USER_GROUPS`` to the
    directory spoke for LOCAL users and maps the raw directory groups through
    ``access.groups_for_ldap_membership`` — the SAME mapping the Entra OIDC
    callback uses (``oidc.provision_or_sync_entra_user`` →
    ``groups_and_tenants_for_membership``), so LDAP and Entra membership both land
    on the same hub permission groups. The Entra login path is unchanged and
    remains the source of truth for Entra-provisioned users."""

    def __init__(self, config: Dict[str, Any]):
        """Store the LDAP config (server, base_dn, optional hub reference)."""
        # Keep the whole config; server/base_dn are read at login time.
        self.config = config
        # Optional hub reference enables the spoke relay + RBAC group mapping.
        self.hub = config.get("hub")

    def authenticate(self, username, password) -> Optional[Dict]:
        """Bind to LDAP as ``uid=<username>,<base_dn>``; return ``{username,
        groups}`` (groups = mapped hub permission-group ids) on success, else
        None."""
        # Log the attempt (never the password) for auditing.
        logger.info(f"Attempting LDAP auth for user: {username}")
        # Without a configured LDAP server, LDAP login is disabled.
        server = self.config.get("server", "")
        if not server:
            logger.warning("LDAP server not configured — auth disabled")
            return None
        # Import ldap3 lazily so the hub runs without it when LDAP is unused.
        try:
            import ldap3
            # Describe the server to connect to.
            srv = ldap3.Server(server, get_info=ldap3.ALL)
            # Build the bind DN uid=<user>,<base_dn>, or use the name as-is if no base DN is set.
            base_dn = self.config.get("base_dn", "")
            user_dn = f"uid={username},{base_dn}" if base_dn else username
            # auto_bind performs the bind now and raises if the credentials are rejected.
            conn = ldap3.Connection(srv, user=user_dn, password=password, auto_bind=True)
            logger.info(f"LDAP auth successful for {username}")
            # Bind succeeded: return the username plus their mapped hub groups.
            return {"username": username, "groups": self.get_user_groups(username)}
        # Wrong password, unreachable server, etc.: log and report failure.
        except Exception as e:
            logger.warning(f"LDAP auth failed for {username}: {e}")
            return None

    def get_directory_groups(self, username, tenant_slug: Optional[str] = None) -> list:
        """Raw directory group identifiers for a LOCAL directory user (LDAP DNs/
        cns), fetched by relaying ``LDAP_GET_USER_GROUPS`` to the directory spoke.
        Returns ``[]`` when no hub/spoke is available (auth still succeeds — RBAC
        just adds no directory-derived groups)."""
        # Ask the directory spoke for the user's raw group list.
        data = _relay_sync(self.hub, "LDAP_GET_USER_GROUPS",
                           {"uid": username, "tenant_slug": (tenant_slug or "")})
        # No relay possible: no directory groups.
        if data is None:
            return []
        # The reply may be {"groups": [...]} or a bare list; normalise to non-empty strings.
        raw = data.get("groups") if isinstance(data, dict) else data
        return [str(g) for g in (raw or []) if g]

    def get_user_groups(self, username, tenant_slug: Optional[str] = None) -> list:
        """A directory user's HUB permission-group ids, derived from their
        LDAP/Entra group membership. Fetches the raw directory groups
        (:meth:`get_directory_groups`) then maps them through
        ``access.groups_for_ldap_membership`` (identical to the Entra path).
        Returns ``[]`` gracefully when no hub is wired or nothing matches."""
        # Fetch the raw directory groups first.
        raw = self.get_directory_groups(username, tenant_slug)
        # Without a hub or any raw groups there is nothing to map.
        if self.hub is None or not raw:
            return []
        # Map directory groups to hub permission groups (shared with the Entra login path).
        try:
            from access import groups_for_ldap_membership
            return groups_for_ldap_membership(self.hub, raw)
        # A mapping error leaves the user with no extra groups instead of failing login.
        except Exception as e:  # noqa: BLE001
            logger.warning("group mapping for %s failed: %s", username, e)
            return []

class AuthManager:
    """Facade over the configured ``AuthProvider`` for login + group lookup."""

    def __init__(self, provider: AuthProvider):
        """Wrap the provider that will handle all logins."""
        # The provider (e.g. LDAPAuthProvider) does the real work.
        self.provider = provider

    def login(self, username, password) -> Optional[Dict]:
        """Authenticate via the provider; return its user dict on success, else None."""
        # Delegate straight to the provider.
        return self.provider.authenticate(username, password)

    def get_groups(self, username) -> list[str]:
        """Return the user's group list from the provider."""
        # Delegate straight to the provider.
        return self.provider.get_user_groups(username)
