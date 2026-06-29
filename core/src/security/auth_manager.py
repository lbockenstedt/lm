"""LM Hub authentication providers — local + LDAP.

The Hub authenticates users through a pluggable ``AuthProvider``. Local users
(hashed passwords in ``state.system_state["users"]``) are verified by the
``/auth/login`` handler in ``api.py``; LDAP users bind against a configured
LDAP server through ``LDAPAuthProvider``. ``AuthManager`` is the thin facade
the Hub holds, delegating ``login``/``get_groups`` to the configured provider.
Audience: Hub developers; see ``docs/security.md`` for the zero-trust model.
"""

import logging
from typing import Optional, Dict, Any

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("Auth")

class AuthProvider:
    """Base class for identity management providers."""
    def authenticate(self, username, password) -> Optional[Dict]:
        raise NotImplementedError()

    def get_user_groups(self, username) -> list[str]:
        raise NotImplementedError()

class LDAPAuthProvider(AuthProvider):
    """LDAP authentication — real bind performed when server is configured."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def authenticate(self, username, password) -> Optional[Dict]:
        """Bind to LDAP as ``uid=<username>,<base_dn>``; return ``{username, groups}`` on success, else None."""
        logger.info(f"Attempting LDAP auth for user: {username}")
        server = self.config.get("server", "")
        if not server:
            logger.warning("LDAP server not configured — auth disabled")
            return None
        try:
            import ldap3
            srv = ldap3.Server(server, get_info=ldap3.ALL)
            base_dn = self.config.get("base_dn", "")
            user_dn = f"uid={username},{base_dn}" if base_dn else username
            conn = ldap3.Connection(srv, user=user_dn, password=password, auto_bind=True)
            logger.info(f"LDAP auth successful for {username}")
            return {"username": username, "groups": self.get_user_groups(username)}
        except Exception as e:
            logger.warning(f"LDAP auth failed for {username}: {e}")
            return None

    def get_user_groups(self, username) -> list[str]:
        return []

class AuthManager:
    """Facade over the configured ``AuthProvider`` for login + group lookup."""

    def __init__(self, provider: AuthProvider):
        self.provider = provider

    def login(self, username, password) -> Optional[Dict]:
        """Authenticate via the provider; return its user dict on success, else None."""
        return self.provider.authenticate(username, password)

    def get_groups(self, username) -> list[str]:
        """Return the user's group list from the provider."""
        return self.provider.get_user_groups(username)
