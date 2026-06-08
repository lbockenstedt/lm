import logging
from typing import Optional, Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Auth")

class AuthProvider:
    """Base class for identity management providers."""
    def authenticate(self, username, password) -> Optional[Dict]:
        raise NotImplementedError()

    def get_user_groups(self, username) -> list[str]:
        raise NotImplementedError()

class LDAPAuthProvider(AuthProvider):
    """Initial target: LDAP authentication."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mock_users = {
            "admin": {"password": "password123", "groups": ["admins", "users"]},
            "user1": {"password": "user1pass", "groups": ["users"]}
        }

    def authenticate(self, username, password) -> Optional[Dict]:
        logger.info(f"Attempting LDAP auth for user: {username}")
        user = self.mock_users.get(username)
        if user and user["password"] == password:
            logger.info(f"LDAP auth successful for {username}")
            return {"username": username, "groups": user["groups"]}

        logger.warning(f"LDAP auth failed for {username}")
        return None

    def get_user_groups(self, username) -> list[str]:
        user = self.mock_users.get(username)
        return user["groups"] if user else []

class AuthManager:
    def __init__(self, provider: AuthProvider):
        self.provider = provider

    def login(self, username, password) -> Optional[Dict]:
        return self.provider.authenticate(username, password)

    def get_groups(self, username) -> list[str]:
        return self.provider.get_user_groups(username)
