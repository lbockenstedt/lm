import json
import os
import logging
import asyncio
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("State")

class StateManager:
    def __init__(self, storage_path="state_cache.json"):
        self.storage_path = storage_path
        self.state: Dict[str, Any] = {
            "tenants": {},
            "resources": {},
            "global_config": {},
            "active_sessions": {}
        }
        self.load_state()

    def load_state(self):
        """Loads the state from the JSON disk cache for cold starts."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    self.state = json.load(f)
                logger.info(f"State loaded from {self.storage_path}")
            except Exception as e:
                logger.error(f"Failed to load state from disk: {e}")

    def save_state(self):
        """Saves the current memory state to the JSON disk cache."""
        try:
            with open(self.storage_path, "w") as f:
                json.dump(self.state, f, indent=2)
            logger.info(f"State saved to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save state to disk: {e}")

    async def persistence_loop(self, interval=60):
        """Background task to periodically persist state to disk."""
        while True:
            await asyncio.sleep(interval)
            self.save_state()

    # --- Tenant Management ---

    def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        return self.state["tenants"].get(tenant_id)

    def update_tenant(self, tenant_id: str, data: Dict):
        if tenant_id not in self.state["tenants"]:
            self.state["tenants"][tenant_id] = {}
        self.state["tenants"][tenant_id].update(data)

    def map_tenant_resource(self, tenant_id: str, resource_id: str, metadata: Dict):
        """
        Maps a resource to a tenant.
        Example: Maps a Proxmox VM ID to a NetBox Tenant ID.
        """
        if resource_id not in self.state["resources"]:
            self.state["resources"][resource_id] = {}

        self.state["resources"][resource_id].update({
            "tenant_id": tenant_id,
            "metadata": metadata
        })

    # --- Quota Management ---

    def get_quota(self, tenant_id: str, resource_type: str) -> int:
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return 0
        return tenant.get("quotas", {}).get(resource_type, 0)

    def set_quota(self, tenant_id: str, resource_type: str, limit: int):
        self.update_tenant(tenant_id, {"quotas": {resource_type: limit}})

    def check_quota(self, tenant_id: str, resource_type: str, requested_amount: int) -> bool:
        current_usage = sum(
            1 for res in self.state["resources"].values()
            if res.get("tenant_id") == tenant_id and res.get("metadata", {}).get("type") == resource_type
        )
        limit = self.get_quota(tenant_id, resource_type)
        return (current_usage + requested_amount) <= limit
