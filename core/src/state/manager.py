import json
import os
import logging
import asyncio
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("State")

class StateManager:
    def __init__(self, system_path="system.json", tenants_path="tenants.json"):
        self.system_path = system_path
        self.tenants_path = tenants_path

        # System-level state: Hardware, Global Config, Modules, Auth
        self.system_state: Dict[str, Any] = {
            "global_config": {},
            "resources": {},
            "approved_modules": {},
            "known_modules": [],
            "active_sessions": {}
        }

        # Tenant-level state: User settings, Quotas, Mappings
        self.tenant_state: Dict[str, Any] = {
            "tenants": {}
        }

        self.load_state()

    def load_state(self):
        """Loads state from dual JSON disk caches."""
        # Load System State
        if os.path.exists(self.system_path):
            try:
                with open(self.system_path, "r") as f:
                    self.system_state = json.load(f)
                logger.info(f"System state loaded from {self.system_path}")
            except Exception as e:
                logger.error(f"Failed to load system state: {e}")

        # Load Tenant State
        if os.path.exists(self.tenants_path):
            try:
                with open(self.tenants_path, "r") as f:
                    self.tenant_state = json.load(f)
                logger.info(f"Tenant state loaded from {self.tenants_path}")
            except Exception as e:
                logger.error(f"Failed to load tenant state: {e}")

    def save_state(self):
        """Saves memory state to dual JSON disk caches."""
        try:
            with open(self.system_path, "w") as f:
                json.dump(self.system_state, f, indent=2)
            with open(self.tenants_path, "w") as f:
                json.dump(self.tenant_state, f, indent=2)
            logger.info("State persisted to disk (system & tenants)")
        except Exception as e:
            logger.error(f"Failed to save state to disk: {e}")

    async def persistence_loop(self, interval=60):
        """Background task to periodically persist state to disk."""
        while True:
            await asyncio.sleep(interval)
            self.save_state()

    # --- System Management ---

    def get_global_config(self) -> Dict:
        return self.system_state.get("global_config", {})

    def update_global_config(self, config: Dict):
        self.system_state["global_config"].update(config)

    def register_module(self, module_id: str, approved: bool = False):
        if module_id not in self.system_state["known_modules"]:
            self.system_state["known_modules"].append(module_id)
        self.system_state["approved_modules"][module_id] = approved

    def get_approved_modules(self) -> Dict[str, bool]:
        return self.system_state["approved_modules"]

    # --- Tenant Management ---

    def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        return self.tenant_state["tenants"].get(tenant_id)

    def update_tenant(self, tenant_id: str, data: Dict):
        if tenant_id not in self.tenant_state["tenants"]:
            self.tenant_state["tenants"][tenant_id] = {}
        self.tenant_state["tenants"][tenant_id].update(data)

    def map_tenant_resource(self, tenant_id: str, resource_id: str, metadata: Dict):
        """
        Maps a resource to a tenant.
        The resource itself is system-level, but the mapping is tenant-level.
        """
        if resource_id not in self.system_state["resources"]:
            self.system_state["resources"][resource_id] = {}

        self.system_state["resources"][resource_id].update({
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
            1 for res in self.system_state["resources"].values()
            if res.get("tenant_id") == tenant_id and res.get("metadata", {}).get("type") == resource_type
        )
        limit = self.get_quota(tenant_id, resource_type)
        return (current_usage + requested_amount) <= limit
