import json
import os
import logging
import asyncio
from typing import Dict, Any, Optional
from security.encryption import hub_encryption

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("State")

class StateManager:
    def __init__(self, system_path="system.json", tenants_path="tenants.json"):
        # Use /var/lib/lm/state for production persistence to avoid being overwritten by git updates
        # Fallback to a local 'data' directory if /var/lib/lm is not writable (e.g. in dev environments)
        self.data_dir = "/var/lib/lm/state"
        try:
            if not os.path.exists(self.data_dir):
                os.makedirs(self.data_dir, exist_ok=True)
            # Test writability
            test_file = os.path.join(self.data_dir, ".write_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            logger.warning(f"Cannot use {self.data_dir} (Permission denied or error: {e}). Falling back to home directory state storage.")
            self.data_dir = os.path.expanduser("~/.local/share/lm/state")
            os.makedirs(self.data_dir, exist_ok=True)

        self.system_path = os.path.join(self.data_dir, system_path)
        self.tenants_path = os.path.join(self.data_dir, tenants_path)

        # System-level state: Hardware, Global Config, Modules, Auth
        self.system_state: Dict[str, Any] = {
            "global_config": {},
            "resources": {},
            "approved_modules": {},
            "known_modules": [],
            "active_sessions": {},
            "active_tenant": "default"
        }

        # Tenant-level state: User settings, Quotas, Mappings
        self.tenant_state: Dict[str, Any] = {
            "tenants": {}
        }

        self.load_state()

    def load_state(self):
        """Loads state from dual JSON disk caches with decryption."""
        # Load System State
        if os.path.exists(self.system_path):
            try:
                with open(self.system_path, "rb") as f:
                    content = f.read()
                    try:
                        # Try decrypting
                        decrypted = hub_encryption.decrypt(content)
                        self.system_state = json.loads(decrypted)
                    except Exception:
                        # Fallback to plain text for migration
                        with open(self.system_path, "r") as pf:
                            self.system_state = json.load(pf)
                logger.info(f"System state loaded from {self.system_path}")
            except Exception as e:
                logger.error(f"Failed to load system state: {e}")

        # Load Tenant State
        if os.path.exists(self.tenants_path):
            try:
                with open(self.tenants_path, "rb") as f:
                    content = f.read()
                    try:
                        # Try decrypting
                        decrypted = hub_encryption.decrypt(content)
                        self.tenant_state = json.loads(decrypted)
                    except Exception:
                        # Fallback to plain text for migration
                        with open(self.tenants_path, "r") as pf:
                            self.tenant_state = json.load(pf)
                logger.info(f"Tenant state loaded from {self.tenants_path}")
            except Exception as e:
                logger.error(f"Failed to load tenant state: {e}")

    def save_state(self):
        """Saves memory state to dual JSON disk caches with encryption."""
        try:
            # Save System State
            sys_json = json.dumps(self.system_state, indent=2)
            with open(self.system_path, "wb") as f:
                f.write(hub_encryption.encrypt(sys_json))

            # Save Tenant State
            ten_json = json.dumps(self.tenant_state, indent=2)
            with open(self.tenants_path, "wb") as f:
                f.write(hub_encryption.encrypt(ten_json))

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

    def set_active_tenant(self, tenant_id: str):
        self.system_state["active_tenant"] = tenant_id
        logger.info(f"Active tenant switched to: {tenant_id}")

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
