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
            "module_names": {},
            "active_sessions": {},
            "active_tenant": "default"
        }

        # Tenant-level state: User settings, Quotas, Mappings
        self.tenant_state: Dict[str, Any] = {
            "tenants": {}
        }

        self.load_state()

    def _load_file(self, path: str) -> Optional[Dict]:
        """Helper to load and decrypt a state file, falling back to plain text."""
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as f:
                content = f.read()
                if not content:
                    return None
                try:
                    # Try decrypting
                    decrypted = hub_encryption.decrypt(content)
                    return json.loads(decrypted)
                except Exception as e:
                    logger.warning(f"Decryption failed for {path}, trying plain text: {e}")
                    # Fallback to plain text for migration (re-read as text)
                    with open(path, "r") as pf:
                        return json.load(pf)
        except Exception as e:
            logger.error(f"Critical error reading state file {path}: {e}")
            return None

    def _save_file(self, path: str, data: Dict):
        """Helper to save state file atomically with encryption and backup."""
        tmp_path = path + ".tmp"
        bak_path = path + ".bak"
        try:
            json_data = json.dumps(data, indent=2)
            encrypted_data = hub_encryption.encrypt(json_data)

            # 1. Write to temporary file
            with open(tmp_path, "wb") as f:
                f.write(encrypted_data)
                f.flush()
                os.fsync(f.fileno())

            # 2. Create backup of existing file if it exists
            if os.path.exists(path):
                import shutil
                shutil.copy2(path, bak_path)

            # 3. Atomic replace
            os.replace(tmp_path, path)
        except Exception as e:
            logger.error(f"Failed to atomically save state to {path}: {e}")
            raise e

    def load_state(self):
        """Loads state from dual JSON disk caches with backup recovery."""
        # Load System State
        sys_state = self._load_file(self.system_path)
        if sys_state is None and os.path.exists(self.system_path + ".bak"):
            logger.warning(f"System state {self.system_path} corrupted or missing, trying backup...")
            sys_state = self._load_file(self.system_path + ".bak")

        if sys_state:
            # Migration: move global_config["opn"] to global_config["firewalls"]
            global_config = sys_state.get("global_config", {})
            if "opn" in global_config and "firewalls" not in global_config:
                opn_cfg = global_config.pop("opn")
                if isinstance(opn_cfg, dict):
                    import uuid
                    firewall_id = str(uuid.uuid4())
                    firewall_entry = {
                        "id": firewall_id,
                        "name": "Default OPNsense Firewall",
                        "model": "opnsense",
                        **opn_cfg
                    }
                    global_config["firewalls"] = [firewall_entry]
                    sys_state["global_config"] = global_config
                    logger.info(f"Migrated OPNsense singleton config to multi-firewall list (ID: {firewall_id})")

            self.system_state = sys_state
            logger.info(f"System state loaded successfully from {self.system_path}")
        else:
            logger.info("No valid system state found, using defaults.")

        # Load Tenant State
        ten_state = self._load_file(self.tenants_path)
        if ten_state is None and os.path.exists(self.tenants_path + ".bak"):
            logger.warning(f"Tenant state {self.tenants_path} corrupted or missing, trying backup...")
            ten_state = self._load_file(self.tenants_path + ".bak")

        if ten_state:
            self.tenant_state = ten_state
            logger.info(f"Tenant state loaded successfully from {self.tenants_path}")
        else:
            logger.info("No valid tenant state found, using defaults.")

    def save_state(self):
        """Saves memory state to dual JSON disk caches with atomic writes."""
        try:
            self._save_file(self.system_path, self.system_state)
            self._save_file(self.tenants_path, self.tenant_state)
            logger.info("State persisted to disk (system & tenants) atomically")
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

    def register_module(self, module_id: str, approved: bool = False, display_name: str = None):
        if module_id not in self.system_state["known_modules"]:
            self.system_state["known_modules"].append(module_id)
        self.system_state["approved_modules"][module_id] = approved
        if display_name:
            self.system_state["module_names"][module_id] = display_name
        elif module_id not in self.system_state["module_names"]:
            self.system_state["module_names"][module_id] = module_id

    def set_module_name(self, module_id: str, name: str):
        self.system_state["module_names"][module_id] = name

    def get_module_name(self, module_id: str) -> str:
        return self.system_state["module_names"].get(module_id, module_id)

    def get_approved_modules(self) -> Dict[str, bool]:
        return self.system_state["approved_modules"]

    # --- Tenant Management ---

    def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        logger.info(f"StateManager: get_tenant requested for id='{tenant_id}'. Available tenants: {list(self.tenant_state['tenants'].keys())}")
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
