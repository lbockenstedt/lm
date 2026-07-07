"""LM Hub state store — ``StateManager``.

Persists the Hub's JSON state to disk and serves as the single source of truth
for system-level and tenant-level configuration. State lives under
``data_dir`` (``/var/lib/lm/state`` in production, ``~/.local/share/lm/state``
fallback in dev) so it is **not** overwritten by git-driven hub updates.

- ``system_state`` — global config, approved/known modules, module display
  names + metadata, per-agent config (display name + per-agent cs/usb config),
  users, and an ``active_sessions``/``active_tenant`` view.
- ``tenant_state`` — per-tenant user settings, quotas, and module mappings.

Loads on construction, saves on mutation + via a background ``persistence_loop``
(atomic write through ``_save_file``), and merges defaults on load so new
fields appear without a migration. Sensitive values are encrypted at rest via
``security.encryption.hub_encryption``. Audience: Hub developers; see
``docs/modules/core.md`` for the module-level overview.
"""

import json
import os
import logging
import asyncio
import threading
import time
from typing import Dict, Any, Optional
from security.encryption import hub_encryption

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("State")

class StateManager:
    """JSON-backed Hub state store — the single source of truth for config.

    See the module docstring. ``__init__`` resolves ``data_dir`` (production
    ``/var/lib/lm/state`` with a home-dir fallback for dev), builds the system
    and tenant state dicts with their default shape, and loads from disk.
    """

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

        # Set by _load_file when a state file decrypted only via a FALLBACK
        # (previous/legacy) Fernet key; load_state re-saves to migrate it to the
        # current key so a rotated LM_FERNET_KEY can't strand it later.
        self._needs_rekey = False

        # System-level state: Hardware, Global Config, Modules, Auth
        self.system_state: Dict[str, Any] = {
            "global_config": {},
            "resources": {},
            "approved_modules": {},
            "known_modules": [],
            "module_names": {},
            "module_metadata": {},  # { spoke_id: { "display_name": "...", "description": "..." } }
            "active_sessions": {},
            "active_tenant": "default",
            "users": {},
            # Named permission GROUPS (RBAC). Keyed by group_id. Each:
            #   { "name": str, "description": str,
            #     "permissions": { <right-key>: bool, ... },   # same keys as a
            #                                                   # user's permissions
            #     "ldap_group": str,   # optional DN/cn for phase-2 LDAP linkage
            #     "protected": bool, "updated_at": float }
            # A user's effective permissions = union of the permissions of every
            # group in user["groups"] OR'd with the user's own per-user
            # permissions overrides (resolve_effective_permissions in access.py).
            # _merge_defaults back-fills this on existing encrypted state with no
            # migration.
            "permission_groups": {},
            # Per-Proxmox-agent config (unified agent). Shape:
            #   { agent_id: { display_name: str,
            #                 client_simulation: { enabled: bool, tenant_id: str|None, usb_config: {} } } }
            # `display_name` is the new home for the rename value; `agent_display_names`
            # (below) is kept as a read fallback for one release during migration.
            "agent_config": {},
            # Per-spoke last-contacted unix epoch, persisted across hub reboots
            # so an approved spoke that WAS connected doesn't reset to "Never
            # connected / RED" the moment the hub restarts (in-memory
            # heartbeat.last_seen / spoke_telemetry are lost on reboot; this
            # survives in the Fernet-encrypted system.json). Seeded back into
            # hub.heartbeat.last_seen at startup. Written via _mark_dirty (the
            # 60s persistence_loop flushes) — NOT save_state — so a heartbeat
            # tick never costs a disk write. Stale entries are pruned when a
            # spoke is deleted (delete_module).
            "spoke_last_seen": {},
        }

        # Tenant-level state: User settings, Quotas, Mappings
        self.tenant_state: Dict[str, Any] = {
            "tenants": {}
        }

        self.load_state()

        # Write coalescing: the persistence_loop is the backstop for in-memory
        # mutations that don't explicitly save_state() (update_global_config,
        # register_module, update_tenant, …). A dirty flag lets the loop skip
        # the encrypt+fsync+backup rewrite when nothing changed — previously it
        # rewrote both files every 60s unconditionally, forever, even when idle
        # (pure write amplification at scale). _dirty_lock guards the flag
        # (touched on every mutation); _write_lock serializes the file writes
        # across the api thread (explicit save_state) and the asyncio-loop
        # thread (persistence_loop), which could otherwise race on the shared
        # ``<path>.tmp`` and corrupt the atomic write.
        self._dirty: bool = False
        self._dirty_lock = threading.Lock()
        self._write_lock = threading.Lock()

    def _mark_dirty(self) -> None:
        """Flag that in-memory state changed and needs persisting.

        Set by the in-memory mutators (update_global_config, register_module,
        update_module_metadata, update_tenant, set_active_tenant,
        map_tenant_resource). The persistence_loop flushes it within one
        interval; an explicit save_state() flushes immediately and clears it.
        """
        with self._dirty_lock:
            self._dirty = True

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
                    # Try decrypting (current key → previous rotation keys →
                    # legacy). If a FALLBACK key succeeded, flag a re-key so
                    # load_state re-encrypts under the current key — otherwise a
                    # rotated LM_FERNET_KEY leaves system.json/tenants.json
                    # readable only by the old key, and a later rotation strands
                    # them (the incident this guards against).
                    decrypted, used_primary = hub_encryption.decrypt_with_meta(content)
                    if not used_primary:
                        self._needs_rekey = True
                        logger.warning("State file %s decrypted with a FALLBACK key "
                                       "(previous/legacy); will re-encrypt under the "
                                       "current key on next save.", path)
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
            json_data = json.dumps(data, indent=2, default=str)
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
            # Clean up tmp file if it exists
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            raise

    def _merge_defaults(self, loaded: Dict, defaults: Dict) -> Dict:
        """Merge loaded state with defaults to ensure all keys exist."""
        for key, default_val in defaults.items():
            if key not in loaded:
                loaded[key] = default_val
            elif isinstance(default_val, dict) and isinstance(loaded[key], dict):
                # Recursively merge dicts one level deep
                for sub_key, sub_default in default_val.items():
                    if sub_key not in loaded[key]:
                        loaded[key][sub_key] = sub_default
        return loaded

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

            # Merge with defaults to ensure all keys exist (handles old state files)
            sys_defaults = {
                "global_config": {},
                "resources": {},
                "approved_modules": {},
                "known_modules": [],
                "module_names": {},
                "module_metadata": {},
                "active_sessions": {},
                "active_tenant": "default",
                "users": {},
                "agent_config": {}
            }
            sys_state = self._merge_defaults(sys_state, sys_defaults)
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
            # Merge with defaults
            ten_defaults = {"tenants": {}}
            ten_state = self._merge_defaults(ten_state, ten_defaults)
            self.tenant_state = ten_state
            logger.info(f"Tenant state loaded successfully from {self.tenants_path}")
        else:
            logger.info("No valid tenant state found, using defaults.")

        # A state file decrypted via a fallback (previous/legacy) key — re-save
        # NOW to re-encrypt everything under the current key so the old key can
        # be retired safely and a future rotation can't strand these files.
        if self._needs_rekey:
            logger.warning("Re-encrypting state under the current key (fallback-key "
                           "load detected) …")
            try:
                self.save_state()
            except Exception as e:  # noqa: BLE001
                logger.error("Re-key save failed: %s", e)
            self._needs_rekey = False

    def save_state(self):
        """Saves memory state to dual JSON disk caches with atomic writes.

        Synchronous + immediate: callers (request handlers, key rotation, the
        update pipeline) get durability before they return. Clears the dirty
        flag so the persistence_loop doesn't redundantly rewrite the same
        state on its next tick. The _write_lock serializes this against a
        concurrent loop flush.
        """
        try:
            with self._write_lock:
                self._save_file(self.system_path, self.system_state)
                self._save_file(self.tenants_path, self.tenant_state)
            with self._dirty_lock:
                self._dirty = False
            logger.info("State persisted to disk (system & tenants) atomically")
        except Exception as e:
            logger.error(f"Failed to save state to disk: {e}")
            raise

    async def persistence_loop(self, interval=60):
        """Background task that persists state to disk — but only when dirty.

        Previously this rewrote both encrypted state files every ``interval``
        unconditionally, which at scale (hundreds of tenants, large tenants.json)
        meant an encrypt+fsync+backup-copy every 60s forever, even when nothing
        had changed. Now it flushes only when a mutation marked the state dirty,
        via ``_flush_if_dirty`` (extracted so the dirty-flag mechanics are unit
        testable without sleeping a full interval). ``interval`` is also the
        max staleness bound for an in-memory-only mutation (the crash-recovery
        safety net).
        """
        while True:
            await asyncio.sleep(interval)
            await self._flush_if_dirty()

    async def _flush_if_dirty(self) -> bool:
        """Persist state if dirty; return True if a write happened.

        Clear-before-write: the flag is dropped *before* the write so a mutation
        during the write re-marks dirty and is picked up on the next tick (no
        loss). On write failure the flag is restored so the next tick retries.
        """
        with self._dirty_lock:
            if not self._dirty:
                return False
            self._dirty = False
        try:
            with self._write_lock:
                self._save_file(self.system_path, self.system_state)
                self._save_file(self.tenants_path, self.tenant_state)
            logger.info("State persisted to disk (dirty-flagged flush)")
            return True
        except Exception as e:
            logger.error(f"Persistence loop error: {e}")
            with self._dirty_lock:
                self._dirty = True  # retry next tick
            return False

    # --- System Management ---

    def get_global_config(self) -> Dict:
        """Return the global config dict (update sources, global branch, etc.)."""
        return self.system_state.get("global_config", {})

    def update_global_config(self, config: Dict):
        """Merge ``config`` into the global config (caller is responsible for saving)."""
        gc = self.system_state.setdefault("global_config", {})
        gc.update(config)
        self._mark_dirty()

    def register_module(self, module_id: str, approved: bool = False, display_name: str = None):
        """Record a module as known, set its approval flag, and seed its metadata."""
        known_modules = self.system_state.setdefault("known_modules", [])
        if module_id not in known_modules:
            known_modules.append(module_id)

        self.system_state.setdefault("approved_modules", {})[module_id] = approved

        # Initialize metadata
        module_metadata = self.system_state.setdefault("module_metadata", {})
        if module_id not in module_metadata:
            module_metadata[module_id] = {
                "display_name": display_name or module_id,
                "description": ""
            }

        if display_name:
            module_metadata[module_id]["display_name"] = display_name

        # Sync with legacy module_names for compatibility
        self.system_state.setdefault("module_names", {})[module_id] = module_metadata[module_id]["display_name"]
        self._mark_dirty()

    def remove_module(self, module_id: str):
        """Symmetric counterpart to register_module: drop a spoke/agent and all
        of its persisted metadata. Used by the "Delete" action in Setup → Spokes
        & Agents to remove a dead/unwanted registration entirely."""
        known = self.system_state.get("known_modules", [])
        if module_id in known:
            known.remove(module_id)
        self.system_state.get("approved_modules", {}).pop(module_id, None)
        self.system_state.get("module_names", {}).pop(module_id, None)
        self.system_state.get("module_metadata", {}).pop(module_id, None)
        # Proxmox node-agent display-name overrides live here; harmless if absent.
        self.system_state.get("agent_display_names", {}).pop(module_id, None)
        self.save_state()

    def update_module_metadata(self, module_id: str, metadata: Dict[str, Any]):
        """Updates the display name and description for a spoke."""
        module_metadata = self.system_state.setdefault("module_metadata", {})
        if module_id not in module_metadata:
            module_metadata[module_id] = {"display_name": module_id, "description": ""}

        module_metadata[module_id].update(metadata)

        # Sync with legacy module_names
        if "display_name" in metadata:
            self.system_state.setdefault("module_names", {})[module_id] = metadata["display_name"]
        self._mark_dirty()

    def rename_module(self, old_id: str, new_id: str) -> None:
        """Re-key a spoke/agent's persisted state from ``old_id`` → ``new_id``.

        Used when a cloned+renamed spoke reconnects with the same install UUID but
        a new id (derived from its new hostname): we carry over its approval,
        tenant binding, display name, and install UUID/hostname so it does NOT
        need re-approval. Moves every module-keyed store. ``agent_config`` (keyed
        by agent_id) is handled separately by :meth:`rename_agent`. Idempotent if
        ``old_id == new_id`` or ``old_id`` is unknown.
        """
        if old_id == new_id:
            return
        ss = self.system_state
        am = ss.get("approved_modules", {})
        if old_id in am:
            am[new_id] = am.pop(old_id)
        km = ss.get("known_modules", [])
        if old_id in km:
            km[km.index(old_id)] = new_id
        mn = ss.get("module_names", {})
        if old_id in mn:
            mn[new_id] = mn.pop(old_id)
        mm = ss.get("module_metadata", {})
        if old_id in mm:
            mm[new_id] = mm.pop(old_id)
        # Legacy per-agent display-name override (read fallback during migration).
        adn = ss.get("agent_display_names", {})
        if old_id in adn:
            adn[new_id] = adn.pop(old_id)
        self._mark_dirty()

    def rename_agent(self, old_id: str, new_id: str) -> None:
        """Re-key an agent's per-agent config (``agent_config``) ``old_id`` → ``new_id``.

        Called when a cloned+renamed Proxmox node reconnects with the same agent
        install UUID but a new agent id, so its client-simulation/tenant config
        carries over instead of being lost. Idempotent.
        """
        if old_id == new_id:
            return
        ac = self.system_state.get("agent_config", {})
        if old_id in ac:
            ac[new_id] = ac.pop(old_id)
            self._mark_dirty()

    def set_module_name(self, module_id: str, name: str):
        self.update_module_metadata(module_id, {"display_name": name})

    def get_module_name(self, module_id: str) -> str:
        return self.system_state.get("module_metadata", {}).get(module_id, {}).get("display_name", module_id)

    def set_spoke_tenant(self, module_id: str, tenant_id: str):
        """Bind a spoke to a tenant (admin assigns at approval time). Stored in
        module_metadata so it persists with the rest of system_state."""
        self.update_module_metadata(module_id, {"tenant_id": tenant_id})

    def get_spoke_tenant(self, module_id: str) -> Optional[str]:
        return self.system_state.get("module_metadata", {}).get(module_id, {}).get("tenant_id")

    def get_approved_modules(self) -> Dict[str, bool]:
        """Return the ``{module_id: approved}`` map for all registered modules."""
        return self.system_state.get("approved_modules", {})

    # --- Spoke last-seen (persisted across hub reboots) ---

    def get_spoke_last_seen(self) -> Dict[str, float]:
        """Return the persisted ``{spoke_id: unix_epoch}`` map.

        Source of truth for ``hub.heartbeat.last_seen`` re-seeding at startup:
        the in-memory heartbeat dict is wiped on a hub reboot, which made every
        approved spoke flip to RED / "Never connected" even though it was
        connected seconds before the restart. This dict lives in the
        Fernet-encrypted ``system.json`` so it survives.
        """
        return self.system_state.get("spoke_last_seen", {}) or {}

    def set_spoke_last_seen(self, spoke_id: str, ts: float) -> None:
        """Record ``spoke_id``'s last-contacted epoch.

        Marks the state dirty so the 60s persistence_loop flushes it — does NOT
        call save_state(), so a heartbeat tick (the hot-path caller) never
        triggers an encrypt+fsync+backup disk write. Best-effort: a crash
        within the 60s window loses at most one minute of last_seen granularity,
        which is fine for the 15-min staleness threshold the UI uses.
        """
        if not spoke_id:
            return
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            return
        ls = self.system_state.setdefault("spoke_last_seen", {})
        if ls.get(spoke_id) != ts:
            ls[spoke_id] = ts
            self._mark_dirty()

    def clear_spoke_last_seen(self, spoke_id: str) -> None:
        """Drop a spoke's persisted last-seen (on delete/recreate)."""
        if not spoke_id:
            return
        ls = self.system_state.get("spoke_last_seen", {}) or {}
        if spoke_id in ls:
            ls.pop(spoke_id, None)
            self._mark_dirty()

    # --- Tenant Management ---

    def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        """Return a tenant record by id (exact match first, then case-insensitive), or None."""
        # Standardize the input ID: remove whitespace and treat as string
        clean_id = str(tenant_id).strip()

        tenants = self.tenant_state.get("tenants", {})

        # Try exact match first
        tenant = tenants.get(clean_id)
        if tenant:
            return tenant

        # Try converting to int if the input looks like a number
        try:
            int_id = int(clean_id)
            tenant = tenants.get(int_id)
            if tenant:
                return tenant
        except (ValueError, TypeError):
            pass

        # Final fallback: scan all keys and strip them to find a match
        for key in tenants.keys():
            if str(key).strip() == clean_id:
                return tenants[key]

        # Tenant miss: log at DEBUG (not INFO) and never dump the full tenant-id
        # list. A miss can fire on every frame for a misconfigured spoke/tenant,
        # and INFO-listing every tenant id on each miss floods the hub log and
        # leaks the full tenant roster. Keep the miss detectable at DEBUG with
        # the requested id + a tenant count so operators can still confirm a
        # lookup happened without grepping a noisy INFO stream.
        logger.debug(
            f"StateManager: get_tenant miss for id='{tenant_id}' "
            f"(cleaned: '{clean_id}'); tenant_count={len(tenants)}"
        )
        return None

    def update_tenant(self, tenant_id: str, data: Dict):
        """Merge ``data`` into a tenant's record, creating the tenant if new."""
        tenants = self.tenant_state.setdefault("tenants", {})
        if tenant_id not in tenants:
            tenants[tenant_id] = {}
        tenants[tenant_id].update(data)
        self._mark_dirty()

    def set_active_tenant(self, tenant_id: str):
        self.system_state["active_tenant"] = tenant_id
        logger.info(f"Active tenant switched to: {tenant_id}")
        self._mark_dirty()

    def map_tenant_resource(self, tenant_id: str, resource_id: str, metadata: Dict):
        """
        Maps a resource to a tenant.
        The resource itself is system-level, but the mapping is tenant-level.
        """
        resources = self.system_state.setdefault("resources", {})
        if resource_id not in resources:
            resources[resource_id] = {}

        resources[resource_id].update({
            "tenant_id": tenant_id,
            "metadata": metadata
        })
        self._mark_dirty()

    # --- Quota Management ---

    def get_quota(self, tenant_id: str, resource_type: str) -> int:
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return 0
        return tenant.get("quotas", {}).get(resource_type, 0)

    def set_quota(self, tenant_id: str, resource_type: str, limit: int):
        self.update_tenant(tenant_id, {"quotas": {resource_type: limit}})

    def assign_user_to_tenant(self, user_id: str, tenant_id: str):
        """Assigns a user to a specific tenant. Users can belong to multiple tenants."""
        users = self.system_state.setdefault("users", {})
        if user_id not in users:
            users[user_id] = {"permissions": {}, "updated_at": time.time()}

        user_data = users[user_id]
        if "tenants" not in user_data:
            user_data["tenants"] = []

        if tenant_id not in user_data["tenants"]:
            user_data["tenants"].append(tenant_id)
            logger.info(f"User {user_id} assigned to tenant {tenant_id}")
            self.save_state()

    def remove_user_from_tenant(self, user_id: str, tenant_id: str):
        """Removes a user from a specific tenant."""
        users = self.system_state.get("users", {})
        if user_id in users:
            user_data = users[user_id]
            tenants = user_data.get("tenants", [])
            if tenant_id in tenants:
                tenants.remove(tenant_id)
                user_data["tenants"] = tenants
                logger.info(f"User {user_id} removed from tenant {tenant_id}")
                self.save_state()

    def ensure_admin_lockout(self) -> bool:
        """Anti-lockout + admin-flag normalization.

        Ensures the first user is a fully-privileged, protected, tenant-free
        admin, and that EVERY admin user carries both admin-flag forms
        (``permissions.role == "admin"`` AND ``permissions.admin == True``).

        The WebUI "System Admin" checkbox reads ``permissions.admin`` while the
        first-run bootstrap and older repair code wrote only ``permissions.role
        == "admin"``. A role-only admin therefore rendered as a *non-admin* in
        the users table, and editing that row submitted ``{admin: false, ...}``
        with no ``role`` — silently demoting a non-protected admin and locking
        them out of setup/logs/system. Keeping both forms in sync on every
        startup/update, and on every user write, closes that gap.

        Returns True if state was modified (the caller should ``save_state()``).
        Does not create new admins — it only reconciles the two forms for users
        that are already admin by either measure.
        """
        users = self.system_state.get("users", {})
        if not users:
            return False
        changed = False

        def _as_admin(perm):
            perm = dict(perm or {})
            perm["role"] = "admin"
            perm["admin"] = True
            return perm

        first_uid = next(iter(users))
        first = users[first_uid]
        p = first.get("permissions", {})
        if not (p.get("admin") or p.get("role") == "admin"):
            first["permissions"] = _as_admin(p)
            changed = True
        elif not p.get("admin") or p.get("role") != "admin":
            first["permissions"] = _as_admin(p)
            changed = True
        if not first.get("protected"):
            first["protected"] = True
            changed = True
        if first.get("tenants"):
            first["tenants"] = []
            changed = True

        # Reconcile the two admin-flag forms on every admin user so the UI
        # checkbox and _is_admin() can never diverge.
        for u in users.values():
            up = u.get("permissions", {})
            if (up.get("admin") or up.get("role") == "admin") and (
                not up.get("admin") or up.get("role") != "admin"
            ):
                u["permissions"] = _as_admin(up)
                changed = True

        if changed:
            logger.warning(
                f"Anti-lockout: ensured admin/protected/no-tenant on '{first_uid}' "
                f"and reconciled admin flags across all admin users"
            )
        return changed

    def check_quota(self, tenant_id: str, resource_type: str, requested_amount: int) -> bool:
        current_usage = sum(
            1 for res in self.system_state.get("resources", {}).values()
            if res.get("tenant_id") == tenant_id and res.get("metadata", {}).get("type") == resource_type
        )
        limit = self.get_quota(tenant_id, resource_type)
        return (current_usage + requested_amount) <= limit