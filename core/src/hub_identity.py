"""Install-UUID identity tracking for the LM Hub (clone/rename detection)."""

from __future__ import annotations

import logging
from typing import Dict, Optional

logger = logging.getLogger("Hub")


class HubIdentityMixin:
    """Correlate spokes/agents by stable install_uuid so a cloned+renamed box is
    recognized and its approval / tenant binding / per-agent config / key
    material are migrated to the new id, with the rename surfaced as a lifecycle
    event. State (``self.install_uuid_index`` etc.) is owned by
    ``LabManagerHub.__init__``."""

    # ── Install-UUID identity tracking (clone/rename detection) ──────────────────
    # Spokes/agents report a stable install_uuid (minted at first start, persisted
    # in their .env) + their current OS hostname on every connect. The hub
    # correlates by UUID so a cloned+renamed box is recognized, its approval /
    # tenant binding / per-agent config is carried over to the new id, and the
    # rename is reported as a lifecycle event (visible in Setup → diagnostics).
    # Three cases: same UUID + new id → identity_changed + migrate; same id +
    # new hostname → hostname_changed; new UUID reusing a known id → reimaged.
    def _rebuild_install_uuid_index(self) -> None:
        """Rebuild the install_uuid → id index from persisted metadata on load."""
        idx: Dict[str, str] = {}
        for sid, meta in self.state.system_state.get("module_metadata", {}).items():
            iu = (meta or {}).get("install_uuid")
            if iu:
                idx[iu] = sid
        for aid, cfg in self.state.system_state.get("agent_config", {}).items():
            iu = (cfg or {}).get("install_uuid")
            if iu:
                idx[iu] = aid
        self.install_uuid_index = idx

    def _reconcile_spoke_identity(self, new_id: str, install_uuid: str,
                                  hostname: str, is_agent: bool = False,
                                  parent_spoke_id: Optional[str] = None,
                                  migrate_if: bool = True) -> None:
        """Detect a clone-and-rename on connect and migrate state to the new id.

        Called from handle_connection (spokes) and _handle_agent_relay_up (agents).
        Emits ``identity_changed`` / ``hostname_changed`` / ``reimaged`` lifecycle
        events. Safe to call with an empty install_uuid (.env unwritable): it only
        records hostname when known, no correlation.

        CC2 guard: the spoke path passes ``migrate_if`` set by the caller ONLY
        when the connecting box proved it owns the OLD id's secret (verified in
        handle_connection via ``get_valid_key(old_id, secret)`` before this call).
        A known install_uuid under a NEW id WITHOUT that proof is NOT migrated —
        new_id is recorded as a fresh spoke (pending approval / PSK) and the index
        stays on the real (old) id, so a bare UUID + new spoke_id can no longer
        inherit the victim's approval + a freshly minted session key. The agent
        relay path is post-auth and migrates unconditionally (default True).
        """
        if not new_id:
            return
        if is_agent:
            self._reconcile_agent_identity(new_id, install_uuid, hostname, parent_spoke_id)
            return
        mm = self.state.system_state.setdefault("module_metadata", {})
        meta = mm.get(new_id, {})
        prev_hostname = meta.get("hostname")
        prev_uuid = meta.get("install_uuid")

        # owns_uuid: whether new_id is allowed to claim this install_uuid (and
        # thus whether we record it into new_id's metadata + repoint the index).
        # False only in the unproven-rename branch below.
        owns_uuid = True
        if install_uuid:
            old_id = self.install_uuid_index.get(install_uuid)
            if old_id and old_id != new_id:
                if migrate_if:
                    # Same install UUID, new id → cloned+renamed spoke WITH proof of
                    # the old id's secret. Migrate so the renamed box keeps its
                    # approval/tenant binding + key material.
                    self.record_spoke_event(old_id, "identity_changed",
                                            f"was {old_id}, now {new_id} (hostname={hostname or '?'})")
                    self._migrate_spoke_identity(old_id, new_id)
                    self.record_spoke_event(new_id, "identity_changed",
                                            f"migrated from {old_id} (hostname={hostname or '?'})")
                    self.install_uuid_index[install_uuid] = new_id
                else:
                    # CC2 guard: known install_uuid under a NEW id with NO proof
                    # of the old id's secret. Do NOT migrate approval/keys and do
                    # NOT repoint the index — the real (old) id keeps its identity.
                    # new_id is left as a fresh spoke (pending approval / PSK),
                    # never an inheritance. The uuid is not recorded under new_id
                    # so a reload can't drift the index onto it.
                    self.record_spoke_event(new_id, "identity_rename_unproven",
                                            f"install_uuid seen under {old_id} but no valid secret "
                                            f"for it — migration to {new_id} refused")
                    logger.warning("[identity] %s claimed install_uuid of %s without a "
                                   "valid secret for it — migration refused (CC2 guard).",
                                   new_id, old_id)
                    owns_uuid = False
            elif not old_id:
                # Fresh UUID. If this id slot already had a different UUID, the box
                # was re-imaged (prep-for-imaging wiped the UUID) reusing the id.
                if prev_uuid and prev_uuid != install_uuid:
                    self.record_spoke_event(new_id, "reimaged",
                                            f"install_uuid {prev_uuid[:8]}… → {install_uuid[:8]}…")
                    if self.install_uuid_index.get(prev_uuid) == new_id:
                        del self.install_uuid_index[prev_uuid]
                self.install_uuid_index[install_uuid] = new_id
            # old_id == new_id: normal reconnect — nothing to migrate.

        # Hostname-change detection (independent of id/uuid change). Covers the
        # pinned-id case where the id is frozen but the OS host was renamed.
        # Skip in the unproven-rename case — we're refusing to recognize new_id,
        # so a fabricated hostname_changed would be misleading.
        if owns_uuid and hostname and prev_hostname and prev_hostname != hostname:
            self.record_spoke_event(new_id, "hostname_changed",
                                    f"was {prev_hostname}, now {hostname}")

        # Persist current hostname + install_uuid so the next reconnect can diff.
        # install_uuid is recorded only when new_id actually owns it.
        self.state.update_module_metadata(new_id, {
            "hostname": hostname or "",
            "install_uuid": (install_uuid or "") if owns_uuid else "",
        })

    def _migrate_spoke_identity(self, old_id: str, new_id: str) -> None:
        """Carry a spoke's approval/tenant binding/keys/timeline from old→new id."""
        if old_id == new_id:
            return
        # Persisted module-keyed state (approved_modules / known_modules /
        # module_names / module_metadata / agent_display_names). The in-memory
        # self.approved_modules + self.known_modules are the SAME objects as the
        # system_state dicts, so rename_module mutates them in place.
        self.state.rename_module(old_id, new_id)
        self.state.save_state()
        # In-memory-only mirrors (not in system_state).
        if old_id in self.spoke_module_types:
            self.spoke_module_types[new_id] = self.spoke_module_types.pop(old_id)
        if old_id in self.spoke_versions:
            self.spoke_versions[new_id] = self.spoke_versions.pop(old_id)
        if old_id in self.spoke_telemetry:
            self.spoke_telemetry[new_id] = self.spoke_telemetry.pop(old_id)
        if old_id in self.spoke_events:
            self.spoke_events[new_id] = self.spoke_events.pop(old_id)
        if old_id in self.spoke_recovery:
            self.spoke_recovery[new_id] = self.spoke_recovery.pop(old_id)
        if old_id in self.rate_limiters:
            self.rate_limiters[new_id] = self.rate_limiters.pop(old_id)
        # An old live connection under the stale id would be evicted/replaced by
        # _install_active_connection under the new id; just drop the stale pointer.
        self.active_connections.pop(old_id, None)
        self.active_connection_key_ids.pop(old_id, None)
        # KeyManager re-key (CRITICAL): without this the new id has no key and the
        # renamed spoke falls into pending-negotiation despite the approval carryover.
        self.key_manager.rename_spoke_keys(old_id, new_id)
        # Composite heartbeat keys for any agents relayed under this spoke.
        for key in list(self.heartbeat.last_seen.keys()):
            if key.startswith(f"{old_id}:"):
                self.heartbeat.last_seen[key.replace(f"{old_id}:", f"{new_id}:", 1)] = \
                    self.heartbeat.last_seen.pop(key)
        logger.info(f"[identity] migrated spoke {old_id} → {new_id}")

    def _reconcile_agent_identity(self, new_id: str, install_uuid: str,
                                  hostname: str, parent_spoke_id: Optional[str]) -> None:
        """Agent counterpart of _reconcile_spoke_identity for relayed pxmx agents."""
        if not new_id:
            return
        ac = self.state.system_state.setdefault("agent_config", {})
        cfg = ac.get(new_id, {})
        prev_hostname = cfg.get("hostname")
        prev_uuid = cfg.get("install_uuid")

        if install_uuid:
            old_id = self.install_uuid_index.get(install_uuid)
            if old_id and old_id != new_id:
                # Cloned+renamed Proxmox node: carry over per-agent config.
                self.record_spoke_event(parent_spoke_id or new_id, "identity_changed",
                                        f"agent {old_id} → {new_id} (hostname={hostname or '?'})")
                self._migrate_agent_identity(old_id, new_id, parent_spoke_id)
                self.install_uuid_index[install_uuid] = new_id
            elif not old_id:
                if prev_uuid and prev_uuid != install_uuid:
                    self.record_spoke_event(parent_spoke_id or new_id, "reimaged",
                                            f"agent {new_id} install_uuid {prev_uuid[:8]}… → {install_uuid[:8]}…")
                    if self.install_uuid_index.get(prev_uuid) == new_id:
                        del self.install_uuid_index[prev_uuid]
                self.install_uuid_index[install_uuid] = new_id

        if hostname and prev_hostname and prev_hostname != hostname:
            self.record_spoke_event(parent_spoke_id or new_id, "hostname_changed",
                                    f"agent {new_id}: was {prev_hostname}, now {hostname}")

        cfg_new = ac.setdefault(new_id, {})
        cfg_new["hostname"] = hostname or ""
        cfg_new["install_uuid"] = install_uuid or ""
        self.state._mark_dirty()

    def _migrate_agent_identity(self, old_id: str, new_id: str,
                                parent_spoke_id: Optional[str]) -> None:
        """Carry an agent's per-agent config + logs + heartbeat from old→new id."""
        if old_id == new_id:
            return
        # Persisted per-agent config (client_simulation/tenant binding/display_name).
        self.state.rename_agent(old_id, new_id)
        self.state.save_state()
        # Legacy display-name override.
        adn = self.state.system_state.get("agent_display_names", {})
        if old_id in adn:
            adn[new_id] = adn.pop(old_id)
        # In-memory agent logs + telemetry.
        if old_id in self.agent_logs:
            self.agent_logs[new_id] = self.agent_logs.pop(old_id)
        # Agent→spoke index: keep the routing entry under the new id so command
        # relay survives a clone-and-rename.
        if old_id in self.agent_info:
            self.agent_info[new_id] = self.agent_info.pop(old_id)
        if parent_spoke_id:
            if parent_spoke_id in self.spoke_telemetry:
                nested = self.spoke_telemetry[parent_spoke_id]
                if old_id in nested:
                    nested[new_id] = nested.pop(old_id)
            # Composite heartbeat keys "{spoke}:{agent}".
            old_hb = f"{parent_spoke_id}:{old_id}"
            new_hb = f"{parent_spoke_id}:{new_id}"
            if old_hb in self.heartbeat.last_seen:
                self.heartbeat.last_seen[new_hb] = self.heartbeat.last_seen.pop(old_hb)
        self.key_manager.rename_spoke_keys(old_id, new_id)
        logger.info(f"[identity] migrated agent {old_id} → {new_id}")
