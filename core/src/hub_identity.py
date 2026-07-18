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

    def _primary_key(self, spoke_id: str) -> str:
        """The key this spoke's routing/approval/crypto/mailbox state lives
        under.

        Returns the guid once the spoke has been lazily migrated to
        guid-primary (recorded in ``spoke_id_alias``), else ``spoke_id``
        (legacy — the fail-safe). A spoke still CONNECTS by its
        operator-chosen spoke_id (the auth-frame id), so this is the single
        resolve point mapping that connect-id to the guid-keyed state. With
        ``spoke_id_alias`` empty (before the Phase 2b migration trigger arms)
        this returns ``spoke_id`` for every spoke → identical to today.
        """
        return self.spoke_id_alias.get(spoke_id, spoke_id)

    def _agent_primary_key(self, agent_id: str) -> str:
        """The key a relayed agent's hub-side state lives under.

        Mirrors ``_primary_key`` for the agent-relay path: returns the guid once
        the agent has been lazily migrated to guid-primary (recorded in
        ``agent_id_alias``), else ``agent_id`` (the fail-safe). A relayed agent
        still reports its self-chosen ``agent_id`` (the name the spoke knows it
        by) on every AGENT_RELAY_UP frame; the guid is the hub-internal primary
        key, translated to the raw name at the relay boundary (option (b)).
        With ``agent_id_alias`` empty (before the B2 arm fires) this returns
        ``agent_id`` for every agent → identical to today.
        """
        return self.agent_id_alias.get(agent_id, agent_id)

    def _agent_relay_name(self, agent_id: str) -> str:
        """Translate an agent primary key (guid) OR raw name to the raw name the
        spoke knows the agent by — for the relay envelope ``target_agent_id``
        (option b: guid is the hub-side key, the wire name stays raw).

        Idempotent: a raw name pre-arm resolves to itself; a guid post-arm
        resolves via ``agent_info[guid]["agent_id"]`` (the raw name stored at the
        AGENT_RELAY_UP write site); an unknown / offline id falls back to itself
        so a relay to a just-disconnected agent still targets the right name.
        """
        apk = self._agent_primary_key(agent_id)
        return (self.agent_info.get(apk) or {}).get("agent_id") or agent_id

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
        # Cold-restart re-arm: the install_uuid_index is rebuilt guid-keyed on
        # load (module_metadata is guid-keyed post-arm), but spoke_id_alias is
        # in-memory (empty after a hub restart). If this uuid is already indexed
        # to itself (== the guid), this is an armed spoke reconnecting BY NAME
        # after a restart — pre-arm the alias so new_pk resolves to the guid and
        # the clone-rename check below sees old_id == new_pk (no spurious
        # guid→name reversal + identity_changed on every restart). Idempotent
        # with the lazy arm at the end. Skipped when the uuid is unset, when the
        # spoke already has an alias, or when new_id IS the guid (nothing to arm).
        if install_uuid and not self.spoke_id_alias.get(new_id) \
                and self.install_uuid_index.get(install_uuid) == install_uuid \
                and install_uuid != new_id:
            self.spoke_id_alias[new_id] = install_uuid
        # Resolve to the guid primary key once armed (== new_id until the lazy
        # arm at the end of this method flips it). All state ops key through
        # new_pk so a reconnecting spoke — which still DIALS IN by its
        # operator-chosen name — lands on its guid-keyed state instead of
        # re-creating a name-keyed record and splitting. Pre-arm this is just
        # new_id (alias empty), so behavior is identical to today.
        new_pk = self._primary_key(new_id)
        mm = self.state.system_state.setdefault("module_metadata", {})
        meta = mm.get(new_pk, {})
        prev_hostname = meta.get("hostname")
        prev_uuid = meta.get("install_uuid")

        # owns_uuid: whether new_id is allowed to claim this install_uuid (and
        # thus whether we record it into new_id's metadata + repoint the index).
        # False only in the unproven-rename branch below.
        owns_uuid = True
        if install_uuid:
            old_id = self.install_uuid_index.get(install_uuid)
            if old_id and old_id != new_pk:
                if migrate_if:
                    # Same install UUID, new id → cloned+renamed spoke WITH proof of
                    # the old id's secret. Migrate so the renamed box keeps its
                    # approval/tenant binding + key material. Target is new_pk
                    # (the primary key) so the chain old_id→new_pk→guid converges
                    # on the guid when the arm below relocates name→guid.
                    self.record_spoke_event(old_id, "identity_changed",
                                            f"was {old_id}, now {new_id} (hostname={hostname or '?'})")
                    self._migrate_spoke_identity(old_id, new_pk)
                    self.record_spoke_event(new_pk, "identity_changed",
                                            f"migrated from {old_id} (hostname={hostname or '?'})")
                    self.install_uuid_index[install_uuid] = new_pk
                else:
                    # CC2 guard: known install_uuid under a NEW id with NO proof
                    # of the old id's secret. Do NOT migrate approval/keys and do
                    # NOT repoint the index — the real (old) id keeps its identity.
                    # new_id is left as a fresh spoke (pending approval / PSK),
                    # never an inheritance. The uuid is not recorded under new_id
                    # so a reload can't drift the index onto it.
                    self.record_spoke_event(new_pk, "identity_rename_unproven",
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
                    self.record_spoke_event(new_pk, "reimaged",
                                            f"install_uuid {prev_uuid[:8]}… → {install_uuid[:8]}…")
                    if self.install_uuid_index.get(prev_uuid) == new_pk:
                        del self.install_uuid_index[prev_uuid]
                self.install_uuid_index[install_uuid] = new_pk
            # old_id == new_pk: normal reconnect — nothing to migrate. (Comparing
            # against new_pk, not new_id, is what prevents the arm from ping-
            # ponging state guid↔name every reconnect once the alias is armed:
            # index[uuid]=guid and _primary_key(name)=guid → equal → no rename.)

        # Hostname-change detection (independent of id/uuid change). Covers the
        # pinned-id case where the id is frozen but the OS host was renamed.
        # Skip in the unproven-rename case — we're refusing to recognize new_id,
        # so a fabricated hostname_changed would be misleading.
        if owns_uuid and hostname and prev_hostname and prev_hostname != hostname:
            self.record_spoke_event(new_pk, "hostname_changed",
                                    f"was {prev_hostname}, now {hostname}")

        # Persist current hostname + install_uuid so the next reconnect can diff.
        # install_uuid is recorded only when new_id actually owns it.
        self.state.update_module_metadata(new_pk, {
            "hostname": hostname or "",
            "install_uuid": (install_uuid or "") if owns_uuid else "",
        })

        # Lazy guid-primary arm: relocate this spoke's hub-side state from its
        # connect-id (the operator-chosen name) to its stable install_uuid, so
        # the guid becomes the primary key (_primary_key(name)→guid). Idempotent
        # and silent (a key relocation, not a rename — no identity_changed
        # event). Only when the caller proved uuid ownership (owns_uuid); the
        # CC2 unproven-rename branch leaves the spoke name-keyed. See
        # _arm_guid_primary for the re-key contract.
        if owns_uuid and install_uuid:
            self._arm_guid_primary(new_id, install_uuid)

    def _migrate_spoke_identity(self, old_id: str, new_id: str,
                                rekey_agent_composite: bool = True) -> None:
        """Carry a spoke's approval/tenant binding/keys/timeline from old→new id.

        ``rekey_agent_composite``: whether to relocate the ``{spoke}:{agent}``
        composite heartbeat keys whose spoke-prefix matches ``old_id``. True
        for a clone-rename (the spoke now dials in by ``new_id``, so the write
        site — ``_handle_agent_relay_up`` keys the composite by the raw dial-in
        name — writes ``{new_id}:{agent}`` and the re-key must follow). False
        for the guid arm: the spoke STILL dials in by its connect-id name, so
        the composite write site keeps writing ``{name}:{agent}`` and the
        composite must stay name-keyed (agent composites are B2 territory).
        """
        if old_id == new_id:
            return
        # Persisted module-keyed state (approved_modules / known_modules /
        # module_names / module_metadata / agent_display_names). The in-memory
        # self.approved_modules + self.known_modules are the SAME objects as the
        # system_state dicts, so rename_module mutates them in place.
        self.state.rename_module(old_id, new_id)
        self.state._mark_dirty()
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
        # Composite heartbeat keys for any agents relayed under this spoke. Skipped
        # for the guid arm (see param docstring) so agent composites stay name-keyed.
        if rekey_agent_composite:
            for key in list(self.heartbeat.last_seen.keys()):
                if key.startswith(f"{old_id}:"):
                    self.heartbeat.last_seen[key.replace(f"{old_id}:", f"{new_id}:", 1)] = \
                        self.heartbeat.last_seen.pop(key)
        logger.info(f"[identity] migrated spoke {old_id} → {new_id}")

    def _arm_guid_primary(self, spoke_id: str, install_uuid: str) -> None:
        """Lazily migrate a spoke's hub-side state from its connect-id (the
        operator-chosen name) to its stable ``install_uuid`` (guid) as the
        primary key, so ``_primary_key(spoke_id)`` resolves name→guid.

        Sets ``spoke_id_alias[spoke_id] = install_uuid`` then re-keys every
        name-keyed store name→guid. Idempotent: an already-armed spoke (alias
        set to this guid) is a no-op; a spoke armed to a *different* guid is
        left untouched (a uuid is stable per-install — a mismatch shouldn't
        happen, and thrashing the state would only make it worse).

        Reuses ``_migrate_spoke_identity`` for the bulk re-key (persisted
        module-keyed state + in-memory mirrors + KeyManager keys). Called from
        ``_reconcile_spoke_identity`` BEFORE the connect path registers the
        spoke / installs its live websocket, so:

        * ``_migrate_spoke_identity``'s ``active_connections.pop(name)`` is a
          safe no-op (no connection is installed yet at arm time — the live ws
          is installed under guid afterward by ``_install_active_connection``,
          which resolves ``_primary_key``).
        * the in-memory mirrors (telemetry / versions / module_types / events /
          recovery / rate_limiters) are empty on a first-connect arm, so their
          re-key is a no-op; on the rare arm that follows a clone-rename chain
          they carry whatever the rename just migrated.

        Silent — no ``identity_changed`` event (this is a key relocation, not a
        rename; the guid is the same box). Agent-side state (agent_config /
        agent_info / agent_logs / the ``{spoke}:{agent}`` heartbeat composite)
        is NOT re-keyed here — that is B2 (agent-relay guid-primary); re-keying
        the agent composite now would split it from its still-name-keyed write
        site (``_handle_agent_relay_up`` writes ``{spoke_id}:{agent_id}`` raw).
        ``spoke_last_seen`` (offline-only contact metadata, module-keyed) is
        re-keyed for accuracy. ``install_uuid_index`` repoints to the guid (the
        new primary key).
        """
        if not install_uuid or install_uuid == spoke_id:
            return
        existing = self.spoke_id_alias.get(spoke_id)
        if existing == install_uuid:
            return  # already armed to this guid — idempotent no-op
        if existing:
            # Armed to a different guid — leave it; a uuid is stable per-install.
            logger.warning("[identity] %s already guid-armed to %s; ignoring %s",
                           spoke_id, existing, install_uuid)
            return
        self.spoke_id_alias[spoke_id] = install_uuid
        # Bulk re-key name→guid (state + in-memory + keys). The active-connection
        # pop inside is a safe no-op at arm time (no ws installed yet). Agent
        # composite heartbeat keys are NOT re-keyed (rekey_agent_composite=False):
        # the spoke still dials in by its connect-id name, so the composite write
        # site (_handle_agent_relay_up) keeps writing {name}:{agent}; re-keying to
        # {guid}:{agent} here would split it from the write site. Agent composites
        # stay name-keyed until B2.
        self._migrate_spoke_identity(spoke_id, install_uuid,
                                     rekey_agent_composite=False)
        self.install_uuid_index[install_uuid] = install_uuid
        # spoke_last_seen is module-keyed offline-only contact metadata; re-key
        # so a hub reboot doesn't reset this spoke to "Never connected / RED".
        sls = self.state.system_state.get("spoke_last_seen", {})
        if spoke_id in sls:
            sls[install_uuid] = sls.pop(spoke_id)
        self.state._mark_dirty()
        logger.info("[identity] armed guid-primary %s → %s", spoke_id, install_uuid)

    def _reconcile_agent_identity(self, new_id: str, install_uuid: str,
                                  hostname: str, parent_spoke_id: Optional[str]) -> None:
        """Agent counterpart of _reconcile_spoke_identity for relayed pxmx agents.

        Keys all state ops through ``new_pk = _agent_primary_key(new_id)`` (the
        guid once armed, else the raw name) so a reconnecting agent — which still
        REPORTS its self-chosen ``agent_id`` name on every AGENT_RELAY_UP frame —
        lands on its guid-keyed state instead of re-creating a name-keyed record
        and splitting. Pre-arm ``new_pk == new_id`` (alias empty), so behavior is
        identical to today. The agent relay path is post-auth and migrates
        unconditionally (no CC2 ``migrate_if`` gate — the spoke vouched for the
        agent by relaying it). Arms guid-primary at the end (B2).
        """
        if not new_id:
            return
        # Cold-restart re-arm (mirror the spoke path): agent_id_alias is in-memory
        # (empty after a hub restart) but install_uuid_index is rebuilt guid-keyed
        # on load (agent_config is guid-keyed post-arm). If this uuid is already
        # indexed to itself (== the guid), this is an armed agent reconnecting BY
        # NAME after a restart — pre-arm the alias so new_pk resolves to the guid
        # and the clone-rename check sees old_id == new_pk (no spurious guid→name
        # reversal + identity_changed on every restart). Idempotent with the
        # lazy arm at the end.
        if install_uuid and not self.agent_id_alias.get(new_id) \
                and self.install_uuid_index.get(install_uuid) == install_uuid \
                and install_uuid != new_id:
            self.agent_id_alias[new_id] = install_uuid
        new_pk = self._agent_primary_key(new_id)
        ac = self.state.system_state.setdefault("agent_config", {})
        cfg = ac.get(new_pk, {})
        prev_hostname = cfg.get("hostname")
        prev_uuid = cfg.get("install_uuid")

        if install_uuid:
            old_id = self.install_uuid_index.get(install_uuid)
            if old_id and old_id != new_pk:
                # Cloned+renamed Proxmox node: carry over per-agent config. Target
                # is new_pk (the primary key) so the chain old_id→new_pk→guid
                # converges on the guid when the arm below relocates name→guid.
                self.record_spoke_event(parent_spoke_id or new_pk, "identity_changed",
                                        f"agent {old_id} → {new_id} (hostname={hostname or '?'})")
                self._migrate_agent_identity(old_id, new_pk, parent_spoke_id)
                self.record_spoke_event(new_pk, "identity_changed",
                                        f"migrated from {old_id} (hostname={hostname or '?'})")
                self.install_uuid_index[install_uuid] = new_pk
            elif not old_id:
                if prev_uuid and prev_uuid != install_uuid:
                    self.record_spoke_event(parent_spoke_id or new_pk, "reimaged",
                                            f"agent {new_id} install_uuid {prev_uuid[:8]}… → {install_uuid[:8]}…")
                    if self.install_uuid_index.get(prev_uuid) == new_pk:
                        del self.install_uuid_index[prev_uuid]
                self.install_uuid_index[install_uuid] = new_pk
            # old_id == new_pk: normal reconnect — nothing to migrate. (Comparing
            # against new_pk, not new_id, is what prevents the arm from ping-
            # ponging agent state guid↔name every reconnect once the alias is
            # armed: index[uuid]=guid and _agent_primary_key(name)=guid → equal.)

        if hostname and prev_hostname and prev_hostname != hostname:
            self.record_spoke_event(parent_spoke_id or new_pk, "hostname_changed",
                                    f"agent {new_id}: was {prev_hostname}, now {hostname}")

        cfg_new = ac.setdefault(new_pk, {})
        cfg_new["hostname"] = hostname or ""
        cfg_new["install_uuid"] = install_uuid or ""
        self.state._mark_dirty()

        # Lazy guid-primary arm: relocate this agent's hub-side state from its
        # reported name to its stable install_uuid (guid) so _agent_primary_key
        # resolves name→guid. Idempotent + silent (a key relocation, not a rename
        # — same box, same install_uuid). Mirrors _arm_guid_primary.
        if install_uuid:
            self._arm_agent_guid_primary(new_id, install_uuid, parent_spoke_id)

    def _migrate_agent_identity(self, old_id: str, new_id: str,
                                parent_spoke_id: Optional[str]) -> None:
        """Carry an agent's per-agent config + logs + heartbeat from old→new id.

        ``new_id`` is the agent primary key (guid once armed, else the raw name).
        Parent-spoke-keyed state (``spoke_telemetry`` nested + the
        ``{spoke}:{agent}`` composite heartbeat) resolves the spoke half through
        ``_primary_key(parent_spoke_id)`` so it matches the write site in
        ``_handle_agent_relay_up`` (which keys the composite ``{spoke_pk}:{agent_pk}``
        post-B2). A pre-arm migrate (parent unarmed) lands on the raw name, same
        as today; the next AGENT_HEARTBEAT overwrites the composite with the
        armed form, so a transient mismatch self-heals within ~30s.
        """
        if old_id == new_id:
            return
        # Persisted per-agent config (client_simulation/tenant binding/display_name).
        self.state.rename_agent(old_id, new_id)
        self.state._mark_dirty()
        # Legacy display-name override.
        adn = self.state.system_state.get("agent_display_names", {})
        if old_id in adn:
            adn[new_id] = adn.pop(old_id)
        # In-memory agent logs + telemetry.
        if old_id in self.agent_logs:
            self.agent_logs[new_id] = self.agent_logs.pop(old_id)
        # Agent→spoke index: keep the routing entry under the new id so command
        # relay survives a clone-and-rename. The embedded ``agent_id`` (raw name
        # for relay translation) travels with the dict; the write site in
        # _handle_agent_relay_up refreshes it on the next frame.
        if old_id in self.agent_info:
            self.agent_info[new_id] = self.agent_info.pop(old_id)
        if parent_spoke_id:
            parent_pk = self._primary_key(parent_spoke_id)
            if parent_pk in self.spoke_telemetry:
                nested = self.spoke_telemetry[parent_pk]
                if old_id in nested:
                    nested[new_id] = nested.pop(old_id)
            # Composite heartbeat keys "{spoke_pk}:{agent}".
            old_hb = f"{parent_pk}:{old_id}"
            new_hb = f"{parent_pk}:{new_id}"
            if old_hb in self.heartbeat.last_seen:
                self.heartbeat.last_seen[new_hb] = self.heartbeat.last_seen.pop(old_hb)
        self.key_manager.rename_spoke_keys(old_id, new_id)
        logger.info(f"[identity] migrated agent {old_id} → {new_id}")

    def _arm_agent_guid_primary(self, agent_id: str, install_uuid: str,
                                parent_spoke_id: Optional[str]) -> None:
        """Lazily migrate a relayed agent's hub-side state from its reported name
        to its stable ``install_uuid`` (guid) as the agent primary key, so
        ``_agent_primary_key(agent_id)`` resolves name→guid. Mirrors
        ``_arm_guid_primary`` for the agent-relay path (B2, option b: guid is the
        hub-side key; the relay envelope ``target_agent_id`` stays the raw name).

        Sets ``agent_id_alias[agent_id] = install_uuid`` then re-keys every
        name-keyed agent store name→guid via ``_migrate_agent_identity``:
        agent_config / agent_display_names / agent_logs / agent_info / the
        ``{spoke}:{agent}`` composite heartbeat / the spoke_telemetry nested
        agent entry. Idempotent: already-armed → no-op; armed to a *different*
        guid is left untouched. ``install_uuid_index`` repoints to the guid.
        ``agent_info[guid]["agent_id"]`` holds the raw name (set by the write
        site in _handle_agent_relay_up) for guid→name relay translation.
        """
        if not install_uuid or install_uuid == agent_id:
            return
        existing = self.agent_id_alias.get(agent_id)
        if existing == install_uuid:
            return  # already armed to this guid — idempotent no-op
        if existing:
            # Armed to a different guid — leave it; a uuid is stable per-install.
            logger.warning("[identity] agent %s already guid-armed to %s; ignoring %s",
                           agent_id, existing, install_uuid)
            return
        self.agent_id_alias[agent_id] = install_uuid
        self._migrate_agent_identity(agent_id, install_uuid, parent_spoke_id)
        self.install_uuid_index[install_uuid] = install_uuid
        logger.info("[identity] armed agent guid-primary %s → %s", agent_id, install_uuid)