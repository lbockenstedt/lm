"""Read-only spoke/agent lookup helpers for the LM Hub — ``SpokeRegistryMixin``.

Pure textual extraction from ``main.py``: the connected/approved-spoke lookup
and display-online helpers mixed into ``LabManagerHub``. Every method uses only
``self`` state (active_connections, heartbeat, spoke_module_types,
module_metadata, agent_info, netbox_server_agents, ...) plus the
``_MODULE_TYPE_PREFIX`` legacy-prefix map moved here with them. No behavior
change — ``LabManagerHub`` inherits these exactly as before.
"""

# logging reports lookup problems.
import logging
# time compares last-seen timestamps against the grace window.
import time
# Optional marks lookups that may find nothing.
from typing import Optional

# Module-level logger named after this module.
logger = logging.getLogger(__name__)

# module_type → spoke_id prefix substring, for legacy spoke resolution.
# Used by get_spoke_by_type / get_all_spokes_by_type. The prefix is matched as
# a substring of the spoke_id (e.g. an "opn-edge-1" spoke → firewall).
_MODULE_TYPE_PREFIX = {
    "hypervisor": "pxmx",
    "firewall":   "opn",
    "nac":        "cppm",
    "directory":  "ldap",
    "ipam":       "netbox",
    "simulation": "cs",
    "dns":        "dns",
    "henet":      "henet",
    "dhcp":       "dhcp",
    "agent":      "agent",
    "nw":         "nw",
    "certificates": "le",
    "storage":    "truenas",
}


def _nac_instances(hub) -> list:
    """The NAC instance records (``nac_instances``) in config order, without
    malformed entries."""
    return [i for i in (hub.state.get_global_config().get("nac_instances", []) or [])
            if isinstance(i, dict)]


# The record id the push ledger uses for the legacy single ClearPass config
# (global_config["cppm"]). NAC record ids are UUIDs, so it never matches one.
LEGACY_NAC_RECORD_ID = "legacy-cppm"


def nac_legacy_record(gc) -> Optional[dict]:
    """The legacy single ClearPass config (``global_config["cppm"]``) as the
    hub's own NAC record with no spoke, or None when it does not apply.

    It applies only while there is no NAC instance record at all; the push
    then sends it to every NAC spoke (``push_nac_config``). As a record, the
    push ledger and the NAC resolvers treat it like the hub's own spoke-less
    record: a spoke is stale until it confirms it, and a spoke bound to a
    tenant that holds it serves the hub's ClearPass, not the tenant's own.
    A config without a host is never sent, so it is no record.
    """
    if not isinstance(gc, dict) or gc.get("nac_instances"):
        return None
    legacy = gc.get("cppm")
    if not isinstance(legacy, dict) or not str(legacy.get("host") or "").strip():
        return None
    return {"id": LEGACY_NAC_RECORD_ID, "host": legacy["host"], "tenant_id": ""}


def instance_records_for_spoke(hub, instances, spoke_id) -> list:
    """The instance records (NAC, IPAM, directory) that configure ``spoke_id``.

    Every record bound to the spoke counts, compared by primary key so a
    record saved under the spoke's pre-migration id still matches. When none
    is bound, the first spoke-less record counts: a single-instance
    deployment never binds one, so every spoke gets it. main.py sends a spoke
    the first of these, and the NAC resolvers judge a spoke by all of them,
    so the push and the resolvers always read the same records.
    """
    records = [i for i in instances or [] if isinstance(i, dict)]
    # The records bound to this spoke, else the first spoke-less one.
    pk = hub._primary_key(spoke_id)
    mine = [i for i in records if hub._primary_key(i.get("spoke_id") or "") == pk]
    return mine or [i for i in records if not i.get("spoke_id")][:1]


def _nac_spoke_records(hub, spoke_id) -> list:
    """The NAC instance records that configure ``spoke_id``
    (``instance_records_for_spoke``). All of them count, not only the first
    one the push sends, so a spoke an admin bound to two tenants' records is
    judged by both. With no NAC instance record at all, the legacy single
    config configures every NAC spoke (``nac_legacy_record``)."""
    records = instance_records_for_spoke(hub, _nac_instances(hub), spoke_id)
    if records:
        return records
    # No instance record: the legacy single config, if it has a host.
    legacy = nac_legacy_record(hub.state.get_global_config())
    return [legacy] if legacy else []


def nac_push_key(record) -> Optional[str]:
    """What a NAC spoke holds once it is sent ``record``: the record's id and
    host. None when there is no record or it has no host, because such a
    config is never sent."""
    if not isinstance(record, dict) or not str(record.get("host") or "").strip():
        return None
    return f"{record.get('id') or ''}@{str(record['host']).strip()}"


def _nac_pushed(hub) -> dict:
    """The persisted ``{spoke primary key: nac_push_key}`` map of the NAC
    config each spoke last confirmed, or "" while that is unknown
    (``system_state["nac_config_pushed"]``)."""
    state = getattr(hub, "state", None)
    return (getattr(state, "system_state", None) or {}).get("nac_config_pushed") or {}


def record_nac_push(hub, spoke_id, record) -> None:
    """Remember that ``spoke_id`` confirmed it now holds ``record``'s config.

    The legacy single ClearPass config is recorded as its own record
    (``nac_legacy_record``). ``record`` None drops the entry, so the spoke
    counts as never sent one; ``_evict_spoke`` does this for a deleted
    spoke. The map is saved with the rest of system_state.
    """
    pushed = hub.state.system_state.setdefault("nac_config_pushed", {})
    pk = hub._primary_key(spoke_id)
    key = nac_push_key(record)
    # Store or drop the entry, and save only when it changed.
    if key is None:
        changed = pushed.pop(pk, None) is not None
    else:
        changed = pushed.get(pk) != key
        pushed[pk] = key
    if changed:
        hub.state._mark_dirty()


def mark_nac_push_unknown(hub, spoke_id, sending=None) -> None:
    """Mark that the hub does not know which NAC config ``spoke_id`` holds.

    The entry becomes "" until the spoke confirms a push (``record_nac_push``),
    and ``nac_spoke_stale`` reads "" as stale, so no NAC read or write
    reaches the spoke meanwhile. Two moments call for it:

    - A new connection (``sending`` None): the cppm spoke keeps the config
      the hub sent it in memory only, so a new process holds its ``.env``
      config until the reconnect push is confirmed.
    - Just before a push (``sending`` is the record being sent): the spoke
      may refuse the config or not answer, and holds its old one until it
      confirms the new one.

    The entry is kept when nothing is in doubt: the spoke was never sent a
    config and none is on its way (it runs on its own ``.env``), or it is
    about to be re-sent exactly what it confirmed last.
    """
    # Hub objects built without state (tests) have no ledger.
    system_state = getattr(getattr(hub, "state", None), "system_state", None)
    if system_state is None:
        return
    pushed = system_state.setdefault("nac_config_pushed", {})
    pk = hub._primary_key(spoke_id)
    current = pushed.get(pk)
    # Nothing in doubt: keep the entry.
    if current is None and sending is None:
        return
    if current == "" or (current is not None and current == nac_push_key(sending)):
        return
    pushed[pk] = ""
    hub.state._mark_dirty()


def nac_spoke_stale(hub, spoke_id) -> bool:
    """Whether ``spoke_id`` may hold a ClearPass other than the one the hub gives it now.

    A cppm spoke keeps the last config it was sent until it restarts: it
    rejects a config without a host and has no command to forget one. The
    hub remembers what each spoke confirmed it holds (``record_nac_push``),
    and the NAC resolvers skip a stale spoke until it confirms the right
    config:

    - A spoke a NAC record configures is stale until it confirmed that
      record. Until then it may still answer from a ClearPass set up through
      its own ``.env`` or from another record. A record with no host is
      never sent, so its spoke stays stale.
    - A spoke no record configures is stale only while it holds a record
      the hub sent it before (the record moved away or was deleted). A spoke
      set up through its own ``.env`` and never sent a record is not stale.
    - An entry of "" (``mark_nac_push_unknown``: a new connection, or a push
      not yet confirmed) is stale in both cases.

    With no NAC instance record at all, the legacy single config is the
    record that configures every NAC spoke (``nac_legacy_record``), so a
    spoke is stale until it confirmed that config's current host.
    """
    pushed = _nac_pushed(hub).get(hub._primary_key(spoke_id))
    records = _nac_spoke_records(hub, spoke_id)
    # No record configures it: stale only while it holds one the hub sent.
    if not records:
        return pushed is not None
    # A record configures it: stale until it holds exactly that record.
    expected = nac_push_key(records[0])
    return expected is None or pushed != expected


def _nac_instance_owners(hub, spoke_id) -> set:
    """Real tenants whose NAC instance records configure ``spoke_id``.

    A spoke's own binding (``module_metadata``) can say unassigned while the
    spoke serves a tenant's ClearPass: an instance keeps its tenant when
    Setup → NAC moves it to another spoke (routes/nw.py update_instance), and
    a Global Admin can give a spoke-less instance a tenant. The records are
    the ones ``_nac_spoke_records`` finds. Unassigned, shared and ADMIN
    records own nothing (``access.tenant_is_unbound``). Each owner keeps its
    stored spelling (``access.raw_tenant_id``): stripping " ACME " would name
    its legacy twin "ACME" instead.
    """
    # Lazy import: access imports hub modules at load time.
    from access import raw_tenant_id, tenant_is_unbound
    # Keep only real tenants.
    return {raw_tenant_id(i.get("tenant_id")) for i in _nac_spoke_records(hub, spoke_id)
            if not tenant_is_unbound(i.get("tenant_id"))}


def _nac_spoke_serves_only(hub, spoke_id, tenant_id) -> bool:
    """Whether everything ``spoke_id`` serves belongs to ``tenant_id``.

    A tenant's own spoke is read without the tenant's subnet filter, so a
    spoke that also serves someone else must not count as the tenant's own,
    or the tenant would see every session on that ClearPass.

    The NAC records that configure the spoke (``_nac_spoke_records``)
    decide, whatever the spoke's own binding says: every one must be the
    tenant's. A record with no tenant (blank or ADMIN) is the hub's own
    ClearPass, as is the legacy single config (``nac_legacy_record``): only
    the shared view may read it unfiltered, because with no
    shared tenant configured the hub's ClearPass is the shared one. Without
    this, a spoke bound to a tenant but holding no record of its own, which
    the reconnect push hands the hub's spoke-less record, would show that
    tenant the hub's ClearPass unfiltered. A spoke no record configures
    serves the ClearPass it was set up with locally, so its binding decides.

    For the shared tenant, any spelling of shared matches
    (``access.tenant_is_shared``).
    """
    # Lazy import: access imports hub modules at load time.
    from access import ADMIN_TENANT_ID, same_tenant, tenant_is_shared
    shared = tenant_is_shared(tenant_id)

    def is_tenant(tag):
        """Whether ``tag`` names ``tenant_id``."""
        return tenant_is_shared(tag) if shared else same_tenant(tag, tenant_id)

    def hubs_own(tag):
        """Blank or ADMIN: the hub's own ClearPass."""
        return not str(tag or "").strip() or same_tenant(tag, ADMIN_TENANT_ID)

    # No record configures it: its binding decides.
    records = _nac_spoke_records(hub, spoke_id)
    if not records:
        return is_tenant(hub.state.get_spoke_tenant(spoke_id))
    # Every record it serves: the tenant's, or the hub's own for the shared view.
    return all(is_tenant(t) or (shared and hubs_own(t))
               for t in (i.get("tenant_id") for i in records))


def _tagged(record, tenant_id) -> bool:
    """Whether a spoke's metadata, or a module instance record, is tagged with
    ``tenant_id``, compared as the access checks compare tenants (fleet rule
    6.1: any case). An untagged record never matches, so a picker never claims
    an unbound spoke this way."""
    # Imported here, as elsewhere in this module, to avoid an import cycle.
    from access import tenant_among
    return tenant_among((record or {}).get("tenant_id"), [tenant_id])


def _admin_view(tenant_id) -> bool:
    """No tenant, or the built-in ADMIN tenant "default" in any case: the
    admin/global view, which the single-spoke pickers answer with any spoke."""
    from access import ADMIN_TENANT_ID, same_tenant
    return not tenant_id or same_tenant(tenant_id, ADMIN_TENANT_ID)


class SpokeRegistryMixin:
    """Read-only spoke/agent registry lookups mixed into ``LabManagerHub``."""

    # Ask global config for the display grace window; any config problem means default.
    def _online_grace_s(self) -> float:
        """Grace window (s) for the DISPLAY online/offline status. A module reads
        offline only after being out of contact THIS long — so a transient loop
        stall or a brief reconnect never flips the tile. Default 180s; the alert
        tiers (5 min warn / 30 min error) escalate genuine outages from there."""
        try:
            return float((self.state.get_global_config() or {}).get(
                "display", {}).get("online_grace_s", 180))
        except Exception:
            # Malformed or missing config falls back to the 180-second default.
            return 180.0

    def is_spoke_in_contact(self, spoke_id: str, grace_s: Optional[float] = None) -> bool:
        """True if the spoke is connected NOW or was seen within the grace window.
        This is the DISPLAY notion of 'online' — decoupled from instantaneous WS
        membership so a few-second stall doesn't drop the tile. Command routing
        still uses ``active_connections`` directly (must be live-accurate)."""
        # A live WebSocket connection always counts as in contact.
        if self._primary_key(spoke_id) in self.active_connections:
            return True
        # Otherwise look up when the spoke was last heard from; never seen means offline.
        ts = self.heartbeat.last_seen.get(self._primary_key(spoke_id))
        if not ts:
            return False
        # Use the caller's grace window if given, else the configured one.
        g = self._online_grace_s() if grace_s is None else grace_s
        # In contact if the last contact is within the grace window.
        return (time.time() - ts) <= g

    def spokes_in_contact(self, grace_s: Optional[float] = None) -> list:
        """Ids considered 'in contact' for display: connected now OR seen within
        the grace window. The WebUI colours online/offline tiles from this."""
        # Resolve the grace window and the current time once for the whole scan.
        g = self._online_grace_s() if grace_s is None else grace_s
        now = time.time()
        # Start with every live connection.
        ids = set(self.active_connections.keys())
        # Add every id whose last heartbeat falls inside the grace window.
        for sid, ts in list(self.heartbeat.last_seen.items()):
            if ts and (now - ts) <= g:
                ids.add(sid)
        # Return a stable, sorted list for the UI.
        return sorted(ids)

    def _evict_spoke(self, spoke_id: str) -> None:
        """Drop ALL per-spoke in-memory state for ``spoke_id``.

        Called when an admin deletes a spoke (api.delete_spoke) so the
        per-spoke dicts (simulations_cache, spoke_telemetry, rate_limiters,
        spoke_events, spoke_recovery, agent_logs) don't accumulate entries for
        ids that no longer exist — unbounded growth as spokes are deleted/recreated
        over time at scale. NOT called on a transient disconnect: spoke_telemetry
        must keep its DISCONNECTED status for the WebUI, and spoke_recovery is
        needed by the watchdog if the spoke is flapping. Reconnect re-creates
        rate_limiters / re-pushes simulations_cache, so eviction on delete is safe.
        """
        # Normalise the id to its primary key, then drop every per-spoke cache entry.
        pk = self._primary_key(spoke_id)
        self.simulations_cache.pop(pk, None)
        self.spoke_telemetry.pop(pk, None)
        self.rate_limiters.pop(pk, None)
        self.spoke_events.pop(pk, None)
        self.spoke_recovery.pop(pk, None)
        self.agent_logs.pop(pk, None)
        self.heartbeat.last_seen.pop(pk, None)  # else grows unbounded across delete/recreate
        # Also drop the persisted last-seen so a deleted spoke doesn't keep a
        # stale timestamp that would surface as a ghost "last seen" entry.
        self.state.clear_spoke_last_seen(pk)
        # Forget which ClearPass config it was sent (keyed by the same primary
        # key), so a spoke re-approved under this id is not stale (nac_spoke_stale).
        record_nac_push(self, spoke_id, None)
        # Purge the IDENTITY-correlation indices too. remove_module() clears the
        # persisted module_metadata, but the in-memory spoke_id_alias (NOT
        # persisted — rebuilt at runtime) and install_uuid_index still map this
        # spoke's connect-name(s) and install_uuid(s) onto its guid. Without this,
        # a clone-correlated spoke RESURRECTS on the very next reconnect:
        # _reconcile_spoke_identity resolves the reconnecting box back to the
        # deleted guid via the surviving alias/index and re-creates its metadata —
        # so "Delete" never sticks for a cloned fleet (all clones keep collapsing
        # into one guid no matter how many times it's deleted). Drop every alias/
        # index entry that resolves to pk, plus pk's own guid-keyed entries.
        # Remove connect-name aliases that point at (or are) the deleted spoke.
        for _name, _guid in list(getattr(self, "spoke_id_alias", {}).items()):
            if _guid == pk or _name == pk:
                self.spoke_id_alias.pop(_name, None)
        # Remove install-uuid index entries that point at (or are) the deleted spoke.
        for _iu, _guid in list(getattr(self, "install_uuid_index", {}).items()):
            if _guid == pk or _iu == pk:
                self.install_uuid_index.pop(_iu, None)
        # Purge the out-of-contact alert-loop state too (SpokeAlertMixin). Without
        # this a spoke/agent deleted WHILE it has an active alert leaves an orphaned
        # entry in _spoke_alerts: the alert loop only re-evaluates APPROVED modules,
        # so the deleted id never transitions to NONE and the entry lingers until a
        # hub restart. That orphan keeps inflating the header "Module Status"
        # out-of-contact count (len(_spoke_alerts)) even though the Spokes & Agents
        # page — which only walks known_modules — shows nothing out of contact. The
        # decommission route already does this (setup.py); delete must match.
        try:
            # Clear any active alert and its tier/absence bookkeeping for this spoke.
            self._spoke_alert_clear(pk)
            self._spoke_alert_tier.pop(pk, None)
            self._spoke_absent_since.pop(pk, None)
        except Exception:  # noqa: BLE001 — alert state is best-effort
            # Missing alert state is fine; there is nothing to clear.
            pass

    def _mark_spoke_disconnected(self, spoke_id: str) -> None:
        """Record a clean-WS-close disconnect in ``spoke_telemetry``.

        A spoke deleted via ``DELETE /setup/spokes/{id}`` is evicted
        (``_evict_spoke`` pops ``spoke_telemetry``) BEFORE that socket's 1008
        "Removed by admin" close fires the disconnect handler, so the entry
        may already be gone — re-create a minimal ``DISCONNECTED`` stub rather
        than ``KeyError`` on the index. A transient disconnect (entry still
        present) just updates the status in place.
        """
        # Look up the telemetry entry under the spoke's primary key.
        pk = self._primary_key(spoke_id)
        tel = self.spoke_telemetry.get(pk)
        # Entry already evicted (spoke deleted): create a minimal DISCONNECTED stub.
        if tel is None:
            self.spoke_telemetry[pk] = {
                "last_attempt": time.time(),
                "status": "DISCONNECTED",
            }
        else:
            # Entry still present (transient drop): just flip its status.
            tel["status"] = "DISCONNECTED"

    def get_spoke_by_type(self, module_type: str) -> Optional[str]:
        """Return the first connected, approved spoke that advertised the given module_type."""
        # Prefer a connected spoke that explicitly declared this module_type.
        for sid, mtype in self.spoke_module_types.items():
            if mtype == module_type and sid in self.active_connections:
                return sid
        # Legacy fallback: derive type from known spoke_id prefixes for spokes that
        # pre-date the module_type system and never sent the field. See _MODULE_TYPE_PREFIX.
        prefix = _MODULE_TYPE_PREFIX.get(module_type)
        if prefix:
            return next((sid for sid in self.active_connections if prefix in sid), None)
        # No match at all.
        return None

    def get_spoke_for_agent(self, agent_id: str, fallback_hypervisor: bool = True) -> Optional[str]:
        """Return the connected spoke_id that owns ``agent_id``.

        ``agent_info`` is populated from every ``AGENT_RELAY_UP`` frame, so a
        pxmx-dialed agent indexes to the pxmx spoke and a cs-dialed agent
        indexes to the cs spoke. ``agent_info`` is in-memory only though —
        wiped on hub restart and evicted on spoke disconnect — so a quiet
        agent (no relayed frame since the last restart, or one that just
        hasn't sent anything in a while) can read as unindexed even though
        it's genuinely connected. Before falling back, this also tries the
        DURABLE composite heartbeat key ``{spoke_pk}:{agent_pk}`` (persisted
        via ``spoke_last_seen``, re-seeded into ``heartbeat.last_seen`` on
        boot — same source ``_spoke_effective_tenants``/
        ``_offline_relay_agents`` use) so a tenant-pinned host's VMs don't
        silently drop out of ``_merge_pinned_agent_vms`` (``fallback_hypervisor=
        False``) just because ``agent_info`` hasn't been (re)populated yet —
        this was the reported "pinned host's VMs still missing" gap: the
        agent_config pin was correct but the merge couldn't resolve a spoke
        for the agent and silently skipped it.

        Returns None when the agent is not connected / not yet indexed by
        EITHER signal (e.g. the first ~30s after connect, before any relayed
        frame OR heartbeat has landed).

        When ``fallback_hypervisor`` is True, a missing index falls back to the
        pxmx (``hypervisor``) spoke — correct for the all-in-one path where
        every agent is on the pxmx spoke. Callers that must NOT misroute a
        cs-dialed agent (e.g. the CS bridge relaying commands) pass
        ``fallback_hypervisor=False`` and skip when None is returned.
        """
        # Normalise the agent id and check the in-memory relay index first.
        agent_pk = self._agent_primary_key(agent_id)
        info = self.agent_info.get(agent_pk)
        if info:
            # Use the indexed spoke only if it is still connected.
            sid = info.get("spoke_id")
            if sid and self._primary_key(sid) in self.active_connections:
                return sid
        # Fall back to the durable "spoke:agent" heartbeat keys to find the owning spoke.
        hb_last = getattr(getattr(self, "heartbeat", None), "last_seen", None) or {}
        for key in hb_last:
            # Only composite keys carry a spoke/agent pair; split them apart.
            if isinstance(key, str) and ":" in key:
                spoke_pk, apk = key.split(":", 1)
                spoke_pk = self._primary_key(spoke_pk)
                # Match this agent on a spoke that is connected right now.
                if apk == agent_pk and spoke_pk in self.active_connections:
                    return spoke_pk
        # Still unknown: optionally assume the hypervisor (pxmx) spoke owns it.
        if fallback_hypervisor:
            return self.get_hypervisor_spoke()
        return None

    def _cert_target_spoke(self, module_type: str, identifier: str = "") -> Optional[str]:
        """Resolve the spoke to receive ``INSTALL_CERT`` for a cert-distribution
        target. For agent-hosting types (``hypervisor``/``simulation``) the
        target spoke is the one that OWNS the target pxmx agent — in the split
        topology the agents dial the cs (simulation) spoke, so a ``hypervisor``
        target must route THERE, not to a connected-but-agent-less pxmx spoke
        (which returns ``No agent resolved for cert install`` and leaves a
        deployed-cert target showing red on the UI).

        A specific ``identifier`` (the per-node agent_id from
        ``build_available_targets``) resolves via the ``agent_info`` index
        (``get_spoke_for_agent`` with the hypervisor fallback OFF so a
        cs-dialed agent isn't misrouted to the pxmx spoke). An empty
        identifier (the "all nodes" broadcast target) resolves to any
        connected agent-hosting spoke that has an indexed agent. The
        ``agent_info`` index lags connect by ~30s, so the final fallback
        prefers ``simulation`` (where split-topology agents live) over a bare
        pxmx spoke that may have none.

        Non-agent-hosting types (firewall, ipam, directory, statuspage, ...)
        are one distinct target PER connected spoke of that type —
        ``build_available_targets`` sets ``identifier`` to that spoke's own
        id (there is no "any <type>" broadcast target to fall back to). A
        specific identifier that's a currently-connected spoke of the right
        type is used directly. Before this, a stored 'firewall' target
        carried no way to tell WHICH of two connected firewall spokes it
        meant, so distribution always fell back to ``get_spoke_by_type``
        (first-connected-wins), silently pushing a tenant's cert to the
        WRONG firewall in a multi-spoke deployment. No identifier (a target
        added before this fix shipped, or targeting a module_type with no
        such concept) or a stale/disconnected identifier falls back to
        ``get_spoke_by_type`` unchanged — the pre-fix behavior, for
        backward compat."""
        # Agent-hosting types route by which spoke owns the agent.
        if module_type in ("hypervisor", "simulation"):
            # A specific agent id: find the spoke that owns that agent (no pxmx guess).
            if identifier:
                sid = self.get_spoke_for_agent(identifier, fallback_hypervisor=False)
                if sid:
                    return sid
            # No specific agent: pick any connected agent-hosting spoke that has an indexed agent.
            for info in (self.agent_info or {}).values():
                sid = (info or {}).get("spoke_id")
                pk = self._primary_key(sid)
                if (sid and pk in self.active_connections
                        and self.spoke_module_types.get(pk) in ("hypervisor", "simulation")):
                    return sid
            # Indexes not populated yet: prefer the simulation spoke, then any pxmx spoke.
            return (self.get_spoke_by_type("simulation")
                    or self.get_spoke_by_type("hypervisor"))
        # netbox-server targets are generic agents that deployed NetBox locally.
        if module_type == "netbox-server":
            # The cert target is a generic agent that ran the netbox-server
            # deploy (has the local nginx cert helper + root). A specific
            # identifier picks that agent; empty picks any connected one.
            # Use the named agent if it is a known NetBox host and currently connected.
            if identifier and self._primary_key(identifier) in self.netbox_server_agents \
                    and self._primary_key(identifier) in self.active_connections:
                return identifier
            # Otherwise pick any connected NetBox-hosting agent (or None).
            return next((sid for sid in self.netbox_server_agents
                         if sid in self.active_connections), None)
        # ldap-server targets are generic agents that deployed the LDAP server locally.
        if module_type == "ldap-server":
            # The cert target is a generic agent that ran the ldap-server deploy
            # (has the local lm-ldap-install-cert helper + root). Mirrors the
            # netbox-server branch.
            # Use the named agent if it is a known LDAP host and currently connected.
            if identifier and self._primary_key(identifier) in self.ldap_server_agents \
                    and self._primary_key(identifier) in self.active_connections:
                return identifier
            # Otherwise pick any connected LDAP-hosting agent (or None).
            return next((sid for sid in self.ldap_server_agents
                         if sid in self.active_connections), None)
        # zabbix-server targets are generic agents hosting the Zabbix web frontend.
        if module_type == "zabbix-server":
            # Generic agent hosting the Zabbix web frontend (nginx); mirrors
            # the ldap-server branch.
            # Set of agents known to host Zabbix (attribute may not exist on older hubs).
            agents = getattr(self, "zabbix_server_agents", set())
            # Use the named agent if it is a known Zabbix host and currently connected.
            if identifier and self._primary_key(identifier) in agents \
                    and self._primary_key(identifier) in self.active_connections:
                return identifier
            # Otherwise pick any connected Zabbix-hosting agent (or None).
            return next((sid for sid in agents
                         if sid in self.active_connections), None)
        # Other types: honour a specific identifier if it is a connected spoke of that type.
        if identifier:
            pk = self._primary_key(identifier)
            if pk in self.active_connections and self.spoke_module_types.get(pk) == module_type:
                return identifier
            # A registered spoke that is just offline: wait for it. Falling back
            # would install on ANOTHER spoke (e.g. the other firewall) and mark
            # this target SUCCESS, so the sweep would never retry it.
            ss = getattr(getattr(self, "state", None), "system_state", None) or {}
            registered = pk in (ss.get("approved_modules") or {}) or pk in (ss.get("known_modules") or [])
            if registered and pk not in self.active_connections:
                return None
        # Fall back to the first connected spoke of the type (legacy behaviour).
        return self.get_spoke_by_type(module_type)

    def get_hypervisor_spoke(self) -> Optional[str]:
        """Return a connected spoke that can answer Proxmox-agent commands —
        either a dedicated hypervisor (pxmx) spoke, or, in the split-topology
        case, a simulation (cs) spoke hosting its own agent listener with no
        separate pxmx spoke at all. Prefers a real hypervisor spoke if one is
        connected.

        Drop-in replacement for the ~18 call sites across api.py that called
        ``get_spoke_by_type("hypervisor")`` directly (VM/console/node/pool/
        ISO/storage/template browsing, agent removal, endpoint/NAC sync's
        Proxmox enrichment, the pxmx_vms cache refresh, ...) — every one of
        them silently returned nothing for an all-cs-hosted deployment like
        this one, the same blind spot cs_bridge.py's CSBridgePoller had (see
        that fix's commit) before it was taught to check every agent-hosting
        spoke type instead of only "hypervisor". Doesn't replace
        get_spoke_for_agent, which is still the right choice wherever a
        specific agent_id is already in scope — this is for the handful of
        callers that only ever assumed a single global hypervisor spoke."""
        # Prefer a real pxmx spoke, else a cs spoke that hosts agents itself.
        return self.get_spoke_by_type("hypervisor") or self.get_spoke_by_type("simulation")

    def get_hypervisor_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware hypervisor spoke for per-tenant VM queries (dashboard
        counts, sync). With a real ``tenant_id``, return ONLY a connected,
        approved hypervisor spoke BOUND to that tenant — NEVER one bound to a
        different tenant, which would leak another tenant's VMs into this
        tenant's count (the dashboard all-tenants overview otherwise showed the
        whole hypervisor's VM list under every tagless/unbound tenant).

        No unassigned fallback here (unlike ``get_client_sim_spoke``): an
        unassigned hypervisor attributed to every asking tenant would put the
        same VMs on every tenant row — exactly the leak we're closing. If no
        hypervisor is bound to the tenant, the tenant simply has no VMs to
        count (``None`` → caller returns 0). Bind the spoke to the tenant to
        see its VMs.

        With ``tenant_id`` None / ``"default"`` (admin unscoped / global view),
        fall back to ``get_hypervisor_spoke`` so the admin's default dashboard
        still shows a global count (unchanged legacy behavior).
        """
        # Admin/global view: any hypervisor-capable spoke will do.
        if _admin_view(tenant_id):
            return self.get_hypervisor_spoke()
        # Collect every hypervisor and simulation spoke as candidates.
        cands = (list(self.get_all_spokes_by_type("hypervisor") or [])
                 + list(self.get_all_spokes_by_type("simulation") or []))
        # Keep only connected, approved candidates.
        cands = [sid for sid in cands if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        if not cands:
            return None
        # Return the first candidate bound to this tenant, else None (no cross-tenant fallback).
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
        return bound[0] if bound else None

    def _spoke_effective_tenants(self, spoke_id: str) -> set:
        """The set of tenant_ids an agent-hosting spoke is EFFECTIVELY scoped to
        — driven by its AGENTS' own tenant scope, NOT just the spoke's
        ``module_metadata`` binding.

        A single Proxmox host can dial a SHARED spoke yet be PINNED (per-agent
        Tenant button → ``agent_config[agent].client_simulation.tenant_id``,
        ``tenant_pinned``) to one specific tenant. That pin — not the shared
        spoke's binding — must decide who sees the host's node on their Overview,
        or the pinned host leaks onto EVERY tenant's Overview (the reported
        cross-tenant leak: a Proxmox pinned to LRB on a shared spoke showed up in
        RA). Each connected agent contributes its PINNED tenant when set, else
        the spoke's own binding (an unpinned agent inherits the spoke tenant —
        mirrors ``_inherit_agent_tenant``). A spoke with no indexed agents yet
        (``agent_info`` lags connect ~30s) falls back to its own binding so a
        freshly-bound spoke still resolves. Empty set = no scope (unbound)."""
        # Read the module metadata and the spoke's own tenant binding, as
        # stored: stripping " ACME " would merge it with a twin "ACME".
        from access import raw_tenant_id
        md = self.state.system_state.get("module_metadata", {}) or {}
        spoke_pk = self._primary_key(spoke_id)
        spoke_tid = raw_tenant_id((md.get(spoke_id, {}) or md.get(spoke_pk, {}) or {})
                                  .get("tenant_id"))
        # Per-agent config holds any per-agent tenant pin.
        agent_cfg = self.state.system_state.get("agent_config", {}) or {}
        # Agents on this spoke, from BOTH the live index (agent_info, wiped on hub
        # restart / evicted on spoke disconnect) AND the DURABLE composite
        # heartbeat keys ``{spoke_pk}:{agent_pk}`` (persisted via spoke_last_seen,
        # re-seeded on boot — same source _offline_relay_agents uses). Without the
        # durable source a hub restart would blank agent_info for ~30s and the
        # pinned-host scope would fall back to the spoke's (shared) binding,
        # re-leaking the host onto every tenant's Overview until agents relay.
        # Collect agents indexed live to this spoke.
        agents = set()
        for apk, info in (getattr(self, "agent_info", {}) or {}).items():
            if info and info.get("spoke_id") \
                    and self._primary_key(info.get("spoke_id")) == spoke_pk:
                agents.add(apk)
        # Add agents seen on this spoke via the durable composite heartbeat keys.
        hb_last = getattr(getattr(self, "heartbeat", None), "last_seen", None) or {}
        for key in hb_last:
            if isinstance(key, str) and ":" in key:
                s_pk, a_pk = key.split(":", 1)
                if self._primary_key(s_pk) == spoke_pk:
                    agents.add(a_pk)
        # No agents known yet: use the spoke's own binding (or no scope).
        if not agents:
            return {spoke_tid} if spoke_tid else set()
        # Each agent contributes its pinned tenant, else inherits the spoke's tenant.
        effs = set()
        for apk in agents:
            pin = raw_tenant_id(((agent_cfg.get(apk, {}) or {}).get("client_simulation") or {})
                                .get("tenant_id"))
            eff = pin or spoke_tid
            if eff:
                effs.add(eff)
        # Union of effective tenants across the spoke's agents.
        return effs

    def get_hypervisor_spokes_for_tenant(self, tenant_id: str = None) -> list:
        """PLURAL sibling of ``get_hypervisor_spoke_for_tenant``: EVERY connected,
        approved agent-hosting spoke (hypervisor=pxmx AND simulation=cs) VISIBLE to
        ``tenant_id`` — i.e. EFFECTIVELY scoped to it OR to the SHARED tenant.

        A single tenant can legitimately host Proxmox on more than one spoke — a
        dedicated pxmx hypervisor AND a CS-enabled box whose agent dials a cs
        spoke's ``/ws/agent`` (a mix of infra + sim-client VMs). The Overview /
        node list must aggregate across ALL of them, not just the one
        ``bound[0]`` the singular resolver returns, or the sim-hosted host
        silently drops off the Hypervisors page. SHARED-tenant spokes (a lab
        hypervisor marked shared, visible to every tenant — mirrors
        ``spoke_visible_to_session``) are INCLUDED: without this a shared Proxmox
        host's VMs still list (get_pxmx_vms fans every spoke + subnet-filters) but
        its node dropped off the per-tenant Overview once the tenant gained any
        bound spoke, so the fallback stopped firing (the reported regression).

        Visibility is by the spoke's EFFECTIVE tenant scope
        (``_spoke_effective_tenants``), NOT its raw ``module_metadata`` binding:
        a Proxmox agent PINNED to a real tenant on a SHARED spoke is visible ONLY
        to that tenant, never to every other tenant (the reported leak — the host
        stayed on the shared spoke but was assigned to LRB, yet showed in RA).
        Still no cross-tenant leak — a spoke effectively scoped to a DIFFERENT
        real tenant is excluded. Empty (not a global fallback) when nothing is
        visible: the caller decides whether to fall back, as with the singular
        resolver.

        ``tenant_id == "default"`` (the built-in ADMIN tenant) is NOT a special
        "no aggregation" case here — it is scoped exactly like any other
        tenant (mirrors ``access.tenant_scope_ids``'s "default" → {"", "default"}
        convention): UNASSIGNED hosts (no agent pin, no spoke binding) and
        hosts explicitly bound/pinned to ``"default"`` are visible to it, plus
        shared infra, but a host bound to some OTHER real tenant is never
        pulled in (that firehose was the originally-reported leak). Without
        this, a Proxmox host the admin deliberately assigned to the ADMIN
        tenant would never appear on its own Overview — the reported "servers
        I just added don't show up" bug."""
        # Ids compared as the access checks compare them (any case).
        from access import ADMIN_TENANT_ID, first_shared_tenant, _norm_tenant_id as _norm
        me = _norm(tenant_id)
        # No tenant given (or a blank one) means nothing is visible.
        if not me:
            return []
        # Candidates are all pxmx and cs spokes.
        cands = (list(self.get_all_spokes_by_type("hypervisor") or [])
                 + list(self.get_all_spokes_by_type("simulation") or []))
        # Find the tenant flagged as "shared" (visible to everyone), if any.
        try:
            _tenants = (getattr(self.state, "tenant_state", {}) or {}).get("tenants", {}) or {}
            shared = first_shared_tenant(_tenants)
        except Exception:
            # Tenant state unreadable: behave as if there is no shared tenant.
            shared = None
        # Build the set of tenant ids whose spokes this tenant may see.
        want = {me}
        if me == ADMIN_TENANT_ID:
            want.add("")  # UNASSIGNED resources are visible to the ADMIN scope
        if shared:
            want.add(_norm(shared))
        # Helpers that work out a spoke's module type and whether a tenant owns its own spoke.
        from access import spoke_module_type, tenant_left_shared
        # Walk the candidates and keep those visible to the tenant.
        out = []
        for sid in cands:
            # Skip disconnected and unapproved spokes.
            if sid not in self.active_connections:
                continue
            if not self.approved_modules.get(sid, False):
                continue
            # Skip spokes whose effective scope does not overlap the visible set.
            effs = {_norm(t) for t in self._spoke_effective_tenants(sid)} or {""}
            if not effs & want:
                continue
            # A tenant with its own spoke of this type is out of the shared
            # environment: only hosts scoped to the tenant itself remain.
            if me not in effs and tenant_left_shared(
                    self, tenant_id, spoke_module_type(self, sid)):
                continue
            # Visible: include it.
            out.append(sid)
        return out

    def get_nw_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware network-devices (nw) spoke — mirrors
        ``get_hypervisor_spoke_for_tenant``. With a real ``tenant_id``, return
        ONLY a connected, approved nw spoke BOUND to that tenant — NEVER one
        bound to a different tenant (that would leak another tenant's devices
        into this tenant's live data surface / offline cache). No unassigned
        fallback: an unassigned nw spoke attributed to every asking tenant
        would put the same fleet on every tenant row — exactly the leak the
        nw tenant-scoping closes. If no nw spoke is bound to the tenant, the
        tenant has no live devices (``None`` → caller falls back to the
        offline cache / empty). Bind the spoke to the tenant to see its
        devices.

        With ``tenant_id`` None / ``"default"`` (admin unscoped / global view),
        fall back to ``get_spoke_by_type("nw")`` so the admin's Network
        Devices page still shows the global fleet (unchanged legacy behavior).
        """
        # Admin/global view: return any nw spoke.
        if _admin_view(tenant_id):
            return self.get_spoke_by_type("nw")
        # Candidates are connected, approved nw spokes.
        cands = [sid for sid in (self.get_all_spokes_by_type("nw") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        # None connected means no live devices.
        if not cands:
            return None
        # Return the nw spoke bound to this tenant, or None (never another tenant's).
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
        return bound[0] if bound else None

    def get_directory_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware directory (LDAP) spoke — mirrors
        ``get_nw_spoke_for_tenant`` but with ONE key difference: the directory's
        tenancy is OU-partitioning on a SHARED server (``ou=<slug>,<base_dn>``),
        not per-tenant spokes. A typical deploy is a single (mirror-pair)
        directory spoke that is UNASSIGNED and serves every tenant via its OU.
        So unlike nw/hypervisor (which return ``None`` when no spoke is bound to
        the tenant — strict, no unassigned fallback), this resolver FALLS BACK
        to an unassigned directory spoke: that shared OU server legitimately
        serves the asking tenant.

        With a real ``tenant_id``: prefer a connected, approved directory spoke
        BOUND to that tenant; if none, fall back to an UNASSIGNED or
        SHARED-tenant directory spoke (the shared OU server); else ``None``. NEVER return a spoke bound to a
        DIFFERENT tenant — that would relay this tenant's OU ops to another
        tenant's spoke (the cross-tenant leak this closes in a multi-spoke
        deploy; the spoke-side OU slug is the backstop, this is defense-in-depth).

        With ``tenant_id`` None / ``"default"`` (admin unscoped / global view),
        fall back to ``get_spoke_by_type("directory")`` so a Global Admin still
        sees / manages every tenant's OU (unchanged legacy behavior).
        """
        # Admin/global view: return any directory spoke.
        if _admin_view(tenant_id):
            return self.get_spoke_by_type("directory")
        # Candidates are connected, approved directory spokes.
        cands = [sid for sid in (self.get_all_spokes_by_type("directory") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        # None connected means nothing to route to.
        if not cands:
            return None
        # Look for a directory spoke bound to this tenant; use it if found.
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
        if bound:
            return bound[0]
        # No spoke bound to this tenant → the shared OU-partitioned server: an
        # UNASSIGNED directory spoke serves every tenant via ou=<slug>,<base>.
        # This fallback is intentional and DIFFERENT from nw/hypervisor (which
        # return None here) — do not "fix" it to match them.
        # A spoke bound to the SHARED tenant is the same shared server.
        # Helpers that detect the shared tenant and tenants owning their own spoke.
        from access import tenant_is_shared, tenant_shared_fallback_blocked
        # A tenant with its own directory spoke (or denied shared access) must
        # never fall through to the shared server.
        if tenant_shared_fallback_blocked(self, tenant_id, "directory"):
            return None  # own (offline) spoke → never the shared one
        # Otherwise use an unassigned or shared-tenant directory spoke (the shared OU server).
        shared = [sid for sid in cands
                  if not (md.get(sid, {}).get("tenant_id") or "")
                  or tenant_is_shared(md.get(sid, {}).get("tenant_id"))]
        return shared[0] if shared else None

    def get_nw_spoke_for_shared(self) -> Optional[str]:
        """The nw spoke that owns the SHARED-tenant devices. Shared devices are
        visible to every tenant (the shared-tenant-flag invariant), so when a
        non-admin's visible slice includes a shared device the hub must relay
        to the spoke bound to the shared tenant. Resolves the shared tenant id
        via ``access.shared_tenant_id`` (lazy local import — ``access`` never
        imports the registry, so it's cycle-safe) then defers to
        ``get_nw_spoke_for_tenant``. With no shared tenant configured, falls
        back to the global nw spoke (admin path)."""
        # Look up the shared tenant id lazily (avoids an import cycle).
        from access import shared_tenant_id
        sid = shared_tenant_id()
        # Resolve that tenant's nw spoke, or any nw spoke if no shared tenant exists.
        return self.get_nw_spoke_for_tenant(sid) if sid else self.get_spoke_by_type("nw")

    def get_truenas_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware TrueNAS (storage) spoke — mirrors
        ``get_nw_spoke_for_tenant``. With a real ``tenant_id``, return ONLY a
        connected, approved storage spoke BOUND to that tenant — NEVER one
        bound to a different tenant (that would leak another tenant's
        appliances into this tenant's live surface / offline cache). No
        unassigned fallback. With ``tenant_id`` None / ``"default"`` (admin
        unscoped), fall back to ``get_spoke_by_type("storage")`` so the admin's
        Storage page still shows the global fleet."""
        # Admin/global view: return any storage spoke.
        if _admin_view(tenant_id):
            return self.get_spoke_by_type("storage")
        # Candidates are connected, approved storage spokes.
        cands = [sid for sid in (self.get_all_spokes_by_type("storage") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        # None connected means nothing to route to.
        if not cands:
            return None
        # Return the storage spoke bound to this tenant, or None (never another tenant's).
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
        return bound[0] if bound else None

    def get_logging_spokes_for_tenant(self, tenant_id: str) -> list:
        """Every connected, approved syslog (``logging``) spoke bound to
        ``tenant_id``. A tenant may run several collectors, so this is a list.
        Never returns another tenant's collector and has no unassigned or
        admin fallback: syslog data is always read per tenant."""
        # No tenant means nothing to return.
        if not tenant_id:
            return []
        # Candidates are connected, approved logging spokes.
        from access import same_tenant
        md = self.state.system_state.get("module_metadata", {})
        return [sid for sid in (self.get_all_spokes_by_type("logging") or [])
                if sid in self.active_connections
                and self.approved_modules.get(sid, False)
                and same_tenant(md.get(sid, {}).get("tenant_id"), tenant_id)]

    def get_truenas_spoke_for_shared(self) -> Optional[str]:
        """The storage spoke that owns the SHARED-tenant TrueNAS appliances.
        Mirrors ``get_nw_spoke_for_shared``."""
        # Look up the shared tenant id lazily (avoids an import cycle).
        from access import shared_tenant_id
        sid = shared_tenant_id()
        # Resolve that tenant's storage spoke, or any storage spoke if no shared tenant exists.
        return (self.get_truenas_spoke_for_tenant(sid)
                if sid else self.get_spoke_by_type("storage"))

    def get_cppm_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware NAC (ClearPass/cppm) spoke — mirrors
        ``get_nw_spoke_for_tenant``. With a real ``tenant_id``, return ONLY a
        live ``nac`` spoke (``get_nac_live_spokes``) that serves that tenant alone
        (``_nac_spoke_serves_only``) — NEVER one that also serves another
        tenant or the shared ClearPass, because a tenant's own spoke is read
        without the tenant's subnet filter. No shared fallback here — see
        ``get_cppm_spoke_for_shared`` for the explicit shared-tenant path a
        caller falls back to when the tenant has no dedicated spoke of its
        own. With ``tenant_id`` None / ``"default"`` (admin unscoped / global
        view), use ``get_cppm_spoke_for_global`` so a global request never
        falls through to an arbitrary tenant-bound spoke.

        The tenant's own ``nac_instances`` records decide first, in config
        order, the way main.py push_nac_config sends them: a bound
        record is served by its spoke (compared by primary key, so a record
        saved under a spoke's pre-migration id still matches), and the first
        spoke-less record by every NAC spoke that no record is bound to.
        Tenant ids compare case-insensitively (``access.same_tenant``). Only
        then does a spoke bound to the tenant without a record of its own
        count.

        Regression this fixes: a tenant with TWO nac spokes (two ClearPass
        appliances, e.g. on different network segments only one spoke can
        reach) used to resolve via ``bound[0]`` over
        ``get_all_spokes_by_type("nac")`` — a list whose order tracks
        connection/reconnection timing (each spoke's entry is popped on
        disconnect and re-inserted at the end on reconnect), NOT any stable
        assignment. So which of the two spokes answered a query flipped
        every time EITHER nac spoke's connection blipped — intermittently
        routing a query to a spoke with no network route to the OTHER
        instance's ClearPass host ("no route to host", then working again
        once the order flipped back). Records are walked in config order and
        candidate spokes are sorted by id, so the pick no longer depends on
        connection order."""
        # Admin/global view: use only the shared or unassigned NAC source.
        if _admin_view(tenant_id):
            return self.get_cppm_spoke_for_global()
        from access import same_tenant
        # Connected, approved, not stale NAC spokes, sorted so the pick is stable.
        live = self.get_nac_live_spokes()
        # Which spokes have a record bound to them, and which record the rest receive.
        instances = _nac_instances(self)
        bound = {self._primary_key(i["spoke_id"]) for i in instances if i.get("spoke_id")}
        first_spokeless = next((i for i in instances if not i.get("spoke_id")), None)
        # The tenant's own records first, in config order.
        for inst in instances:
            if not same_tenant(inst.get("tenant_id"), tenant_id):
                continue
            if inst.get("spoke_id"):
                served = [self._primary_key(inst["spoke_id"])]
            elif inst is first_spokeless:
                served = [sid for sid in live if sid not in bound]
            else:
                served = []  # never pushed to any spoke
            sid = next((s for s in served
                        if s in live and _nac_spoke_serves_only(self, s, tenant_id)), None)
            if sid:
                return sid
        # Else a spoke bound to the tenant that serves no one else.
        return next((sid for sid in live
                     if same_tenant(self.state.get_spoke_tenant(sid), tenant_id)
                     and _nac_spoke_serves_only(self, sid, tenant_id)), None)

    def get_dhcp_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware DHCP (Kea) spoke — mirrors ``get_nw_spoke_for_tenant``.
        With a real ``tenant_id``, return ONLY a connected, approved ``dhcp``
        spoke BOUND to that tenant — NEVER one bound to a different tenant.
        No unassigned fallback here — see ``get_dhcp_spoke_for_shared`` for the
        explicit shared-tenant path a caller falls back to when the tenant has
        no dedicated DHCP spoke of its own. DHCP is commonly deployed as ONE
        shared Kea server for the whole hub (see net_services.py's record-level
        subnet filtering, which stays the primary tenant isolation for that
        common case) — this resolver only matters once a SECOND dhcp spoke is
        connected. With ``tenant_id`` None / ``"default"`` (admin unscoped /
        global view), fall back to ``get_spoke_by_type("dhcp")`` so the admin's
        DHCP page still shows a spoke (unchanged legacy behavior)."""
        # Admin/global view: return any dhcp spoke.
        if _admin_view(tenant_id):
            return self.get_spoke_by_type("dhcp")
        # Candidates are connected, approved dhcp spokes.
        cands = [sid for sid in (self.get_all_spokes_by_type("dhcp") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        # None connected means nothing to route to.
        if not cands:
            return None
        # Return the dhcp spoke bound to this tenant, or None (never another tenant's).
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
        return bound[0] if bound else None

    def get_dns_spoke_for_tenant(self, tenant_id: str = None) -> Optional[str]:
        """Tenant-aware DNS (Unbound) spoke — mirrors ``get_nw_spoke_for_tenant``.
        With a real ``tenant_id``, return ONLY a connected, approved ``dns``
        spoke BOUND to that tenant — NEVER one bound to a different tenant.
        No unassigned fallback here — see ``get_dns_spoke_for_shared`` for the
        explicit shared-tenant path a caller falls back to when the tenant has
        no dedicated DNS spoke of its own. DNS is commonly deployed as ONE
        shared Unbound server for the whole hub (see net_services.py's
        record-level subnet filtering, which stays the primary tenant
        isolation for that common case) — this resolver only matters once a
        SECOND dns spoke is connected. With ``tenant_id`` None / ``"default"``
        (admin unscoped / global view), fall back to
        ``get_spoke_by_type("dns")`` so the admin's DNS page still shows a
        spoke (unchanged legacy behavior)."""
        # Admin/global view: return any dns spoke.
        if _admin_view(tenant_id):
            return self.get_spoke_by_type("dns")
        # Candidates are connected, approved dns spokes.
        cands = [sid for sid in (self.get_all_spokes_by_type("dns") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        # None connected means nothing to route to.
        if not cands:
            return None
        # Return the dns spoke bound to this tenant, or None (never another tenant's).
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
        return bound[0] if bound else None

    def get_nac_live_spokes(self) -> list:
        """The NAC spokes the hub may send NAC reads and writes to: connected,
        approved and not stale (``nac_spoke_stale``: possibly holding a
        ClearPass other than the one the hub gives it now).
        Sorted, so a pick from it never depends on connection order."""
        return sorted(sid for sid in (self.get_all_spokes_by_type("nac") or [])
                      if sid in self.active_connections
                      and self.approved_modules.get(sid, False)
                      and not nac_spoke_stale(self, sid))

    def get_nac_usable_spokes(self) -> list:
        """The live NAC spokes (``get_nac_live_spokes``) the hub has a
        ClearPass config for. ``push_nac_config`` puts a spoke it has no
        config for in ``_nac_unconfigured_spokes`` until it can send one."""
        unconfigured = getattr(self, "_nac_unconfigured_spokes", None) or set()
        return [sid for sid in self.get_nac_live_spokes() if sid not in unconfigured]

    def _unbound_cppm_spoke(self) -> Optional[str]:
        """A connected, approved NAC spoke that no real tenant owns.

        "Unbound" is ``access.spoke_is_unbound``: unassigned, or bound to the
        shared or admin tenant. A spoke bound to any other tenant is never
        returned, because its ClearPass belongs to that tenant alone, and
        neither is a spoke whose NAC instance records belong to one
        (``_nac_instance_owners``), whatever its own binding says, or a stale
        spoke (``get_nac_live_spokes``). Spoke ids are sorted so the pick
        does not flip with connection order when two unbound spokes are
        connected.
        """
        # Lazy import: access imports hub modules at load time.
        from access import spoke_is_unbound
        return next((sid for sid in self.get_nac_live_spokes() if spoke_is_unbound(self, sid)
                     and not _nac_instance_owners(self, sid)), None)

    def get_cppm_spoke_for_shared(self) -> Optional[str]:
        """The NAC spoke that owns the SHARED ClearPass appliance — the source
        a tenant with no dedicated NAC spoke of its own resolves to, and the
        target of shared writes (endpoint sync, NAD registration, 802.1X JIT
        for the shared tenant).

        With a shared tenant configured, only that tenant's spoke qualifies;
        an unassigned spoke is not silently substituted when it is offline.
        With no shared tenant configured, the hub's own ClearPass is the
        shared one: the single-ClearPass deployment registers it unassigned.
        Only an unbound spoke qualifies then, never a spoke bound to a real
        tenant (the generic ``get_spoke_by_type("nac")`` pick used before
        could hand shared writes to another tenant's ClearPass)."""
        # Look up the shared tenant id lazily (avoids an import cycle).
        from access import shared_tenant_id
        tenant_id = shared_tenant_id()
        if not _admin_view(tenant_id):
            return self.get_cppm_spoke_for_tenant(tenant_id)
        # No shared tenant: the unassigned (hub-owned) ClearPass is the shared one.
        return self._unbound_cppm_spoke()

    def get_cppm_spoke_for_global(self) -> Optional[str]:
        """Return the configured shared NAC spoke or an unbound NAC spoke.

        A global read must not be answered by an arbitrary tenant's ClearPass
        instance. If the configured shared source is unavailable, an unbound
        spoke (unassigned, shared or admin) is the only safe fallback.
        """
        # Prefer the explicitly configured shared source when it is available.
        from access import shared_tenant_id
        shared_tid = shared_tenant_id()
        if not _admin_view(shared_tid):
            shared_spoke = self.get_cppm_spoke_for_tenant(shared_tid)
            if shared_spoke:
                return shared_spoke
        # Otherwise choose only a connected, approved NAC spoke no tenant owns.
        return self._unbound_cppm_spoke()

    def get_cppm_spoke_for_scope(self, tenant_id: str = None) -> Optional[str]:
        """The one NAC spoke that answers a single-source read for a scope.

        ``tenant_id`` None or ``"default"`` in any case (admin, no tenant
        selected) uses the global source. A tenant uses the first spoke of its NAC view
        (``get_cppm_spokes_for_tenant``: its own spoke, else the shared one
        when it may use shared), and never another tenant's spoke. Use this
        for one-spoke reads such as dashboard counts, search and a VM's
        policy lookup; the NAC pages merge every spoke in the view instead.
        """
        # Admin, unscoped (no tenant, or "default" in any case): the shared
        # or unbound ClearPass only.
        if _admin_view(tenant_id):
            return self.get_cppm_spoke_for_global()
        # Tenant: the first source of its own NAC view, or nothing.
        spokes = self.get_cppm_spokes_for_tenant(tenant_id)
        return spokes[0] if spokes else None

    def get_cppm_spokes_for_tenant(self, tenant_id: str = None) -> list:
        """Every nac spoke whose records belong in ``tenant_id``'s NAC view:
        their own dedicated spoke when they have one (connected or not: a
        tenant with its own ClearPass, a NAC spoke bound to it or a NAC
        instance record of its own, is out of the shared environment), else
        the hub's shared-tenant CPPM spoke, IF a shared tenant is actually
        configured. A shared CPPM's records are narrowed to just this
        tenant's own by the SAME downstream subnet/tag filter every NAC route
        already applies to a single source.

        Deliberately resolves the shared tenant directly instead of using
        ``get_cppm_spoke_for_shared()``: with no shared tenant configured,
        that method returns the hub's unassigned ClearPass as the target of
        shared writes, but a tenant's read view gains a shared source only
        once a shared tenant is actually configured (unchanged behavior).

        With ``tenant_id`` None / ``"default"`` (admin, unscoped), returns
        ``[]`` — that view fans out across EVERY connected nac spoke via a
        different path (``routes/cppm.py``'s ``_nac_merge_fanout``), which
        also tags each record by its owning tenant, a distinct need this list
        isn't for."""
        # The admin view uses a separate fan-out path, so return nothing here.
        if _admin_view(tenant_id):
            return []
        # Find the tenant's own dedicated NAC spoke.
        own = self.get_cppm_spoke_for_tenant(tenant_id)
        # Helpers for the shared tenant id and own-ClearPass detection.
        from access import shared_tenant_id as _shared_tenant_id, tenant_left_shared
        # Out of shared: its own spoke or NAC record (tenant_has_own_nac), or shared access denied.
        if tenant_left_shared(self, tenant_id, "nac"):
            return [own] if own else []
        # Otherwise add the shared tenant's NAC spoke, but only if a shared tenant exists.
        shared_tid = _shared_tenant_id()
        shared = self.get_cppm_spoke_for_tenant(shared_tid) if shared_tid else None
        # De-duplicate while keeping order and dropping empty entries.
        return list(dict.fromkeys(sid for sid in (own, shared) if sid))

    def get_nac_spoke_owner(self, spoke_id) -> Optional[str]:
        """The tenant whose own ClearPass ``spoke_id`` serves, read without
        that tenant's subnet filter (``access.spoke_data_owner``). None means
        the shared or an unassigned ClearPass, which holds every tenant's
        sessions, so readers get them filtered by their subnets.
        ``access.ADMIN_ONLY_OWNER`` means the spoke serves no one tenant
        alone, so only a Global Admin with no tenant selected reads it.

        The NAC records the hub pushes to the spoke (``_nac_spoke_records``)
        decide first, whatever the spoke's own binding says, because a record
        keeps its tenant when Setup → NAC moves it to another spoke:

        - real tenants' records: that tenant when every record is that
          tenant's (``_nac_spoke_serves_only``), else admin-only. Two
          tenants' records on one spoke, or a tenant's record next to a
          shared or hub record, are a misconfiguration; filtering it by
          subnet instead would still show one tenant's ClearPass to another.
        - a shared record: None, the shared ClearPass.
        - no record, or only the hub's own (blank or ADMIN): the spoke's
          binding (``access.spoke_owner_tenant``: None for unassigned or
          shared, ``"default"`` for ADMIN). A spoke bound to a tenant but
          pushed the hub's record serves the hub's ClearPass, not that
          tenant's, so it is admin-only too.

        A stale spoke (``nac_spoke_stale``) may still hold a record's
        ClearPass that its records no longer show, so it is admin-only."""
        # Lazy import: access imports hub modules at load time.
        from access import ADMIN_ONLY_OWNER, spoke_owner_tenant, tenant_is_shared, tenant_is_unbound
        if not spoke_id:
            return None
        # It may still hold a ClearPass the hub no longer gives it.
        if nac_spoke_stale(self, spoke_id):
            return ADMIN_ONLY_OWNER
        # Records naming real tenants: the spoke serves those tenants' ClearPass.
        owners = sorted(_nac_instance_owners(self, spoke_id))
        if not owners:
            # A shared record: the shared ClearPass, filtered for everyone.
            if any(tenant_is_shared(i.get("tenant_id")) for i in _nac_spoke_records(self, spoke_id)):
                return None
            # Otherwise the spoke's own binding decides.
            bound = spoke_owner_tenant(self, spoke_id)
            if not bound or tenant_is_unbound(bound):
                return bound
            owners = [bound]
        # The one tenant the spoke serves alone, else admin-only.
        return next((t for t in owners if _nac_spoke_serves_only(self, spoke_id, t)),
                    ADMIN_ONLY_OWNER)

    def get_dhcp_spoke_for_shared(self) -> Optional[str]:
        """The DHCP spoke that owns the SHARED-tenant Kea server — the
        fallback a tenant with no dedicated DHCP spoke of its own resolves to.
        Mirrors ``get_nw_spoke_for_shared``."""
        # Look up the shared tenant id lazily (avoids an import cycle).
        from access import shared_tenant_id
        sid = shared_tenant_id()
        # Resolve that tenant's dhcp spoke, or any dhcp spoke if no shared tenant exists.
        return (self.get_dhcp_spoke_for_tenant(sid)
                if sid else self.get_spoke_by_type("dhcp"))

    def get_dns_spoke_for_shared(self) -> Optional[str]:
        """The DNS spoke that owns the SHARED-tenant Unbound server — the
        fallback a tenant with no dedicated DNS spoke of its own resolves to.
        Mirrors ``get_nw_spoke_for_shared``."""
        # Look up the shared tenant id lazily (avoids an import cycle).
        from access import shared_tenant_id
        sid = shared_tenant_id()
        # Resolve that tenant's dns spoke, or any dns spoke if no shared tenant exists.
        return (self.get_dns_spoke_for_tenant(sid)
                if sid else self.get_spoke_by_type("dns"))

    def get_all_spokes_by_type(self, module_type: str):
        """Return all connected spoke IDs that advertised the given module_type."""
        # netbox-server is a capability (advertised in the auth frame), not a
        # module_type any spoke registers under — so the wildcard fan-out + cert
        # targeting resolve it from the netbox_server_agents set.
        # Capability-based server types resolve from their agent sets (connected only).
        if module_type == "netbox-server":
            return [sid for sid in getattr(self, "netbox_server_agents", set())
                    if sid in self.active_connections]
        if module_type == "ldap-server":
            return [sid for sid in getattr(self, "ldap_server_agents", set())
                    if sid in self.active_connections]
        if module_type == "zabbix-server":
            return [sid for sid in getattr(self, "zabbix_server_agents", set())
                    if sid in self.active_connections]
        # Legacy fallback: same prefix map as get_spoke_by_type. See
        # _MODULE_TYPE_PREFIX.
        # Spokes that registered this module_type and are connected.
        by_registry = [sid for sid, mt in self.spoke_module_types.items()
                       if mt == module_type and sid in self.active_connections]
        # Registry matches win; otherwise use the legacy id-prefix fallback.
        if by_registry:
            return by_registry
        # Legacy fallback: any connected spoke whose id contains the type's prefix.
        prefix = _MODULE_TYPE_PREFIX.get(module_type)
        if prefix:
            return [sid for sid in self.active_connections if prefix in sid]
        # Unknown type with no prefix: nothing matches.
        return []

    def _is_client_sim_spoke(self, spoke_id: str) -> bool:
        """True if ``spoke_id`` is an approved Client-Sim spoke.

        Used to deliver a relayed CS_* event to the spoke the agent actually
        dials rather than the tenant's first cs spoke. Accepts the legacy
        "simulation" module type for older combined-spoke builds, matching
        get_client_sim_spoke."""
        # An empty id can never be a Client-Sim spoke.
        if not spoke_id:
            return False
        # Normalise to the primary key; if that fails, use the id as given.
        try:
            pk = self._primary_key(spoke_id)
        except Exception:  # noqa: BLE001
            pk = spoke_id
        # All connected Client-Sim spokes, including the legacy "simulation" type.
        cands = set(self.get_all_spokes_by_type("Client-Sim") or []) | \
            set(self.get_all_spokes_by_type("simulation") or [])
        # Not a Client-Sim spoke at all.
        if not (spoke_id in cands or pk in cands):
            return False
        # It must also be approved (under either id form).
        return bool(self.approved_modules.get(spoke_id)
                    or self.approved_modules.get(pk))

    def get_client_sim_spoke(self, tenant_id: str = None) -> Optional[str]:
        """Return the approved, connected Client-Sim spoke for a tenant.

        Tenant binding lives in module_metadata[spoke_id]["tenant_id"], set by
        an admin at approval time. Returns None if no Client-Sim spoke is
        connected+approved.

        Tenant isolation (IMPORTANT): the cs speak holds a SINGLE CSSettings
        store per spoke, so a spoke shared across tenants = one tenant's
        hub-config push / auto-provision toggle clobbers another's. When a
        tenant_id is given we therefore return ONLY a spoke bound to that
        tenant, or — if none is bound — an UNASSIGNED spoke (no tenant_id in its
        metadata) that the tenant implicitly claims. We NEVER fall back to a
        spoke bound to a different tenant. When tenant_id is None (admin/global
        view) any connected spoke is fine.
        """
        # Connected Client-Sim spokes; fall back to legacy "simulation" type for
        # older combined-spoke builds that haven't adopted "Client-Sim" yet.
        cands = self.get_all_spokes_by_type("Client-Sim") or self.get_all_spokes_by_type("simulation")
        # Only approved spokes carry cached telemetry (unapproved frames are dropped).
        cands = [sid for sid in cands if self.approved_modules.get(sid, False)]
        if not cands:
            return None
        # Tenant-scoped request: look for spokes bound to that tenant.
        if tenant_id:
            md = self.state.system_state.get("module_metadata", {})
            # Sorted so the choice is deterministic.
            bound = sorted(sid for sid in cands
                           if _tagged(md.get(sid), tenant_id))
            if bound:
                return self._sticky_cs_broker(tenant_id, bound)
            # No spoke bound to this tenant — claim an UNASSIGNED one (no
            # tenant_id in metadata). Never cands[0] blindly: that may be a
            # spoke bound to another tenant, whose CSSettings this tenant's
            # push would overwrite (cross-tenant leak).
            unassigned = sorted(sid for sid in cands
                                if not md.get(sid, {}).get("tenant_id"))
            if unassigned:
                return self._sticky_cs_broker(tenant_id, unassigned)
            return None
        # tenant_id is None: admin / global view — any connected spoke. Sorted
        # so repeated calls agree with each other.
        return sorted(cands)[0]

    def _sticky_cs_broker(self, tenant_id: str, candidates: list) -> Optional[str]:
        """Pick a tenant's Client-Sim broker and KEEP it while it stays eligible.

        The caller passes the connected+approved candidates. Returning
        ``candidates[0]`` off a raw list made the broker a function of dict
        ordering over a set that changes every time any spoke reconnects — so a
        single flapping spoke reassigned the broker fleet-wide. Observed
        2026-07-30: one spoke dropping every 60-130s ("no close frame received
        or sent") made the same host log a different ``cs_spoke`` minutes apart,
        and the sim-quota reconcile read a DIFFERENT spoke's effective set each
        pass — reporting "STILL stale after 3 re-push(es)" when nothing was
        refusing the push; several spokes were answering the same question.

        So: hold the previous choice as long as it is still a candidate, and
        only re-elect when it genuinely drops out. Re-election is logged, which
        makes a real broker change visible instead of inferred from a diff of
        two log lines. Falls back to a SORTED pick so a cold hub (or a broker
        that really did go away) is at least deterministic across calls.
        """
        # Lazily create the per-tenant sticky broker map on first use.
        store = getattr(self, "_cs_broker_sticky", None)
        if store is None:
            store = {}
            self._cs_broker_sticky = store
        # Keep the previous broker while it is still eligible.
        prev = store.get(tenant_id)
        if prev and prev in candidates:
            return prev
        # Otherwise elect the first candidate, logging the change if one was replaced.
        chosen = candidates[0]                      # candidates arrive sorted
        if prev:
            logger.info(
                "[cs-broker] tenant %s: broker %s -> %s (previous no longer "
                "connected/approved/bound; %d candidate(s))",
                tenant_id, prev, chosen, len(candidates))
        # Remember the choice for subsequent calls.
        store[tenant_id] = chosen
        return chosen

    def get_client_sim_spokes(self, tenant_id: str = None) -> list:
        """Return ALL approved, connected Client-Sim spokes for a tenant.

        Plural counterpart to ``get_client_sim_spoke``. A tenant may have
        SEVERAL Client-Sim spokes bound (e.g. cs-svr-02 / -03 / -04), and a
        config push — auto-provision toggle, hub-config save, USB approval
        merge — must reach EVERY one of them. The singular helper returns only
        ``bound[0]``, so a toggle on a 3-spoke tenant pushed to one and the
        WebUI toast read "Pushed to 1 spoke(s)" while 3 were connected; this
        list is what the push fans out over so the count is honest.

        Tenant isolation is identical to the singular helper: with a
        ``tenant_id`` we return ONLY spokes bound to that tenant, or — if none
        are bound — a single UNASSIGNED spoke the tenant implicitly claims
        (never a spoke bound to a different tenant, whose CSSettings a push
        would overwrite). With ``tenant_id is None`` (admin / global) every
        connected, approved Client-Sim spoke is returned so an admin push
        reaches the whole fleet, not just ``cands[0]``.
        """
        cands = self.get_all_spokes_by_type("Client-Sim") or self.get_all_spokes_by_type("simulation")
        # Only approved spokes carry cached telemetry (unapproved frames are dropped).
        cands = [sid for sid in cands if self.approved_modules.get(sid, False)]
        # None connected and approved: nothing to push to.
        if not cands:
            return []
        # Tenant-scoped request: return every spoke bound to the tenant.
        if tenant_id:
            md = self.state.system_state.get("module_metadata", {})
            bound = [sid for sid in cands if _tagged(md.get(sid), tenant_id)]
            if bound:
                return bound
            # No spoke bound to this tenant — claim ONE unassigned (never a
            # spoke bound to another tenant — cross-tenant CSSettings leak).
            unassigned = [sid for sid in cands if not md.get(sid, {}).get("tenant_id")]
            if unassigned:
                return [unassigned[0]]
            return []
        # tenant_id is None: admin / global view — every connected spoke.
        return cands

    def get_spoke_for_firewall(self, firewall_id: str) -> Optional[str]:
        """Finds the spoke associated with a given firewall ID."""
        # Look up the firewall record in global config and return its spoke binding.
        firewalls = self.state.get_global_config().get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        return fw.get("spoke_id") if fw else None

    # ------------------------------------------------------------------
    # Durable per-agent role registry (hub side of role re-adoption).
    #
    # A runtime-loaded role (a WebUI ``LOAD_ROLE``) makes a base ``agent`` spoke
    # host a role sub-spoke (``{base}-{role}``). Today that role only survives
    # an agent restart if the AGENT re-seeds it from its own ``.env``
    # (``LOADED_ROLES``); if that spoke-side record is ever lost the role
    # silently vanishes and the sub-spoke strands "out of contact" until a human
    # re-loads it (the recurring console-vanished outage). This registry is the
    # hub-side source of truth: every role the hub assigns to an agent is
    # persisted here (keyed by the agent's PRIMARY KEY so it is stable across a
    # raw→guid re-key), so on the agent's next (re)connect the hub re-pushes
    # ``LOAD_ROLE`` for any assigned role whose sub-spoke isn't connected —
    # self-healing the role with no human. Persisted in ``system_state`` so it
    # survives a hub restart; the write is eventual (``_mark_dirty`` + the
    # offloaded flush), never a synchronous encrypt+write on the connect path.
    # ------------------------------------------------------------------
    def _agent_roles_store(self) -> dict:
        """The persisted ``{agent_pk: [role, ...]}`` map (created on first use)."""
        # setdefault creates the empty map the first time and returns the stored one afterwards.
        return self.state.system_state.setdefault("agent_roles", {})

    def agent_assigned_roles(self, agent_id: str) -> list:
        """Sorted role names the hub has on record for ``agent_id``."""
        # Normalise to the primary key and return a copy of the recorded roles.
        pk = self._primary_key(agent_id)
        return list(self._agent_roles_store().get(pk, []) or [])

    def _record_agent_role(self, agent_id: str, role: str) -> None:
        """Durably remember ``role`` is assigned to ``agent_id`` so the hub
        re-pushes it on the agent's next reconnect. Idempotent + no-op when the
        role is already on record (so a reconnect storm doesn't churn state)."""
        # Ignore blank role names.
        role = (role or "").strip()
        if not role:
            return
        # Load the agent's current roles from the persisted store.
        pk = self._primary_key(agent_id)
        store = self._agent_roles_store()
        roles = set(store.get(pk, []) or [])
        # Already recorded: nothing to change (avoids churn on reconnect storms).
        if role in roles:
            return
        # Add the role and store a sorted list for stable output.
        roles.add(role)
        store[pk] = sorted(roles)
        # Mark state dirty so it is persisted on the next flush.
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001 — never let bookkeeping crash a connect
            # A persistence hiccup must not break the connect path.
            pass
        logger.info("agent_roles: recorded role %r for agent %s", role, agent_id)

    def _forget_agent_role(self, agent_id: str, role: str) -> None:
        """Drop ``role`` from an agent's assigned set (explicit ``UNLOAD_ROLE``
        or ``UNINSTALL_ROLE``).
        The role is then no longer re-pushed on reconnect."""
        # Ignore blank role names.
        role = (role or "").strip()
        if not role:
            return
        # Load the agent's current roles from the persisted store.
        pk = self._primary_key(agent_id)
        store = self._agent_roles_store()
        roles = set(store.get(pk, []) or [])
        # Role not on record: nothing to forget.
        if role not in roles:
            return
        # Remove it; drop the agent's entry entirely when no roles remain.
        roles.discard(role)
        if roles:
            store[pk] = sorted(roles)
        else:
            store.pop(pk, None)
        # Mark state dirty so the change is persisted.
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001
            # A persistence hiccup is not worth failing the caller over.
            pass
        logger.info("agent_roles: forgot role %r for agent %s", role, agent_id)

    def _track_role_rpc(self, spoke_id: str, command_type: str,
                        data: dict, result) -> None:
        """Update the durable agent→role registry from a completed hub RPC.

        Called from ``request_response`` for every settled command; only
        ``LOAD_ROLE`` / ``UNLOAD_ROLE`` / ``UNINSTALL_ROLE`` do anything. A LOAD
        that reports SUCCESS records the role for the target agent; an UNLOAD or
        UNINSTALL that didn't hard-ERROR forgets it. Fully fail-open — role
        bookkeeping must never disturb the command's own result."""
        try:
            # Only role load/unload/uninstall commands affect the registry.
            if command_type not in ("LOAD_ROLE", "UNLOAD_ROLE", "UNINSTALL_ROLE"):
                return
            # Without a role name there is nothing to track.
            role = (data or {}).get("role")
            if not role:
                return
            # Unwrap the response envelope down to the handler's result dict.
            pl = result.get("payload", {}).get("data", result) \
                if isinstance(result, dict) else result
            # LOAD_ROLE payload.data may itself nest the handler dict under
            # ``data`` (COMMAND_RESULT envelope); unwrap one more level.
            if isinstance(pl, dict) and "status" not in pl and isinstance(pl.get("data"), dict):
                pl = pl["data"]
            # Read the handler's status (None if the result is not a dict).
            status = pl.get("status") if isinstance(pl, dict) else None
            # A successful LOAD records the role.
            if command_type == "LOAD_ROLE":
                if status == "SUCCESS":
                    self._record_agent_role(spoke_id, role)
            else:  # UNLOAD_ROLE / UNINSTALL_ROLE — forget unless it explicitly failed
                if status != "ERROR":
                    self._forget_agent_role(spoke_id, role)
        except Exception:  # noqa: BLE001
            # Bookkeeping failure is only logged; it never affects the command result.
            logger.debug("_track_role_rpc bookkeeping failed", exc_info=True)
