"""Read-only spoke/agent lookup helpers for the LM Hub — ``SpokeRegistryMixin``.

Pure textual extraction from ``main.py``: the connected/approved-spoke lookup
and display-online helpers mixed into ``LabManagerHub``. Every method uses only
``self`` state (active_connections, heartbeat, spoke_module_types,
module_metadata, agent_info, netbox_server_agents, ...) plus the
``_MODULE_TYPE_PREFIX`` legacy-prefix map moved here with them. No behavior
change — ``LabManagerHub`` inherits these exactly as before.
"""

import time
from typing import Optional

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
    "dhcp":       "dhcp",
    "agent":      "agent",
    "nw":         "nw",
    "certificates": "le",
    "storage":    "truenas",
}


class SpokeRegistryMixin:
    """Read-only spoke/agent registry lookups mixed into ``LabManagerHub``."""

    def _online_grace_s(self) -> float:
        """Grace window (s) for the DISPLAY online/offline status. A module reads
        offline only after being out of contact THIS long — so a transient loop
        stall or a brief reconnect never flips the tile. Default 180s; the alert
        tiers (5 min warn / 30 min error) escalate genuine outages from there."""
        try:
            return float((self.state.get_global_config() or {}).get(
                "display", {}).get("online_grace_s", 180))
        except Exception:
            return 180.0

    def is_spoke_in_contact(self, spoke_id: str, grace_s: Optional[float] = None) -> bool:
        """True if the spoke is connected NOW or was seen within the grace window.
        This is the DISPLAY notion of 'online' — decoupled from instantaneous WS
        membership so a few-second stall doesn't drop the tile. Command routing
        still uses ``active_connections`` directly (must be live-accurate)."""
        if self._primary_key(spoke_id) in self.active_connections:
            return True
        ts = self.heartbeat.last_seen.get(self._primary_key(spoke_id))
        if not ts:
            return False
        g = self._online_grace_s() if grace_s is None else grace_s
        return (time.time() - ts) <= g

    def spokes_in_contact(self, grace_s: Optional[float] = None) -> list:
        """Ids considered 'in contact' for display: connected now OR seen within
        the grace window. The WebUI colours online/offline tiles from this."""
        g = self._online_grace_s() if grace_s is None else grace_s
        now = time.time()
        ids = set(self.active_connections.keys())
        for sid, ts in list(self.heartbeat.last_seen.items()):
            if ts and (now - ts) <= g:
                ids.add(sid)
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
        for _name, _guid in list(getattr(self, "spoke_id_alias", {}).items()):
            if _guid == pk or _name == pk:
                self.spoke_id_alias.pop(_name, None)
        for _iu, _guid in list(getattr(self, "install_uuid_index", {}).items()):
            if _guid == pk or _iu == pk:
                self.install_uuid_index.pop(_iu, None)

    def _mark_spoke_disconnected(self, spoke_id: str) -> None:
        """Record a clean-WS-close disconnect in ``spoke_telemetry``.

        A spoke deleted via ``DELETE /setup/spokes/{id}`` is evicted
        (``_evict_spoke`` pops ``spoke_telemetry``) BEFORE that socket's 1008
        "Removed by admin" close fires the disconnect handler, so the entry
        may already be gone — re-create a minimal ``DISCONNECTED`` stub rather
        than ``KeyError`` on the index. A transient disconnect (entry still
        present) just updates the status in place.
        """
        pk = self._primary_key(spoke_id)
        tel = self.spoke_telemetry.get(pk)
        if tel is None:
            self.spoke_telemetry[pk] = {
                "last_attempt": time.time(),
                "status": "DISCONNECTED",
            }
        else:
            tel["status"] = "DISCONNECTED"

    def get_spoke_by_type(self, module_type: str) -> Optional[str]:
        """Return the first connected, approved spoke that advertised the given module_type."""
        for sid, mtype in self.spoke_module_types.items():
            if mtype == module_type and sid in self.active_connections:
                return sid
        # Legacy fallback: derive type from known spoke_id prefixes for spokes that
        # pre-date the module_type system and never sent the field. See _MODULE_TYPE_PREFIX.
        prefix = _MODULE_TYPE_PREFIX.get(module_type)
        if prefix:
            return next((sid for sid in self.active_connections if prefix in sid), None)
        return None

    def get_spoke_for_agent(self, agent_id: str, fallback_hypervisor: bool = True) -> Optional[str]:
        """Return the connected spoke_id that owns ``agent_id``.

        ``agent_info`` is populated from every ``AGENT_RELAY_UP`` frame, so a
        pxmx-dialed agent indexes to the pxmx spoke and a cs-dialed agent
        indexes to the cs spoke. Returns None when the agent is not connected
        / not yet heartbeat-indexed (e.g. the first ~30s after connect, before
        any relayed frame arrives).

        When ``fallback_hypervisor`` is True, a missing index falls back to the
        pxmx (``hypervisor``) spoke — correct for the all-in-one path where
        every agent is on the pxmx spoke. Callers that must NOT misroute a
        cs-dialed agent (e.g. the CS bridge relaying commands) pass
        ``fallback_hypervisor=False`` and skip when None is returned.
        """
        info = self.agent_info.get(self._agent_primary_key(agent_id))
        if info:
            sid = info.get("spoke_id")
            if sid and self._primary_key(sid) in self.active_connections:
                return sid
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
        pxmx spoke that may have none. Non-agent-hosting types resolve by
        ``module_type`` exactly as before."""
        if module_type in ("hypervisor", "simulation"):
            if identifier:
                sid = self.get_spoke_for_agent(identifier, fallback_hypervisor=False)
                if sid:
                    return sid
            for info in (self.agent_info or {}).values():
                sid = (info or {}).get("spoke_id")
                pk = self._primary_key(sid)
                if (sid and pk in self.active_connections
                        and self.spoke_module_types.get(pk) in ("hypervisor", "simulation")):
                    return sid
            return (self.get_spoke_by_type("simulation")
                    or self.get_spoke_by_type("hypervisor"))
        if module_type == "netbox-server":
            # The cert target is a generic agent that ran the netbox-server
            # deploy (has the local nginx cert helper + root). A specific
            # identifier picks that agent; empty picks any connected one.
            if identifier and self._primary_key(identifier) in self.netbox_server_agents \
                    and self._primary_key(identifier) in self.active_connections:
                return identifier
            return next((sid for sid in self.netbox_server_agents
                         if sid in self.active_connections), None)
        if module_type == "ldap-server":
            # The cert target is a generic agent that ran the ldap-server deploy
            # (has the local lm-ldap-install-cert helper + root). Mirrors the
            # netbox-server branch.
            if identifier and self._primary_key(identifier) in self.ldap_server_agents \
                    and self._primary_key(identifier) in self.active_connections:
                return identifier
            return next((sid for sid in self.ldap_server_agents
                         if sid in self.active_connections), None)
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
        if not tenant_id or tenant_id == "default":
            return self.get_hypervisor_spoke()
        cands = self.get_all_spokes_by_type("hypervisor") or self.get_all_spokes_by_type("simulation")
        cands = [sid for sid in cands if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        if not cands:
            return None
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
        return bound[0] if bound else None

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
        if not tenant_id or tenant_id == "default":
            return self.get_spoke_by_type("nw")
        cands = [sid for sid in (self.get_all_spokes_by_type("nw") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        if not cands:
            return None
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
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
        BOUND to that tenant; if none, fall back to an UNASSIGNED directory spoke
        (the shared OU server); else ``None``. NEVER return a spoke bound to a
        DIFFERENT tenant — that would relay this tenant's OU ops to another
        tenant's spoke (the cross-tenant leak this closes in a multi-spoke
        deploy; the spoke-side OU slug is the backstop, this is defense-in-depth).

        With ``tenant_id`` None / ``"default"`` (admin unscoped / global view),
        fall back to ``get_spoke_by_type("directory")`` so a Global Admin still
        sees / manages every tenant's OU (unchanged legacy behavior).
        """
        if not tenant_id or tenant_id == "default":
            return self.get_spoke_by_type("directory")
        cands = [sid for sid in (self.get_all_spokes_by_type("directory") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        if not cands:
            return None
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
        if bound:
            return bound[0]
        # No spoke bound to this tenant → the shared OU-partitioned server: an
        # UNASSIGNED directory spoke serves every tenant via ou=<slug>,<base>.
        # This fallback is intentional and DIFFERENT from nw/hypervisor (which
        # return None here) — do not "fix" it to match them.
        unassigned = [sid for sid in cands if not (md.get(sid, {}).get("tenant_id") or "")]
        return unassigned[0] if unassigned else None

    def get_nw_spoke_for_shared(self) -> Optional[str]:
        """The nw spoke that owns the SHARED-tenant devices. Shared devices are
        visible to every tenant (the shared-tenant-flag invariant), so when a
        non-admin's visible slice includes a shared device the hub must relay
        to the spoke bound to the shared tenant. Resolves the shared tenant id
        via ``access.shared_tenant_id`` (lazy local import — ``access`` never
        imports the registry, so it's cycle-safe) then defers to
        ``get_nw_spoke_for_tenant``. With no shared tenant configured, falls
        back to the global nw spoke (admin path)."""
        from access import shared_tenant_id
        sid = shared_tenant_id()
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
        if not tenant_id or tenant_id == "default":
            return self.get_spoke_by_type("storage")
        cands = [sid for sid in (self.get_all_spokes_by_type("storage") or [])
                 if sid in self.active_connections
                 and self.approved_modules.get(sid, False)]
        if not cands:
            return None
        md = self.state.system_state.get("module_metadata", {})
        bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
        return bound[0] if bound else None

    def get_truenas_spoke_for_shared(self) -> Optional[str]:
        """The storage spoke that owns the SHARED-tenant TrueNAS appliances.
        Mirrors ``get_nw_spoke_for_shared``."""
        from access import shared_tenant_id
        sid = shared_tenant_id()
        return (self.get_truenas_spoke_for_tenant(sid)
                if sid else self.get_spoke_by_type("storage"))

    def get_all_spokes_by_type(self, module_type: str):
        """Return all connected spoke IDs that advertised the given module_type."""
        # netbox-server is a capability (advertised in the auth frame), not a
        # module_type any spoke registers under — so the wildcard fan-out + cert
        # targeting resolve it from the netbox_server_agents set.
        if module_type == "netbox-server":
            return [sid for sid in getattr(self, "netbox_server_agents", set())
                    if sid in self.active_connections]
        if module_type == "ldap-server":
            return [sid for sid in getattr(self, "ldap_server_agents", set())
                    if sid in self.active_connections]
        # Legacy fallback: same prefix map as get_spoke_by_type. See
        # _MODULE_TYPE_PREFIX.
        by_registry = [sid for sid, mt in self.spoke_module_types.items()
                       if mt == module_type and sid in self.active_connections]
        if by_registry:
            return by_registry
        prefix = _MODULE_TYPE_PREFIX.get(module_type)
        if prefix:
            return [sid for sid in self.active_connections if prefix in sid]
        return []

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
        if tenant_id:
            md = self.state.system_state.get("module_metadata", {})
            bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
            if bound:
                return bound[0]
            # No spoke bound to this tenant — claim an UNASSIGNED one (no
            # tenant_id in metadata). Never cands[0] blindly: that may be a
            # spoke bound to another tenant, whose CSSettings this tenant's
            # push would overwrite (cross-tenant leak).
            unassigned = [sid for sid in cands if not md.get(sid, {}).get("tenant_id")]
            if unassigned:
                return unassigned[0]
            return None
        # tenant_id is None: admin / global view — any connected spoke.
        return cands[0]

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
        if not cands:
            return []
        if tenant_id:
            md = self.state.system_state.get("module_metadata", {})
            bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
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
        firewalls = self.state.get_global_config().get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        return fw.get("spoke_id") if fw else None
