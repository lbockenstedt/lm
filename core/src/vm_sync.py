"""Hypervisor → NetBox VM-record sync subsystem for the Hub.

Mirrors ``endpoint_sync.py`` (IPAM → ClearPass): a self-contained, named
subsystem gathered here as a **mixin** so the Hub class body shrinks with zero
call-site change. ``api.py`` routes call ``hub.HYPERVISOR_SOURCES``,
``hub.sync_tenant_vms()``, ``hub.trigger_vm_sync()``, ``hub._vm_sync_tenants()``,
``hub._vm_sync_source()``, ``hub.tenant_id_for_vm_sync_scope()`` — all of which
resolve via inheritance once ``VmSyncMixin`` is added to ``LabManagerHub`` bases.
The method bodies take ``self`` and use the same state/spoke helpers as the
endpoint sync, so there is no rename and no churn.

The hypervisor source (pxmx / Proxmox) is the source of truth for the VM
inventory; each sync is authoritative for the tenant (payload carries
``replace=True`` → the netbox spoke overwrites that tenant's NetBox VM set to
match, deleting stale records). The netbox spoke's write handler
(``NETBOX_SYNC_VMS`` / ``sync_vms``) lives in the external netbox spoke repo
(not in this tree); the hub only schedules + relays + records per-tenant
last-sync status. The hypervisor source is selectable via the ``source`` config
field (default "proxmox"); adding a product is a one-entry addition to
``HYPERVISOR_SOURCES`` below + a spoke that implements the list-vms command.

This module is a **leaf**: it imports only stdlib and must NOT import ``main``
or ``api`` (no back-import — that would create a cycle, since ``main`` imports
this module to pull in the mixin). Dependency direction is ``main → vm_sync``
only.

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Hub")


class VmSyncMixin:
    """Pulls each tenant's VM inventory from a hypervisor source spoke and
    pushes it to the netbox (IPAM) spoke via ``NETBOX_SYNC_VMS`` so NetBox's
    virtualization records mirror the live Proxmox VMs/CTs — tenant-tagged,
    with vCPUs/disk/cluster/primary_ip4 populated. The hypervisor source is
    selectable via the ``source`` config field (default "proxmox"); adding a
    product is a one-entry addition to ``HYPERVISOR_SOURCES`` below + a spoke
    that implements the list-vms command. The hypervisor source is the source
    of truth: each sync is authoritative for the tenant (payload carries
    replace=True → the spoke overwrites that tenant's NetBox VM set to match).
    The netbox write handler lives in the external netbox spoke repo (not in
    this tree); the hub only schedules + relays + records per-tenant last-sync
    status.
    #
    # HYPERVISOR_SOURCES maps a source name → how the hub talks to that product:
    #   module_type         : spoke module type to resolve (get_spoke_by_type)
    #   list_command        : command the hub sends to fetch the tenant's VMs
    #   tenant_scope_field  : tenant-config key holding the per-tenant scope value
    #                         (Proxmox → proxmox_tag, sent as tag_filter)
    #   request_filter_key  : key the spoke's list command expects for the scope
    #   response_key        : key in the spoke response holding the VM list
    #   label               : human label for the WebUI source selector
    # The spoke contract for <list_command>: request {<request_filter_key>:
    # <scope>}; response {"status":"SUCCESS", <response_key>: [{unique_id,
    # cluster, node, vmid, type, name, status, vcpus, disk_gb, mem_bytes,
    # ips, tags}, ...]} — each product's spoke normalizes its own fields into
    # that shape, so the hub extraction is source-agnostic.
    #
    # The netbox spoke (module_type "ipam") is the VM-record writer today. It is
    # not in HYPERVISOR_SOURCES (that registry is the *pull* side); the push
    # command + target module are fixed below. A future alternate writer could
    # be made pluggable the same way, but only Proxmox→NetBox is wired now.
    """

    HYPERVISOR_SOURCES: Dict[str, Dict[str, str]] = {
        "proxmox": {
            "module_type": "hypervisor",
            "list_command": "PXMX_LIST_VMS",
            "tenant_scope_field": "proxmox_tag",
            "request_filter_key": "tag_filter",
            "response_key": "vms",
            "label": "Proxmox",
        },
    }

    # NetBox (IPAM spoke) is the VM-record writer. Fixed today.
    _VM_SYNC_TARGET_MODULE = "ipam"
    _VM_SYNC_PUSH_COMMAND = "NETBOX_SYNC_VMS"

    _VM_SYNC_CFG_KEY = "pxmx_netbox_vm_sync"  # legacy key; ``source`` selects the hypervisor product

    def _vm_sync_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh (enabled/source/mode/interval/daily_time)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._VM_SYNC_CFG_KEY, {})) or {}

    def _vm_sync_source(self) -> Dict[str, str]:
        """Resolve the configured hypervisor source registry entry (falls back to Proxmox)."""
        name = str(self._vm_sync_cfg().get("source", "proxmox")).strip().lower()
        return self.HYPERVISOR_SOURCES.get(name) or self.HYPERVISOR_SOURCES["proxmox"]

    def _vm_sync_sot(self) -> str:
        """Source of truth for VMs: "external" (Proxmox owns → overwrite, the
        default) or "netbox" (NetBox owns → only-add-missing). Read from
        ``global_config.source_of_truth.vm_sync``. An unknown/blank value falls
        back to the default so a config typo never sends a garbage owner to the
        spoke."""
        raw = str((self.state.system_state.get("global_config", {}) or {})
                 .get("source_of_truth", {}).get("vm_sync", "external")
                 ).strip().lower()
        return raw if raw in ("external", "netbox") else "external"

    def _vm_scope_for_tenant(self, source_entry: Dict[str, str],
                             tenant_id: str) -> str:
        """The per-tenant hypervisor scope value for the active source ('' if unbound).

        e.g. Proxmox → the tenant's proxmox_tag (sent as tag_filter to PXMX_LIST_VMS).
        Which field is read is driven by the source entry's ``tenant_scope_field``
        so the hub stays source-agnostic.
        """
        cfg = self.state.get_tenant(tenant_id) or {}
        return str(cfg.get(source_entry.get("tenant_scope_field", "")) or "").strip()

    def _vm_sync_tenants(self) -> List[str]:
        """Tenant ids bound to the configured hypervisor source (have its scope field set)."""
        out: List[str] = []
        se = self._vm_sync_source()
        field = se.get("tenant_scope_field", "")
        tenants = (self.state.tenant_state or {}).get("tenants", {}) or {}
        for tid, cfg in tenants.items():
            if str((cfg or {}).get(field) or "").strip():
                out.append(str(tid))
        return out

    def tenant_id_for_vm_sync_scope(self, scope_value: str) -> Optional[str]:
        """Reverse-map a hypervisor scope value (for the configured source) → LM tenant id.

        Used by the pxmx-edit trigger if a mutation request carries the
        per-tenant scope value; otherwise the trigger falls back to the acting
        user's tenant.
        """
        se = self._vm_sync_source()
        field = se.get("tenant_scope_field", "")
        val = str(scope_value or "").strip().lower()
        if not val or not field:
            return None
        # Case-insensitive: Proxmox tags are free-form, so a VM carrying the
        # tenant's proxmox_tag in a different case must still attribute to it
        # (mirrors the spoke's tag_filter lowercasing in PXMX_LIST_VMS).
        tenants = (self.state.tenant_state or {}).get("tenants", {}) or {}
        for tid, cfg in tenants.items():
            if str((cfg or {}).get(field) or "").strip().lower() == val:
                return str(tid)
        return None

    def _vm_sync_concurrency(self) -> int:
        """Max tenants synced in parallel per cycle. Bounded so many tenants
        don't stampede the hypervisor/netbox spokes. Clamp 1..8; default 4."""
        try:
            n = int(self._vm_sync_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        return max(1, min(8, n))

    def _vm_sync_next_delay(self, cfg: Dict[str, Any]) -> float:
        """Seconds to sleep before the next scheduled VM sync, per the config mode.

        ``mode`` is ``"daily"`` (run once a day at ``daily_time`` "HH:MM", 24h
        local) or anything else (interval mode → every ``interval_seconds``).
        Always clamped to >= 60 s so a bad config can't hot-loop the hub.
        """
        mode = str(cfg.get("mode", "interval")).strip().lower()
        if mode == "daily":
            hhmm = str(cfg.get("daily_time", "03:00")).strip()
            try:
                hh, mm = (int(p) for p in hhmm.split(":")[:2])
                now = _dt.datetime.now()
                target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if target <= now:
                    target += _dt.timedelta(days=1)
                return max(60.0, (target - now).total_seconds())
            except Exception:
                logger.debug("vm sync: bad daily_time %r — falling back to interval", hhmm)
        interval = 3600
        try:
            interval = int(cfg.get("interval_seconds", 3600))
        except (TypeError, ValueError):
            interval = 3600
        return max(60.0, float(interval))

    # Synthetic tenant-id key for the untagged/no-tenant bucket. Mirrors the
    # netbox spoke's NetBoxEngine._VM_SYNC_UNASSIGNED_KEY so per-tenant status
    # from the grab-all sync round-trips unchanged.
    _VM_SYNC_UNASSIGNED_KEY = "__unassigned__"

    async def sync_all_vms(self) -> Dict[str, Any]:
        """Pull ALL VMs from the configured hypervisor source once, attribute
        each to a tenant by matching its Proxmox ``tags`` against tenants'
        ``proxmox_tag`` (first match wins; no match → unassigned), and push the
        full set to NetBox in one ``NETBOX_SYNC_VMS`` call with ``replace=True``.

        NetBox becomes a complete mirror of the cluster: tagged VMs → their
        NetBox tenant; untagged VMs (or a tag matching no tenant) → created with
        no NetBox tenant (a global/unassigned record). Every VM carries all
        attributes every sync. Replace-delete removes NetBox VMs destroyed in
        Proxmox (cluster-wide, proxmox-sourced only).

        Returns ``{status, pushed, errors, skipped, deleted, vms_total,
        per_tenant, results, message}`` where ``results`` is a per-tenant
        status list (one row per bound tenant + an unassigned row) suitable for
        the on-demand run route, and ``per_tenant`` mirrors the netbox
        breakdown keyed by tenant-slug / ``__unassigned__``. Idempotent +
        best-effort: a hypervisor/netbox outage yields an error result, never
        an unhandled exception (the background loop depends on this).
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        se = self._vm_sync_source()
        label = se.get('label', 'Hypervisor')
        hyp = self.get_spoke_by_type(se.get("module_type", "hypervisor"))
        netbox = self.get_spoke_by_type(self._VM_SYNC_TARGET_MODULE)
        if not hyp or not netbox:
            logger.info("vm sync ALL SKIP: %s or NetBox spoke not connected "
                        "(hyp=%r netbox=%r)", label, bool(hyp), bool(netbox))
            return {"status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "vms_total": 0, "per_tenant": {},
                    "results": [],
                    "message": f"{label} or NetBox spoke not connected"}

        # Tag → tenant attribution map (lowercased tag → tid) + lookups, built once.
        tenants = (self.state.tenant_state or {}).get("tenants", {}) or {}
        tag_to_tid: Dict[str, str] = {}
        tid_to_cfg: Dict[str, Dict[str, Any]] = {}
        for tid, cfg in tenants.items():
            cfg = cfg or {}
            tag = str(cfg.get("proxmox_tag") or "").strip().lower()
            if tag:
                tag_to_tid[tag] = str(tid)
            tid_to_cfg[str(tid)] = cfg

        # One grab-all pull (no tag_filter — the spoke returns every VM).
        list_payload: Dict[str, Any] = {}
        agent_id = str(self._vm_sync_cfg().get("agent_id") or "").strip()
        if agent_id:
            list_payload["agent_id"] = agent_id
        try:
            r = await self.request_response(
                hyp, se.get("list_command", "PXMX_LIST_VMS"),
                list_payload, timeout=30.0)
            data = r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
            if isinstance(data, dict) and data.get("status") == "ERROR":
                msg = f"{label}: {data.get('message', 'error')}"
                logger.info("vm sync ALL SKIP: %s returned ERROR: %s",
                            label, data.get('message', 'error'))
                return {"status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                        "deleted": 0, "vms_total": 0, "per_tenant": {},
                        "results": [], "message": msg}
            resp_key = se.get("response_key", "vms")
            raw_vms = (data.get(resp_key, []) if isinstance(data, dict) else []) or []
        except Exception as e:
            logger.debug("vm sync ALL pull failed: %s", e)
            return {"status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "vms_total": 0, "per_tenant": {},
                    "results": [], "message": str(e)}

        # Attribute + normalize each VM. tagged → that tenant's netbox slug;
        # untagged/no-match → tenant_slug None (NetBox creates it unassigned).
        vms: List[Dict[str, Any]] = []
        attr_counts: Dict[str, int] = {}  # tid | __unassigned__ → VMs attributed
        UNASSIGNED = self._VM_SYNC_UNASSIGNED_KEY
        for vm in raw_vms:
            vm = vm or {}
            uid = str(vm.get("unique_id") or "").strip()
            if not uid:
                continue  # nothing to match in NetBox by
            tags = vm.get("tags") or []
            tid: Optional[str] = None
            for t in tags:
                key = str(t or "").strip().lower()
                if key and key in tag_to_tid:
                    tid = tag_to_tid[key]
                    break
            if tid:
                cfg = tid_to_cfg.get(tid) or {}
                tslug = str(cfg.get("netbox_tenant_slug") or "").strip() or None
            else:
                tid = None
                tslug = None
            # Normalise ips (string or {address}/{ip} dict) → bare address list.
            ip_list: List[str] = []
            for ip in (vm.get("ips") or []):
                if isinstance(ip, dict):
                    s = str(ip.get("address") or ip.get("ip") or "").split("/")[0].strip()
                else:
                    s = str(ip or "").split("/")[0].strip()
                if s:
                    ip_list.append(s)
            mem_bytes = int(vm.get("mem_bytes") or 0)
            # Per-interface network records from the pxmx agent (QGA/LXC
            # hardware-address + guest IPs, with a qm/pct config MAC fallback).
            # Relayed so the netbox spoke builds vminterfaces with MACs + all
            # IPs (not just primary_ip4). Flat ``ips`` kept for back-compat.
            interfaces = []
            for ifc in (vm.get("interfaces") or []):
                if not isinstance(ifc, dict):
                    continue
                interfaces.append({
                    "name": str(ifc.get("name") or "").strip(),
                    "mac":  str(ifc.get("mac") or "").strip(),
                    "ips":  [str(x).split("/")[0].strip()
                             for x in (ifc.get("ips") or []) if str(x or "").strip()],
                })
            vms.append({
                "unique_id": uid,
                "name":      str(vm.get("name") or "").strip(),
                "cluster":   str(vm.get("cluster") or "").strip(),
                "node":      str(vm.get("node") or "").strip(),
                "vmid":      vm.get("vmid"),
                "type":      str(vm.get("type") or "qemu"),
                "status":    str(vm.get("status") or "unknown"),
                "vcpus":     int(vm.get("vcpus") or 0),
                "disk_gb":   round(float(vm.get("disk_gb") or 0), 1),
                "mem_mb":    int(mem_bytes / (1024 * 1024)) if mem_bytes else 0,
                "ips":       ip_list,
                "interfaces": interfaces,
                "tags":      tags,
                "tenant_slug": tslug,
            })
            bkey = tid or UNASSIGNED
            attr_counts[bkey] = attr_counts.get(bkey, 0) + 1

        # Source of truth for VMs: "external" (Proxmox owns → overwrite) or
        # "netbox" (NetBox owns → only-add-missing). Default external (Proxmox).
        sot = self._vm_sync_sot()
        payload = {"source": se.get("label", "Hypervisor"),
                   "replace": True, "vms": vms,
                   "source_of_truth": sot}
        try:
            rr = await self.request_response(netbox, self._VM_SYNC_PUSH_COMMAND,
                                             payload, timeout=180.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(vms)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            per_tenant = (rd or {}).get("per_tenant", {}) or {}
        except Exception as e:
            logger.warning("[sync-error] vm-sync push failed: %s", e)
            return {"status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "vms_total": len(vms), "per_tenant": {},
                    "results": [], "message": str(e)}

        overall = "success" if rstatus != "ERROR" else "error"

        # Per-tenant status rows. Every bound tenant (has a proxmox_tag) gets a
        # row even with zero matched VMs, so the UI shows a fresh "0 sent"
        # instead of a stale last-run; the unassigned bucket is a synthetic row.
        results: List[Dict[str, Any]] = []

        def _row(key: str, tid: str, name: str, total: int,
                 note: str = "") -> Dict[str, Any]:
            b = per_tenant.get(key, {}) or {}
            msg = message or (f"{total} VM(s) sent"
                              if overall != "error" else "NetBox error")
            if note:
                msg = f"{msg} — {note}" if msg else note
            return {"tenant_id": tid, "tenant_name": name, "status": overall,
                    "pushed": int(b.get("pushed", 0) or 0),
                    "errors": int(b.get("errors", 0) or 0),
                    "skipped": int(b.get("skipped", 0) or 0),
                    "deleted": int(b.get("deleted", 0) or 0),
                    "message": msg, "last_sync_ts": now, "vms_total": total}

        for tid, cfg in tid_to_cfg.items():
            cfg = cfg or {}
            if not str(cfg.get("proxmox_tag") or "").strip():
                continue  # not bound → no row (the scheduled loop ignores these too)
            slug = str(cfg.get("netbox_tenant_slug") or "").strip()
            name = cfg.get("name") or tid
            if slug:
                st = _row(slug, tid, name, int(per_tenant.get(slug, {}).get("vms_total", 0) or 0))
            else:
                # Attributed to this tenant but no NetBox slug → netbox wrote the
                # VMs as unassigned. Surface the count we attributed honestly.
                st = _row(UNASSIGNED, tid, name, attr_counts.get(tid, 0),
                          note="no NetBox tenant slug; VMs synced as unassigned")
            results.append(st)
            await self.simulations_store.set_vm_sync_status(tid, st)

        # Unassigned bucket (untagged VMs + tenants-without-slug) — synthetic row.
        un_total = int(per_tenant.get(UNASSIGNED, {}).get("vms_total", 0) or 0)
        if un_total or attr_counts.get(UNASSIGNED):
            st = _row(UNASSIGNED, UNASSIGNED, "Unassigned (no tenant tag)", un_total)
            results.append(st)
            await self.simulations_store.set_vm_sync_status(UNASSIGNED, st)

        # Hub-authoritative sync log: clean run → INFO; any errors/failure →
        # [sync-error] WARNING carrying the sink's message (first-error text) so
        # the cause lands in the hub log + GET_ERROR_LOGS (bugfixer).
        if errors > 0 or overall == "error":
            logger.warning("[sync-error] vm-sync result status=%s sent=%d pushed=%d "
                           "skipped=%d deleted=%d errors=%d rows=%d — %s",
                           overall, len(vms), pushed, skipped, deleted, errors,
                           len(results), message or "NetBox error")
        else:
            logger.info("vm sync ALL result status=%s sent=%d pushed=%d skipped=%d "
                        "deleted=%d errors=%d rows=%d",
                        overall, len(vms), pushed, skipped, deleted, errors,
                        len(results))
        return {"status": overall, "pushed": pushed, "errors": errors,
                "skipped": skipped, "deleted": deleted, "vms_total": len(vms),
                "per_tenant": per_tenant, "results": results,
                "message": message or (f"{len(vms)} VM(s) sent"
                                        if overall != "error" else "NetBox error")}

    async def sync_tenant_vms(self, tenant_id: str) -> Dict[str, Any]:
        """Sync all VMs, then return the status row for one tenant (grab-all model).

        The pull is cluster-wide (one ``PXMX_LIST_VMS``, no ``tag_filter``) so
        the NetBox mirror stays complete; ``tenant_id`` only selects which
        per-tenant row to return — for the on-demand 'Sync now' route and the
        pxmx-edit trigger. A blank ``tenant_id`` returns the unassigned row.
        Every bound tenant's status is refreshed each call (one pull, one push).
        """
        agg = await self.sync_all_vms()
        tid = tenant_id or self._VM_SYNC_UNASSIGNED_KEY
        for st in agg.get("results", []):
            if st.get("tenant_id") == tid:
                return st
        # Tenant not in the results (not bound / no matched VMs) — synthesize a
        # row so the caller gets a well-formed status dict either way.
        cfg = self.state.get_tenant(tid) or {}
        msg = ("no VMs matched tenant tag"
               if tid != self._VM_SYNC_UNASSIGNED_KEY
               else (agg.get("message") or "no untagged VMs"))
        return {"tenant_id": tid, "tenant_name": cfg.get("name") or tid,
                "status": agg.get("status", "success"),
                "pushed": 0, "errors": 0, "skipped": 0, "deleted": 0,
                "message": msg,
                "last_sync_ts": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "vms_total": 0}

    def trigger_vm_sync(self, tenant_id: str) -> None:
        """Fire-and-forget a VM sync for one tenant after a pxmx/hypervisor edit.

        Called from the pxmx VM mutation routes (e.g. vm-action start/stop/
        restart/snapshot) so a lifecycle change propagates to NetBox immediately
        instead of waiting for the next scheduled cycle. No-op when the sync is
        disabled or no NetBox spoke is connected — the one ``enabled`` toggle
        controls all automatic sync behavior. Safe to call from an async route
        (spawns a task on the running loop); silently does nothing if there is
        no running loop. A blank tenant_id (e.g. a superadmin with no tenant)
        is a no-op — the scheduled loop covers unbound/global tenants.
        """
        if not tenant_id:
            return
        if not self._vm_sync_cfg().get("enabled", False):
            return
        if not self.get_spoke_by_type(self._VM_SYNC_TARGET_MODULE):
            return
        try:
            asyncio.create_task(self.sync_tenant_vms(tenant_id))
        except RuntimeError:
            pass  # no running event loop — nothing to do

    async def run_vm_sync_loop(self):
        """Periodically sync ALL hypervisor VMs → NetBox per the configured schedule.

        Reads the config fresh each cycle (enabled / source / mode / interval /
        daily time) so a WebUI change takes effect without a restart. Disabled
        → short sleep + re-check. Skips a cycle entirely if the configured
        hypervisor source or NetBox is offline. One ``sync_all_vms()`` per cycle
        (a single grab-all pull + single NetBox push) replaces the old
        per-tenant fan-out — the sync is cluster-wide now, so there's nothing to
        parallelize. Staggered 45s after the endpoint sync loop so the two heavy
        syncs don't simultaneous-fire on startup.
        """
        await asyncio.sleep(45)  # let spokes connect; stagger after endpoint sync
        while True:
            try:
                cfg = self._vm_sync_cfg()
                se = self._vm_sync_source()
                if cfg.get("enabled", False) and \
                        self.get_spoke_by_type(se.get("module_type", "hypervisor")) and \
                        self.get_spoke_by_type(self._VM_SYNC_TARGET_MODULE):
                    try:
                        await self.sync_all_vms()
                    except Exception as e:  # sync_all_vms already swallows; never let one cycle kill the loop
                        logger.warning("[sync-error] vm-sync loop cycle failed: %s", e)
                delay = self._vm_sync_next_delay(cfg) if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.warning("[sync-error] vm-sync loop failed: %s", e)
                await asyncio.sleep(60)