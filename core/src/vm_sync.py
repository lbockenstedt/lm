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

import time
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

    async def sync_tenant_vms(self, tenant_id: str) -> Dict[str, Any]:
        """Pull this tenant's VMs from the configured hypervisor source, push to NetBox.

        Returns a status dict {tenant_id, status, pushed, errors, skipped,
        deleted, message, last_sync_ts, vms_total}. Idempotent + best-effort: a
        hypervisor/netbox outage or a missing scoping yields a per-tenant
        error/skipped status, never an unhandled exception (the background loop
        depends on this). The NetBox tenant assignment uses the tenant's
        ``netbox_tenant_slug`` (VMs are created without a NetBox tenant when
        unbound — global records).
        """
        now = time.time()
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        se = self._vm_sync_source()
        hyp = self.get_spoke_by_type(se.get("module_type", "hypervisor"))
        netbox = self.get_spoke_by_type(self._VM_SYNC_TARGET_MODULE)
        if not hyp or not netbox:
            logger.info("vm sync tenant=%s(%s) SKIP: %s or NetBox spoke not connected "
                        "(hyp=%r netbox=%r)", tenant_id, tenant_name,
                        se.get('label', 'Hypervisor'), bool(hyp), bool(netbox))
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                      "deleted": 0,
                      "message": f"{se.get('label', 'Hypervisor')} or NetBox spoke not connected",
                      "last_sync_ts": now, "vms_total": 0}
            await self.simulations_store.set_vm_sync_status(tenant_id, status)
            return status
        scope = self._vm_scope_for_tenant(se, tenant_id)
        if not scope:
            logger.info("vm sync tenant=%s(%s) SKIP: not bound to %s (no proxmox_tag)",
                        tenant_id, tenant_name, se.get('label', 'Hypervisor'))
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "skipped", "pushed": 0, "errors": 0, "skipped": 0,
                      "deleted": 0,
                      "message": f"tenant not bound to {se.get('label', 'Hypervisor')}",
                      "last_sync_ts": now, "vms_total": 0}
            await self.simulations_store.set_vm_sync_status(tenant_id, status)
            return status
        # NetBox tenant slug for VM tenancy in NetBox ('' → VMs created globally)
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        # Optional per-agent scoping: when the config pins a specific pxmx agent
        # (a single Proxmox server/cluster), the list call is scoped to that
        # agent_id; unset → pull from every connected agent the spoke aggregates.
        list_payload = {se.get("request_filter_key", "tag_filter"): scope}
        agent_id = str(self._vm_sync_cfg().get("agent_id") or "").strip()
        if agent_id:
            list_payload["agent_id"] = agent_id
        try:
            r = await self.request_response(
                hyp, se.get("list_command", "PXMX_LIST_VMS"),
                list_payload, timeout=30.0)
            data = r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
            if isinstance(data, dict) and data.get("status") == "ERROR":
                logger.info("vm sync tenant=%s(%s) SKIP: %s returned ERROR: %s",
                            tenant_id, tenant_name, se.get('label', 'Hypervisor'),
                            data.get('message', 'error'))
                status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                          "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                          "deleted": 0,
                          "message": f"{se.get('label', 'Hypervisor')}: {data.get('message', 'error')}",
                          "last_sync_ts": now, "vms_total": 0}
                await self.simulations_store.set_vm_sync_status(tenant_id, status)
                return status
            resp_key = se.get("response_key", "vms")
            vms: List[Dict[str, Any]] = []
            for vm in (data.get(resp_key, []) if isinstance(data, dict) else []) or []:
                vm = vm or {}
                uid = str(vm.get("unique_id") or "").strip()
                if not uid:
                    continue  # nothing to match in NetBox by
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
                    "tags":      vm.get("tags") or [],
                })
            payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                       "tenant_name": tenant_name, "source": se.get("label", "Hypervisor"),
                       "replace": True, "vms": vms}
            rr = await self.request_response(netbox, self._VM_SYNC_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(vms)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            logger.info("vm sync tenant=%s(%s) result status=%s sent=%d pushed=%d "
                        "skipped=%d deleted=%d errors=%d",
                        tenant_id, tenant_name,
                        "success" if rstatus != "ERROR" else "error",
                        len(vms), pushed, skipped, deleted, errors)
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "success" if rstatus != "ERROR" else "error",
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted,
                      "message": message or (f"{len(vms)} VM(s) sent" if rstatus != "ERROR" else "NetBox error"),
                      "last_sync_ts": now, "vms_total": len(vms)}
        except Exception as e:
            logger.debug("vm sync for %s failed: %s", tenant_id, e)
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                      "deleted": 0, "message": str(e),
                      "last_sync_ts": now, "vms_total": 0}
        await self.simulations_store.set_vm_sync_status(tenant_id, status)
        return status

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
        """Periodically sync hypervisor VMs → NetBox per the configured schedule.

        Reads the config fresh each cycle (enabled / source / mode / interval /
        daily time) so a WebUI change takes effect without a restart. Disabled
        → short sleep + re-check. Skips a cycle entirely if the configured
        hypervisor source or NetBox is offline (the per-tenant sync records an
        'error' status for it). Staggered 45s after the endpoint sync loop so
        the two heavy syncs don't simultaneous-fire on startup.
        """
        await asyncio.sleep(45)  # let spokes connect; stagger after endpoint sync
        while True:
            try:
                cfg = self._vm_sync_cfg()
                se = self._vm_sync_source()
                if cfg.get("enabled", False) and \
                        self.get_spoke_by_type(se.get("module_type", "hypervisor")) and \
                        self.get_spoke_by_type(self._VM_SYNC_TARGET_MODULE):
                    tenants = self._vm_sync_tenants()
                    sem = asyncio.Semaphore(self._vm_sync_concurrency())

                    async def _one(tid: str):
                        async with sem:
                            try:
                                await self.sync_tenant_vms(tid)
                            except Exception as e:  # sync_tenant_vms already swallows; never let one task kill the gather
                                logger.debug("vm sync gather tenant=%s: %s", tid, e)

                    await asyncio.gather(*(_one(tid) for tid in tenants))
                delay = self._vm_sync_next_delay(cfg) if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.debug("vm sync loop: %s", e)
                await asyncio.sleep(60)