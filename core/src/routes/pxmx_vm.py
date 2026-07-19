"""Proxmox VM lifecycle routes: action, pools, ISOs, storages, create, clone."""
from api import (
    HTTPException, Request, _cache_entry, _refresh_module_all_tenants,
    access, get_tenant_scoping, logger, spoke_or_503, vmid_alloc,
)


def register(app, hub, ctx):
    """Register pxmx_vm routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant
    _filter_tenant = ctx._filter_tenant
    _trigger_vm_sync_after_pxmx_edit = ctx._trigger_vm_sync_after_pxmx_edit

    async def _assert_vm_control(request, vmid=None, node=None, unique_id=None):
        """Authorize a VM CONTROL action (start/stop/reboot/snapshot/backup).
        Global Admin → any VM. Otherwise the caller must (a) be a write-user or
        above (access.has_edit_access) AND (b) OWN the target VM — the VM's
        ips/tags/pool (from GET_VM_INFO) must survive the hypervisor tenant filter,
        exactly like the tenant-filtered VM list + /vm/{id}/details. FAIL-CLOSED:
        an unattributable VM (spoke down, empty info) → 403, so a tenant user can
        never act on a VM they couldn't see. A view user (pxmx right, no edit) is
        rejected before the ownership probe."""
        sess = _session_user(request)
        if _is_admin(sess):
            return
        if not access.has_edit_access(sess):
            raise HTTPException(status_code=403, detail="Edit access required to control VMs")
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        info: dict = {}
        if pxmx_spoke:
            ident = unique_id or (str(vmid) if vmid is not None else "")
            try:
                raw = await hub.request_response(
                    pxmx_spoke, "GET_VM_INFO",
                    {"vm_id": ident, "vmid": vmid, "node": node or ""})
                info = raw.get("payload", {}).get("data", {}) if isinstance(raw, dict) else {}
            except Exception:  # noqa: BLE001 — fail-closed below
                info = {}
        vm_record = {
            "ips": info.get("ips") or [],
            "tags": info.get("tags") or [],
            "pool": info.get("pool") or "",
        }
        # Toggle-independent, fail-closed ownership (subnet or tenant tag). NOT
        # _filter_tenant — that returns the record unchanged when the hypervisor
        # display filter is off, which would fail OPEN for control actions.
        if not await access.vm_in_tenant_scope(hub, sess, vm_record):
            raise HTTPException(status_code=403, detail="not authorized for this VM's tenant")

    @app.post("/api/pxmx/vm-action")
    async def pxmx_vm_action(request: Request):
        """Hypervisors view VM lifecycle: start/stop/reboot/snapshot (ANY vmid).

        Body: ``{unique_id, vmid, node, type, action, snapshot_name?}``. Routes to
        the pxmx spoke's ``PXMX_VM_ACTION`` (unguarded — the agent's cs_guard sim
        90000 floor does NOT apply, so real tenant VMs at arbitrary vmids work).
        Authorized by _assert_vm_control: admin any, else a write-user/tenant-admin
        who OWNS the VM (fail-closed). ``timeout=35`` covers a slow ``qm stop``/
        ``snapshot`` (spoke→agent window is 30s)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            body = await request.json()
        except Exception:
            body = {}
        action = str((body or {}).get("action", "")).lower()
        if action not in ("start", "stop", "reboot", "restart", "snapshot",
                          "backup", "destroy", "delete"):
            raise HTTPException(status_code=400, detail=f"unknown action: {action}")
        # Admin → any VM; a write-user/tenant-admin → only a VM in their tenant.
        await _assert_vm_control(request, vmid=body.get("vmid"),
                                 node=body.get("node"), unique_id=body.get("unique_id"))
        hub = app.state.hub
        # Delete-protection safeguard: a Global Admin can mark VMs non-deletable
        # from Setup → Hypervisors (stored per-tenant, enforced as the UNION across
        # all tenants). A protected VM is rejected here, before the relay runs.
        if action in ("destroy", "delete"):
            uid = str(body.get("unique_id") or "")
            if uid and uid in hub.simulations_store.get_all_protected_vms():
                raise HTTPException(
                    status_code=403,
                    detail="This VM is protected from deletion. Remove the safeguard in Setup → Hypervisors to delete it.")
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")
        node = str(body.get("node", "") or "")
        payload = {
            "unique_id": body.get("unique_id", ""),
            "vmid": body.get("vmid"),
            "node": node,
            "type": body.get("type", "qemu"),
            "action": action,
            "snapshot_name": body.get("snapshot_name"),
        }
        # Backup: inject the tenant's effective vzdump config (per-host override
        # wins over the tenant default) so the agent runs vzdump with the
        # configured storage/mode/keep. Storage is REQUIRED — fail clearly if the
        # Setup → Hypervisors tab hasn't set one for this host.
        if action == "backup":
            tenant_id = sess.get("tenant_id") or ""
            hv = await hub.simulations_store.get_hypervisors_config(tenant_id)
            ph = (hv.get("per_host") or {}).get(node) or {}
            keep = ph.get("backup_keep")
            if keep is None:
                keep = hv.get("backup_keep")
            payload["backup"] = {
                "storage": ph.get("backup_storage") or hv.get("backup_storage") or "",
                "mode": ph.get("backup_mode") or hv.get("backup_mode") or "snapshot",
                "keep": keep or 0,
            }
            if not payload["backup"]["storage"]:
                raise HTTPException(status_code=400,
                    detail=f"No backup storage configured for host '{node or '?'}' — set one in Setup → Hypervisors")
        # Snapshot: name it from the configured prefix when the caller didn't
        # supply one (so snapshots read e.g. "lm-1720…" per the Setup config).
        elif action == "snapshot" and not payload.get("snapshot_name"):
            import time as _time
            tenant_id = sess.get("tenant_id") or ""
            hv = await hub.simulations_store.get_hypervisors_config(tenant_id)
            prefix = str(hv.get("snapshot_prefix") or "lm").strip() or "lm"
            payload["snapshot_name"] = f"{prefix}-{int(_time.time())}"
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_VM_ACTION", payload, timeout=35.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # Best-effort: a VM lifecycle change (start/stop/restart/snapshot)
            # may change the NetBox VM-record view (status at minimum), so re-sync
            # the acting tenant's VMs to NetBox when the VM sync is enabled.
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            # Drop + re-fetch the pxmx_vms tenant cache so a non-admin viewer
            # (whose VM list reads the cache, not a live relay) sees the new
            # state immediately instead of waiting up to 300s for the next tick.
            _refresh_module_all_tenants(hub, "pxmx_vms")
            return data
        except Exception as e:
            logger.exception("pxmx_vm_action failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/vm-action-bulk")
    async def pxmx_vm_action_bulk(request: Request):
        """Bulk VM lifecycle: apply ONE action to many VMs in a single request
        (the Hypervisors view's bulk start/stop/reboot/snapshot/backup) instead of
        one POST per VM. Each item is authorized independently; the PXMX_VM_ACTION
        relays run bounded-concurrent against the hypervisor spoke, and the NetBox
        VM-sync + tenant cache refresh happen ONCE for the whole batch. Body:
        ``{action, items:[{unique_id, vmid, node, type, snapshot_name?}]}``.
        Returns ``{results:[{vmid, ok, error?}], ok, total}`` — one item's failure
        never sinks the rest."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            body = await request.json()
        except Exception:
            body = {}
        action = str((body or {}).get("action", "")).lower()
        if action not in ("start", "stop", "reboot", "restart", "snapshot",
                          "backup", "destroy", "delete"):
            raise HTTPException(status_code=400, detail=f"unknown action: {action}")
        items = (body or {}).get("items") or []
        if not isinstance(items, list) or not items:
            raise HTTPException(status_code=400, detail="items must be a non-empty list")
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")
        tenant_id = sess.get("tenant_id") or ""
        # Delete-protection safeguard (union across all tenants) — computed once
        # for the batch; each protected item is rejected and never reaches the
        # spoke. Same safeguard as the single-VM route.
        protected_set = hub.simulations_store.get_all_protected_vms() if action in ("destroy", "delete") else set()
        # Backup/snapshot config is per-host but read from ONE tenant config.
        hv = None
        if action in ("backup", "snapshot"):
            hv = await hub.simulations_store.get_hypervisors_config(tenant_id)
        import time as _time
        # Authorize each item + build its agent payload (with backup/snapshot
        # config injected) at the hub, THEN send ONE PXMX_VM_ACTION_BULK to the
        # spoke — which fans one message per agent, not one per VM. Auth failures
        # (or missing backup storage) are recorded here and never reach the spoke.
        payload_items = []
        results = []
        for it in items:
            if not isinstance(it, dict):
                continue
            vmid = it.get("vmid")
            node = str(it.get("node", "") or "")
            try:
                await _assert_vm_control(request, vmid=vmid, node=node,
                                         unique_id=it.get("unique_id"))
            except HTTPException as he:
                results.append({"vmid": vmid, "ok": False, "error": str(he.detail)})
                continue
            # Delete-protection: a protected VM is skipped with a clear error
            # (never relayed to the spoke). The other VMs in the batch still run.
            if protected_set:
                _uid = str(it.get("unique_id") or "")
                if _uid and _uid in protected_set:
                    results.append({"vmid": vmid, "ok": False,
                                    "error": "protected from deletion (Setup → Hypervisors)"})
                    continue
            payload = {
                "unique_id": it.get("unique_id", ""),
                "vmid": vmid,
                "node": node,
                "type": it.get("type", "qemu"),
                "snapshot_name": it.get("snapshot_name"),
            }
            if action == "backup":
                ph = (hv.get("per_host") or {}).get(node) or {}
                keep = ph.get("backup_keep")
                if keep is None:
                    keep = hv.get("backup_keep")
                storage = ph.get("backup_storage") or hv.get("backup_storage") or ""
                if not storage:
                    results.append({"vmid": vmid, "ok": False,
                                    "error": f"No backup storage configured for host '{node or '?'}'"})
                    continue
                payload["backup"] = {
                    "storage": storage,
                    "mode": ph.get("backup_mode") or hv.get("backup_mode") or "snapshot",
                    "keep": keep or 0,
                }
            elif action == "snapshot" and not payload.get("snapshot_name"):
                prefix = str((hv or {}).get("snapshot_prefix") or "lm").strip() or "lm"
                payload["snapshot_name"] = f"{prefix}-{int(_time.time())}"
            payload_items.append(payload)

        if payload_items:
            try:
                resp = await hub.request_response(
                    pxmx_spoke, "PXMX_VM_ACTION_BULK",
                    {"action": action, "items": payload_items},
                    timeout=max(60.0, 8.0 * len(payload_items)))
                inner = resp.get("payload", {}).get("data", resp) if isinstance(resp, dict) else resp
                rows = (inner or {}).get("results") if isinstance(inner, dict) else None
                if rows is not None:
                    results.extend(rows)
                else:
                    err = (inner or {}).get("message", "bulk relay failed") if isinstance(inner, dict) else "bulk relay failed"
                    results.extend({"vmid": p.get("vmid"), "ok": False, "error": err} for p in payload_items)
            except Exception as e:  # noqa: BLE001
                logger.exception("pxmx_vm_action_bulk relay failed")
                results.extend({"vmid": p.get("vmid"), "ok": False, "error": str(e)} for p in payload_items)
        # One VM-sync + one cache refresh for the whole batch (not per VM).
        _trigger_vm_sync_after_pxmx_edit(hub, request, body)
        _refresh_module_all_tenants(hub, "pxmx_vms")
        return {"results": results,
                "ok": sum(1 for r in results if r.get("ok")),
                "total": len(results)}

    @app.get("/api/pxmx/pools")
    async def get_pxmx_pools(request: Request):
        """Proxmox resource pool list for the clone/create-VM UI's pool dropdown.

        Aggregates ``/pools`` across every connected pxmx agent (each cluster's
        pools tagged with its cluster name). Admin-only — pool names are a
        Proxmox-organizational detail, not tenant-scoped. Returns
        ``{pools: [{poolid, comment, cluster}], spoke_connected}``."""
        sess = _session_user(request)
        # Gated by the pxmx module right in the middleware; pools/ISOs/storages are
        # cluster-organizational data feeding the create-VM dropdowns, shown to any
        # pxmx-right user (not tenant-scoped).
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"pools": [], "spoke_connected": False}
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_POOLS", {}, timeout=20.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            pools = (data or {}).get("pools", []) if isinstance(data, dict) else []
            return {"pools": pools, "spoke_connected": True}
        except Exception as e:
            logger.exception("get_pxmx_pools failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/pxmx/isos")
    async def get_pxmx_isos(request: Request, node: str = None):
        """ISO images available on a node for the create-VM-from-ISO flow.

        ``?node=<node>`` required — the spoke resolves the agent that owns the
        node and lists its ISO storages. Admin-only. Returns
        ``{isos: [{volid, name, storage, size}], node, spoke_connected}``."""
        sess = _session_user(request)
        # Gated by the pxmx module right in the middleware; pools/ISOs/storages are
        # cluster-organizational data feeding the create-VM dropdowns, shown to any
        # pxmx-right user (not tenant-scoped).
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        node = (node or "").strip()
        if not node:
            raise HTTPException(status_code=400, detail="node query param required")
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"isos": [], "node": node, "spoke_connected": False}
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_ISOS",
                                                {"node": node}, timeout=25.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            isos = (data or {}).get("isos", []) if isinstance(data, dict) else []
            return {"isos": isos, "node": node, "spoke_connected": True}
        except Exception as e:
            logger.exception("get_pxmx_isos failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/pxmx/storages")
    async def get_pxmx_storages(request: Request, node: str = None,
                                content: str = "images"):
        """Storages on a node accepting the given content type (default
        ``images`` — boot-disk targets for create-VM-from-ISO). Admin-only.
        Returns ``{storages: [{storage, type, avail, total, shared}], node, spoke_connected}``."""
        sess = _session_user(request)
        # Gated by the pxmx module right in the middleware; pools/ISOs/storages are
        # cluster-organizational data feeding the create-VM dropdowns, shown to any
        # pxmx-right user (not tenant-scoped).
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        node = (node or "").strip()
        if not node:
            raise HTTPException(status_code=400, detail="node query param required")
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"storages": [], "node": node, "spoke_connected": False}
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_STORAGES",
                                                {"node": node, "content": content},
                                                timeout=25.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            storages = (data or {}).get("storages", []) if isinstance(data, dict) else []
            return {"storages": storages, "node": node, "spoke_connected": True}
        except Exception as e:
            logger.exception("get_pxmx_storages failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/create-vm")
    async def pxmx_create_vm(request: Request):
        """Hypervisors view create-VM-from-ISO: define a new qemu VM that boots
        an installer ISO. The user picks a node, ISO (volid), disk storage +
        size, memory, cores, and optionally a destination pool. The new VM is
        tagged with the acting tenant's display NAME (the visible label) and
        ``proxmox_tag`` (the VM-sync key), placed in the chosen pool, and left
        stopped — the user boots it and installs via the VNC console. Admin-only
        (admin acting as a tenant via the switcher, same as clone). Body:
        ``{node, name, volid, memory_mb?, cores?, disk_storage?, disk_gb?,
        bridge?, pool?, new_vmid?}``. After success the tenant's VM sync is
        re-triggered so NetBox picks up the new VM."""
        sess = _session_user(request)
        # Write-user tier: create/clone tag the new VM with the acting tenant's
        # labels (their own tenant for a non-admin), so a write-user or tenant-
        # admin may create in their tenant; a view user is rejected. Admin any.
        if not sess or not access.has_edit_access(sess):
            raise HTTPException(status_code=403, detail="Edit access required to create VMs")
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body or {}
        node = str(body.get("node", "")).strip()
        if not node:
            raise HTTPException(status_code=400, detail="node is required")
        name = str(body.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        volid = str(body.get("volid", "")).strip()
        if not volid:
            raise HTTPException(status_code=400, detail="volid (ISO) is required")
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")
        # Resolve the acting tenant's labels (display name + proxmox_tag) —
        # same model as clone so the new VM is visible to the tenant and synced.
        tid = _resolve_tenant(request, None)
        scoping = get_tenant_scoping(hub, tid) or {}
        tenant_tag = scoping.get("proxmox_tag") or ""
        tenant_name = ""
        try:
            trec = hub.state.get_tenant(tid) or {}
            tenant_name = str(trec.get("name") or "").strip()
        except Exception:
            pass
        tenant_tags = []
        for t in (tenant_name, tenant_tag):
            if t and t not in tenant_tags:
                tenant_tags.append(t)
        pool = str(body.get("pool", "")).strip()
        # Optional VMID auto-allocation: when the knob is ON and the caller did
        # not supply a new_vmid, pick the next free VMID in the tenant's
        # [vmid_start, vmid_end] NetBox range (cluster-verified). OFF (default)
        # or no range → None → the agent falls back to Proxmox /cluster/nextid.
        new_vmid = body.get("new_vmid")
        if not new_vmid and vmid_alloc.vmid_alloc_cfg(hub).get("enabled", False):
            try:
                new_vmid = await vmid_alloc.allocate_vmid(hub, tid)
            except Exception as e:
                logger.debug("vmid-alloc (create) tenant=%s failed: %s", tid, e)
                new_vmid = None
        payload = {
            "node": node,
            "name": name,
            "volid": volid,
            "memory_mb": body.get("memory_mb", 2048),
            "cores": body.get("cores", 2),
            "disk_storage": body.get("disk_storage", ""),
            "disk_gb": body.get("disk_gb", 32),
            "bridge": body.get("bridge", "vmbr0"),
            "pool": pool,
            "tenant_tags": tenant_tags,
            "new_vmid": new_vmid,
        }
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_CREATE_VM", payload, timeout=130.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            if isinstance(data, dict) and data.get("status") == "ERROR":
                raise HTTPException(status_code=502, detail=data.get("message", "create failed"))
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            _refresh_module_all_tenants(hub, "pxmx_vms")
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("pxmx_create_vm failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/clone")
    async def pxmx_clone_vm(request: Request):
        """Hypervisors view clone-from-template: clone a template-pool VM to a
        new VM tagged for the acting tenant.

        Body: ``{template_unique_id, name, new_vmid?}`` (or ``vmid``/``node``/
        ``type`` instead of ``template_unique_id``). Templates are shared — any
        admin acting as a tenant may clone them; the new VM is tagged with the
        acting tenant's ``proxmox_tag`` so the next VM sync attributes it to that
        tenant. The template MUST live in a configured template pool (the
        hub-side guard; the agent clones whatever vmid it's told, so the guard
        belongs here). A free VMID is auto-assigned by the agent when
        ``new_vmid`` is omitted. The spoke→agent clone window is 600s (full-disk
        clones can take minutes). After a successful clone the tenant's VM sync
        is re-triggered so NetBox picks up the new VM. Admin-only.
        """
        sess = _session_user(request)
        # Write-user tier: create/clone tag the new VM with the acting tenant's
        # labels (their own tenant for a non-admin), so a write-user or tenant-
        # admin may create in their tenant; a view user is rejected. Admin any.
        if not sess or not access.has_edit_access(sess):
            raise HTTPException(status_code=403, detail="Edit access required to create VMs")
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body or {}
        template_unique_id = str(body.get("template_unique_id", "")).strip()
        if not template_unique_id:
            # Allow explicit vmid/node/type as a fallback to the unique_id form.
            vmid = body.get("vmid")
            node = str(body.get("node", "")).strip()
            if vmid is None or not node:
                raise HTTPException(status_code=400,
                                     detail="template_unique_id (or vmid+node) required")
            template_unique_id = f"unknown/{node}/{vmid}"
        name = str(body.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")

        # Resolve the acting tenant's labels for the new VM: the tenant display
        # NAME (the visible "label" the user wants on the VM) AND the
        # proxmox_tag (the Hypervisor→NetBox VM sync matches on it, so the new
        # VM must carry it to be attributed to this tenant on the next sync).
        # Templates are shared across tenants; the cloning tenant owns the new VM.
        tid = _resolve_tenant(request, None)
        scoping = get_tenant_scoping(hub, tid) or {}
        tenant_tag = scoping.get("proxmox_tag") or ""
        tenant_name = ""
        try:
            trec = hub.state.get_tenant(tid) or {}
            tenant_name = str(trec.get("name") or "").strip()
        except Exception:
            pass
        tenant_tags = []
        for t in (tenant_name, tenant_tag):
            if t and t not in tenant_tags:
                tenant_tags.append(t)

        # Optional destination pool the user selected from the Proxmox pool
        # dropdown (populated by /api/pxmx/pools). Blank = no pool. The agent
        # passes it to qm/pct clone --pool.
        pool = str(body.get("pool", "")).strip()

        # Hub-side guard: only a template that lives in a configured template
        # pool may be cloned (the agent clones any vmid it's handed, so the
        # template-pool boundary is enforced here). Look the VM up via the
        # tenant's cached VM list — the unique_id identifies it uniquely.
        template_pools = {p.lower() for p in access._template_pools(hub)}
        template_pool_ok = False
        try:
            cached = _cache_entry(tid, "pxmx_vms")
            vms = (cached["data"] or {}).get("vms", []) if cached else []
            if not vms:
                # No cache yet — ask the spoke for the live list (unfiltered is
                # fine: we only read the template's pool field).
                r = await hub.request_response(pxmx_spoke, "PXMX_LIST_VMS", {})
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                vms = (d or {}).get("vms", [])
            for v in vms:
                if v.get("unique_id") == template_unique_id:
                    pool = str(v.get("pool", "")).lower()
                    if pool and pool in template_pools:
                        template_pool_ok = True
                    elif not template_pools:
                        template_pool_ok = True
                    break
        except Exception as e:
            logger.debug("clone: template-pool guard lookup skipped: %s", e)
        if not template_pool_ok:
            raise HTTPException(status_code=403,
                                 detail="template is not in a configured template pool")

        # Optional VMID auto-allocation: when the knob is ON and the caller did
        # not supply a new_vmid, pick the next free VMID in the tenant's
        # [vmid_start, vmid_end] NetBox range (cluster-verified). OFF (default)
        # or no range → None → the agent falls back to Proxmox /cluster/nextid.
        new_vmid = body.get("new_vmid")
        if not new_vmid and vmid_alloc.vmid_alloc_cfg(hub).get("enabled", False):
            try:
                new_vmid = await vmid_alloc.allocate_vmid(hub, tid)
            except Exception as e:
                logger.debug("vmid-alloc (clone) tenant=%s failed: %s", tid, e)
                new_vmid = None
        payload = {
            "unique_id": template_unique_id,        # routing: cluster → agent
            "template_unique_id": template_unique_id,
            "name": name,
            "tenant_tags": tenant_tags,
            "pool": pool,
            "type": body.get("type", "qemu"),
            "node": template_unique_id.split("/")[1] if template_unique_id.count("/") >= 2 else body.get("node", ""),
            "template_vmid": body.get("vmid"),
            "new_vmid": new_vmid,
        }
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_CLONE_VM", payload, timeout=605.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            if isinstance(data, dict) and data.get("status") == "ERROR":
                raise HTTPException(status_code=502, detail=data.get("message", "clone failed"))
            # Re-sync the acting tenant's VMs to NetBox so the new VM is picked up.
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            _refresh_module_all_tenants(hub, "pxmx_vms")
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("pxmx_clone_vm failed")
            raise HTTPException(status_code=500, detail=str(e))
