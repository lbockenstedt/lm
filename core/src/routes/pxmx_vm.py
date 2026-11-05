"""Proxmox VM lifecycle routes: action, pools, ISOs, storages, create, clone."""
# asyncio runs bulk VM actions concurrently and schedules background syncs.
import asyncio
# Regular expressions parse numbered spoke/VM names like "spoke-05".
import re

# Request/error types, the cross-tenant module refresh, tenant access rules, tenant scoping,
# logger, the "spoke or 503" helper, and the VMID allocator, all re-exported by api.
from api import (
    HTTPException, Request, _refresh_module_all_tenants,
    access, get_tenant_scoping, logger, spoke_or_503, vmid_alloc,
)

# ── Spoke-name numbering (pure; module-level for unit tests) ──────────────────
# Split "<prefix>-<number>" into prefix and number, ignoring leading zeros in the number.
_SPOKE_NAME_RE = re.compile(r"^(.*?)-0*(\d+)$")


def _next_spoke_number(prefix, vm_names, spoke_hostnames):
    """The lowest free positive integer N such that ``<prefix>-0N`` collides with
    no existing VM name (``<prefix>-05``) AND no existing spoke hostname
    (``<prefix>-05`` or ``agent-<prefix>-05``). Case-insensitive; tolerates any
    zero-padding. Scans upward from 1, so a taken number is never reused even when
    a lower gap exists."""
    # Normalise the prefix for case-insensitive comparison and start with no numbers taken.
    pfx = str(prefix or "").strip().lower()
    used = set()

    def _capture(text):
        """Record the number of ``text`` in ``used`` when its prefix matches ``pfx``."""
        # Normalise case/whitespace and drop an "agent-" prefix so agent hostnames match too.
        s = str(text or "").strip().lower()
        if s.startswith("agent-"):
            s = s[len("agent-"):]
        # Only names with the same prefix reserve a number.
        m = _SPOKE_NAME_RE.match(s)
        if m and m.group(1) == pfx:
            # The digit group always parses; guard anyway so a bad name can never crash numbering.
            try:
                used.add(int(m.group(2)))
            except ValueError:
                pass

    # Collect taken numbers from both VM names and spoke hostnames.
    for v in (vm_names or []):
        _capture(v)
    for h in (spoke_hostnames or []):
        _capture(h)
    # Count up from 1 to the first unused number.
    n = 1
    while n in used:
        n += 1
    return n



def _vm_node_name(item):
    """The Proxmox node hostname for a bulk/single VM item: the explicit
    ``node`` field, else the middle segment of ``unique_id``
    (``<cluster>/<node>/<vmid>``). Pure; module-level for unit tests."""
    # Prefer the explicit node field when present.
    node = str((item or {}).get("node") or "").strip()
    if node:
        return node
    # Otherwise take the middle part of "<cluster>/<node>/<vmid>"; "" if it has another shape.
    uid = str((item or {}).get("unique_id") or "")
    parts = uid.split("/")
    return parts[1].strip() if len(parts) >= 3 else ""


def resolve_vm_spoke(hub, item):
    """The agent-hosting spoke that OWNS this VM, or None.

    The Hypervisors VM list is MERGED across every agent-hosting spoke
    (``_merge_pxmx_list_vms`` fans ``PXMX_LIST_VMS`` out to all of them), but VM
    ACTIONS used to relay to the single ``get_hypervisor_spoke()``. With more
    than one hypervisor/cs spoke connected, every action on a VM owned by one of
    the OTHER spokes was sent to a spoke whose agents don't host it — the spoke
    fell back to its first agent and the command failed (or, worse, targeted the
    wrong cluster's vmid). Same class of bug as the DHCP cross-cluster write.

    Resolution order: explicit ``agent_id`` → the VM's node hostname matched
    against the hub's ``agent_info`` index (populated from every relayed agent
    frame) → None so the caller falls back to ``get_hypervisor_spoke()``."""
    # An explicit agent id maps directly to its hosting spoke (without hypervisor fallback).
    aid = str((item or {}).get("agent_id") or "").strip()
    if aid:
        sid = hub.get_spoke_for_agent(aid, fallback_hypervisor=False)
        if sid:
            return sid
    # Otherwise match by the VM's node hostname; give up if it is unknown.
    node = _vm_node_name(item).lower()
    if not node:
        return None
    # Search every known agent for one whose hostname, id or key matches the node.
    for pk, info in (getattr(hub, "agent_info", None) or {}).items():
        # Skip malformed index entries.
        if not isinstance(info, dict):
            continue
        # The names this agent can be referred to by, lowercased for comparison.
        names = {str(info.get("hostname") or "").strip().lower(),
                 str(info.get("agent_id") or "").strip().lower(),
                 str(pk).strip().lower()}
        # Matching agent with a known spoke: that spoke owns the VM.
        if node in names and info.get("spoke_id"):
            return info["spoke_id"]
    return None


def register(app, hub, ctx):
    """Register pxmx_vm routes on the Hub app."""
    # Shared session, admin, tenant and filter helpers from the context object.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant
    # Acting tenant falls back to resolving the request's tenant when ctx lacks the helper.
    _acting_tenant = getattr(ctx, "_acting_tenant", lambda request: _resolve_tenant(request, None))
    _filter_tenant = ctx._filter_tenant
    # Starts a background VM-list refresh after edits so the UI shows changes quickly.
    _trigger_vm_sync_after_pxmx_edit = ctx._trigger_vm_sync_after_pxmx_edit

    async def _assert_vm_control(request, vmid=None, node=None, unique_id=None, agent_id=None):
        """Authorize a VM CONTROL action (start/stop/reboot/snapshot/backup).
        Global Admin → any VM. Otherwise the caller must (a) be a write-user or
        above (access.has_edit_access) AND (b) OWN the target VM — either the VM's
        hypervisor is BOUND to one of the caller's tenants (whole-host ownership),
        or the VM's ips/tags/pool (from GET_VM_INFO) survive the hypervisor tenant
        filter, exactly like the tenant-filtered VM list + /vm/{id}/details.
        FAIL-CLOSED: an unattributable VM (spoke down, empty info) → 403, so a
        tenant user can never act on a VM they couldn't see. A view user (pxmx
        right, no edit) is rejected before the ownership probe."""
        # Look up the caller's session.
        sess = _session_user(request)
        # Global Admins may control any VM.
        if _is_admin(sess):
            return
        # Users without edit rights may only view VMs, never control them.
        if not access.has_edit_access(sess):
            raise HTTPException(status_code=403, detail="Edit access required to control VMs")
        # Pick the spoke hosting the VM: the agent's own spoke if known, else the default
        # hypervisor.
        hub = app.state.hub
        pxmx_spoke = (hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False)
                      if agent_id else None) or hub.get_hypervisor_spoke()
        # Whole-host ownership: a hypervisor bound to one of the caller's tenants
        # means they own every VM on it → allow (mirrors the VM console gate +
        # host shell). Shared/unbound host → per-VM tag/subnet attribution below.
        if access.hypervisor_owned_by_caller(hub, sess, pxmx_spoke):
            return
        # Operator opt-in: on a SHARED/unbound (or own) hypervisor a Tenant Admin
        # may control any VM when Setup → Hypervisors enables it (tenant_console_
        # enabled, or host_shell_enabled). Mirrors the VM console gate; OFF by
        # default. Covers a flat lab whose VMs aren't tagged / subnet-attributed.
        if await access.tenant_admin_console_allowed(hub, sess, pxmx_spoke):
            return
        # Ask the hosting spoke for the VM's ips/tags/pool to attribute it to a tenant.
        info: dict = {}
        if pxmx_spoke:
            # Identify the VM by unique id when known, else by its numeric vmid.
            ident = unique_id or (str(vmid) if vmid is not None else "")
            try:
                raw = await hub.request_response(
                    pxmx_spoke, "GET_VM_INFO",
                    {"vm_id": ident, "vmid": vmid, "node": node or ""})
                info = raw.get("payload", {}).get("data", {}) if isinstance(raw, dict) else {}
            # Any failure leaves info empty, which denies access below (fail closed).
            except Exception:  # noqa: BLE001 — fail-closed below
                info = {}
        # Only the fields the tenant ownership check looks at.
        vm_record = {
            "ips": info.get("ips") or [],
            "tags": info.get("tags") or [],
            "pool": info.get("pool") or "",
        }
        # Recover a stopped / guest-agent-silent VM's last-known ips/tags from the
        # pxmx_vms warm cache so a subnet-owned VM the tenant SEES in their list
        # stays controllable across a stop. Still attributed below against the
        # CALLER's own prefixes → never authorizes another tenant's VM.
        if not vm_record["ips"] or not vm_record["tags"]:
            lk = access.last_known_vm_record(
                hub, unique_id=unique_id, vmid=vmid, node=node)
            if lk:
                # Fill in only the fields the live probe could not supply.
                if not vm_record["ips"]:
                    vm_record["ips"] = lk.get("ips") or []
                if not vm_record["tags"]:
                    vm_record["tags"] = lk.get("tags") or []
                if not vm_record["pool"]:
                    vm_record["pool"] = lk.get("pool") or ""
        # Toggle-independent, fail-closed ownership (subnet or tenant tag). NOT
        # _filter_tenant — that returns the record unchanged when the hypervisor
        # display filter is off, which would fail OPEN for control actions.
        if not await access.vm_in_tenant_scope(hub, sess, vm_record, spoke_id=pxmx_spoke):
            # Log why access was denied with enough detail to fix it; logging must never break the
            # 403.
            try:
                _u = (sess or {}).get("user", {}) or {}
                logger.warning(
                    "pxmx control DENY vm=%s user=%s role=%s tenants=%s spoke=%s "
                    "spoke_tenant=%s vm_tags=%s vm_ips=%s — enable Setup→Hypervisors "
                    "tenant console, tag the VM, or add the tenant's subnet",
                    unique_id or vmid,
                    _u.get("username") or _u.get("user_id"),
                    (_u.get("permissions") or {}).get("role"),
                    _u.get("tenants") or _u.get("tenant_id"), pxmx_spoke,
                    (hub.state.get_spoke_tenant(pxmx_spoke) or "") if pxmx_spoke else "",
                    vm_record["tags"], vm_record["ips"])
            except Exception:  # noqa: BLE001
                pass
            # Not in the caller's tenant scope: refuse.
            raise HTTPException(status_code=403, detail="not authorized for this VM's tenant")

    # Run a lifecycle action on a single VM.
    @app.post("/api/pxmx/vm-action")
    async def pxmx_vm_action(request: Request):
        """Hypervisors view VM lifecycle: start/stop/reboot/snapshot (ANY vmid).

        Body: ``{unique_id, vmid, node, type, action, snapshot_name?}``. Routes to
        the pxmx spoke's ``PXMX_VM_ACTION`` (unguarded — the agent's cs_guard sim
        90000 floor does NOT apply, so real tenant VMs at arbitrary vmids work).
        Authorized by _assert_vm_control: admin any, else a write-user/tenant-admin
        who OWNS the VM (fail-closed). ``timeout=35`` covers a slow ``qm stop``/
        ``snapshot`` (spoke→agent window is 30s)."""
        # Any VM action requires a logged-in user.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # Parse the JSON body; a bad body is treated as empty and fails validation below.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Only a fixed set of actions is allowed.
        action = str((body or {}).get("action", "")).lower()
        if action not in ("start", "stop", "reboot", "restart", "snapshot",
                          "backup", "destroy", "delete"):
            raise HTTPException(status_code=400, detail=f"unknown action: {action}")
        # Admin → any VM; a write-user/tenant-admin → only a VM in their tenant.
        await _assert_vm_control(request, vmid=body.get("vmid"),
                                 node=body.get("node"), unique_id=body.get("unique_id"),
                                 agent_id=body.get("agent_id"))
        # Use the live hub object stored on the app state.
        hub = app.state.hub
        # Delete-protection safeguard: a Global Admin can mark VMs non-deletable
        # from Setup → Hypervisors (stored per-tenant, enforced as the UNION across
        # all tenants). A protected VM is rejected here, before the relay runs.
        if action in ("destroy", "delete"):
            # Reject the delete if this VM is on the protected list.
            uid = str(body.get("unique_id") or "")
            if uid and uid in hub.simulations_store.get_all_protected_vms():
                raise HTTPException(
                    status_code=403,
                    detail="This VM is protected from deletion. Remove the safeguard in Setup → Hypervisors to delete it.")
        # Send to the spoke owning the VM, else the default hypervisor; 503 if none is connected.
        pxmx_spoke = spoke_or_503(
            resolve_vm_spoke(hub, body) or hub.get_hypervisor_spoke(), "Hypervisor")
        # Build the action request in the shape the spoke's PXMX_VM_ACTION handler expects.
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
        # Backups need the tenant's vzdump settings added to the payload.
        if action == "backup":
            # Setup → Hypervisors stores backup config per-tenant, keyed by the
            # UI's selected tenant (the settings route resolves it via
            # get_tenant_id → ?tenant_id=). A non-admin's session carries their
            # own tenant; a Global Admin (no session tenant) passes the selected
            # tenant in the body so the right config is read. NOTE: sess has no
            # top-level tenant_id — it lives at sess["user"]["tenant_id"], so
            # the old sess.get("tenant_id") was always "" and backup always
            # failed with "No backup storage configured".
            tenant_id = (sess.get("user") or {}).get("tenant_id") or ""
            # Fall back to the tenant the admin selected in the UI, sent in the body.
            if not tenant_id:
                tenant_id = str((body or {}).get("tenant") or "")
            # Load the tenant's hypervisor settings and this host's overrides (if any).
            hv = await hub.simulations_store.get_hypervisors_config(tenant_id)
            ph = (hv.get("per_host") or {}).get(node) or {}
            # Per-host retention count wins; otherwise use the tenant default.
            keep = ph.get("backup_keep")
            if keep is None:
                keep = hv.get("backup_keep")
            # Storage and mode: per-host value, then tenant default, then built-in default.
            payload["backup"] = {
                "storage": ph.get("backup_storage") or hv.get("backup_storage") or "",
                "mode": ph.get("backup_mode") or hv.get("backup_mode") or "snapshot",
                "keep": keep or 0,
            }
            # vzdump cannot run without a target storage, so stop with a clear message.
            if not payload["backup"]["storage"]:
                raise HTTPException(status_code=400,
                    detail=f"No backup storage configured for host '{node or '?'}' — set one in Setup → Hypervisors")
        # Snapshot: name it from the configured prefix when the caller didn't
        # supply one (so snapshots read e.g. "lm-1720…" per the Setup config).
        elif action == "snapshot" and not payload.get("snapshot_name"):
            # time gives a unique timestamp suffix for the snapshot name.
            import time as _time
            # Same tenant resolution as backup (see above) — snapshot prefix is
            # per-tenant in Setup → Hypervisors.
            tenant_id = (sess.get("user") or {}).get("tenant_id") or ""
            # Fall back to the tenant the admin selected in the UI.
            if not tenant_id:
                tenant_id = str((body or {}).get("tenant") or "")
            # Read the tenant's snapshot name prefix ("lm" if unset or blank).
            hv = await hub.simulations_store.get_hypervisors_config(tenant_id)
            prefix = str(hv.get("snapshot_prefix") or "lm").strip() or "lm"
            # Name the snapshot "<prefix>-<unix time>".
            payload["snapshot_name"] = f"{prefix}-{int(_time.time())}"
        # Relay the action to the spoke, allowing 60s for slow stop/snapshot commands.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_VM_ACTION", payload, timeout=60.0)
            # unwrap_spoke (not the inline `.get("data", result)`, which only
            # defaults on an ABSENT key): a spoke replying `data: null` used to
            # unwrap to None and this route returned HTTP 200 with a literal
            # JSON `null` body, which the WebUI then dereferenced.
            data = access.unwrap_spoke(result)
            # Best-effort: a VM lifecycle change (start/stop/restart/snapshot)
            # may change the NetBox VM-record view (status at minimum), so re-sync
            # the acting tenant's VMs to NetBox when the VM sync is enabled.
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            # Drop + re-fetch the pxmx_vms tenant cache so a non-admin viewer
            # (whose VM list reads the cache, not a live relay) sees the new
            # state immediately instead of waiting up to 300s for the next tick.
            _refresh_module_all_tenants(hub, "pxmx_vms")
            # Return the spoke's result to the UI.
            return data
        # Any relay failure is logged with a traceback and reported as 500.
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
        # Any VM action requires a logged-in user.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # Parse the JSON body; a bad body is treated as empty and fails validation below.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Only a fixed set of actions is allowed.
        action = str((body or {}).get("action", "")).lower()
        if action not in ("start", "stop", "reboot", "restart", "snapshot",
                          "backup", "destroy", "delete"):
            raise HTTPException(status_code=400, detail=f"unknown action: {action}")
        # The batch must be a non-empty list of VM items.
        items = (body or {}).get("items") or []
        if not isinstance(items, list) or not items:
            raise HTTPException(status_code=400, detail="items must be a non-empty list")
        # Default hypervisor spoke for VMs whose owner cannot be resolved; 503 if none.
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")
        # Setup → Hypervisors stores backup/snapshot config per-tenant (keyed by
        # the UI's selected tenant). A non-admin's session carries their tenant;
        # a Global Admin (no session tenant) passes the selected tenant in the
        # body. sess has no top-level tenant_id — it's sess["user"]["tenant_id"]
        # (the old sess.get("tenant_id") was always "" so bulk backup always
        # failed with "No backup storage configured").
        tenant_id = (sess.get("user") or {}).get("tenant_id") or ""
        # Fall back to the tenant the admin selected in the UI.
        if not tenant_id:
            tenant_id = str((body or {}).get("tenant") or "")
        # Delete-protection safeguard (union across all tenants) — computed once
        # for the batch; each protected item is rejected and never reaches the
        # spoke. Same safeguard as the single-VM route.
        protected_set = hub.simulations_store.get_all_protected_vms() if action in ("destroy", "delete") else set()
        # Backup/snapshot config is per-host but read from ONE tenant config.
        # Load the hypervisor settings once, only when the action needs them.
        hv = None
        if action in ("backup", "snapshot"):
            hv = await hub.simulations_store.get_hypervisors_config(tenant_id)
        # time gives a unique timestamp suffix for generated snapshot names.
        import time as _time
        # Authorize each item + build its agent payload (with backup/snapshot
        # config injected) at the hub, THEN send ONE PXMX_VM_ACTION_BULK to the
        # spoke — which fans one message per agent, not one per VM. Auth failures
        # (or missing backup storage) are recorded here and never reach the spoke.
        # Payloads to send, and per-VM results for items that already failed here.
        payload_items = []
        results = []
        # Check and prepare each requested VM.
        for it in items:
            # Ignore malformed items.
            if not isinstance(it, dict):
                continue
            vmid = it.get("vmid")
            node = str(it.get("node", "") or "")
            # Authorize this VM; a denial is recorded as its result and the batch continues.
            try:
                await _assert_vm_control(request, vmid=vmid, node=node,
                                         unique_id=it.get("unique_id"),
                                         agent_id=it.get("agent_id"))
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
            # Per-VM part of the bulk request.
            payload = {
                "unique_id": it.get("unique_id", ""),
                "vmid": vmid,
                "node": node,
                "type": it.get("type", "qemu"),
                "snapshot_name": it.get("snapshot_name"),
            }
            # Backups need this host's vzdump settings (per-host overrides, then tenant default).
            if action == "backup":
                ph = (hv.get("per_host") or {}).get(node) or {}
                keep = ph.get("backup_keep")
                if keep is None:
                    keep = hv.get("backup_keep")
                storage = ph.get("backup_storage") or hv.get("backup_storage") or ""
                # Without a target storage this VM cannot be backed up; record it and move on.
                if not storage:
                    results.append({"vmid": vmid, "ok": False,
                                    "error": f"No backup storage configured for host '{node or '?'}'"})
                    continue
                payload["backup"] = {
                    "storage": storage,
                    "mode": ph.get("backup_mode") or hv.get("backup_mode") or "snapshot",
                    "keep": keep or 0,
                }
            # Snapshots without a name get "<prefix>-<unix time>".
            elif action == "snapshot" and not payload.get("snapshot_name"):
                prefix = str((hv or {}).get("snapshot_prefix") or "lm").strip() or "lm"
                payload["snapshot_name"] = f"{prefix}-{int(_time.time())}"
            # This VM passed every check, so queue it for the spoke.
            payload_items.append(payload)

        # Only contact spokes when at least one VM passed the checks.
        if payload_items:
            # Group by the spoke that OWNS each VM (the VM list is merged across
            # every agent-hosting spoke, so a batch can legitimately span them)
            # and fan ONE PXMX_VM_ACTION_BULK per spoke, concurrently. Previously
            # the whole batch went to get_hypervisor_spoke() and every VM owned by
            # another spoke failed silently.
            groups: dict = {}
            # Bucket each payload under its owning spoke (default hypervisor if unknown).
            for p in payload_items:
                sid = resolve_vm_spoke(hub, p) or pxmx_spoke
                groups.setdefault(sid, []).append(p)

            async def _relay_group(sid, grp):
                """Send one spoke its bulk request and return per-VM result rows.

                On failure, every VM in the group gets a failed row with the error text.
                """
                # Timeout grows with group size (8s per VM, at least 60s).
                try:
                    resp = await hub.request_response(
                        sid, "PXMX_VM_ACTION_BULK",
                        {"action": action, "items": grp},
                        timeout=max(60.0, 8.0 * len(grp)))
                    # Unwrap the reply and take its results list when present.
                    inner = resp.get("payload", {}).get("data", resp) if isinstance(resp, dict) else resp
                    rows = (inner or {}).get("results") if isinstance(inner, dict) else None
                    if rows is not None:
                        return list(rows)
                    # No results: use the spoke's message (or a generic one) as the error for every
                    # VM.
                    err = (inner or {}).get("message", "bulk relay failed") if isinstance(inner, dict) else "bulk relay failed"
                # Relay error: log it and mark the whole group failed.
                except Exception as e:  # noqa: BLE001
                    logger.exception("pxmx_vm_action_bulk relay failed (spoke %s)", sid)
                    err = str(e)
                return [{"vmid": p.get("vmid"), "ok": False, "error": err} for p in grp]

            # Relay to all spokes at once and merge their result rows.
            for rows in await asyncio.gather(
                    *[_relay_group(sid, grp) for sid, grp in groups.items()]):
                results.extend(rows)
        # One VM-sync + one cache refresh for the whole batch (not per VM).
        _trigger_vm_sync_after_pxmx_edit(hub, request, body)
        _refresh_module_all_tenants(hub, "pxmx_vms")
        # Return all per-VM results plus a count of successes.
        return {"results": results,
                "ok": sum(1 for r in results if r.get("ok")),
                "total": len(results)}

    # Resource pools for the create/clone VM dropdown.
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
        # Any logged-in user may read pools (the middleware already checked the pxmx right).
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # Without a connected hypervisor spoke, return an empty list and say so.
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"pools": [], "spoke_connected": False}
        # Ask the spoke for pools, unwrap the reply and return the list.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_POOLS", {}, timeout=60.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            pools = (data or {}).get("pools", []) if isinstance(data, dict) else []
            return {"pools": pools, "spoke_connected": True}
        # Any relay failure is logged and reported as 500.
        except Exception as e:
            logger.exception("get_pxmx_pools failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ISO images on a node, for create-VM-from-ISO.
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
        # Any logged-in user may read ISOs (the middleware already checked the pxmx right).
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # A node name is required to know where to look.
        node = (node or "").strip()
        if not node:
            raise HTTPException(status_code=400, detail="node query param required")
        # Without a connected hypervisor spoke, return an empty list and say so.
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"isos": [], "node": node, "spoke_connected": False}
        # Ask the spoke for the node's ISOs, unwrap the reply and return the list.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_ISOS",
                                                {"node": node}, timeout=60.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            isos = (data or {}).get("isos", []) if isinstance(data, dict) else []
            return {"isos": isos, "node": node, "spoke_connected": True}
        # Any relay failure is logged and reported as 500.
        except Exception as e:
            logger.exception("get_pxmx_isos failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Storages on a node that accept a content type, for create-VM disk targets.
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
        # Any logged-in user may read storages (the middleware already checked the pxmx right).
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # A node name is required to know where to look.
        node = (node or "").strip()
        if not node:
            raise HTTPException(status_code=400, detail="node query param required")
        # Without a connected hypervisor spoke, return an empty list and say so.
        hub = app.state.hub
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"storages": [], "node": node, "spoke_connected": False}
        # Ask the spoke for matching storages, unwrap the reply and return the list.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_STORAGES",
                                                {"node": node, "content": content},
                                                timeout=60.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            storages = (data or {}).get("storages", []) if isinstance(data, dict) else []
            return {"storages": storages, "node": node, "spoke_connected": True}
        # Any relay failure is logged and reported as 500.
        except Exception as e:
            logger.exception("get_pxmx_storages failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Create a new VM that boots from an installer ISO.
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
        # Parse the JSON body; a bad or empty body becomes {} and fails validation below.
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body or {}
        # Node, VM name and ISO volume id are all required.
        node = str(body.get("node", "")).strip()
        if not node:
            raise HTTPException(status_code=400, detail="node is required")
        name = str(body.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        volid = str(body.get("volid", "")).strip()
        if not volid:
            raise HTTPException(status_code=400, detail="volid (ISO) is required")
        # The default hypervisor spoke handles creation; 503 if none is connected.
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")
        # Resolve the acting tenant's labels (display name + proxmox_tag) —
        # same model as clone so the new VM is visible to the tenant and synced.
        tid = _acting_tenant(request)
        scoping = get_tenant_scoping(hub, tid) or {}
        tenant_tag = scoping.get("proxmox_tag") or ""
        tenant_name = ""
        # Look up the tenant's display name; a lookup error just leaves it blank.
        try:
            trec = hub.state.get_tenant(tid) or {}
            tenant_name = str(trec.get("name") or "").strip()
        except Exception:
            pass
        # Tag list: tenant name and proxmox_tag, skipping blanks and duplicates.
        tenant_tags = []
        for t in (tenant_name, tenant_tag):
            if t and t not in tenant_tags:
                tenant_tags.append(t)
        # Optional destination pool chosen in the UI.
        pool = str(body.get("pool", "")).strip()
        # Optional VMID auto-allocation: when the knob is ON and the caller did
        # not supply a new_vmid, pick the next free VMID in the tenant's
        # [vmid_start, vmid_end] NetBox range (cluster-verified). OFF (default)
        # or no range → None → the agent falls back to Proxmox /cluster/nextid.
        new_vmid = body.get("new_vmid")
        if not new_vmid and vmid_alloc.vmid_alloc_cfg(hub).get("enabled", False):
            # Allocation failure is not fatal: None lets Proxmox pick the next id.
            try:
                new_vmid = await vmid_alloc.allocate_vmid(hub, tid)
            except Exception as e:
                logger.debug("vmid-alloc (create) tenant=%s failed: %s", tid, e)
                new_vmid = None
        # Create request for the agent, with defaults of 2 GiB RAM, 2 cores, 32 GB disk, vmbr0.
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
        # Relay the create; 130s allows for disk allocation on slow storage.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_CREATE_VM", payload, timeout=130.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # The agent reported an error: surface it as 502 (bad upstream).
            if isinstance(data, dict) and data.get("status") == "ERROR":
                raise HTTPException(status_code=502, detail=data.get("message", "create failed"))
            # Refresh NetBox VM sync and the cached VM list so the new VM appears right away.
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            _refresh_module_all_tenants(hub, "pxmx_vms")
            return data
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Anything else is logged and reported as 500.
        except Exception as e:
            logger.exception("pxmx_create_vm failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Clone a template VM into a new tenant VM.
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
        # Parse the JSON body; a bad or empty body becomes {} and fails validation below.
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body or {}
        # Identify the template, preferably by its "<cluster>/<node>/<vmid>" unique id.
        template_unique_id = str(body.get("template_unique_id", "")).strip()
        if not template_unique_id:
            # Allow explicit vmid/node/type as a fallback to the unique_id form.
            vmid = body.get("vmid")
            node = str(body.get("node", "")).strip()
            if vmid is None or not node:
                raise HTTPException(status_code=400,
                                     detail="template_unique_id (or vmid+node) required")
            # Build a unique-id-shaped key with an unknown cluster so routing still finds the node.
            template_unique_id = f"unknown/{node}/{vmid}"
        # The new VM needs a name.
        name = str(body.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        # The default hypervisor spoke handles cloning; 503 if none is connected.
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")

        # Resolve the acting tenant's labels for the new VM: the tenant display
        # NAME (the visible "label" the user wants on the VM) AND the
        # proxmox_tag (the Hypervisor→NetBox VM sync matches on it, so the new
        # VM must carry it to be attributed to this tenant on the next sync).
        # Templates are shared across tenants; the cloning tenant owns the new VM.
        tid = _acting_tenant(request)
        scoping = get_tenant_scoping(hub, tid) or {}
        tenant_tag = scoping.get("proxmox_tag") or ""
        tenant_name = ""
        # Look up the tenant's display name; a lookup error just leaves it blank.
        try:
            trec = hub.state.get_tenant(tid) or {}
            tenant_name = str(trec.get("name") or "").strip()
        except Exception:
            pass
        # Tag list: tenant name and proxmox_tag, skipping blanks and duplicates.
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
        # Configured template pool names (lowercase), and whether this template passes the check.
        template_pools = {p.lower() for p in access._template_pools(hub)}
        template_pool_ok = False
        # Any lookup error leaves the check failed, so the clone is refused (fail closed).
        try:
            # Prefer the cached VM list for this tenant.
            cached = hub.warm_get("pxmx_vms", f"{tid or '_all_'}|agent=")
            vms = (cached or {}).get("vms", []) if isinstance(cached, dict) else []
            if not vms:
                # No cache yet — ask the spoke for the live list (unfiltered is
                # fine: we only read the template's pool field).
                r = await hub.request_response(pxmx_spoke, "PXMX_LIST_VMS", {})
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                vms = (d or {}).get("vms", [])
            # Find the template in the list and check its pool.
            for v in vms:
                if v.get("unique_id") == template_unique_id:
                    # Note: this reuses ``pool`` for the template's pool, replacing the UI-chosen
                    # pool value.
                    pool = str(v.get("pool", "")).lower()
                    # Allowed when the template is in a template pool, or when no template pools are
                    # configured.
                    if pool and pool in template_pools:
                        template_pool_ok = True
                    elif not template_pools:
                        template_pool_ok = True
                    # Stop after the matching template.
                    break
        except Exception as e:
            logger.debug("clone: template-pool guard lookup skipped: %s", e)
        # Template not found or not in a template pool: refuse the clone.
        if not template_pool_ok:
            raise HTTPException(status_code=403,
                                 detail="template is not in a configured template pool")

        # Optional VMID auto-allocation: when the knob is ON and the caller did
        # not supply a new_vmid, pick the next free VMID in the tenant's
        # [vmid_start, vmid_end] NetBox range (cluster-verified). OFF (default)
        # or no range → None → the agent falls back to Proxmox /cluster/nextid.
        new_vmid = body.get("new_vmid")
        if not new_vmid and vmid_alloc.vmid_alloc_cfg(hub).get("enabled", False):
            # Allocation failure is not fatal: None lets Proxmox pick the next id.
            try:
                new_vmid = await vmid_alloc.allocate_vmid(hub, tid)
            except Exception as e:
                logger.debug("vmid-alloc (clone) tenant=%s failed: %s", tid, e)
                new_vmid = None
        # Clone request; the node comes from the unique id when it has one, else from the body.
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
        # Relay the clone; 605s covers the agent's 600s window for full-disk clones.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_CLONE_VM", payload, timeout=605.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # The agent reported an error: surface it as 502 (bad upstream).
            if isinstance(data, dict) and data.get("status") == "ERROR":
                raise HTTPException(status_code=502, detail=data.get("message", "clone failed"))
            # Re-sync the acting tenant's VMs to NetBox so the new VM is picked up.
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            _refresh_module_all_tenants(hub, "pxmx_vms")
            return data
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Anything else is logged and reported as 500.
        except Exception as e:
            logger.exception("pxmx_clone_vm failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── One-click spoke deploy (the "easy button") ────────────────────────────
    # A CS/PXMX spoke used to be a 4-step manual chore: build a Debian VM, set an
    # IP, register the agent, then bind the pxmx host to it. All four collapse
    # into a single clone of a *golden spoke template* — a VM whose agent was
    # installed with ``install_agent.sh --clone-only --onboarding-psk`` (service
    # staged + enabled but STOPPED; PSK carried over). Cloning it with a fresh
    # name and STARTING the clone makes it boot, DHCP an address, derive its
    # spoke id from its own hostname (``agent-<hostname>``), auto-discover the
    # hub, present the carried PSK, and self-approve + tenant-bind — zero touch.
    #
    # The clone must be a cloud-init template so Proxmox seeds the guest hostname
    # from the VM ``name`` on first boot; otherwise every clone keeps the
    # template's hostname and collides on one spoke id. This route only orchestrates
    # existing relays (PXMX_CLONE_VM then PXMX_VM_ACTION start) — no agent change.

    async def _list_all_pxmx_vms(hub, pxmx_spoke, tid):
        """The tenant's cached VM list, or a live unfiltered PXMX_LIST_VMS when the
        cache is cold. Best-effort ([] on any failure) — the caller only reads VM
        names to pick the next free spoke number."""
        # Any failure returns [], since the list only helps pick a free name.
        try:
            # Prefer the cached VM list for this tenant when it is warm.
            cached = hub.warm_get("pxmx_vms", f"{tid or '_all_'}|agent=")
            vms = (cached or {}).get("vms", []) if isinstance(cached, dict) else []
            if vms:
                return vms
            # Cold cache: ask the spoke for the live list and unwrap the reply.
            r = await hub.request_response(pxmx_spoke, "PXMX_LIST_VMS", {})
            d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
            return (d or {}).get("vms", []) or []
        # Lookup failed: log quietly and carry on with no names.
        except Exception as e:  # noqa: BLE001
            logger.debug("deploy-spoke: VM list lookup skipped: %s", e)
            return []

    def _known_spoke_hostnames(hub):
        """Every hostname/display-name the hub already knows for a spoke, so the
        next-number scan also avoids a spoke whose VM was renamed post-clone."""
        out = []
        # Any error just returns whatever names were collected so far.
        try:
            # Read spoke ids, their display names and metadata from hub state.
            st = hub.state.system_state
            names = st.get("module_names", {}) or {}
            meta = st.get("module_metadata", {}) or {}
            # For every known spoke collect its display name, reported hostname and id.
            for sid in (st.get("known_modules", []) or []):
                m = meta.get(sid, {}) or {}
                for cand in (names.get(sid), m.get("hostname"), sid):
                    if cand:
                        out.append(cand)
        # A malformed state entry must not block a deploy; log and return what we have.
        except Exception as e:  # noqa: BLE001
            logger.debug("deploy-spoke: known-spoke scan skipped: %s", e)
        return out

    # Clone a golden spoke template and start it so it onboards itself.
    @app.post("/api/pxmx/deploy-spoke")
    async def pxmx_deploy_spoke(request: Request):
        """One-click spoke deploy: clone a golden spoke template, auto-name it
        ``<prefix>-0N`` (next free, default prefix ``CS-SVR``), tag it for the
        acting tenant, and START it so it self-onboards. Body:
        ``{template_unique_id (or vmid+node), name?, number?, name_prefix?,
        pool?, start?}``. ``start`` defaults to true. Returns the clone result
        plus ``{deployed_name, spoke_id, started}`` (spoke_id is the id the box
        will self-register under: ``agent-<name lowercased>``). Admin/write-user,
        same gate as clone."""
        # Deploying a spoke needs edit rights.
        sess = _session_user(request)
        if not sess or not access.has_edit_access(sess):
            raise HTTPException(status_code=403, detail="Edit access required to deploy spokes")
        # Parse the JSON body; a bad or empty body becomes {} and fails validation below.
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body or {}

        # Identify the template, preferably by its "<cluster>/<node>/<vmid>" unique id.
        template_unique_id = str(body.get("template_unique_id", "")).strip()
        if not template_unique_id:
            vmid = body.get("vmid")
            node = str(body.get("node", "")).strip()
            if vmid is None or not node:
                raise HTTPException(status_code=400,
                                     detail="template_unique_id (or vmid+node) required")
            # Build a unique-id-shaped key with an unknown cluster so routing still finds the node.
            template_unique_id = f"unknown/{node}/{vmid}"

        # The default hypervisor spoke handles cloning (503 if none); note the acting tenant.
        hub = app.state.hub
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "Hypervisor")
        tid = _acting_tenant(request)

        # Resolve the tenant's labels for the new VM (display name + proxmox_tag),
        # identical to clone so the deployed spoke's backing VM is attributed to
        # the right tenant on the next VM sync.
        scoping = get_tenant_scoping(hub, tid) or {}
        tenant_tag = scoping.get("proxmox_tag") or ""
        tenant_name = ""
        # Look up the tenant's display name; a lookup error just leaves it blank.
        try:
            trec = hub.state.get_tenant(tid) or {}
            tenant_name = str(trec.get("name") or "").strip()
        except Exception:
            pass
        # Tag list: tenant name and proxmox_tag, skipping blanks.
        tenant_tags = [t for t in (tenant_name, tenant_tag) if t]

        # Determine the deploy name. Explicit name wins; else <prefix>-0N from an
        # explicit number or the next free one. Prefix normalized to the CS-SVR
        # convention (uppercase) so the guest hostname/spoke id read cleanly.
        prefix = str(body.get("name_prefix") or "CS-SVR").strip() or "CS-SVR"
        explicit_name = str(body.get("name", "")).strip()
        # A caller-supplied name is used as-is.
        if explicit_name:
            deployed_name = explicit_name
        else:
            # Otherwise use the caller's number, or find the next free number.
            num = body.get("number")
            if num is None:
                vms = await _list_all_pxmx_vms(hub, pxmx_spoke, tid)
                vm_names = [v.get("name") for v in vms if isinstance(v, dict)]
                num = _next_spoke_number(prefix, vm_names, _known_spoke_hostnames(hub))
            # The number must be an integer so it can be zero-padded.
            try:
                num = int(num)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="number must be an integer")
            # e.g. "CS-SVR-03".
            deployed_name = f"{prefix}-{num:02d}"

        # Template-pool guard (mirrors clone): only a VM in a configured template
        # pool may be deployed. Also capture its type/node from the cached list.
        template_pools = {p.lower() for p in access._template_pools(hub)}
        template_pool_ok = False
        vm_type = str(body.get("type", "")).strip().lower()
        pool = str(body.get("pool", "")).strip()
        # Any lookup error leaves the check failed, so the deploy is refused (fail closed).
        try:
            vms = await _list_all_pxmx_vms(hub, pxmx_spoke, tid)
            # Find the template in the VM list.
            for v in vms:
                if v.get("unique_id") == template_unique_id:
                    vpool = str(v.get("pool", "")).lower()
                    # Allowed when it is in a template pool, or when no template pools are
                    # configured.
                    if (vpool and vpool in template_pools) or not template_pools:
                        template_pool_ok = True
                    # Learn the VM type (qemu/lxc) from the list if the caller did not say.
                    if not vm_type:
                        vm_type = str(v.get("type", "")).lower()
                    break
        except Exception as e:  # noqa: BLE001
            logger.debug("deploy-spoke: template-pool guard lookup skipped: %s", e)
        # Template not found or not in a template pool: refuse.
        if not template_pool_ok:
            raise HTTPException(status_code=403,
                                 detail="template is not in a configured template pool")

        # Optional automatic VMID from the tenant's range when the feature is enabled.
        new_vmid = body.get("new_vmid")
        if not new_vmid and vmid_alloc.vmid_alloc_cfg(hub).get("enabled", False):
            # Allocation failure is not fatal: None lets Proxmox pick the next id.
            try:
                new_vmid = await vmid_alloc.allocate_vmid(hub, tid)
            except Exception as e:  # noqa: BLE001
                logger.debug("vmid-alloc (deploy) tenant=%s failed: %s", tid, e)
                new_vmid = None

        # Node from the unique id when it has one, else from the body.
        node = (template_unique_id.split("/")[1]
                if template_unique_id.count("/") >= 2 else str(body.get("node", "")))
        # Clone request, same shape as the plain clone route but with the generated name.
        clone_payload = {
            "unique_id": template_unique_id,
            "template_unique_id": template_unique_id,
            "name": deployed_name,
            "tenant_tags": tenant_tags,
            "pool": pool,
            "type": vm_type or "qemu",
            "node": node,
            "template_vmid": body.get("vmid"),
            "new_vmid": new_vmid,
        }
        # Relay the clone; 605s covers the agent's 600s window for full-disk clones.
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_CLONE_VM", clone_payload, timeout=605.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # A non-dict reply or an ERROR status means the clone failed: report 502 (bad upstream).
            if not isinstance(data, dict) or data.get("status") == "ERROR":
                msg = (data or {}).get("message", "clone failed") if isinstance(data, dict) else "clone failed"
                raise HTTPException(status_code=502, detail=msg)
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Anything else is logged and reported as 500.
        except Exception as e:  # noqa: BLE001
            logger.exception("pxmx_deploy_spoke clone failed")
            raise HTTPException(status_code=500, detail=str(e))

        # Start the clone so it boots, DHCPs, and self-onboards. Best-effort — a
        # start failure still leaves a correctly-named, tenant-tagged VM the
        # operator can boot by hand, so it degrades to the clone result + a note.
        # Track whether the start worked and why not, for the response.
        started = False
        start_error = None
        # Start unless the caller opted out, and only when the clone reported its new unique id.
        want_start = body.get("start", True)
        new_unique_id = data.get("unique_id")
        if want_start and new_unique_id:
            # Relay a start action for the new VM.
            try:
                sres = await hub.request_response(pxmx_spoke, "PXMX_VM_ACTION", {
                    "unique_id": new_unique_id,
                    "vmid": data.get("vmid"),
                    "node": data.get("node") or node,
                    "type": data.get("type") or vm_type or "qemu",
                    "action": "start",
                }, timeout=60.0)
                # Unwrap the reply; an ERROR status is recorded rather than raised.
                sdata = sres.get("payload", {}).get("data", sres) if isinstance(sres, dict) else sres
                if isinstance(sdata, dict) and sdata.get("status") == "ERROR":
                    start_error = sdata.get("message", "start failed")
                else:
                    started = True
            # A relay failure is also recorded; the clone itself already succeeded.
            except Exception as e:  # noqa: BLE001
                logger.warning("deploy-spoke: start of %s failed: %s", new_unique_id, e)
                start_error = str(e)

        # Refresh NetBox VM sync and the cached VM list so the new VM appears right away.
        _trigger_vm_sync_after_pxmx_edit(hub, request, body)
        _refresh_module_all_tenants(hub, "pxmx_vms")

        # Return the clone result plus the generated name, the spoke id the box will register as,
        # and whether it was started.
        out = dict(data)
        out["deployed_name"] = deployed_name
        out["spoke_id"] = "agent-" + deployed_name.lower()
        out["started"] = started
        # Include the start error only when there was one.
        if start_error:
            out["start_error"] = start_error
        return out
