"""Proxmox template-backup repository routes (hub-local storage).

Two surfaces:
  * ``/setup/templates*`` — Global-Admin management (list / trigger backup /
    edit metadata / delete). Auto admin-gated by ``access_control_middleware``
    (``/setup/*`` requires an admin session).
  * ``/api/templates/{id}/upload`` + ``/progress`` — the owning node's AGENT
    streams the vzdump archive here and reports progress. Agents have no browser
    session, so these are gated by the per-backup one-time ``_upload_token`` (the
    middleware exempts this exact shape) instead.

Flow: admin POSTs /setup/templates/backup → a pending record + token is created →
the hub relays START_BACKUP to the agent (via the owning spoke) with the upload
URL + token → the agent runs vzdump and PUT-streams the archive to the upload
endpoint → the hub writes it to disk, verifies size/sha256, and marks it complete.
"""
import hashlib
import os
import shutil
import time

from api import HTTPException, Request, logger

# Upper bound on a single stored template (guards a runaway/oversized upload).
_MAX_GB = float(os.environ.get("LM_TEMPLATE_MAX_GB", "300") or "300")
_MAX_BYTES = int(_MAX_GB * 1024 * 1024 * 1024)


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _repo():
        return hub.template_repo

    def _require_admin(request: Request):
        # /setup/* is already admin-gated by the middleware; this is defence in
        # depth + gives us the session for created_by.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin access required")
        return sess

    def _username(sess) -> str:
        if isinstance(sess, dict):
            return str(sess.get("username") or sess.get("user") or sess.get("sub") or "")
        return str(sess or "")

    # ── management (admin) ──────────────────────────────────────────────────
    @app.get("/setup/templates")
    async def list_templates(request: Request):
        _require_admin(request)
        return {"templates": _repo().list()}

    @app.get("/setup/templates/{tid}")
    async def get_template(tid: str, request: Request):
        _require_admin(request)
        rec = _repo().get(tid)
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")
        return rec

    @app.post("/setup/templates/backup")
    async def trigger_backup(request: Request):
        """Global Admin: back up a Proxmox template to the hub repo. Creates a
        pending record + one-time upload token and relays START_BACKUP to the
        owning node's agent with the hub upload URL."""
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        agent_id = str(body.get("agent_id") or "").strip()
        vmid = body.get("vmid")
        node = str(body.get("node") or "").strip()
        unique_id = str(body.get("unique_id") or "").strip()
        # Optional Proxmox storage target for vzdump (file-based only — the
        # WebUI filters out PBS). When set, the agent uses --storage <X> and
        # deletes the archive after streaming. Empty → legacy tempdir fallback.
        storage = str(body.get("storage") or "").strip()
        # The WebUI passes the VM's unique_id ("cluster/node/vmid"); derive vmid +
        # node from it when not given explicitly (mirrors the VM-action routes).
        if unique_id and "/" in unique_id:
            parts = unique_id.split("/")
            if len(parts) >= 3:
                node = node or parts[-2]
                if vmid is None:
                    try:
                        vmid = int(parts[-1])
                    except (TypeError, ValueError):
                        pass
        # Resolve the owning agent by node hostname (agent_info index) when the
        # caller didn't hand us an explicit agent_id.
        if not agent_id and node:
            for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
                if str((info or {}).get("hostname") or "").lower() == node.lower():
                    agent_id = aid
                    break
        name = str(body.get("name") or "").strip() or (f"vmid-{vmid}" if vmid is not None else "")
        if not agent_id or vmid is None:
            raise HTTPException(status_code=400,
                                detail="could not resolve the owning agent/vmid (need agent_id+vmid or a unique_id)")

        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="no connected spoke owns this agent")

        # Tenant is DRIVEN by the PXMX host, per host: prefer the agent's own
        # tenant binding (Agent Config → Client Simulation tenant_id), else the
        # owning spoke's tenant. Resolve a display name so the repo stays readable
        # even if the tenant is later renamed/removed.
        agent_cfg = (hub.state.system_state.get("agent_config", {}) or {}).get(agent_id, {})
        tenant_id = str((agent_cfg.get("client_simulation") or {}).get("tenant_id") or "").strip()
        if not tenant_id:
            try:
                tenant_id = str(hub.state.get_spoke_tenant(owning_spoke) or "").strip()
            except Exception:  # noqa: BLE001
                tenant_id = ""
        tenant_name = tenant_id
        if tenant_id:
            try:
                trec = hub.state.get_tenant(tenant_id) if hasattr(hub.state, "get_tenant") else None
                if trec:
                    tenant_name = trec.get("name") or tenant_id
            except Exception:  # noqa: BLE001
                pass

        rec = _repo().create_pending(
            name=name, source_vmid=vmid, source_node=node,
            source_agent=agent_id, source_spoke=owning_spoke,
            created_by=_username(sess), tenant=tenant_name, tenant_id=tenant_id)
        tid, token = rec["id"], rec["_upload_token"]

        # The agent streams straight to the hub's HTTPS endpoint. Prefer an
        # explicit public URL (browser-facing and agent-facing can differ);
        # otherwise use the URL the admin's browser reached us on.
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        upload_url = f"{base}/api/templates/{tid}/upload"

        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": agent_id,
                "command": "START_BACKUP",
                "data": {"template_id": tid, "vmid": vmid, "node": node,
                         "upload_url": upload_url, "upload_token": token,
                         "storage": storage},
            })
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            accepted = isinstance(data, dict) and data.get("status") in ("SUCCESS", "ACCEPTED")
            if not accepted:
                msg = (data.get("message") if isinstance(data, dict) else None) or "agent did not accept the backup"
                _repo().set_status(tid, "failed", error=msg)
                return {"status": "ERROR", "id": tid, "message": msg}
        except Exception as e:  # noqa: BLE001
            _repo().set_status(tid, "failed", error=f"relay failed: {e}")
            raise HTTPException(status_code=502, detail=f"START_BACKUP relay failed: {e}")

        logger.info("[template-repo] backup queued %s (vmid=%s agent=%s)", tid, vmid, agent_id)
        return {"status": "SUCCESS", "id": tid,
                "message": "Backup queued — the agent is running vzdump and will stream it to the hub."}

    @app.patch("/setup/templates/{tid}")
    async def edit_template(tid: str, request: Request):
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        rec = _repo().update_meta(tid, body if isinstance(body, dict) else {})
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")
        return {"status": "SUCCESS", "template": rec}

    @app.delete("/setup/templates/{tid}")
    async def delete_template(tid: str, request: Request):
        _require_admin(request)
        if not _repo().delete(tid):
            raise HTTPException(status_code=404, detail="template not found")
        logger.info("[template-repo] deleted %s", tid)
        return {"status": "SUCCESS"}

    # ── agent-facing upload (token-authed; middleware-exempt) ────────────────
    def _check_token(tid: str, request: Request):
        token = request.headers.get("x-upload-token") or request.query_params.get("token") or ""
        if not _repo().verify_token(tid, token):
            raise HTTPException(status_code=403, detail="invalid or consumed upload token")

    @app.put("/api/templates/{tid}/upload")
    async def upload_template(tid: str, request: Request):
        """Streamed upload of a vzdump archive from the owning agent. Writes the
        request body straight to disk in chunks (no full-file buffering), verifies
        the size cap + free space, and records size + sha256 on completion."""
        _check_token(tid, request)
        rec = _repo().get(tid, public=False)
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")

        # Size cap + free-space guard (best-effort — Content-Length may be absent).
        clen = request.headers.get("content-length")
        expected = int(clen) if (clen and clen.isdigit()) else 0
        if expected and expected > _MAX_BYTES:
            _repo().set_status(tid, "failed", error=f"too large ({expected} > {_MAX_BYTES} bytes)")
            raise HTTPException(status_code=413, detail=f"exceeds max {_MAX_GB} GB")
        path = _repo().image_path(tid)
        try:
            free = shutil.disk_usage(os.path.dirname(path)).free
            if expected and expected > free - (1 << 30):  # keep ~1 GiB headroom
                _repo().set_status(tid, "failed", error="insufficient disk space on hub")
                raise HTTPException(status_code=507, detail="insufficient disk space on hub")
        except HTTPException:
            raise
        except Exception:
            pass

        _repo().set_status(tid, "uploading", progress=0)
        h = hashlib.sha256()
        size = 0
        last_pct = -1
        try:
            with open(path, "wb") as f:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > _MAX_BYTES:
                        raise ValueError(f"exceeded max {_MAX_GB} GB mid-stream")
                    f.write(chunk)
                    h.update(chunk)
                    if expected:
                        pct = int(size * 100 / expected)
                        if pct != last_pct:
                            last_pct = pct
                            _repo().set_status(tid, "uploading", progress=pct)
        except Exception as e:  # noqa: BLE001
            _repo().set_status(tid, "failed", error=f"upload failed: {e}")
            try:
                os.remove(path)
            except OSError:
                pass
            raise HTTPException(status_code=500, detail=f"upload failed: {e}")

        digest = h.hexdigest()
        _repo().finalize(tid, size=size, sha256=digest)
        logger.info("[template-repo] upload complete %s (%d bytes, sha256=%s)", tid, size, digest[:12])
        return {"status": "SUCCESS", "id": tid, "size": size, "sha256": digest}

    @app.post("/api/templates/{tid}/progress")
    async def backup_progress(tid: str, request: Request):
        """Agent-reported progress during the vzdump phase (before the upload
        stream begins) — token-authed, so the WebUI can show 'dumping… N%'."""
        _check_token(tid, request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        status = str(body.get("status") or "uploading")
        if status not in ("pending", "dumping", "uploading", "failed"):
            status = "uploading"
        _repo().set_status(tid, status, progress=body.get("progress"),
                           error=str(body.get("error") or ""))
        return {"status": "SUCCESS"}

    # ── refresh (restore a stored template onto its host) ────────────────────
    # Destructive orchestration: pause auto-prov → delete the host's sim VMs +
    # the template → download this backup → qmrestore to the original VMID +
    # re-mark as a template → resume auto-prov. The agent does the sequence
    # (REFRESH_TEMPLATE); the hub just authorizes + relays.
    def _acting_tenants(sess):
        return (sess or {}).get("user", {}).get("tenants") or []

    def _owns_tenant(sess, tenant_id):
        # Global Admin → any; tenant-admin → only their assigned tenants.
        if _is_admin(sess):
            return True
        return bool(tenant_id) and tenant_id in _acting_tenants(sess)

    async def _orchestrate_refresh(tid, request, target_agent_id=None, target_vmid=None):
        """Queue a REFRESH_TEMPLATE on the owning agent. By default this is a
        self-restore — the backup goes back to its own ``source_agent`` at the
        original ``source_vmid`` (used by the per-template Refresh buttons on the
        Template Repo page). The fleet seed-distribute path passes an explicit
        ``target_agent_id`` + ``target_vmid`` so the seed backup is restored onto
        a DIFFERENT host at that host's VMID (the agent restores to whatever
        ``template_vmid`` it is given)."""
        rec = _repo().get(tid, public=False)
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")
        if rec.get("status") != "complete":
            raise HTTPException(status_code=409, detail="template backup is not complete")
        agent_id = str(target_agent_id or rec.get("source_agent") or "")
        if not agent_id:
            raise HTTPException(status_code=409, detail="template has no recorded source host")
        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="the target host's spoke is not connected")

        # The VMID to restore onto on the target host. For self-restore this is
        # the backup's source_vmid; for seed-distribute it is the target host's
        # own template VMID (the qmrestore --force destination).
        template_vmid = target_vmid if target_vmid is not None else rec.get("source_vmid")

        dl_token = _repo().mint_refresh_token(tid)
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        download_url = f"{base}/api/templates/{tid}/download"
        _repo().set_refresh_status(tid, "pending", step="queued")
        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": agent_id,
                "command": "REFRESH_TEMPLATE",
                "data": {"template_id": tid, "template_vmid": template_vmid,
                         "download_url": download_url, "refresh_token": dl_token},
            })
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            if not (isinstance(data, dict) and data.get("status") in ("SUCCESS", "ACCEPTED")):
                msg = (data.get("message") if isinstance(data, dict) else None) or "agent did not accept the refresh"
                _repo().set_refresh_status(tid, "failed", error=msg)
                return {"status": "ERROR", "message": msg}
        except Exception as e:  # noqa: BLE001
            _repo().set_refresh_status(tid, "failed", error=f"relay failed: {e}")
            raise HTTPException(status_code=502, detail=f"REFRESH_TEMPLATE relay failed: {e}")
        logger.info("[template-repo] refresh queued %s → agent %s (vmid %s)",
                    tid, agent_id, template_vmid)
        return {"status": "SUCCESS",
                "message": "Refresh queued — pausing auto-provisioning, clearing the host's sim VMs + template, restoring the backup, then resuming auto-provisioning."}

    @app.post("/setup/templates/{tid}/refresh")
    async def refresh_template_admin(tid: str, request: Request):
        _require_admin(request)
        return await _orchestrate_refresh(tid, request)

    @app.get("/tenant/templates")
    async def list_templates_tenant(request: Request):
        # /tenant/* is gated to tenant-admin + admin by the middleware. Admin sees
        # all; a tenant-admin sees only templates whose derived tenant is theirs.
        sess = _session_user(request)
        allt = _repo().list()
        if _is_admin(sess):
            return {"templates": allt}
        mine = set(_acting_tenants(sess))
        return {"templates": [t for t in allt if (t.get("tenant_id") or "") in mine]}

    @app.post("/tenant/templates/{tid}/refresh")
    async def refresh_template_tenant(tid: str, request: Request):
        sess = _session_user(request)
        rec = _repo().get(tid)  # public view (no tokens)
        # Anti-IDOR: a template the caller can't own reads as not-found.
        if rec is None or not _owns_tenant(sess, rec.get("tenant_id")):
            raise HTTPException(status_code=404, detail="template not found")
        return await _orchestrate_refresh(tid, request)

    def _resolve_target_agent(host_id):
        """Reverse-lookup ``hub.agent_info`` for the connected agent whose
        hostname matches ``host_id`` (case-insensitive, short-name tolerant —
        same shape as ``template_repo.latest_complete_for_host``). Returns the
        ``agent_id`` (key into agent_info / agent_config) or None. The fleet rows
        key on the agent's reported OS hostname, which can differ from the
        Proxmox cluster node name recorded on a backup — so we resolve via the
        live agent index, not the backup's source_node."""
        hid = str(host_id or "").strip()
        if not hid:
            return None
        hid_l = hid.lower()
        hid_short = hid_l.split(".", 1)[0]

        def _match(val):
            v = str(val or "").strip().lower()
            if not v:
                return False
            return v == hid_l or v.split(".", 1)[0] == hid_short

        for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
            info = info or {}
            if _match(info.get("hostname")) and info.get("spoke_id") in hub.active_connections:
                return aid
        return None

    def _host_template_vmid(agent_id):
        """The host's configured clone-source template VMID (``image1_template_id``
        — a number), from ``agent_config[agent_id].client_simulation.usb_config``.
        This is the default qmrestore destination when the caller does not pass an
        explicit ``target_vmid``. Returns an int or None."""
        ac = (getattr(hub, "state", None) and hub.state.system_state.get("agent_config", {}) or {}) \
            .get(agent_id, {})
        usb = (ac.get("client_simulation") or {}).get("usb_config") or {}
        v = usb.get("image1_template_id")
        try:
            return int(v) if v is not None and str(v).strip() != "" else None
        except (TypeError, ValueError):
            return None

    def _agent_tenant_id(agent_id):
        ac = (getattr(hub, "state", None) and hub.state.system_state.get("agent_config", {}) or {}) \
            .get(agent_id, {})
        return str((ac.get("client_simulation") or {}).get("tenant_id") or "").strip()

    @app.post("/tenant/templates/refresh-hosts")
    async def refresh_templates_by_host(request: Request):
        """Fleet multi-select refresh (VM Server / VMs) — SEED-AND-DISTRIBUTE.

        One PXMX host is the seed: its template is prepped + backed up to the hub
        (Template Repo). The operator selects the OTHER target hosts here and
        this endpoint pushes that seed backup onto each target: pause auto-prov →
        wipe the target's sim VMs + template → qmrestore the seed backup onto the
        target at the target's VMID → re-mark template → resume auto-prov.

        Body:
          * ``host_ids: [...]`` — target hosts (agent OS hostname; unique per
            host). ``{spoke_ids: [...]}`` still accepted for older clients (the
            host is resolved per the spoke's owning agent).
          * ``template_id`` (opt) — the seed backup to distribute. Default: the
            newest COMPLETE template in a tenant the caller owns.
          * ``target_vmid`` (opt int) — override the restore VMID on every
            target. Default: each target host's configured ``image1_template_id``.

        Tenant isolation: the seed backup AND every target host must be in a
        tenant the caller owns (admin = any). Anti-IDOR: an un-ownable seed
        reads as not-found; an un-ownable target is SKIPPED (not revealed)."""
        sess = _session_user(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        host_ids = body.get("host_ids") or []
        by_host = bool(host_ids)
        ids = host_ids if by_host else (body.get("spoke_ids") or [])
        if not isinstance(ids, list) or not ids:
            raise HTTPException(status_code=400, detail="host_ids (non-empty list) required")

        # ── resolve the seed backup ──────────────────────────────────────────
        template_id = str(body.get("template_id") or "").strip()
        if template_id:
            rec = _repo().get(template_id, public=False)
            if rec is None:
                raise HTTPException(status_code=404, detail="template not found")
        else:
            # Default: newest COMPLETE template in a tenant the caller owns.
            mine = set(_acting_tenants(sess))
            cands = [t for t in _repo().list()
                     if t.get("status") == "complete"
                     and (_is_admin(sess) or (t.get("tenant_id") or "") in mine)]
            if not cands:
                raise HTTPException(status_code=404,
                                     detail="no completed template backup in your tenant — "
                                            "back one up first (Setup → Hypervisors → ⬆ Back up to Hub)")
            rec = dict(cands[0])  # list() is sorted newest-first
            template_id = rec["id"]
        if rec.get("status") != "complete":
            raise HTTPException(status_code=409, detail="template backup is not complete")
        if not _owns_tenant(sess, rec.get("tenant_id")):
            # Anti-IDOR: a seed the caller can't own reads as not-found.
            raise HTTPException(status_code=404, detail="template not found")

        # ── target VMID override ─────────────────────────────────────────────
        target_vmid = body.get("target_vmid")
        if target_vmid is not None and str(target_vmid).strip() != "":
            try:
                target_vmid = int(target_vmid)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="target_vmid must be an integer")
            if target_vmid <= 0:
                raise HTTPException(status_code=400, detail="target_vmid must be a positive integer")
        else:
            target_vmid = None

        results = []
        for sid in ids:
            sid = str(sid or "")
            # Resolve the target host → its owning agent (live agent index).
            agent_id = _resolve_target_agent(sid) if by_host else None
            if by_host and agent_id is None:
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": f"host '{sid}' not connected / no owning agent"})
                continue
            if not by_host:
                # Legacy spoke_ids path: resolve via the spoke's owning agent.
                # Pick any agent indexed under this spoke.
                agent_id = None
                for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
                    if (info or {}).get("spoke_id") == sid and aid:
                        agent_id = aid
                        break
                if agent_id is None:
                    results.append({"spoke_id": sid, "status": "SKIPPED",
                                    "message": "no agent connected for this spoke"})
                    continue

            # Tenant-own the target host (anti-IDOR / tenant isolation).
            host_tenant = _agent_tenant_id(agent_id)
            if not _owns_tenant(sess, host_tenant):
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": "not permitted for this host's tenant"})
                continue

            # Resolve the restore VMID: override → host's image1_template_id.
            vmid = target_vmid if target_vmid is not None else _host_template_vmid(agent_id)
            if vmid is None:
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": "no target VMID for this host — pass target_vmid or "
                                            "configure the host's VM Image 1 Template VMID"})
                continue

            try:
                r = await _orchestrate_refresh(template_id, request,
                                               target_agent_id=agent_id, target_vmid=vmid)
                results.append({"spoke_id": sid, "host": sid, "template_id": template_id,
                                "name": rec.get("name"), "target_vmid": vmid,
                                "status": r.get("status"), "message": r.get("message")})
            except HTTPException as e:
                results.append({"spoke_id": sid, "host": sid, "template_id": template_id,
                                "target_vmid": vmid,
                                "status": "ERROR", "message": str(e.detail)})
        ok = sum(1 for r in results if r.get("status") == "SUCCESS")
        return {"status": "SUCCESS" if ok else "ERROR",
                "refreshed": ok, "total": len(results), "results": results}

    # ── agent-facing download + refresh progress (token-authed) ──────────────
    def _check_refresh_token(tid: str, request: Request):
        token = request.headers.get("x-refresh-token") or request.query_params.get("token") or ""
        if not _repo().verify_refresh_token(tid, token):
            raise HTTPException(status_code=403, detail="invalid refresh token")

    def _refresh_hosts_registry():
        """In-memory per-host refresh state, keyed ``"<tid>|<agent_id>"``. The
        agent's progress posts carry host/agent_id/vmid/bytes/total so the fleet
        UI can show WHICH host is at WHICH step (+ download progress) instead of
        the single template-scoped ``refresh_status`` shared across concurrent
        target hosts. Lost on hub restart (refreshes are short-lived)."""
        if not getattr(hub, "template_refresh_hosts", None):
            hub.template_refresh_hosts = {}
        return hub.template_refresh_hosts

    @app.get("/api/templates/{tid}/download")
    async def download_template(tid: str, request: Request):
        """Stream a stored archive to the target agent during a refresh
        (refresh-token-authed; middleware-exempt)."""
        from fastapi.responses import FileResponse
        _check_refresh_token(tid, request)
        rec = _repo().get(tid, public=False)
        if rec is None or rec.get("status") != "complete":
            raise HTTPException(status_code=404, detail="template not found or incomplete")
        path = _repo().image_path(tid)
        if not os.path.isfile(path):
            raise HTTPException(status_code=404, detail="archive missing on disk")
        return FileResponse(path, media_type="application/octet-stream",
                            filename=rec.get("filename") or "image.vma.zst")

    @app.post("/api/templates/{tid}/refresh-progress")
    async def refresh_progress(tid: str, request: Request):
        _check_refresh_token(tid, request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        status = str(body.get("status") or "restoring")
        step = str(body.get("step") or "")
        error = str(body.get("error") or "")
        _repo().set_refresh_status(tid, status, step=step, error=error)
        # Per-host registry: the agent sends host/agent_id/vmid/bytes/total so the
        # fleet UI shows which host is at which step (+ download progress).
        agent_id = str(body.get("agent_id") or "")
        host = str(body.get("host") or "")
        key_agent = agent_id or host
        if key_agent:
            reg = _refresh_hosts_registry()
            key = f"{tid}|{key_agent}"
            reg[key] = {
                "tid": tid, "agent_id": agent_id, "host": host,
                "vmid": body.get("vmid"), "status": status, "step": step,
                "error": error, "bytes": body.get("bytes"),
                "total": body.get("total"),
                "tenant_id": (_agent_tenant_id(agent_id) if agent_id else ""),
                "updated_at": time.time(),
            }
        return {"status": "SUCCESS"}

    @app.get("/tenant/templates/refresh-status")
    async def refresh_status(request: Request):
        """Live per-host template-refresh state for the VM Server status chip.
        Returns entries updated within the last 10 min (terminal complete/failed
        states linger briefly so the UI can show the outcome before they clear).
        Tenant-admin sees only their tenants; admin sees all."""
        sess = _session_user(request)
        reg = _refresh_hosts_registry()
        now = time.time()
        # Prune stale entries (>10 min) so the registry can't grow unbounded.
        for k in [k for k, v in reg.items() if now - (v.get("updated_at") or 0) > 600]:
            reg.pop(k, None)
        entries = list(reg.values())
        if not _is_admin(sess):
            mine = set(_acting_tenants(sess))
            entries = [e for e in entries if (e.get("tenant_id") or "") in mine]
        entries.sort(key=lambda e: e.get("updated_at") or 0, reverse=True)
        return {"hosts": entries}
