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

    async def _orchestrate_refresh(tid: str, request: Request):
        rec = _repo().get(tid, public=False)
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")
        if rec.get("status") != "complete":
            raise HTTPException(status_code=409, detail="template backup is not complete")
        agent_id = str(rec.get("source_agent") or "")
        if not agent_id:
            raise HTTPException(status_code=409, detail="template has no recorded source host")
        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="the source host's spoke is not connected")

        dl_token = _repo().mint_refresh_token(tid)
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        download_url = f"{base}/api/templates/{tid}/download"
        _repo().set_refresh_status(tid, "pending", step="queued")
        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": agent_id,
                "command": "REFRESH_TEMPLATE",
                "data": {"template_id": tid, "template_vmid": rec.get("source_vmid"),
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
                    tid, agent_id, rec.get("source_vmid"))
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

    @app.post("/tenant/templates/refresh-hosts")
    async def refresh_templates_by_host(request: Request):
        """Fleet multi-select refresh (VM Server / VMs): refresh the template on
        each selected PXMX host. Body: ``{spoke_ids: [...]}``. For each host we
        resolve its latest complete template (by source_spoke), enforce tenant
        ownership, and orchestrate the destructive refresh. Returns a per-host
        result so the UI can toast successes + skips."""
        sess = _session_user(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        spoke_ids = body.get("spoke_ids") or []
        if not isinstance(spoke_ids, list) or not spoke_ids:
            raise HTTPException(status_code=400, detail="spoke_ids (non-empty list) required")
        results = []
        for sid in spoke_ids:
            sid = str(sid or "")
            rec = _repo().latest_complete_for_spoke(sid)
            if rec is None:
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": "no completed template backup for this host"})
                continue
            if not _owns_tenant(sess, rec.get("tenant_id")):
                # Anti-IDOR: don't reveal a template the caller can't own.
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": "not permitted for this host's tenant"})
                continue
            try:
                r = await _orchestrate_refresh(rec["id"], request)
                results.append({"spoke_id": sid, "template_id": rec["id"],
                                "name": rec.get("name"),
                                "status": r.get("status"), "message": r.get("message")})
            except HTTPException as e:
                results.append({"spoke_id": sid, "template_id": rec.get("id"),
                                "status": "ERROR", "message": str(e.detail)})
        ok = sum(1 for r in results if r.get("status") == "SUCCESS")
        return {"status": "SUCCESS" if ok else "ERROR",
                "refreshed": ok, "total": len(results), "results": results}

    # ── agent-facing download + refresh progress (token-authed) ──────────────
    def _check_refresh_token(tid: str, request: Request):
        token = request.headers.get("x-refresh-token") or request.query_params.get("token") or ""
        if not _repo().verify_refresh_token(tid, token):
            raise HTTPException(status_code=403, detail="invalid refresh token")

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
        _repo().set_refresh_status(tid, status, step=str(body.get("step") or ""),
                                   error=str(body.get("error") or ""))
        return {"status": "SUCCESS"}
