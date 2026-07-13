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
        name = str(body.get("name") or "").strip() or (f"vmid-{vmid}" if vmid is not None else "")
        if not agent_id or vmid is None:
            raise HTTPException(status_code=400, detail="agent_id and vmid are required")

        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="no connected spoke owns this agent")

        rec = _repo().create_pending(
            name=name, source_vmid=vmid, source_node=node,
            source_agent=agent_id, source_spoke=owning_spoke,
            created_by=_username(sess))
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
                         "upload_url": upload_url, "upload_token": token},
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
