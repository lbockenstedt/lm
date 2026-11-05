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
# hashlib computes the sha256 checksum of uploaded archives.
import hashlib
# os reads env vars and builds/removes archive file paths.
import os
# re validates user-supplied names (e.g. storage ids) against safe patterns.
import re
# shutil checks free disk space before accepting an upload.
import shutil
# time stamps records and timeouts.
import time

# FastAPI request/error types plus the hub-wide logger, re-exported by the api module.
from api import HTTPException, Request, logger

# Upper bound on a single stored template (guards a runaway/oversized upload).
# Maximum template size in GB (default 300, overridable via LM_TEMPLATE_MAX_GB), and the
# same limit in bytes for the upload checks.
_MAX_GB = float(os.environ.get("LM_TEMPLATE_MAX_GB", "300") or "300")
_MAX_BYTES = int(_MAX_GB * 1024 * 1024 * 1024)


def register(app, hub, ctx):
    """Register the template-backup repository routes on the Hub app.

    Args: app is the FastAPI app, hub is the running hub (owns ``template_repo``), ctx carries
    shared auth helpers.
    """
    # Pull the session and admin-check helpers off the shared context once for all routes.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _repo():
        """Return the hub's template repository (looked up each call so a re-created repo is used).
        """
        return hub.template_repo

    def _require_admin(request: Request):
        """Raise 403 unless a Global Admin is logged in; return the session."""
        # /setup/* is already admin-gated by the middleware; this is defence in
        # depth + gives us the session for created_by.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin access required")
        return sess

    def _username(sess) -> str:
        """Return a printable username from a session dict (or the value itself as a string)."""
        # Session dicts may store the name under different keys; use the first one set.
        if isinstance(sess, dict):
            return str(sess.get("username") or sess.get("user") or sess.get("sub") or "")
        return str(sess or "")

    # ── management (admin) ──────────────────────────────────────────────────
    # List stored templates.
    @app.get("/setup/templates")
    async def list_templates(request: Request):
        """Return every template record in the repository (admin only)."""
        # Admin only; then return the list.
        _require_admin(request)
        return {"templates": _repo().list()}

    # Read one template record.
    @app.get("/setup/templates/{tid}")
    async def get_template(tid: str, request: Request):
        """Return template ``tid`` (admin only), 404 if it does not exist."""
        # Admin only; then look up the record.
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
        # Admin only; keep the session to record who started the backup.
        sess = _require_admin(request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Read the backup target: agent, vmid, node and unique id.
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
            # A full "cluster/node/vmid" id: take the node and (if it parses) the vmid from it.
            if len(parts) >= 3:
                node = node or parts[-2]
                if vmid is None:
                    # A non-numeric vmid is left unset and rejected below.
                    try:
                        vmid = int(parts[-1])
                    except (TypeError, ValueError):
                        pass
        # Resolve the owning agent by node hostname (agent_info index) when the
        # caller didn't hand us an explicit agent_id.
        if not agent_id and node:
            # Use the first agent whose reported hostname matches the node.
            for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
                if str((info or {}).get("hostname") or "").lower() == node.lower():
                    agent_id = aid
                    break
        # Template name from the body, else "vmid-<n>".
        name = str(body.get("name") or "").strip() or (f"vmid-{vmid}" if vmid is not None else "")
        # Without both an agent and a vmid there is nothing to back up.
        if not agent_id or vmid is None:
            raise HTTPException(status_code=400,
                                detail="could not resolve the owning agent/vmid (need agent_id+vmid or a unique_id)")

        # Spoke that relays to the agent: its own spoke, else the default hypervisor spoke.
        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        # No connected spoke means the agent cannot be reached.
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="no connected spoke owns this agent")

        # Tenant is DRIVEN by the PXMX host, per host: prefer the agent's own
        # tenant binding (Agent Config → Client Simulation tenant_id), else the
        # owning spoke's tenant. Resolve a display name so the repo stays readable
        # even if the tenant is later renamed/removed.
        # The agent's stored config, keyed by its primary key.
        agent_cfg = (hub.state.system_state.get("agent_config", {}) or {}).get(
            hub._agent_primary_key(agent_id), {})
        tenant_id = str((agent_cfg.get("client_simulation") or {}).get("tenant_id") or "").strip()
        # No agent tenant: fall back to the owning spoke's tenant (none on error).
        if not tenant_id:
            try:
                tenant_id = str(hub.state.get_spoke_tenant(owning_spoke) or "").strip()
            except Exception:  # noqa: BLE001
                tenant_id = ""
        # Show the tenant's display name when it can be looked up; otherwise the id.
        tenant_name = tenant_id
        if tenant_id:
            try:
                trec = hub.state.get_tenant(tenant_id) if hasattr(hub.state, "get_tenant") else None
                if trec:
                    tenant_name = trec.get("name") or tenant_id
            except Exception:  # noqa: BLE001
                pass

        # Create a pending record; this also generates the one-time upload token.
        rec = _repo().create_pending(
            name=name, source_vmid=vmid, source_node=node,
            source_agent=hub._agent_relay_name(agent_id), source_spoke=owning_spoke,
            created_by=_username(sess), tenant=tenant_name, tenant_id=tenant_id)
        tid, token = rec["id"], rec["_upload_token"]

        # The agent streams straight to the hub's HTTPS endpoint. Prefer an
        # explicit public URL (browser-facing and agent-facing can differ);
        # otherwise use the URL the admin's browser reached us on.
        # Base URL the agent should upload to; the env override wins over the browser URL.
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        upload_url = f"{base}/api/templates/{tid}/upload"

        # Ask the agent (via its spoke) to start vzdump and stream the archive back.
        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": hub._agent_relay_name(agent_id),
                "command": "START_BACKUP",
                "data": {"template_id": tid, "vmid": vmid, "node": node,
                         "upload_url": upload_url, "upload_token": token,
                         "storage": storage},
            })
            # Unwrap the reply; SUCCESS or ACCEPTED means the agent took the job.
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            accepted = isinstance(data, dict) and data.get("status") in ("SUCCESS", "ACCEPTED")
            # Rejected: mark the record failed and tell the UI why.
            if not accepted:
                msg = (data.get("message") if isinstance(data, dict) else None) or "agent did not accept the backup"
                _repo().set_status(tid, "failed", error=msg)
                return {"status": "ERROR", "id": tid, "message": msg}
        # Relay error: mark the record failed and report 502 (bad upstream).
        except Exception as e:  # noqa: BLE001
            _repo().set_status(tid, "failed", error=f"relay failed: {e}")
            raise HTTPException(status_code=502, detail=f"START_BACKUP relay failed: {e}")

        # Log and confirm the backup is queued.
        logger.info("[template-repo] backup queued %s (vmid=%s agent=%s)", tid, vmid, agent_id)
        return {"status": "SUCCESS", "id": tid,
                "message": "Backup queued — the agent is running vzdump and will stream it to the hub."}

    # Edit a template's metadata.
    @app.patch("/setup/templates/{tid}")
    async def edit_template(tid: str, request: Request):
        """Update template ``tid``'s editable metadata from the JSON body (admin only)."""
        # Admin only.
        _require_admin(request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Apply the metadata changes; None means the template does not exist.
        rec = _repo().update_meta(tid, body if isinstance(body, dict) else {})
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")
        return {"status": "SUCCESS", "template": rec}

    # Delete a stored template.
    @app.delete("/setup/templates/{tid}")
    async def delete_template(tid: str, request: Request):
        """Delete template ``tid`` and its archive (admin only)."""
        # Admin only; delete returns False when the id is unknown.
        _require_admin(request)
        if not _repo().delete(tid):
            raise HTTPException(status_code=404, detail="template not found")
        # Log and confirm.
        logger.info("[template-repo] deleted %s", tid)
        return {"status": "SUCCESS"}

    # ── agent-facing upload (token-authed; middleware-exempt) ────────────────
    def _check_token(tid: str, request: Request):
        """Raise 403 unless the request carries the valid one-time upload token for ``tid``."""
        # Token from the X-Upload-Token header, else the ?token= query value.
        token = request.headers.get("x-upload-token") or request.query_params.get("token") or ""
        # The repository checks the token matches this template and is still valid.
        if not _repo().verify_token(tid, token):
            raise HTTPException(status_code=403, detail="invalid or consumed upload token")

    # Agent streams the backup archive here.
    @app.put("/api/templates/{tid}/upload")
    async def upload_template(tid: str, request: Request):
        """Streamed upload of a vzdump archive from the owning agent. Writes the
        request body straight to disk in chunks (no full-file buffering), verifies
        the size cap + free space, and records size + sha256 on completion."""
        # Check the token, then load the full record (including private fields).
        _check_token(tid, request)
        rec = _repo().get(tid, public=False)
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")

        # Size cap + free-space guard (best-effort — Content-Length may be absent).
        # Declared upload size, if the agent sent Content-Length (0 when unknown).
        clen = request.headers.get("content-length")
        expected = int(clen) if (clen and clen.isdigit()) else 0
        # Reject an upload that declares itself over the size cap.
        if expected and expected > _MAX_BYTES:
            _repo().set_status(tid, "failed", error=f"too large ({expected} > {_MAX_BYTES} bytes)")
            raise HTTPException(status_code=413, detail=f"exceeds max {_MAX_GB} GB")
        # Where the archive will be written.
        path = _repo().image_path(tid)
        # Check free space; errors in the check itself are ignored (best-effort).
        try:
            free = shutil.disk_usage(os.path.dirname(path)).free
            if expected and expected > free - (1 << 30):  # keep ~1 GiB headroom
                _repo().set_status(tid, "failed", error="insufficient disk space on hub")
                raise HTTPException(status_code=507, detail="insufficient disk space on hub")
        # Re-raise our own 507 unchanged.
        except HTTPException:
            raise
        # Any other error from the space check is ignored.
        except Exception:
            pass

        # Mark the upload started and set up the checksum, byte count and last reported percent.
        _repo().set_status(tid, "uploading", progress=0)
        h = hashlib.sha256()
        size = 0
        last_pct = -1
        # Any write or size failure below marks the record failed and deletes the partial file.
        try:
            # Write each chunk to disk as it arrives, never holding the whole archive in memory.
            with open(path, "wb") as f:
                async for chunk in request.stream():
                    # Skip empty keep-alive chunks.
                    if not chunk:
                        continue
                    # Count bytes and stop if the real size passes the cap, even if Content-Length
                    # lied.
                    size += len(chunk)
                    if size > _MAX_BYTES:
                        raise ValueError(f"exceeded max {_MAX_GB} GB mid-stream")
                    # Save the chunk and add it to the checksum.
                    f.write(chunk)
                    h.update(chunk)
                    # Report progress only when the percentage changes, to limit status writes.
                    if expected:
                        pct = int(size * 100 / expected)
                        if pct != last_pct:
                            last_pct = pct
                            _repo().set_status(tid, "uploading", progress=pct)
        # Mark failed, delete the partial file (it may not exist), and report 500.
        except Exception as e:  # noqa: BLE001
            _repo().set_status(tid, "failed", error=f"upload failed: {e}")
            try:
                os.remove(path)
            except OSError:
                pass
            raise HTTPException(status_code=500, detail=f"upload failed: {e}")

        # Finish: record size and checksum on the template, log, and return them.
        digest = h.hexdigest()
        _repo().finalize(tid, size=size, sha256=digest)
        logger.info("[template-repo] upload complete %s (%d bytes, sha256=%s)", tid, size, digest[:12])
        return {"status": "SUCCESS", "id": tid, "size": size, "sha256": digest}

    # Agent reports dump progress before the upload starts.
    @app.post("/api/templates/{tid}/progress")
    async def backup_progress(tid: str, request: Request):
        """Agent-reported progress during the vzdump phase (before the upload
        stream begins) — token-authed, so the WebUI can show 'dumping… N%'."""
        # Check the upload token.
        _check_token(tid, request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Accept only known status values; anything else is treated as "uploading".
        status = str(body.get("status") or "uploading")
        if status not in ("pending", "dumping", "uploading", "failed"):
            status = "uploading"
        # Save the status, progress and any error text.
        _repo().set_status(tid, status, progress=body.get("progress"),
                           error=str(body.get("error") or ""))
        return {"status": "SUCCESS"}

    # ── refresh (restore a stored template onto its host) ────────────────────
    # Destructive orchestration: pause auto-prov → delete the host's sim VMs +
    # the template → download this backup → qmrestore to the original VMID +
    # re-mark as a template → resume auto-prov. The agent does the sequence
    # (REFRESH_TEMPLATE); the hub just authorizes + relays.
    def _acting_tenants(sess):
        """Return the tenant ids assigned to the session's user ([] if none)."""
        return (sess or {}).get("user", {}).get("tenants") or []

    def _owns_tenant(sess, tenant_id):
        """Return True if the caller may act on resources of ``tenant_id``."""
        # Global Admin → any; tenant-admin → only their assigned tenants.
        # Global Admins own every tenant.
        if _is_admin(sess):
            return True
        # Others own only their assigned tenants; a blank tenant is owned by nobody.
        return bool(tenant_id) and tenant_id in _acting_tenants(sess)

    def _clean_storage(raw):
        """Validate + normalise an optional destination-storage id from a request
        body. Blank/None → None (keep the backup's recorded storage). A Proxmox
        storage id is ``[A-Za-z0-9._-]`` only; reject anything else so a bogus
        value can't reach ``qmrestore --storage``."""
        # Blank means "keep the backup's recorded storage".
        s = str(raw or "").strip()
        if not s:
            return None
        # Allow only characters valid in a Proxmox storage id.
        if not re.fullmatch(r"[A-Za-z0-9._-]+", s):
            raise HTTPException(status_code=400,
                                detail="target_storage must be a valid Proxmox storage id")
        return s

    async def _body_storage(request):
        """Optional ``target_storage`` from a JSON body (endpoints that used to
        take no body still work — a missing/blank value yields None)."""
        # Parse the body; endpoints may be called with no body at all.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Validate the optional target_storage field.
        return _clean_storage((body or {}).get("target_storage"))

    async def _orchestrate_refresh(tid, request, target_agent_id=None, target_vmid=None,
                                   target_storage=None):
        """Queue a REFRESH_TEMPLATE on the owning agent. By default this is a
        self-restore — the backup goes back to its own ``source_agent`` at the
        original ``source_vmid`` (used by the per-template Refresh buttons on the
        Template Repo page). The fleet seed-distribute path passes an explicit
        ``target_agent_id`` + ``target_vmid`` so the seed backup is restored onto
        a DIFFERENT host at that host's VMID (the agent restores to whatever
        ``template_vmid`` it is given).

        ``target_storage`` (opt) is the Proxmox storage id the restored disks land
        on (``qmrestore --storage``). Blank keeps the backup's recorded storage —
        needed when a seed backed up from a host whose storage id does not exist
        on the target, which otherwise made the restore fail."""
        # Load the full record; it must exist and have a finished backup.
        rec = _repo().get(tid, public=False)
        if rec is None:
            raise HTTPException(status_code=404, detail="template not found")
        if rec.get("status") != "complete":
            raise HTTPException(status_code=409, detail="template backup is not complete")
        # Restore target: the explicit agent, else the host the backup came from.
        agent_id = str(target_agent_id or rec.get("source_agent") or "")
        if not agent_id:
            raise HTTPException(status_code=409, detail="template has no recorded source host")
        # Spoke that relays to that agent: its own spoke, else the default hypervisor spoke.
        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="the target host's spoke is not connected")

        # The VMID to restore onto on the target host. For self-restore this is
        # the backup's source_vmid; for seed-distribute it is the target host's
        # own template VMID (the qmrestore --force destination).
        template_vmid = target_vmid if target_vmid is not None else rec.get("source_vmid")

        # One-time token the agent uses to download the archive, plus the download URL.
        dl_token = _repo().mint_refresh_token(tid)
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        download_url = f"{base}/api/templates/{tid}/download"
        # Mark the refresh queued so the UI shows progress straight away.
        _repo().set_refresh_status(tid, "pending", step="queued")
        # Instructions for the agent's REFRESH_TEMPLATE handler.
        refresh_data = {"template_id": tid, "template_vmid": template_vmid,
                        "download_url": download_url, "refresh_token": dl_token,
                        "archive_name": rec.get("filename") or ""}
        # Only send a storage override when one was given.
        if target_storage:
            refresh_data["storage"] = target_storage
        # Ask the agent (via its spoke) to run the refresh.
        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": hub._agent_relay_name(agent_id),
                "command": "REFRESH_TEMPLATE",
                "data": refresh_data,
            })
            # Unwrap the reply; SUCCESS or ACCEPTED means the agent took the job.
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            if not (isinstance(data, dict) and data.get("status") in ("SUCCESS", "ACCEPTED")):
                # Rejected: mark the refresh failed and tell the UI why.
                msg = (data.get("message") if isinstance(data, dict) else None) or "agent did not accept the refresh"
                _repo().set_refresh_status(tid, "failed", error=msg)
                return {"status": "ERROR", "message": msg}
        # Relay error: mark the refresh failed and report 502 (bad upstream).
        except Exception as e:  # noqa: BLE001
            _repo().set_refresh_status(tid, "failed", error=f"relay failed: {e}")
            raise HTTPException(status_code=502, detail=f"REFRESH_TEMPLATE relay failed: {e}")
        # Log and confirm the refresh is queued.
        logger.info("[template-repo] refresh queued %s → agent %s (vmid %s)",
                    tid, agent_id, template_vmid)
        return {"status": "SUCCESS",
                "message": "Refresh queued — pausing auto-provisioning, clearing the host's sim VMs + template, restoring the backup, then resuming auto-provisioning."}

    # Admin: restore a template backup onto its original host.
    @app.post("/setup/templates/{tid}/refresh")
    async def refresh_template_admin(tid: str, request: Request):
        """Restore template ``tid`` onto its source host (admin only); optional target_storage in
           body.
        """
        # Admin only; then queue the self-restore.
        _require_admin(request)
        return await _orchestrate_refresh(tid, request,
                                          target_storage=await _body_storage(request))

    # Tenant view of the template repository.
    @app.get("/tenant/templates")
    async def list_templates_tenant(request: Request):
        """List templates visible to the caller: all for admins, own tenants' for tenant-admins."""
        # /tenant/* is gated to tenant-admin + admin by the middleware. Admin sees
        # all; a tenant-admin sees only templates whose derived tenant is theirs.
        # Read the session and every template.
        sess = _session_user(request)
        allt = _repo().list()
        # Admins see everything.
        if _is_admin(sess):
            return {"templates": allt}
        # Others see only templates stamped with one of their tenants.
        mine = set(_acting_tenants(sess))
        return {"templates": [t for t in allt if (t.get("tenant_id") or "") in mine]}

    # Tenant-admin: restore a template backup onto its original host.
    @app.post("/tenant/templates/{tid}/refresh")
    async def refresh_template_tenant(tid: str, request: Request):
        """Restore template ``tid`` onto its source host if the caller owns its tenant."""
        # Read the session and the public record (no tokens).
        sess = _session_user(request)
        rec = _repo().get(tid)  # public view (no tokens)
        # Anti-IDOR: a template the caller can't own reads as not-found.
        if rec is None or not _owns_tenant(sess, rec.get("tenant_id")):
            raise HTTPException(status_code=404, detail="template not found")
        return await _orchestrate_refresh(tid, request,
                                          target_storage=await _body_storage(request))

    @app.post("/tenant/templates/upload-init")
    async def upload_init_tenant(request: Request):
        """Tenant-admin/admin: register a MANUAL (browser) template upload from
        the Simulations UI. This is the offline counterpart to the agent backup
        flow (``/setup/templates/backup``) — used when the source Proxmox host is
        offline (no live agent to run vzdump) or the operator only has the archive
        as a file. Creates a pending record with NO source host/agent + a one-time
        upload token so the browser can PUT the vzdump archive straight to the
        token-authed ``/api/templates/{id}/upload`` endpoint. The template is
        stamped to the caller's acting sim tenant (anti-IDOR: must be owned)."""
        # Read the session.
        sess = _session_user(request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # A template name is required.
        name = str(body.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="a template name is required")
        # Tenant is the caller's acting sim tenant (stamped by the WebUI). A
        # tenant-admin may only upload to a tenant they own; admin → any.
        tenant_id = str(body.get("tenant_id") or "").strip()
        if not _owns_tenant(sess, tenant_id):
            raise HTTPException(status_code=403, detail="not permitted for this tenant")
        # Resolve a readable display name the same way trigger_backup does.
        # Show the tenant's display name when it can be looked up; otherwise the id.
        tenant_name = tenant_id
        if tenant_id:
            try:
                trec = hub.state.get_tenant(tenant_id) if hasattr(hub.state, "get_tenant") else None
                if trec:
                    tenant_name = trec.get("name") or tenant_id
            except Exception:  # noqa: BLE001
                pass

        # Create a pending record with no source host; this also generates the upload token.
        rec = _repo().create_pending(
            name=name, source_vmid=None, source_node="", source_agent="",
            source_spoke="", created_by=_username(sess),
            tenant=tenant_name, tenant_id=tenant_id)
        tid, token = rec["id"], rec["_upload_token"]

        # Persist optional operator metadata via the same path edit_template uses.
        meta = {k: body.get(k) for k in ("os", "version", "purpose") if body.get(k)}
        if meta:
            _repo().update_meta(tid, meta)

        # Same URL derivation as trigger_backup — prefer an explicit public URL,
        # else the URL the caller's browser reached us on.
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        # Upload URL for the browser.
        upload_url = f"{base}/api/templates/{tid}/upload"

        # Log and return the URL and token so the browser can start the upload.
        logger.info("[template-repo] manual upload init (tenant) %s (name=%s by=%s tenant=%s)",
                    tid, name, _username(sess), tenant_id or "-")
        return {"status": "SUCCESS", "id": tid,
                "upload_url": upload_url, "upload_token": token}

    def _resolve_target_agent(host_id):
        """Reverse-lookup ``hub.agent_info`` for the connected agent whose
        hostname matches ``host_id`` (case-insensitive, short-name tolerant).
        Returns the
        ``agent_id`` (key into agent_info / agent_config) or None. The fleet rows
        key on the agent's reported OS hostname, which can differ from the
        Proxmox cluster node name recorded on a backup — so we resolve via the
        live agent index, not the backup's source_node."""
        # Trimmed host id; nothing to resolve when blank.
        hid = str(host_id or "").strip()
        if not hid:
            return None
        # Lowercased full name and short name (before the first dot) for matching.
        hid_l = hid.lower()
        hid_short = hid_l.split(".", 1)[0]

        def _match(val):
            """Return True if ``val`` matches the host id by full or short name, ignoring case."""
            # Normalise; blank never matches.
            v = str(val or "").strip().lower()
            if not v:
                return False
            # Match either the full name or the short host name.
            return v == hid_l or v.split(".", 1)[0] == hid_short

        # Pick the first agent with a matching hostname whose spoke is connected right now.
        for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
            info = info or {}
            if _match(info.get("hostname")) and hub._primary_key(info.get("spoke_id")) in hub.active_connections:
                return aid
        return None

    def _host_template_vmid(agent_id):
        """The host's configured clone-source template VMID (``image1_template_id``
        — a number), from ``agent_config[agent_id].client_simulation.usb_config``.
        This is the default qmrestore destination when the caller does not pass an
        explicit ``target_vmid``. Returns an int or None."""
        # The agent's stored config (empty if hub state is unavailable).
        ac = (getattr(hub, "state", None) and hub.state.system_state.get("agent_config", {}) or {}) \
            .get(hub._agent_primary_key(agent_id), {})
        # Configured template VMID under client_simulation.usb_config.
        usb = (ac.get("client_simulation") or {}).get("usb_config") or {}
        v = usb.get("image1_template_id")
        # Convert to int; blank or non-numeric values mean "not configured".
        try:
            return int(v) if v is not None and str(v).strip() != "" else None
        except (TypeError, ValueError):
            return None

    def _agent_tenant_id(agent_id):
        """Return the tenant id the agent's client simulation is bound to ("" if none)."""
        # The agent's stored config (empty if hub state is unavailable).
        ac = (getattr(hub, "state", None) and hub.state.system_state.get("agent_config", {}) or {}) \
            .get(hub._agent_primary_key(agent_id), {})
        # Tenant id from the client_simulation section.
        return str((ac.get("client_simulation") or {}).get("tenant_id") or "").strip()

    # Tenant-admin fleet action: push one seed backup onto several hosts.
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
          * ``target_storage`` (opt str) — Proxmox storage id the restored disks
            land on (``qmrestore --storage``) for every target. Default: the
            storage recorded in the backup (which may not exist on a target host,
            the reason a cross-host restore could fail).

        Tenant isolation: the seed backup AND every target host must be in a
        tenant the caller owns (admin = any). Anti-IDOR: an un-ownable seed
        reads as not-found; an un-ownable target is SKIPPED (not revealed)."""
        # Read the session.
        sess = _session_user(request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Target list: host ids, or spoke ids from older clients; must be a non-empty list.
        host_ids = body.get("host_ids") or []
        by_host = bool(host_ids)
        ids = host_ids if by_host else (body.get("spoke_ids") or [])
        if not isinstance(ids, list) or not ids:
            raise HTTPException(status_code=400, detail="host_ids (non-empty list) required")

        # ── resolve the seed backup ──────────────────────────────────────────
        # An explicit seed backup id, if given, must exist.
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
        # The seed must be a finished backup.
        if rec.get("status") != "complete":
            raise HTTPException(status_code=409, detail="template backup is not complete")
        # The caller must own the seed's tenant.
        if not _owns_tenant(sess, rec.get("tenant_id")):
            # Anti-IDOR: a seed the caller can't own reads as not-found.
            raise HTTPException(status_code=404, detail="template not found")

        # ── target VMID override ─────────────────────────────────────────────
        # Optional VMID override: must be a positive integer when given.
        target_vmid = body.get("target_vmid")
        if target_vmid is not None and str(target_vmid).strip() != "":
            try:
                target_vmid = int(target_vmid)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="target_vmid must be an integer")
            if target_vmid <= 0:
                raise HTTPException(status_code=400, detail="target_vmid must be a positive integer")
        # Not given: each target's configured template VMID is used.
        else:
            target_vmid = None

        # ── destination storage override (applies to every target) ───────────
        target_storage = _clean_storage(body.get("target_storage"))

        # One result row per requested target.
        results = []
        # Restore the seed onto each target host in turn.
        for sid in ids:
            # Normalise the id to a string.
            sid = str(sid or "")
            # Resolve the target host → its owning agent (live agent index).
            agent_id = _resolve_target_agent(sid) if by_host else None
            # Host not connected: skip it and say why.
            if by_host and agent_id is None:
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": f"host '{sid}' not connected / no owning agent"})
                continue
            if not by_host:
                # Legacy spoke_ids path: resolve via the spoke's owning agent.
                # Pick any agent indexed under this spoke.
                agent_id = None
                # Use the first agent whose spoke matches this spoke id.
                for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
                    if hub._primary_key((info or {}).get("spoke_id")) == hub._primary_key(sid) and aid:
                        agent_id = aid
                        break
                # No agent under that spoke: skip it.
                if agent_id is None:
                    results.append({"spoke_id": sid, "status": "SKIPPED",
                                    "message": "no agent connected for this spoke"})
                    continue

            # Tenant-own the target host (anti-IDOR / tenant isolation).
            # Skip hosts in tenants the caller does not own.
            host_tenant = _agent_tenant_id(agent_id)
            if not _owns_tenant(sess, host_tenant):
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": "not permitted for this host's tenant"})
                continue

            # Resolve the restore VMID: override → host's image1_template_id.
            # Use the override VMID, else the host's configured template VMID.
            vmid = target_vmid if target_vmid is not None else _host_template_vmid(agent_id)
            # No VMID known for this host: skip it.
            if vmid is None:
                results.append({"spoke_id": sid, "status": "SKIPPED",
                                "message": "no target VMID for this host — pass target_vmid or "
                                            "configure the host's VM Image 1 Template VMID"})
                continue

            # Queue the restore on this host and record the outcome.
            try:
                r = await _orchestrate_refresh(template_id, request,
                                               target_agent_id=agent_id, target_vmid=vmid,
                                               target_storage=target_storage)
                results.append({"spoke_id": sid, "host": sid, "template_id": template_id,
                                "name": rec.get("name"), "target_vmid": vmid,
                                "status": r.get("status"), "message": r.get("message")})
            # A failure for one host is recorded and the loop continues with the next.
            except HTTPException as e:
                results.append({"spoke_id": sid, "host": sid, "template_id": template_id,
                                "target_vmid": vmid,
                                "status": "ERROR", "message": str(e.detail)})
        # Overall success when at least one host was queued.
        ok = sum(1 for r in results if r.get("status") == "SUCCESS")
        return {"status": "SUCCESS" if ok else "ERROR",
                "refreshed": ok, "total": len(results), "results": results}

    @app.post("/tenant/templates/backup")
    async def trigger_backup_tenant(request: Request):
        """Tenant-admin/admin: back up a live Proxmox template VM to the hub repo
        from the Simulations module. This is the tenant-gated mirror of the
        Global-Admin ``/setup/templates/backup`` — same agent/vmid resolution,
        pending record, one-time upload token and START_BACKUP relay — but gated
        by tenant ownership of the resolved host instead of ``_require_admin``.

        A tenant-admin has no Setup/Hypervisors access, so this is their only way
        to seed a template backup. Anti-IDOR: the resolved host's tenant
        (``_agent_tenant_id``) must be one the caller owns (admin → any)."""
        # Read the session.
        sess = _session_user(request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Read the backup target: agent, vmid, node and unique id.
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
            # A full "cluster/node/vmid" id: take the node and (if it parses) the vmid from it.
            if len(parts) >= 3:
                node = node or parts[-2]
                if vmid is None:
                    # A non-numeric vmid is left unset and rejected below.
                    try:
                        vmid = int(parts[-1])
                    except (TypeError, ValueError):
                        pass
        # Resolve the owning agent by node hostname (agent_info index) when the
        # caller didn't hand us an explicit agent_id.
        if not agent_id and node:
            # Use the first agent whose reported hostname matches the node.
            for aid, info in (getattr(hub, "agent_info", {}) or {}).items():
                if str((info or {}).get("hostname") or "").lower() == node.lower():
                    agent_id = aid
                    break
        # Template name from the body, else "vmid-<n>".
        name = str(body.get("name") or "").strip() or (f"vmid-{vmid}" if vmid is not None else "")
        # Without both an agent and a vmid there is nothing to back up.
        if not agent_id or vmid is None:
            raise HTTPException(status_code=400,
                                detail="could not resolve the owning agent/vmid (need agent_id+vmid or a unique_id)")

        # Anti-IDOR: the resolved host must belong to a tenant the caller owns.
        # Admin short-circuits _owns_tenant for any tenant; a tenant-admin may
        # only back up hosts bound to one of their assigned tenants (a
        # foreign/unassigned host → 403).
        host_tenant = _agent_tenant_id(agent_id)
        if not _owns_tenant(sess, host_tenant):
            raise HTTPException(status_code=403, detail="not permitted for this host's tenant")

        # Spoke that relays to the agent: its own spoke, else the default hypervisor spoke.
        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        # No connected spoke means the agent cannot be reached.
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="no connected spoke owns this agent")

        # Tenant is DRIVEN by the PXMX host, per host: prefer the agent's own
        # tenant binding (Agent Config → Client Simulation tenant_id), else the
        # owning spoke's tenant. Resolve a display name so the repo stays readable
        # even if the tenant is later renamed/removed.
        # The agent's stored config, keyed by its primary key.
        agent_cfg = (hub.state.system_state.get("agent_config", {}) or {}).get(
            hub._agent_primary_key(agent_id), {})
        tenant_id = str((agent_cfg.get("client_simulation") or {}).get("tenant_id") or "").strip()
        # No agent tenant: fall back to the owning spoke's tenant (none on error).
        if not tenant_id:
            try:
                tenant_id = str(hub.state.get_spoke_tenant(owning_spoke) or "").strip()
            except Exception:  # noqa: BLE001
                tenant_id = ""
        # Show the tenant's display name when it can be looked up; otherwise the id.
        tenant_name = tenant_id
        if tenant_id:
            try:
                trec = hub.state.get_tenant(tenant_id) if hasattr(hub.state, "get_tenant") else None
                if trec:
                    tenant_name = trec.get("name") or tenant_id
            except Exception:  # noqa: BLE001
                pass

        # Create a pending record; this also generates the one-time upload token.
        rec = _repo().create_pending(
            name=name, source_vmid=vmid, source_node=node,
            source_agent=hub._agent_relay_name(agent_id), source_spoke=owning_spoke,
            created_by=_username(sess), tenant=tenant_name, tenant_id=tenant_id)
        tid, token = rec["id"], rec["_upload_token"]

        # The agent streams straight to the hub's HTTPS endpoint. Prefer an
        # explicit public URL (browser-facing and agent-facing can differ);
        # otherwise use the URL the caller's browser reached us on.
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        upload_url = f"{base}/api/templates/{tid}/upload"

        # Ask the agent (via its spoke) to start vzdump and stream the archive back.
        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": hub._agent_relay_name(agent_id),
                "command": "START_BACKUP",
                "data": {"template_id": tid, "vmid": vmid, "node": node,
                         "upload_url": upload_url, "upload_token": token,
                         "storage": storage},
            })
            # Unwrap the reply; SUCCESS or ACCEPTED means the agent took the job.
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            accepted = isinstance(data, dict) and data.get("status") in ("SUCCESS", "ACCEPTED")
            # Rejected: mark the record failed and tell the UI why.
            if not accepted:
                msg = (data.get("message") if isinstance(data, dict) else None) or "agent did not accept the backup"
                _repo().set_status(tid, "failed", error=msg)
                return {"status": "ERROR", "id": tid, "message": msg}
        # Relay error: mark the record failed and report 502 (bad upstream).
        except Exception as e:  # noqa: BLE001
            _repo().set_status(tid, "failed", error=f"relay failed: {e}")
            raise HTTPException(status_code=502, detail=f"START_BACKUP relay failed: {e}")

        # Log and confirm the backup is queued.
        logger.info("[template-repo] backup queued (tenant) %s (vmid=%s agent=%s by=%s)",
                    tid, vmid, agent_id, _username(sess))
        return {"status": "SUCCESS", "id": tid,
                "message": "Backup queued — the agent is running vzdump and will stream it to the hub."}

    # ── agent-facing download + refresh progress (token-authed) ──────────────
    def _check_refresh_token(tid: str, request: Request):
        """Raise 403 unless the request carries the valid refresh (download) token for ``tid``."""
        # Token from the X-Refresh-Token header, else the ?token= query value.
        token = request.headers.get("x-refresh-token") or request.query_params.get("token") or ""
        # The repository checks the token matches this template.
        if not _repo().verify_refresh_token(tid, token):
            raise HTTPException(status_code=403, detail="invalid refresh token")

    def _refresh_hosts_registry():
        """In-memory per-host refresh state, keyed ``"<tid>|<agent_id>"``. The
        agent's progress posts carry host/agent_id/vmid/bytes/total so the fleet
        UI can show WHICH host is at WHICH step (+ download progress) instead of
        the single template-scoped ``refresh_status`` shared across concurrent
        target hosts. Lost on hub restart (refreshes are short-lived)."""
        # Create the registry on the hub object the first time it is needed.
        if not getattr(hub, "template_refresh_hosts", None):
            hub.template_refresh_hosts = {}
        return hub.template_refresh_hosts

    @app.get("/api/templates/{tid}/download")
    async def download_template(tid: str, request: Request):
        """Stream a stored archive to the target agent during a refresh
        (refresh-token-authed; middleware-exempt)."""
        # FileResponse streams a file from disk without loading it into memory.
        from fastapi.responses import FileResponse
        # Check the refresh token, then make sure the backup exists and is complete.
        _check_refresh_token(tid, request)
        rec = _repo().get(tid, public=False)
        if rec is None or rec.get("status") != "complete":
            raise HTTPException(status_code=404, detail="template not found or incomplete")
        # The archive file must also be present on disk.
        path = _repo().image_path(tid)
        if not os.path.isfile(path):
            raise HTTPException(status_code=404, detail="archive missing on disk")
        # Stream it as a binary download with its original filename.
        return FileResponse(path, media_type="application/octet-stream",
                            filename=rec.get("filename") or "image.vma.zst")

    # Agent reports refresh progress.
    @app.post("/api/templates/{tid}/refresh-progress")
    async def refresh_progress(tid: str, request: Request):
        """Record refresh progress posted by the agent (refresh-token-authed)."""
        # Check the refresh token.
        _check_refresh_token(tid, request)
        # Parse the body; a bad body becomes {}.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Status (default "restoring"), current step and any error text.
        status = str(body.get("status") or "restoring")
        step = str(body.get("step") or "")
        error = str(body.get("error") or "")
        # Update the template-level refresh status.
        _repo().set_refresh_status(tid, status, step=step, error=error)
        # Per-host registry: the agent sends host/agent_id/vmid/bytes/total so the
        # fleet UI shows which host is at which step (+ download progress).
        # Identify the reporting host by agent id, else hostname.
        agent_id = str(body.get("agent_id") or "")
        host = str(body.get("host") or "")
        key_agent = agent_id or host
        # Store a per-host entry when the host is known.
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
        # Acknowledge.
        return {"status": "SUCCESS"}

    # Per-host refresh progress for the UI.
    @app.get("/tenant/templates/refresh-status")
    async def refresh_status(request: Request):
        """Live per-host template-refresh state for the VM Server status chip.
        Returns entries updated within the last 10 min (terminal complete/failed
        states linger briefly so the UI can show the outcome before they clear).

        Scoped to the header tenant picker: the Simulations views are per-tenant,
        so an explicit ``?tenant=`` narrows the chip to that tenant. A global
        admin sees only the SELECTED tenant's refreshes (not every tenant's);
        with no ``?tenant=`` an admin sees all. A tenant-admin is always confined
        to their own tenants, then narrowed to the selected one when provided."""
        # Read the session, the selected tenant, the registry, and the current time.
        sess = _session_user(request)
        sel = (request.query_params.get("tenant") or "").strip()
        reg = _refresh_hosts_registry()
        now = time.time()
        # Prune stale entries (>10 min) so the registry can't grow unbounded.
        for k in [k for k, v in reg.items() if now - (v.get("updated_at") or 0) > 600]:
            reg.pop(k, None)
        # Snapshot the remaining entries.
        entries = list(reg.values())
        # Admins see everything, narrowed to the selected tenant when one is chosen.
        if _is_admin(sess):
            # Admin may see any tenant, but the sim view is per-tenant — when a
            # tenant is selected in the picker, scope the chip to it so a global
            # admin viewing tenant A doesn't see tenant B's refresh.
            if sel:
                entries = [e for e in entries if (e.get("tenant_id") or "") == sel]
        # Others see only their own tenants' entries, narrowed to the selection if it is theirs.
        else:
            mine = set(_acting_tenants(sess))
            entries = [e for e in entries if (e.get("tenant_id") or "") in mine]
            if sel and sel in mine:
                entries = [e for e in entries if (e.get("tenant_id") or "") == sel]
        # Newest updates first.
        entries.sort(key=lambda e: e.get("updated_at") or 0, reverse=True)
        return {"hosts": entries}
