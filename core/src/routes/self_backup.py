"""Self-backup admin routes: run-now, test-copy, status.

Placed under the ``/setup/`` prefix so the existing auth middleware admin-gate
(``api.py``: any ``/setup/`` path requires a valid session AND
``_is_admin(sess)``) blocks non-admins before these handlers run —
belt-and-suspenders on top of the per-handler ``_is_admin`` check. A
tenant_admin / plain user gets 403 here; only a Global Admin can trigger a
backup, test the SSH copy, or read the status. No new gate-prefix set is
added.

The persistent config itself (``global_config["self_backup"]``) is written
through the existing ``POST /setup/config`` route in ``setup_misc.py`` (also
admin-gated), so this module only exposes the action + status endpoints — no
new persistence path.
"""
# os.path.basename gives the archive's filename for the download header.
import os

# Raw Response lets the download endpoint send archive bytes with custom headers.
from fastapi import Response

# FastAPI request/error types plus the hub-wide logger, re-exported by the api module.
from api import HTTPException, Request, logger

# Uploads are read fully into memory, so cap them to keep a huge file from exhausting RAM.
_MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # 512 MB cap on an uploaded restore archive


def register(app, hub, ctx):
    """Register the self-backup admin routes on the Hub app."""
    # Pull the session and admin-check helpers off the shared context once for all routes.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request: Request):
        """Raise 403 unless a Global Admin is logged in; return the session otherwise."""
        # Look up the logged-in session for this request.
        sess = _session_user(request)
        # No session or a non-admin session cannot manage backups.
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin only")
        return sess

    # Run a backup on demand.
    @app.post("/setup/backup/run")
    async def backup_run_now(request: Request):
        """Trigger one backup immediately (regardless of the schedule). If
        copy_enabled + after_each_backup, the push fires too. Returns the
        run + optional copy result."""
        # Only Global Admins may run backups.
        _require_admin(request)
        # Let the hub do the backup (and optional copy) and return its result to the UI.
        try:
            result = await hub.run_backup_now()
            return result
        # Any backup failure is logged and returned as a 500 with the reason.
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/run failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))

    # Validate the SSH copy settings by pushing the latest backup once.
    @app.post("/setup/backup/test-copy")
    async def backup_test_copy(request: Request):
        """Push the latest local backup to the configured SSH destination
        once, regardless of copy_mode / schedule. Used by the WebUI 'Test copy'
        button to validate the SSH config without waiting for a cycle."""
        # Only Global Admins may test the copy.
        _require_admin(request)
        # Ask the hub to copy the latest backup to the SSH destination.
        try:
            result = await hub.test_self_backup_copy()
            if result.get("status") != "ok":
                # surface a 400 with the cause so the UI toast is actionable
                raise HTTPException(status_code=400,
                                     detail=result.get("error", "copy failed"))
            return result
        # Re-raise our own 400 unchanged so the generic handler below does not wrap it.
        except HTTPException:
            raise
        # Any other failure is logged and returned as a 500 with the reason.
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/test-copy failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))

    # Download one backup archive by name.
    @app.get("/setup/backup/download")
    async def backup_download(request: Request, name: str):
        """Stream one on-disk backup archive to the admin for off-box keeping
        (manual/system-recovery). ``name`` is a basename in the backup dir;
        traversal + non-archive names are rejected."""
        # Only Global Admins may download backups.
        _require_admin(request)
        # Resolve the name to a safe path inside the backup dir; None if invalid or missing.
        path = hub._sb_resolve_archive(name)
        # Unknown or rejected names look the same to the caller: not found.
        if not path:
            raise HTTPException(status_code=404, detail="backup not found")
        # Read the whole archive; a read failure becomes a 500 with the OS error.
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise HTTPException(status_code=500, detail=str(e))
        # Send the bytes as a file download named after the archive.
        return Response(content=data, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{os.path.basename(path)}"'})

    # Upload an archive so it can be restored on this box.
    @app.post("/setup/backup/upload")
    async def backup_upload(request: Request):
        """Accept an operator-uploaded backup archive (system-recovery) and drop
        it into the backup dir so it lists + can be restored on-box. Multipart
        form field ``file``; falls back to a raw body with ?name=."""
        # Only Global Admins may upload backups.
        _require_admin(request)
        # The filename may come from ?name=; start with empty data until the body is read.
        filename = request.query_params.get("name", "")
        data = b""
        # Content type decides whether this is a multipart form or a raw body upload.
        ctype = (request.headers.get("content-type") or "").lower()
        try:
            # Multipart upload: take the file from the "file" form field.
            if "multipart/form-data" in ctype:
                form = await request.form()
                up = form.get("file")
                # A multipart upload without the expected field is a client error.
                if up is None:
                    raise HTTPException(status_code=400, detail="no 'file' field in the upload")
                # Prefer ?name=, else the uploaded file's own name.
                filename = filename or getattr(up, "filename", "") or ""
                data = await up.read()
            # Raw body upload: the whole request body is the archive.
            else:
                data = await request.body()
        # Re-raise our own 400 unchanged so the generic handler below does not wrap it.
        except HTTPException:
            raise
        # Any other read error means a broken upload, reported as 400.
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        # Reject empty uploads and anything over the size cap (413 = payload too large).
        if not data:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(data) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="upload exceeds 512 MB limit")
        # Hand the archive to the hub, which validates the name and writes it to the backup dir.
        try:
            res = hub.sb_save_uploaded_archive(filename, data)
        # ValueError means the name or archive was rejected by validation.
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        # Anything else is an unexpected server-side failure.
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/upload failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))
        # Return the hub's save details (e.g. the stored name) with an ok status.
        return {"status": "ok", **res}

    # Report backup config and the archives currently on disk.
    @app.get("/setup/backup/status")
    async def backup_status(request: Request):
        """Config snapshot + on-disk archive list for the Self-Backup status
        panel. Never exposes private-key material (ssh_keyfile is a path only)."""
        # Only Global Admins may see backup status.
        _require_admin(request)
        # Return the hub's status snapshot; failures are logged and returned as 500.
        try:
            return hub.get_self_backup_status()
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/status failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))