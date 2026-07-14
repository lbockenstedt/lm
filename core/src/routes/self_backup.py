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
import os

from fastapi import Response

from api import HTTPException, Request, logger

_MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # 512 MB cap on an uploaded restore archive


def register(app, hub, ctx):
    """Register the self-backup admin routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin only")
        return sess

    @app.post("/setup/backup/run")
    async def backup_run_now(request: Request):
        """Trigger one backup immediately (regardless of the schedule). If
        copy_enabled + after_each_backup, the push fires too. Returns the
        run + optional copy result."""
        _require_admin(request)
        try:
            result = await hub.run_backup_now()
            return result
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/run failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/backup/test-copy")
    async def backup_test_copy(request: Request):
        """Push the latest local backup to the configured SSH destination
        once, regardless of copy_mode / schedule. Used by the WebUI 'Test copy'
        button to validate the SSH config without waiting for a cycle."""
        _require_admin(request)
        try:
            result = await hub.test_self_backup_copy()
            if result.get("status") != "ok":
                # surface a 400 with the cause so the UI toast is actionable
                raise HTTPException(status_code=400,
                                     detail=result.get("error", "copy failed"))
            return result
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/test-copy failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/backup/download")
    async def backup_download(request: Request, name: str):
        """Stream one on-disk backup archive to the admin for off-box keeping
        (manual/system-recovery). ``name`` is a basename in the backup dir;
        traversal + non-archive names are rejected."""
        _require_admin(request)
        path = hub._sb_resolve_archive(name)
        if not path:
            raise HTTPException(status_code=404, detail="backup not found")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise HTTPException(status_code=500, detail=str(e))
        return Response(content=data, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{os.path.basename(path)}"'})

    @app.post("/setup/backup/upload")
    async def backup_upload(request: Request):
        """Accept an operator-uploaded backup archive (system-recovery) and drop
        it into the backup dir so it lists + can be restored on-box. Multipart
        form field ``file``; falls back to a raw body with ?name=."""
        _require_admin(request)
        filename = request.query_params.get("name", "")
        data = b""
        ctype = (request.headers.get("content-type") or "").lower()
        try:
            if "multipart/form-data" in ctype:
                form = await request.form()
                up = form.get("file")
                if up is None:
                    raise HTTPException(status_code=400, detail="no 'file' field in the upload")
                filename = filename or getattr(up, "filename", "") or ""
                data = await up.read()
            else:
                data = await request.body()
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        if not data:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(data) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="upload exceeds 512 MB limit")
        try:
            res = hub.sb_save_uploaded_archive(filename, data)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/upload failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))
        return {"status": "ok", **res}

    @app.get("/setup/backup/status")
    async def backup_status(request: Request):
        """Config snapshot + on-disk archive list for the Self-Backup status
        panel. Never exposes private-key material (ssh_keyfile is a path only)."""
        _require_admin(request)
        try:
            return hub.get_self_backup_status()
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] /setup/backup/status failed: %s", e)
            raise HTTPException(status_code=500, detail=str(e))