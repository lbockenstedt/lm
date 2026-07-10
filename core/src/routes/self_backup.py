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
from api import HTTPException, Request, logger


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