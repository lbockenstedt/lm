"""Cloud NAC admin routes (Setup) — config + manual provision/deprovision + the
idle sweep. The automatic JIT path is driven by the cs engine (spoke → hub
command); these routes let an admin configure it and test/operate it by hand.

Under ``/setup/`` so the access-control middleware gates them to admins.
"""
# Postpone evaluation of type hints.
from __future__ import annotations

# Timestamps for the idle sweep cutoff.
import datetime

# Shared Hub helpers: HTTP error type, request object and the hub logger.
from api import HTTPException, Request, logger
# Entra OIDC app config; used to authenticate the Graph calls.
from security.oidc import get_oidc_config
# Cloud NAC engine: Entra account provision/delete, sign-in lookups and records.
import cloud_nac as _cn

# The config keys an admin may set (anything else in the POST is ignored).
_CFG_FIELDS = ("enabled", "domain", "idle_days", "group_id", "group_name")


def register(app, hub, ctx):
    """Register the Setup -> Cloud NAC admin routes on the Hub app."""
    def _cfg() -> dict:
        """Return the current Cloud NAC config (with defaults filled in)."""
        return _cn.get_config(hub.state.system_state)

    def _accounts() -> dict:
        """Return the recorded provisioned accounts, keyed by username."""
        return hub.state.system_state.get("cloud_nac_accounts", {}) or {}

    def _masked(rec: dict) -> dict:
        """Return a copy of an account record without its password."""
        # Never echo the recorded password back to the browser.
        return {k: v for k, v in (rec or {}).items() if k != "password"}

    # Read the config and the list of provisioned accounts.
    @app.get("/setup/cloud-nac")
    async def get_cloud_nac():
        """Return the config, the (password-free) accounts and their count."""
        accts = _accounts()
        return {"config": _cfg(),
                "accounts": [_masked(r) for r in accts.values()],
                "count": len(accts)}

    # Save the Cloud NAC config.
    @app.post("/setup/cloud-nac")
    async def set_cloud_nac(request: Request):
        """Merge the posted config into the stored one, clean it up and save it."""
        # Read the JSON body (defaulting to {}); accept {"config": {...}} or a bare config.
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        # Copy only the allowed fields onto the current config.
        cur = _cfg()
        for k in _CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        # Clean up types: bool enabled, idle_days at least 1 (7 if invalid), trimmed strings.
        cur["enabled"] = bool(cur.get("enabled", False))
        try:
            cur["idle_days"] = max(1, int(cur.get("idle_days", 7)))
        except (TypeError, ValueError):
            cur["idle_days"] = 7
        cur["domain"] = str(cur.get("domain") or "").strip()
        cur["group_id"] = str(cur.get("group_id") or "").strip()
        cur["group_name"] = str(cur.get("group_name") or "").strip()
        # Store the cleaned config and mark hub state for saving.
        gc = hub.state.system_state.get("global_config", {})
        gc["cloud_nac"] = {k: cur[k] for k in _CFG_FIELDS}
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Return the saved config.
        return {"status": "ok", "config": cur}

    # Manually create/reset an Entra account for a username.
    @app.post("/setup/cloud-nac/provision")
    async def provision_cloud_nac(request: Request):
        """Manually JIT-provision a username (create/reset the Entra account, set a
        random password, record it). Returns the password ONCE so an admin can
        verify — the automatic path delivers it to the client, not the browser."""
        # Read the JSON body (defaulting to {}) and get the lower-cased username.
        try:
            body = await request.json()
        except Exception:
            body = {}
        username = str((body or {}).get("username") or "").strip().lower()
        # A username and the UPN domain are both required.
        if not username:
            raise HTTPException(status_code=400, detail="username required")
        cfg = _cfg()
        if not cfg.get("domain"):
            raise HTTPException(status_code=400, detail="set the UPN domain first")
        # Create/reset the account; an Entra error is a 502.
        try:
            res = await _cn.provision_user(get_oidc_config(hub), cfg["domain"], username)
        except _cn.CloudNacError as e:
            raise HTTPException(status_code=502, detail=str(e))
        # Record the account and save state right away.
        _cn.record_account(hub.state.system_state, res)
        await hub.state.save_state_now()
        # Auto-add to the configured Entra group (best-effort — surfaced as a
        # warning so the account+password still succeed if group-add is misconfig).
        group_warn = ""
        added = False
        if cfg.get("group_id") and res.get("oid"):
            try:
                added = await _cn.add_user_to_group(get_oidc_config(hub), cfg["group_id"], res["oid"])
            except _cn.CloudNacError as e:
                group_warn = str(e)
        # Return the result, including the one-time password.
        return {"status": "ok", "username": res["username"], "upn": res["upn"],
                "created": res["created"], "password": res["password"],
                "group_added": added, "group_warning": group_warn}

    # Manually delete a provisioned Entra account.
    @app.post("/setup/cloud-nac/deprovision")
    async def deprovision_cloud_nac(request: Request):
        """Delete the named provisioned account from Entra and forget it locally."""
        # Read the JSON body (defaulting to {}) and look up the account record.
        try:
            body = await request.json()
        except Exception:
            body = {}
        username = str((body or {}).get("username") or "").strip().lower()
        rec = _accounts().get(username)
        # Unknown accounts are a 404.
        if not rec:
            raise HTTPException(status_code=404, detail="no such provisioned account")
        # Delete the user in Entra (by object id, else UPN); an Entra error is a 502.
        try:
            await _cn.delete_user(get_oidc_config(hub), rec.get("oid") or rec.get("upn"))
        except _cn.CloudNacError as e:
            raise HTTPException(status_code=502, detail=str(e))
        # Drop the local record and mark hub state for saving.
        _cn.forget_account(hub.state.system_state, username)
        hub.state._mark_dirty()
        return {"status": "ok", "deleted": username}

    # Delete accounts that have been idle too long.
    @app.post("/setup/cloud-nac/sweep")
    async def sweep_cloud_nac():
        """Delete Entra accounts idle for >= idle_days (by actual sign-in activity).
        A never-signed-in account is aged from its created_at. Returns per-account
        outcomes. Also runnable on a schedule (wired separately)."""
        # Work out the idle cutoff time from the config.
        cfg = _cfg()
        idle_days = int(cfg.get("idle_days", 7))
        oidc = get_oidc_config(hub)
        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(days=idle_days)
        results = []

        def _parse(ts):
            """Parse an ISO timestamp (``Z`` allowed); return None if empty or invalid."""
            if not ts:
                return None
            try:
                return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                return None

        # Check each recorded account; skip it if we can't read its last sign-in.
        for username, rec in list(_accounts().items()):
            ident = rec.get("oid") or rec.get("upn")
            try:
                last = await _cn.last_signin(oidc, ident)
            except _cn.CloudNacError as e:
                results.append({"username": username, "action": "skip", "reason": str(e)})
                continue
            # Age from the last sign-in, or from creation if it never signed in; keep active ones.
            ref = _parse(last) or _parse(rec.get("created_at"))
            idle = ref is None or ref < cutoff
            if not idle:
                results.append({"username": username, "action": "keep", "last": last})
                continue
            # Idle: delete it in Entra and forget it locally; record any error.
            try:
                await _cn.delete_user(oidc, ident)
                _cn.forget_account(hub.state.system_state, username)
                results.append({"username": username, "action": "deleted", "last": last})
            except _cn.CloudNacError as e:
                results.append({"username": username, "action": "error", "reason": str(e)})
        # Save state, log how many were deleted, and return the per-account results.
        hub.state._mark_dirty()
        deleted = sum(1 for r in results if r["action"] == "deleted")
        logger.info("Cloud NAC sweep: deleted %d idle account(s) of %d", deleted, len(results))
        return {"status": "ok", "deleted": deleted, "results": results}
