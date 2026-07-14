"""Cloud NAC admin routes (Setup) — config + manual provision/deprovision + the
idle sweep. The automatic JIT path is driven by the cs engine (spoke → hub
command); these routes let an admin configure it and test/operate it by hand.

Under ``/setup/`` so the access-control middleware gates them to admins.
"""
from __future__ import annotations

import datetime

from api import HTTPException, Request, logger
from security.oidc import get_oidc_config
import cloud_nac as _cn

_CFG_FIELDS = ("enabled", "domain", "idle_days")


def register(app, hub, ctx):
    def _cfg() -> dict:
        return _cn.get_config(hub.state.system_state)

    def _accounts() -> dict:
        return hub.state.system_state.get("cloud_nac_accounts", {}) or {}

    def _masked(rec: dict) -> dict:
        # Never echo the recorded password back to the browser.
        return {k: v for k, v in (rec or {}).items() if k != "password"}

    @app.get("/setup/cloud-nac")
    async def get_cloud_nac():
        accts = _accounts()
        return {"config": _cfg(),
                "accounts": [_masked(r) for r in accts.values()],
                "count": len(accts)}

    @app.post("/setup/cloud-nac")
    async def set_cloud_nac(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        cur = _cfg()
        for k in _CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        cur["enabled"] = bool(cur.get("enabled", False))
        try:
            cur["idle_days"] = max(1, int(cur.get("idle_days", 7)))
        except (TypeError, ValueError):
            cur["idle_days"] = 7
        cur["domain"] = str(cur.get("domain") or "").strip()
        gc = hub.state.system_state.get("global_config", {})
        gc["cloud_nac"] = {k: cur[k] for k in _CFG_FIELDS}
        hub.state.system_state["global_config"] = gc
        hub.state.save_state()
        return {"status": "ok", "config": cur}

    @app.post("/setup/cloud-nac/provision")
    async def provision_cloud_nac(request: Request):
        """Manually JIT-provision a username (create/reset the Entra account, set a
        random password, record it). Returns the password ONCE so an admin can
        verify — the automatic path delivers it to the client, not the browser."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        username = str((body or {}).get("username") or "").strip().lower()
        if not username:
            raise HTTPException(status_code=400, detail="username required")
        cfg = _cfg()
        if not cfg.get("domain"):
            raise HTTPException(status_code=400, detail="set the UPN domain first")
        try:
            res = await _cn.provision_user(get_oidc_config(hub), cfg["domain"], username)
        except _cn.CloudNacError as e:
            raise HTTPException(status_code=502, detail=str(e))
        _cn.record_account(hub.state.system_state, res)
        hub.state.save_state()
        return {"status": "ok", "username": res["username"], "upn": res["upn"],
                "created": res["created"], "password": res["password"]}

    @app.post("/setup/cloud-nac/deprovision")
    async def deprovision_cloud_nac(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        username = str((body or {}).get("username") or "").strip().lower()
        rec = _accounts().get(username)
        if not rec:
            raise HTTPException(status_code=404, detail="no such provisioned account")
        try:
            await _cn.delete_user(get_oidc_config(hub), rec.get("oid") or rec.get("upn"))
        except _cn.CloudNacError as e:
            raise HTTPException(status_code=502, detail=str(e))
        _cn.forget_account(hub.state.system_state, username)
        hub.state.save_state()
        return {"status": "ok", "deleted": username}

    @app.post("/setup/cloud-nac/sweep")
    async def sweep_cloud_nac():
        """Delete Entra accounts idle for >= idle_days (by actual sign-in activity).
        A never-signed-in account is aged from its created_at. Returns per-account
        outcomes. Also runnable on a schedule (wired separately)."""
        cfg = _cfg()
        idle_days = int(cfg.get("idle_days", 7))
        oidc = get_oidc_config(hub)
        now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(days=idle_days)
        results = []

        def _parse(ts):
            if not ts:
                return None
            try:
                return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                return None

        for username, rec in list(_accounts().items()):
            ident = rec.get("oid") or rec.get("upn")
            try:
                last = await _cn.last_signin(oidc, ident)
            except _cn.CloudNacError as e:
                results.append({"username": username, "action": "skip", "reason": str(e)})
                continue
            ref = _parse(last) or _parse(rec.get("created_at"))
            idle = ref is None or ref < cutoff
            if not idle:
                results.append({"username": username, "action": "keep", "last": last})
                continue
            try:
                await _cn.delete_user(oidc, ident)
                _cn.forget_account(hub.state.system_state, username)
                results.append({"username": username, "action": "deleted", "last": last})
            except _cn.CloudNacError as e:
                results.append({"username": username, "action": "error", "reason": str(e)})
        hub.state.save_state()
        deleted = sum(1 for r in results if r["action"] == "deleted")
        logger.info("Cloud NAC sweep: deleted %d idle account(s) of %d", deleted, len(results))
        return {"status": "ok", "deleted": deleted, "results": results}
