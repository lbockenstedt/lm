"""VM snapshot schedules (Global Admin): snapshot chosen VMs, or every VM with a
Proxmox tag or in a pool, every N hours, keeping the last K. The work is done by
the shared ``vm_snapshots`` service, which OS Updates also uses for its
pre-patch snapshots.

  GET    /api/vm-snapshots/schedules            list (+ the VMs/tags/pools to pick from)
  POST   /api/vm-snapshots/schedules            create
  PUT    /api/vm-snapshots/schedules/{id}       replace
  DELETE /api/vm-snapshots/schedules/{id}       delete (existing snapshots stay)
  POST   /api/vm-snapshots/schedules/{id}/run   snapshot its VMs now
"""
import asyncio

import vm_snapshots
from api import HTTPException, Request, logger


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request):
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin required")
        return ((sess or {}).get("user_id") or (sess or {}).get("username") or "?")

    async def _body(request):
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object body required")
        return body

    def _save(body, sid=""):
        try:
            return vm_snapshots.save_schedule(hub, body, sid)
        except KeyError:
            raise HTTPException(status_code=404, detail="no such schedule")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/api/vm-snapshots/schedules")
    async def vm_snapshot_schedules(request: Request):
        _require_admin(request)
        vms = vm_snapshots.all_vms(hub)
        schedules = [{**s, "vm_count": len(vm_snapshots.schedule_vms(s, vms)),
                      "running": vm_snapshots.is_running(s["id"])}
                     for s in vm_snapshots.list_schedules(hub)]
        return {"schedules": schedules,
                "vms": [vm_snapshots.vm_ref(vm) for vm in vms],
                "tags": sorted({t for vm in vms for t in vm.get("tags") or []}),
                "pools": sorted({vm["pool"] for vm in vms if vm.get("pool")})}

    @app.post("/api/vm-snapshots/schedules")
    async def vm_snapshot_schedule_create(request: Request):
        actor = _require_admin(request)
        s = _save(await _body(request))
        logger.warning("[vm-snapshot] schedule %s (%s) created by %s", s["id"], s["name"], actor)
        return s

    @app.put("/api/vm-snapshots/schedules/{sid}")
    async def vm_snapshot_schedule_update(sid: str, request: Request):
        actor = _require_admin(request)
        s = _save(await _body(request), sid)
        logger.warning("[vm-snapshot] schedule %s (%s) updated by %s", sid, s["name"], actor)
        return s

    @app.delete("/api/vm-snapshots/schedules/{sid}")
    async def vm_snapshot_schedule_delete(sid: str, request: Request):
        actor = _require_admin(request)
        try:
            vm_snapshots.delete_schedule(hub, sid)
        except KeyError:
            raise HTTPException(status_code=404, detail="no such schedule")
        logger.warning("[vm-snapshot] schedule %s deleted by %s", sid, actor)
        return {"status": "ok"}

    @app.post("/api/vm-snapshots/schedules/{sid}/run")
    async def vm_snapshot_schedule_run(sid: str, request: Request):
        """Starts the run and returns; the result lands on the schedule's
        ``last_result``."""
        actor = _require_admin(request)
        if sid not in {s["id"] for s in vm_snapshots.list_schedules(hub)}:
            raise HTTPException(status_code=404, detail="no such schedule")
        if vm_snapshots.is_running(sid):
            raise HTTPException(status_code=409, detail="this schedule is already running")
        logger.warning("[vm-snapshot] schedule %s run now by %s", sid, actor)
        asyncio.create_task(vm_snapshots.run_schedule(hub, sid, actor))
        return {"status": "started"}
