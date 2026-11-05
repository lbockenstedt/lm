"""VM snapshot schedules (Global Admin): snapshot chosen VMs, or every VM with a
Proxmox tag or in a pool, every N hours, keeping the last K. Every call takes
``?tenant=<id>`` (the tenant being viewed): a schedule belongs to that tenant
and only ever sees — and snapshots — that tenant's VMs. The work is done by
the shared ``vm_snapshots`` service, which OS Updates also uses for its
pre-patch snapshots.

  GET    /api/vm-snapshots/schedules            list (+ the VMs/tags/pools to pick from)
  POST   /api/vm-snapshots/schedules            create
  PUT    /api/vm-snapshots/schedules/{id}       replace
  DELETE /api/vm-snapshots/schedules/{id}       delete (existing snapshots stay)
  POST   /api/vm-snapshots/schedules/{id}/run   snapshot its VMs now
"""
# asyncio lets the "run now" endpoint start a snapshot run in the background.
import asyncio

# Shared snapshot service that stores schedules and performs the actual snapshots.
import vm_snapshots
# FastAPI request/error types plus the hub-wide logger, re-exported by the api module.
from api import HTTPException, Request, logger


def register(app, hub, ctx):
    """Register the VM snapshot schedule API routes on the Hub app.

    Args: app is the FastAPI app, hub is the running hub (holds config and spoke links), and ctx
    carries shared auth helpers.
    """
    # Pull the session and admin-check helpers off the shared context once for all routes.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request):
        """Reject the request with 403 unless a Global Admin is logged in.

        Returns the admin's user id (or username, or "?") for audit logging.
        """
        # Look up the logged-in session for this request.
        sess = _session_user(request)
        # Snapshot schedules are a Global Admin feature, so anyone else is refused.
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin required")
        # Pick the best available identifier for audit logs; "?" if the session has neither.
        return ((sess or {}).get("user_id") or (sess or {}).get("username") or "?")

    async def _body(request):
        """Parse the request body as JSON and require it to be a JSON object (dict)."""
        # Read and decode the JSON body.
        try:
            body = await request.json()
        # Malformed or empty JSON is treated like a missing body and rejected just below.
        except Exception:  # noqa: BLE001
            body = None
        # Schedules are described by a JSON object, so anything else is a client error.
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON object body required")
        return body

    def _tenant(tenant):
        """Normalise the ``?tenant=`` query value to a trimmed string ("" when missing)."""
        return str(tenant or "").strip()

    def _check_owned(sid, tenant):
        """Raise 404 unless schedule ``sid`` belongs to ``tenant``."""
        # Only the tenant's own schedules are visible, so a foreign id looks like it does not exist.
        if sid not in {s["id"] for s in vm_snapshots.list_schedules(hub, tenant)}:
            raise HTTPException(status_code=404, detail="no such schedule")

    def _save(body, sid="", tenant=""):
        """Create (empty ``sid``) or replace a schedule, mapping service errors to HTTP errors."""
        # Delegate validation and storage to the shared snapshot service.
        try:
            return vm_snapshots.save_schedule(hub, body, sid, tenant)
        # KeyError means the schedule id to update does not exist.
        except KeyError:
            raise HTTPException(status_code=404, detail="no such schedule")
        # ValueError means the body failed validation; pass the reason back to the client.
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # List the tenant's schedules plus the VMs, tags and pools the UI can choose from.
    @app.get("/api/vm-snapshots/schedules")
    async def vm_snapshot_schedules(request: Request, tenant: str = ""):
        """Return this tenant's schedules and the VM/tag/pool choices for the schedule editor."""
        # Only Global Admins may view schedules.
        _require_admin(request)
        # Normalise the tenant id and load every VM that tenant owns.
        tenant = _tenant(tenant)
        vms = await vm_snapshots.tenant_vms(hub, tenant)
        # Enrich each schedule with how many VMs it currently matches and whether it is running.
        schedules = [{**s, "vm_count": len(vm_snapshots.schedule_vms(s, vms)),
                      "running": vm_snapshots.is_running(s["id"])}
                     for s in vm_snapshots.list_schedules(hub, tenant)]
        # Return the schedules alongside the pickable VMs, the unique set of Proxmox tags, and the
        # unique set of pools, sorted so the UI shows them in a stable order.
        return {"schedules": schedules,
                "vms": [vm_snapshots.vm_ref(vm) for vm in vms],
                "tags": sorted({t for vm in vms for t in vm.get("tags") or []}),
                "pools": sorted({vm["pool"] for vm in vms if vm.get("pool")})}

    # Create a new schedule for the tenant.
    @app.post("/api/vm-snapshots/schedules")
    async def vm_snapshot_schedule_create(request: Request, tenant: str = ""):
        """Create a snapshot schedule owned by the given tenant and return it."""
        # Require a Global Admin and remember who did it for the audit log.
        actor = _require_admin(request)
        # Save the body as a brand-new schedule (empty id) under this tenant.
        s = _save(await _body(request), "", _tenant(tenant))
        # Log at warning level so schedule changes always appear in the audit trail.
        logger.warning("[vm-snapshot] schedule %s (%s) for tenant %r created by %s",
                       s["id"], s["name"], s["tenant"], actor)
        return s

    # Replace an existing schedule.
    @app.put("/api/vm-snapshots/schedules/{sid}")
    async def vm_snapshot_schedule_update(sid: str, request: Request, tenant: str = ""):
        """Replace schedule ``sid`` with the request body and return the saved schedule."""
        # Require a Global Admin and remember who did it for the audit log.
        actor = _require_admin(request)
        # Save over the existing id; the service raises KeyError if it is not this tenant's.
        s = _save(await _body(request), sid, _tenant(tenant))
        # Record the change in the audit trail.
        logger.warning("[vm-snapshot] schedule %s (%s) updated by %s", sid, s["name"], actor)
        return s

    # Delete a schedule; snapshots it already took are kept.
    @app.delete("/api/vm-snapshots/schedules/{sid}")
    async def vm_snapshot_schedule_delete(sid: str, request: Request, tenant: str = ""):
        """Delete schedule ``sid`` (its existing snapshots are left in place)."""
        # Require a Global Admin and make sure the schedule belongs to the viewed tenant.
        actor = _require_admin(request)
        _check_owned(sid, _tenant(tenant))
        # Remove the schedule; it may have vanished between the ownership check and now.
        try:
            vm_snapshots.delete_schedule(hub, sid)
        # Already gone, so report it as not found.
        except KeyError:
            raise HTTPException(status_code=404, detail="no such schedule")
        # Record the deletion in the audit trail and confirm.
        logger.warning("[vm-snapshot] schedule %s deleted by %s", sid, actor)
        return {"status": "ok"}

    # Trigger a schedule immediately instead of waiting for its next interval.
    @app.post("/api/vm-snapshots/schedules/{sid}/run")
    async def vm_snapshot_schedule_run(sid: str, request: Request, tenant: str = ""):
        """Starts the run and returns; the result lands on the schedule's
        ``last_result``."""
        # Require a Global Admin and make sure the schedule belongs to the viewed tenant.
        actor = _require_admin(request)
        _check_owned(sid, _tenant(tenant))
        # Refuse overlapping runs of the same schedule so VMs are not snapshotted twice at once.
        if vm_snapshots.is_running(sid):
            raise HTTPException(status_code=409, detail="this schedule is already running")
        # Record who started the run, then launch it in the background so the request returns fast.
        logger.warning("[vm-snapshot] schedule %s run now by %s", sid, actor)
        asyncio.create_task(vm_snapshots.run_schedule(hub, sid, actor))
        # Tell the UI the run has started; it polls the schedule for the result.
        return {"status": "started"}
