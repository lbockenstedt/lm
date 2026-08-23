"""Shared auto-load / auto-unload helpers for coordinator-role instance binding.

Coordinator roles (cppm/NAC, netbox/IPAM, ldap/directory — thin API/CLI
clients, no live daemon of their own) are loaded onto a spoke via the
existing LOAD_ROLE/UNLOAD_ROLE RPCs (``routes/agents.py``), which normally
requires an operator to manually load the role BEFORE they can point an
instance record (e.g. a ClearPass server) at that spoke.

This module removes that manual step: binding an instance to a spoke that
hasn't loaded the matching role yet auto-triggers LOAD_ROLE as a side effect
of the save, and un-binding the last instance referencing a role auto-triggers
UNLOAD_ROLE so idle role code doesn't linger connected on a spoke forever.

Both ``routes/tenant_devices.py`` (tenant-scoped CRUD) and ``routes/nw.py``
(admin-scoped CRUD) manage the same nac/ipam/ldap instance products with
mirrored logic (per the existing "MIRROR nw.py _instance_crud" convention
between those two files) — this module is the ONE place the auto-load/
auto-unload behavior lives, so both stay in sync automatically instead of by
hand-kept-parallel code.

Security note: this reuses the exact same LOAD_ROLE/UNLOAD_ROLE RPC and the
exact same tenant-admin authorization boundary (``can_bind_spoke``) that
already gates manual role-loading today — it only changes what TRIGGERS the
call (a config-bind action instead of a manual button), not who is allowed to
trigger it or what the call can do.
"""
from api import HTTPException, logger
from routes.agents import _agent_role_preflight, _load_roles_impl

# product route-prefix -> (LOAD_ROLE/UNLOAD_ROLE role name, module_type the
# resulting sub-spoke self-reports once connected)
PRODUCT_ROLE = {
    "nac-instances":  ("cppm", "nac"),
    "ipam-instances": ("netbox", "ipam"),
    "ldap-instances": ("ldap", "directory"),
}


def _sub_spoke_id(base_id, role):
    return f"{base_id}-{role}"


def _base_id(spoke_id, role):
    suffix = f"-{role}"
    return spoke_id[:-len(suffix)] if spoke_id.endswith(suffix) else spoke_id


def _is_loaded(hub, spoke_id, module_type):
    conns = getattr(hub, "active_connections", {}) or {}
    module_types = getattr(hub, "spoke_module_types", {}) or {}
    pk = hub._primary_key(spoke_id)
    return pk in conns and module_types.get(pk) == module_type


async def ensure_role_loaded(hub, chosen_spoke_id, role, module_type):
    """Resolve whatever spoke_id an operator picked — a bare base agent, or
    an already-loaded role sub-spoke (today's only valid choice) — to the
    sub-spoke id to actually bind/push config to, auto-loading the role on
    the base agent first if it isn't already loaded. Returns
    ``chosen_spoke_id`` unchanged if it's falsy (unbound instance — nothing
    to load). Raises HTTPException (mirroring ``_agent_role_preflight``/
    ``_load_roles_impl``'s existing errors) when the base agent is offline
    or the load fails."""
    if not chosen_spoke_id:
        return chosen_spoke_id

    # Already the right, connected sub-spoke — nothing to do (today's path).
    if _is_loaded(hub, chosen_spoke_id, module_type):
        return chosen_spoke_id

    # Maybe the operator picked the BASE agent id — its derived sub-spoke
    # might already be loaded and connected.
    candidate = _sub_spoke_id(chosen_spoke_id, role)
    if _is_loaded(hub, candidate, module_type):
        return candidate

    # Not loaded yet anywhere — auto-load it on the base agent the operator
    # picked. Reuses the exact preflight + LOAD_ROLE call a manual "Load
    # Role" click would make.
    base_id = chosen_spoke_id
    _agent_role_preflight(hub, base_id)
    payload = await _load_roles_impl(hub, base_id, {"role": role, "config": {}})
    if not isinstance(payload, dict) or payload.get("status") != "SUCCESS":
        msg = (payload or {}).get("message") if isinstance(payload, dict) else None
        raise HTTPException(status_code=502,
                            detail=msg or f"Could not load the {role} role on {base_id}")
    return payload.get("sub_spoke_id") or candidate


async def maybe_unload_orphaned_role(hub, sub_spoke_id, role, other_records):
    """Best-effort cleanup: after a record stops referencing ``sub_spoke_id``
    (deleted, or reassigned to a different spoke), unload the role from its
    base agent if no OTHER record in ``other_records`` still references it.
    Never raises — a cleanup failure must not block the delete/reassign that
    triggered it; logs and moves on."""
    if not sub_spoke_id:
        return
    still_used = any(isinstance(r, dict) and r.get("spoke_id") == sub_spoke_id
                     for r in other_records)
    if still_used:
        return
    base_id = _base_id(sub_spoke_id, role)
    if base_id == sub_spoke_id:
        return  # doesn't look like a role sub-spoke id — nothing we own to unload
    if hub._primary_key(base_id) not in (getattr(hub, "active_connections", {}) or {}):
        return  # base agent offline — nothing we can do right now
    try:
        await hub.request_response(base_id, "UNLOAD_ROLE", {"role": role}, timeout=60.0)
    except Exception as e:  # noqa: BLE001
        logger.warning("role_pool: auto-unload %s on %s failed: %s", role, base_id, e)
