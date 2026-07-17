"""Tenant-scoped device management routes (``/tenant/devices/*``).

A **tenant-admin** manages the firewall / network-device / NAC / IPAM /
directory / DNS / DHCP records bound to their OWN tenant(s), without the
Global-Admin-only ``/setup/*`` surface. Every handler derives the acting tenant
set from the SESSION and refuses to read or mutate any record whose ``tenant_id``
is outside it — so there is no insecure-direct-object-reference path: a record
id belonging to another tenant is indistinguishable from a missing one (404),
and the delete/update handlers never take a client-supplied tenant.

Storage is shared with the ``/setup/*`` CRUD (the same ``global_config`` lists),
so an admin and a tenant-admin see a consistent world; only the visibility and
mutation SCOPE differ. Simulations are intentionally excluded (their tenant
model is handled by the cs module).

Route shapes mirror ``/setup/*`` exactly (``…/firewalls``, ``…/nw-devices``,
``…/{nac,ipam,ldap,dns,dhcp}-instances``) so the WebUI shares one device driver
(``DEVICE_TYPES``) and only swaps the base path. The middleware gate in
``api.py`` restricts the whole ``/tenant/*`` namespace to tenant-admin (or
Global Admin); this module enforces per-record ownership on top of that.
"""
import copy

from api import (
    HTTPException, Request, _hub_msg, access, logger, uuid,
)


# Per-product descriptor. ``key`` is the global_config storage list; ``resp`` is
# the JSON response key the WebUI reads; ``payload_key`` is the POST body
# wrapper; ``kind`` is the human label for error messages; ``push`` selects the
# spoke-config push strategy (see _push_record); ``payload_fn`` projects the
# spoke-side config for instance products. The instance payload projections
# MIRROR nw.py ``_instance_crud`` — keep the two in sync.
_NAC_PAYLOAD = lambda i: {  # noqa: E731
    "host": i.get("host"), "client_id": i.get("client_id"),
    "client_secret": i.get("client_secret"), "user": i.get("user"),
    "password": i.get("password"),
}
_IPAM_PAYLOAD = lambda i: {  # noqa: E731
    "netbox_url": i.get("url"), "api_token": i.get("api_token"),
    "netbox_verify_ssl": i.get("verify_ssl"),
}
_LDAP_PAYLOAD = lambda i: {  # noqa: E731
    "LDAP_SERVER_URL": i.get("server_url"), "LDAP_BASE_DN": i.get("base_dn"),
    "LDAP_ADMIN_DN": i.get("admin_dn"), "LDAP_ADMIN_PW": i.get("admin_pw"),
}

_PRODUCTS = {
    "firewalls":      {"key": "firewalls",      "resp": "firewalls",  "payload_key": "firewall", "kind": "firewall",        "push": "firewall"},
    "nw-devices":     {"key": "nw_devices",     "resp": "nw_devices", "payload_key": "device",   "kind": "network device",  "push": "nw"},
    "nac-instances":  {"key": "nac_instances",  "resp": "instances",  "payload_key": "instance", "kind": "NAC connection",  "push": "instance", "payload_fn": _NAC_PAYLOAD},
    "ipam-instances": {"key": "ipam_instances", "resp": "instances",  "payload_key": "instance", "kind": "IPAM connection", "push": "instance", "payload_fn": _IPAM_PAYLOAD},
    "ldap-instances": {"key": "ldap_instances", "resp": "instances",  "payload_key": "instance", "kind": "directory",       "push": "instance", "payload_fn": _LDAP_PAYLOAD},
    "dns-instances":  {"key": "dns_instances",  "resp": "instances",  "payload_key": "instance", "kind": "DNS connection",  "push": None},
    "dhcp-instances": {"key": "dhcp_instances", "resp": "instances",  "payload_key": "instance", "kind": "DHCP connection", "push": None},
}

_NW_OBJECT_TYPES = ("aos_switch", "cx_switch", "ex_switch", "gateway")


def register(app, hub, ctx):
    """Register the ``/tenant/devices/*`` CRUD routes (one set per product)."""
    _session_user = ctx._session_user

    def _acting_tenants(sess):
        return (sess or {}).get("user", {}).get("tenants") or []

    def _owns(sess, record):
        """Strictly-own manageability. Global Admin → any record; tenant-admin →
        only a record whose ``tenant_id`` is one of their assigned tenants — NOT
        the shared tenant (shared infra is admin-managed, matching
        ``access.can_bind_spoke``). This is the anti-IDOR gate: a record failing
        it is treated as not-found so existence never leaks across tenants."""
        if access.is_admin(sess):
            return True
        tid = (record or {}).get("tenant_id") or ""
        return bool(tid) and tid in _acting_tenants(sess)

    def _store(prod):
        return hub.state.system_state.get("global_config", {}).get(prod["key"], []) or []

    def _find(prod, rid):
        for r in _store(prod):
            if isinstance(r, dict) and r.get("id") == rid:
                return r
        return None

    def _save(prod, records):
        gc = hub.state.system_state.get("global_config", {})
        gc[prod["key"]] = records
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    async def _push_record(prod, record):
        """Push a record's config to its bound spoke when connected. Mirrors each
        product's ``/setup`` push: firewall → UPDATE_CONFIG(record); nw → the
        bound fleet slice; instance → UPDATE_CONFIG(payload_fn(record)); dns/dhcp
        → save-only (no push). Returns True when a message was sent."""
        spoke_id = (record or {}).get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            return False
        mode = prod.get("push")
        if mode == "firewall":
            await hub.send_to_spoke(_hub_msg(spoke_id, "UPDATE_CONFIG", record))
            return True
        if mode == "nw":
            # Re-push the spoke's device slice (bound-to-it, else unbound) so it
            # reflects the current fleet — mirrors nw.py _nw_push_fleet.
            devices = _store(prod)
            mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
            if not mine:
                mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
            payload = {"devices": [copy.deepcopy(d) for d in mine]}
            await hub.send_to_spoke(_hub_msg(spoke_id, "UPDATE_CONFIG", payload))
            return True
        if mode == "instance":
            fn = prod.get("payload_fn")
            payload = fn(record) if fn else None
            if not payload:
                return False
            await hub.send_to_spoke(_hub_msg(spoke_id, "UPDATE_CONFIG", payload))
            return True
        return False

    def _bind_gate(sess, prod, spoke_id):
        """Enforce the tenant-bind rule for a NEW record and return the tenant_id
        to stamp. Tenant-admin → must bind to an own-tenant spoke (403 otherwise),
        record homed to that spoke's tenant. Global Admin → unrestricted; record
        tenant defaults to the bound spoke's tenant (or blank when unbound)."""
        if not access.is_admin(sess):
            if not access.is_tenant_admin(sess):
                raise HTTPException(status_code=403, detail=f"Tenant-admin access required to add a {prod['kind']}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403, detail=f"You can only bind a {prod['kind']} to a spoke assigned to your tenant")
        return (hub.state.get_spoke_tenant(spoke_id) or "") if spoke_id else ""

    # Offline-spoke module_type fallback (mirror setup.py get_all_spokes_status /
    # _module_type_for): live registration wins, then the persisted metadata,
    # then a spoke_id-prefix guess so a disconnected spoke still labels.
    _PREFIX_MODULE = {
        "pxmx": "hypervisor", "opn": "firewall", "cppm": "nac",
        "cs": "simulation", "netbox": "ipam", "ldap": "directory",
        "dns": "dns", "dhcp": "dhcp", "nw": "nw",
    }

    def _module_type_for(sid):
        mt = hub.spoke_module_types.get(sid)
        if mt:
            return mt
        meta = (hub.state.system_state.get("module_metadata", {}) or {}).get(sid, {}) or {}
        if meta.get("module_type"):
            return meta["module_type"]
        for prefix, fallback in _PREFIX_MODULE.items():
            if sid == prefix or sid.startswith(prefix + "-"):
                return fallback
        return None

    @app.get("/tenant/devices/spokes", operation_id="tdev_bindable_spokes")
    async def _bindable_spokes(request: Request):
        """Approved spokes the caller may bind a device to — a tenant-admin's OWN
        tenant spokes only (access.can_bind_spoke), a Global Admin's every
        approved spoke. Shaped like /setup/pending_spokes (spoke_id/display_name/
        approved/module_type/tenant_id) so the WebUI spoke dropdown
        (loadApprovedSpokes) consumes it unchanged."""
        sess = _session_user(request)
        known = hub.state.system_state.get("known_modules", []) or []
        names = hub.state.system_state.get("module_names", {}) or {}
        out = []
        for sid in known:
            if not hub.approved_modules.get(sid, False):
                continue
            if not access.can_bind_spoke(hub, sess, sid):
                continue
            out.append({
                "spoke_id": sid,
                "display_name": names.get(sid, sid),
                "approved": True,
                "module_type": _module_type_for(sid),
                "tenant_id": hub.state.get_spoke_tenant(sid) or "",
            })
        return {"spokes": out}

    def _register_product(route, prod):
        base = f"/tenant/devices/{route}"
        op = route.replace("-", "_")

        @app.get(base, operation_id=f"tdev_list_{op}")
        async def _list_route(request: Request, _prod=prod):
            """List only the records the caller owns (their tenant(s))."""
            sess = _session_user(request)
            items = [r for r in _store(_prod) if isinstance(r, dict) and _owns(sess, r)]
            return {_prod["resp"]: items}

        @app.post(base, operation_id=f"tdev_add_{op}")
        async def _add_route(request: Request, _prod=prod):
            """Add a record bound to an own-tenant spoke; push to the spoke."""
            try:
                data = await request.json()
                rec = data.get(_prod["payload_key"], {}) or {}
                if not rec.get("name"):
                    raise HTTPException(status_code=400, detail="Missing name")
                if _prod["key"] == "firewalls" and not rec.get("model"):
                    raise HTTPException(status_code=400, detail="Missing firewall model")
                if _prod["key"] == "nw_devices":
                    if not rec.get("object_type"):
                        raise HTTPException(status_code=400, detail="Missing object_type")
                    if rec.get("object_type") not in _NW_OBJECT_TYPES:
                        raise HTTPException(status_code=400, detail="Invalid object_type")
                sess = _session_user(request)
                spoke_id = rec.get("spoke_id")
                # tenant_id is server-assigned from the bound spoke — never trust
                # a client-supplied tenant on the way in.
                rec["tenant_id"] = _bind_gate(sess, _prod, spoke_id)
                if "id" not in rec:
                    rec["id"] = str(uuid.uuid4())
                records = _store(_prod)
                records.append(rec)
                _save(_prod, records)
                pushed = await _push_record(_prod, rec)
                return {"status": "ok" if pushed else "partial_success",
                        _prod["payload_key"]: rec, "pushed": pushed}
            except HTTPException:
                raise
            except Exception as e:  # noqa: BLE001
                logger.exception("tenant add_device failed (%s)", route)
                raise HTTPException(status_code=500, detail=str(e))

        @app.put(base + "/{rid}", operation_id=f"tdev_update_{op}")
        async def _update_route(rid: str, request: Request, _prod=prod):
            """Update an OWNED record; re-validate the bind if the spoke changes."""
            try:
                data = await request.json()
                upd = dict(data.get("config", {}) or {})
                sess = _session_user(request)
                rec = _find(_prod, rid)
                if rec is None or not _owns(sess, rec):
                    raise HTTPException(status_code=404, detail="Not found")
                # A tenant can never re-home a record to another tenant, so drop
                # any client-supplied tenant_id. If the bound spoke changes,
                # re-run the bind gate (which re-stamps tenant_id).
                upd.pop("tenant_id", None)
                new_spoke = upd.get("spoke_id")
                if new_spoke and new_spoke != rec.get("spoke_id"):
                    upd["tenant_id"] = _bind_gate(sess, _prod, new_spoke)
                rec.update(upd)
                _save(_prod, _store(_prod))
                pushed = await _push_record(_prod, rec)
                return {"status": "ok" if pushed else "partial_success", "pushed": pushed}
            except HTTPException:
                raise
            except Exception as e:  # noqa: BLE001
                logger.exception("tenant update_device failed (%s)", route)
                raise HTTPException(status_code=500, detail=str(e))

        @app.delete(base + "/{rid}", operation_id=f"tdev_delete_{op}")
        async def _delete_route(rid: str, request: Request, _prod=prod):
            """Delete an OWNED record (404 for a record outside the caller's tenant)."""
            sess = _session_user(request)
            rec = _find(_prod, rid)
            if rec is None or not _owns(sess, rec):
                raise HTTPException(status_code=404, detail="Not found")
            spoke_id = rec.get("spoke_id")
            records = [r for r in _store(_prod)
                       if not (isinstance(r, dict) and r.get("id") == rid)]
            _save(_prod, records)
            # nw: re-push the (now-smaller) fleet so the bound spoke drops it.
            pushed = False
            if _prod.get("push") == "nw" and spoke_id and spoke_id in hub.active_connections:
                pushed = await _push_record(_prod, {"spoke_id": spoke_id})
            return {"status": "ok", "message": f"{_prod['kind']} deleted.", "pushed": pushed}

    for _route, _prod in _PRODUCTS.items():
        _register_product(_route, _prod)
