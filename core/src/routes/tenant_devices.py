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
# copy.deepcopy sends spokes independent copies of device records.
import copy

# Credential Vault helpers: overlay secrets at push time and keep them out of global_config.
import instance_vault
# Request/error types, the hub message builder, tenant access rules, logger and uuid,
# all re-exported by the api module.
from api import (
    HTTPException, Request, _hub_msg, access, logger, uuid,
)
# Shared address validator so tenant and admin network-device edits accept the same values.
from routes.nw import validate_nw_address
# Works out a spoke's module type the same way the admin spoke list does.
from routes.setup import _module_type_for
# Role auto-load/unload helpers shared with the admin CRUD in nw.py.
from routes.role_pool import PRODUCT_ROLE, ensure_role_loaded, maybe_unload_orphaned_role


# String values that mean "off" when a flag was stored as text; "" counts as off too.
_FALSEY = {"0", "false", "no", "off", "none", "null", ""}


def _as_bool(value, default=True):
    """Coerce a stored/relayed config flag to a real bool WITHOUT the
    ``bool("false") is True`` trap. ``verify_ssl`` can be persisted as a string
    ("false"/"0") by an older UI, a hand-edited config, or a stringifying relay;
    pushing that verbatim let the cppm spoke re-enable TLS verification on a
    self-signed ClearPass and 502 every call. Mirror of cppm ``client._as_bool``
    — keep the two in sync. ``None``/absent → ``default``."""
    # Missing flag: use the caller's default.
    if value is None:
        return default
    # Strings are compared against the "off" words, ignoring case and whitespace.
    if isinstance(value, str):
        return value.strip().lower() not in _FALSEY
    # Anything else (bool, int) uses normal truthiness.
    return bool(value)


# Per-product descriptor. ``key`` is the global_config storage list; ``resp`` is
# the JSON response key the WebUI reads; ``payload_key`` is the POST body
# wrapper; ``kind`` is the human label for error messages; ``push`` selects the
# spoke-config push strategy (see _push_record); ``payload_fn`` projects the
# spoke-side config for instance products. The instance payload projections
# MIRROR nw.py ``_instance_crud`` — keep the two in sync.
# ClearPass (NAC) spoke config: API host and credentials, with verify_ssl forced to a real bool.
_NAC_PAYLOAD = lambda i: {  # noqa: E731
    "host": i.get("host"), "client_id": i.get("client_id"),
    "client_secret": i.get("client_secret"), "user": i.get("user"),
    "password": i.get("password"), "verify_ssl": _as_bool(i.get("verify_ssl"), True),
}
# NetBox (IPAM) spoke config: URL, token and TLS-verify flag in the spoke's key names.
_IPAM_PAYLOAD = lambda i: {  # noqa: E731
    "netbox_url": i.get("url"), "api_token": i.get("api_token"),
    "netbox_verify_ssl": i.get("verify_ssl"),
}
# LDAP (directory) spoke config, in the env-style key names the ldap spoke expects.
_LDAP_PAYLOAD = lambda i: {  # noqa: E731
    "LDAP_SERVER_URL": i.get("server_url"), "LDAP_BASE_DN": i.get("base_dn"),
    "LDAP_ADMIN_DN": i.get("admin_dn"), "LDAP_ADMIN_PW": i.get("admin_pw"),
}

# One entry per URL route segment; register() below creates list/add/update/delete for each.
_PRODUCTS = {
    "firewalls":      {"key": "firewalls",      "resp": "firewalls",  "payload_key": "firewall", "kind": "firewall",        "push": "firewall"},
    "nw-devices":     {"key": "nw_devices",     "resp": "nw_devices", "payload_key": "device",   "kind": "network device",  "push": "nw"},
    "nac-instances":  {"key": "nac_instances",  "resp": "instances",  "payload_key": "instance", "kind": "NAC connection",  "push": "instance", "payload_fn": _NAC_PAYLOAD},
    "ipam-instances": {"key": "ipam_instances", "resp": "instances",  "payload_key": "instance", "kind": "IPAM connection", "push": "instance", "payload_fn": _IPAM_PAYLOAD},
    "ldap-instances": {"key": "ldap_instances", "resp": "instances",  "payload_key": "instance", "kind": "directory",       "push": "instance", "payload_fn": _LDAP_PAYLOAD},
    "dns-instances":  {"key": "dns_instances",  "resp": "instances",  "payload_key": "instance", "kind": "DNS connection",  "push": None},
    "dhcp-instances": {"key": "dhcp_instances", "resp": "instances",  "payload_key": "instance", "kind": "DHCP connection", "push": None},
}

# Allowed network-device object types; anything else is rejected on add.
_NW_OBJECT_TYPES = ("aos_switch", "cx_switch", "ex_switch", "gateway", "ipmi")


def register(app, hub, ctx):
    """Register the ``/tenant/devices/*`` CRUD routes (one set per product)."""
    # Session lookup helper used by every route below.
    _session_user = ctx._session_user

    def _acting_tenants(sess):
        """Return the tenant ids assigned to the session's user ([] if none)."""
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
        """Return the stored record list for a product (``[]`` when none exist yet)."""
        return hub.state.system_state.get("global_config", {}).get(prod["key"], []) or []

    def _find(prod, rid):
        """Return the record with id ``rid`` from a product's list, or None."""
        # Linear scan is fine: device lists are small.
        for r in _store(prod):
            if isinstance(r, dict) and r.get("id") == rid:
                return r
        return None

    def _save(prod, records):
        """Replace a product's record list in global_config and mark state for saving."""
        # Write the list back into global_config (creating it if missing) and flag it dirty.
        gc = hub.state.system_state.get("global_config", {})
        gc[prod["key"]] = records
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    async def _push_record(prod, record):
        """Push a record's config to its bound spoke when connected. Mirrors each
        product's ``/setup`` push: firewall → the spoke's whole firewall list
        (hub.opn_config_for_spoke, as on reconnect); nw → the
        bound fleet slice; instance → UPDATE_CONFIG(payload_fn(record)); dns/dhcp
        → save-only (no push). Returns True when a message was sent."""
        # Only push when the record is bound to a spoke that is connected right now.
        spoke_id = (record or {}).get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # The product's push strategy decides what gets sent.
        mode = prod.get("push")
        if mode == "firewall":
            # Every firewall bound to the spoke (e.g. both boxes of an HA
            # pair), vault secrets resolved; sending only this record would
            # leave the spoke with one box until it reconnects.
            config = await hub.opn_config_for_spoke(spoke_id)
            await hub.send_to_spoke(_hub_msg(spoke_id, "UPDATE_CONFIG", config))
            return True
        # Network devices: send the spoke its whole device slice.
        if mode == "nw":
            # Re-push the spoke's device slice (bound-to-it, else unbound) so it
            # reflects the current fleet — mirrors nw.py _nw_push_fleet.
            devices = _store(prod)
            # Devices bound to this spoke; if none, the spoke manages the unbound devices instead.
            mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
            if not mine:
                mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
            # Fill in vault secrets, then send independent copies.
            mine = await instance_vault.overlay_many(hub, mine, prod["key"])
            payload = {"devices": [copy.deepcopy(d) for d in mine]}
            await hub.send_to_spoke(_hub_msg(spoke_id, "UPDATE_CONFIG", payload))
            return True
        # Coordinator instances: send the projected spoke-side config.
        if mode == "instance":
            fn = prod.get("payload_fn")
            # Fill in vault secrets, then build the spoke payload.
            record = await instance_vault.overlay(hub, record, prod["key"])
            payload = fn(record) if fn else None
            # No projection or empty payload means there is nothing to send.
            if not payload:
                return False
            await hub.send_to_spoke(_hub_msg(spoke_id, "UPDATE_CONFIG", payload))
            return True
        # Products with no push strategy (dns/dhcp) are save-only.
        return False

    def _bind_gate(sess, prod, spoke_id):
        """Enforce the tenant-bind rule for a NEW record and return the tenant_id
        to stamp. Tenant-admin → must bind to an own-tenant spoke (403 otherwise),
        record homed to that spoke's tenant. Global Admin → unrestricted; record
        tenant defaults to the bound spoke's tenant (or blank when unbound)."""
        # Non-admins must be tenant-admins and must bind to a spoke of their own tenant.
        if not access.is_admin(sess):
            if not access.is_tenant_admin(sess):
                raise HTTPException(status_code=403, detail=f"Tenant-admin access required to add a {prod['kind']}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403, detail=f"You can only bind a {prod['kind']} to a spoke assigned to your tenant")
        # The record's tenant follows the bound spoke; unbound records get no tenant.
        return (hub.state.get_spoke_tenant(spoke_id) or "") if spoke_id else ""

    # Spokes the caller can bind new devices to.
    @app.get("/tenant/devices/spokes", operation_id="tdev_bindable_spokes")
    async def _bindable_spokes(request: Request):
        """Approved spokes the caller may bind a device to — a tenant-admin's OWN
        tenant spokes only (access.can_bind_spoke), a Global Admin's every
        approved spoke. Shaped like /setup/pending_spokes (spoke_id/display_name/
        approved/module_type/tenant_id) so the WebUI spoke dropdown
        (loadApprovedSpokes) consumes it unchanged."""
        # Read the session and the hub's known spokes, display names and metadata.
        sess = _session_user(request)
        known = hub.state.system_state.get("known_modules", []) or []
        names = hub.state.system_state.get("module_names", {}) or {}
        meta = hub.state.system_state.get("module_metadata", {}) or {}
        out = []
        # Build one row per approved spoke the caller may bind to.
        for sid in known:
            # Skip spokes not yet approved.
            if not hub.approved_modules.get(hub._primary_key(sid), False):
                continue
            # Skip spokes outside the caller's own tenant(s).
            if not access.can_bind_spoke(hub, sess, sid):
                continue
            # Metadata holds the install guid and role/parent info for sub-spokes.
            m = meta.get(sid, {}) or {}
            # Row shape matches /setup/pending_spokes so the WebUI dropdown can reuse it.
            out.append({
                "spoke_id": sid,
                "display_name": names.get(sid, sid),
                "approved": True,
                "module_type": _module_type_for(hub, sid),
                "tenant_id": hub.state.get_spoke_tenant(sid) or "",
                # B4: mirror /setup/pending_spokes so the WebUI spoke dropdown +
                # Spokes & Agents page share one guid-keyed shape (``spoke_id``
                # is the guid once armed; ``spoke_guid``/``install_uuid`` are the
                # explicit guid for display + consistency hardening).
                "spoke_guid": m.get("install_uuid", ""),
                "install_uuid": m.get("install_uuid", ""),
                # B4: explicit parent linkage for role sub-spokes (see setup.py
                # _aggregate_spokes). Resolved to the parent's current primary
                # key so it matches the parent row's ``spoke_id``.
                "parent_spoke_id": (hub._primary_key(m.get("parent_name", ""))
                                    if m.get("parent_name") else ""),
                "role_name": m.get("role_name", ""),
            })
        return {"spokes": out}

    # Spokes the caller can SEE (own plus shared), used by the WebUI navigation.
    @app.get("/tenant/spokes", operation_id="tdev_visible_spokes")
    async def _visible_spokes(request: Request):
        """Approved spokes VISIBLE to the caller — a tenant-admin's OWN-tenant
        AND shared-tenant approved spokes (access.spoke_visible_to_session), a
        Global Admin's every approved spoke. Shaped like /setup/pending_spokes so
        the WebUI left-nav builder (_rebuildMainNav) consumes it unchanged.

        Distinct from /tenant/devices/spokes: that one uses can_bind_spoke
        (own-tenant ONLY — for the Add-device dropdown), which excludes SHARED
        spokes; the nav must ALSO show shared modules, so this endpoint mirrors
        the frontend _spokeVisibleToTenant (own + shared) instead.

        Reuses the CANONICAL /setup/pending_spokes aggregation (_aggregate_spokes)
        rather than hand-rolling a parallel row build: that guarantees the exact
        same ``module_type`` derivation the admin nav uses (so a module_type that
        lights the admin's menu lights the tenant-admin's identically) AND picks
        up orphan approved spokes that never mirrored into ``known_modules`` — a
        hand-rolled ``known_modules`` walk would silently miss both. The ONLY
        difference from the admin endpoint is the per-row visibility filter."""
        # Read the session, then build rows via the same aggregation the admin endpoint uses.
        sess = _session_user(request)
        from routes.setup import _aggregate_spokes  # lazy: avoid import cycle
        payload = await _aggregate_spokes(hub)
        # Keep approved spokes the caller is allowed to see.
        rows = (payload or {}).get("spokes", []) or []
        out = [r for r in rows
               if r.get("approved")
               and access.spoke_visible_to_session(sess, r.get("tenant_id") or "")]
        # Shared spokes of a module the tenant has its own of are hidden.
        if not access.is_admin(sess):
            tid = access.request_effective_tenant(sess, request)
            out = [r for r in out
                   if access.spoke_owner_tenant(hub, r.get("spoke_id"))
                   or not access.tenant_left_shared(hub, tid, r.get("module_type") or "")]
        # Return the filtered rows in the admin endpoint's shape.
        return {"spokes": out}

    def _register_product(route, prod):
        """Register list/add/update/delete routes for one product under /tenant/devices/<route>."""
        # URL base path and a route-safe suffix for unique OpenAPI operation ids.
        base = f"/tenant/devices/{route}"
        op = route.replace("-", "_")

        # List the caller's records of this product.
        @app.get(base, operation_id=f"tdev_list_{op}")
        async def _list_route(request: Request, _prod=prod):
            """List only the records the caller owns (their tenant(s))."""
            # Filter the shared store down to records the caller owns.
            sess = _session_user(request)
            items = [r for r in _store(_prod) if isinstance(r, dict) and _owns(sess, r)]
            return {_prod["resp"]: items}

        # Create a new record of this product.
        @app.post(base, operation_id=f"tdev_add_{op}")
        async def _add_route(request: Request, _prod=prod):
            """Add a record bound to an own-tenant spoke; push to the spoke."""
            # Any unexpected failure below becomes a 500; our own HTTP errors pass through.
            try:
                # Read the body and pull out the record under the product's wrapper key.
                data = await request.json()
                rec = data.get(_prod["payload_key"], {}) or {}
                # Every record needs a name.
                if not rec.get("name"):
                    raise HTTPException(status_code=400, detail="Missing name")
                # Firewalls also need a model.
                if _prod["key"] == "firewalls" and not rec.get("model"):
                    raise HTTPException(status_code=400, detail="Missing firewall model")
                # Network devices need a known object type and a valid address.
                if _prod["key"] == "nw_devices":
                    if not rec.get("object_type"):
                        raise HTTPException(status_code=400, detail="Missing object_type")
                    if rec.get("object_type") not in _NW_OBJECT_TYPES:
                        raise HTTPException(status_code=400, detail="Invalid object_type")
                    validate_nw_address(rec.get("address"))
                # Who is acting and which spoke they chose.
                sess = _session_user(request)
                spoke_id = rec.get("spoke_id")
                # tenant_id is server-assigned from the bound spoke — never trust
                # a client-supplied tenant on the way in. Authorize against
                # whatever the operator picked (base agent OR an already-loaded
                # role sub-spoke) BEFORE any auto-load below, since a freshly
                # auto-loaded sub-spoke has no tenant of its own yet — the base
                # agent's already-established tenant is the real source of truth.
                rec["tenant_id"] = _bind_gate(sess, _prod, spoke_id)
                if spoke_id and route in PRODUCT_ROLE:
                    # Auto-load the matching coordinator role if the operator
                    # picked a bare base agent rather than an already-loaded
                    # role sub-spoke — removes the separate manual "Load Role"
                    # step. Resolves to the sub-spoke id actually pushed to.
                    role, module_type = PRODUCT_ROLE[route]
                    spoke_id = await ensure_role_loaded(hub, spoke_id, role, module_type)
                    rec["spoke_id"] = spoke_id
                # Check any vault reference is one the caller may use, then drop inline secrets so
                # they
                # are never stored in global_config.
                await instance_vault.validate_ref(
                    hub, rec, sess, is_admin=access.is_admin(sess), storage_key=_prod["key"])
                instance_vault.strip_inline_secrets(rec, _prod["key"])
                # Give the record an id if the client did not supply one.
                if "id" not in rec:
                    rec["id"] = str(uuid.uuid4())
                # Append to the shared store and save.
                records = _store(_prod)
                records.append(rec)
                _save(_prod, records)
                # Push to the bound spoke; "partial_success" tells the UI it saved but did not push.
                pushed = await _push_record(_prod, rec)
                return {"status": "ok" if pushed else "partial_success",
                        _prod["payload_key"]: rec, "pushed": pushed}
            # Re-raise our own HTTP errors unchanged.
            except HTTPException:
                raise
            # Anything else is logged with a traceback and reported as 500.
            except Exception as e:  # noqa: BLE001
                logger.exception("tenant add_device failed (%s)", route)
                raise HTTPException(status_code=500, detail=str(e))

        # Update one record the caller owns.
        @app.put(base + "/{rid}", operation_id=f"tdev_update_{op}")
        async def _update_route(rid: str, request: Request, _prod=prod):
            """Update an OWNED record; re-validate the bind if the spoke changes."""
            # Any unexpected failure below becomes a 500; our own HTTP errors pass through.
            try:
                # Read the changes (under "config") and find the record.
                data = await request.json()
                upd = dict(data.get("config", {}) or {})
                sess = _session_user(request)
                rec = _find(_prod, rid)
                # Missing or not owned look the same, so ids never leak across tenants.
                if rec is None or not _owns(sess, rec):
                    raise HTTPException(status_code=404, detail="Not found")
                # A tenant can never re-home a record to another tenant, so drop
                # any client-supplied tenant_id. If the bound spoke changes,
                # re-run the bind gate (which re-stamps tenant_id).
                upd.pop("tenant_id", None)
                new_spoke = upd.get("spoke_id")
                old_spoke = rec.get("spoke_id")
                # Spoke changed: re-check the bind and, for coordinator products, auto-load the
                # role.
                if new_spoke and new_spoke != old_spoke:
                    upd["tenant_id"] = _bind_gate(sess, _prod, new_spoke)
                    if route in PRODUCT_ROLE:
                        role, module_type = PRODUCT_ROLE[route]
                        new_spoke = await ensure_role_loaded(hub, new_spoke, role, module_type)
                        upd["spoke_id"] = new_spoke
                # Validate the effective (post-merge) address BEFORE mutating the
                # stored record, so a rejected edit can't blank/corrupt a good
                # device (mirrors nw.py update_nw_device).
                if _prod["key"] == "nw_devices":
                    effective_addr = (upd["address"] if "address" in upd
                                      else rec.get("address"))
                    validate_nw_address(effective_addr)
                # Apply the changes, re-check vault refs, drop inline secrets, and save.
                rec.update(upd)
                await instance_vault.validate_ref(
                    hub, rec, sess, is_admin=access.is_admin(sess), storage_key=_prod["key"])
                instance_vault.strip_inline_secrets(rec, _prod["key"])
                _save(_prod, _store(_prod))
                # Push the updated config to the (possibly new) bound spoke.
                # Moved off a spoke: the old one is re-sent its list (as on
                # reconnect), and an unbind has no new spoke to push to.
                moved = _prod.get("push") == "firewall" and old_spoke and old_spoke != rec.get("spoke_id")
                pushed = True if moved and not rec.get("spoke_id") else await _push_record(_prod, rec)
                if moved:
                    pushed = await _push_record(_prod, {"spoke_id": old_spoke}) and pushed
                # If the record moved off a role sub-spoke, unload that role when nothing else uses
                # it.
                if route in PRODUCT_ROLE and old_spoke and old_spoke != rec.get("spoke_id"):
                    role, _mt = PRODUCT_ROLE[route]
                    await maybe_unload_orphaned_role(hub, old_spoke, role, _store(_prod))
                return {"status": "ok" if pushed else "partial_success", "pushed": pushed}
            # Re-raise our own HTTP errors unchanged.
            except HTTPException:
                raise
            # Anything else is logged with a traceback and reported as 500.
            except Exception as e:  # noqa: BLE001
                logger.exception("tenant update_device failed (%s)", route)
                raise HTTPException(status_code=500, detail=str(e))

        # Delete one record the caller owns.
        @app.delete(base + "/{rid}", operation_id=f"tdev_delete_{op}")
        async def _delete_route(rid: str, request: Request, _prod=prod):
            """Delete an OWNED record (404 for a record outside the caller's tenant)."""
            # Look up the record; missing or not owned is reported as 404.
            sess = _session_user(request)
            rec = _find(_prod, rid)
            if rec is None or not _owns(sess, rec):
                raise HTTPException(status_code=404, detail="Not found")
            # Remember its spoke, then save the list without it.
            spoke_id = rec.get("spoke_id")
            records = [r for r in _store(_prod)
                       if not (isinstance(r, dict) and r.get("id") == rid)]
            _save(_prod, records)
            # nw/firewall: re-push the (now-smaller) list so the bound spoke drops it.
            # (nw has done this since before; its unbound fallback is why a nw
            # move is not re-pushed to the old spoke as a firewall move is.)
            pushed = False
            if _prod.get("push") in ("nw", "firewall") and spoke_id and hub._primary_key(spoke_id) in hub.active_connections:
                pushed = await _push_record(_prod, {"spoke_id": spoke_id})
            # Unload the role from the spoke if no remaining record still uses it.
            if route in PRODUCT_ROLE and spoke_id:
                role, _mt = PRODUCT_ROLE[route]
                await maybe_unload_orphaned_role(hub, spoke_id, role, records)
            return {"status": "ok", "message": f"{_prod['kind']} deleted.", "pushed": pushed}

    # Register the route set for every product.
    for _route, _prod in _PRODUCTS.items():
        _register_product(_route, _prod)
