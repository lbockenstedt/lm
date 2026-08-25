"""Network-devices routes + multi-instance product CRUD (_instance_crud)."""
import asyncio
import ipaddress
import time

import instance_vault
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access, get_spoke_or_503,
    logger, uuid,
)
from routes.role_pool import PRODUCT_ROLE, ensure_role_loaded, maybe_unload_orphaned_role


# ── cache-first (stale-while-revalidate) read path ───────────────────────────
# The Network Devices read routes serve the local nw cache FIRST (the JSON-
# persisted store warmed continuously by spoke poll telemetry — apply_nw_auto_
# poll) instead of blocking every page load on live SSH. A cached hit returns
# immediately; if the data is older than _NW_SERVE_MAX_AGE_S and a spoke is
# connected, a single background revalidate is kicked off (deduped) so the NEXT
# load is fresh — the spoke's own poll cadence is the primary revalidator. Only
# a cold miss (or an explicit ?refresh=1) falls through to a blocking live
# fetch. This trades a bounded staleness window for an instant, poll-free UI.
_NW_SERVE_MAX_AGE_S = 60.0

# In-flight guard so rapid navigation coalesces to at most one background
# revalidate per key (fleet: "__fleet__"; device: "<id>:<endpoint>"). The task
# set keeps a strong ref so the fire-and-forget tasks aren't GC'd mid-flight.
_NW_BG_INFLIGHT: set = set()
_NW_BG_TASKS: set = set()


def _nw_truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _nw_spawn_refresh(key, coro_factory) -> None:
    """Fire ONE background revalidate for ``key`` (deduped). ``coro_factory`` is
    a zero-arg callable returning the coroutine — built INSIDE the guard so a
    skipped spawn never leaves an un-awaited coroutine. No running loop (sync
    test path) → no-op."""
    if key in _NW_BG_INFLIGHT:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _NW_BG_INFLIGHT.add(key)

    async def _run():
        try:
            await coro_factory()
        except Exception as e:  # noqa: BLE001 - best-effort revalidate
            logger.debug("nw bg refresh [%s] failed: %s", key, e)
        finally:
            _NW_BG_INFLIGHT.discard(key)

    t = loop.create_task(_run())
    _NW_BG_TASKS.add(t)
    t.add_done_callback(_NW_BG_TASKS.discard)


async def _nw_bg_refresh_fleet(hub) -> None:
    """Whole-fleet revalidate: query every connected+approved nw spoke for the
    full inventory ({} = no tenant filter) and refresh the global fleet cache.
    Server-side (no session) — writes only the authoritative whole-fleet
    snapshot the offline/cache-first read path filters per-reader."""
    spokes = [s for s in (hub.get_all_spokes_by_type("nw") or [])
              if s in hub.active_connections and hub.approved_modules.get(s, False)]
    if not spokes:
        return
    merged, seen = [], set()
    for sid in spokes:
        try:
            result = await hub.request_response(sid, "NW_LIST_DEVICES", {}, timeout=20.0)
            env = access.unwrap_spoke(result)
            rows = env.get("data") if isinstance(env, dict) else None
            if isinstance(rows, list):
                for r in rows:
                    if isinstance(r, dict) and r.get("id") and r["id"] not in seen:
                        seen.add(r["id"])
                        merged.append(r)
        except Exception as e:  # noqa: BLE001
            logger.debug("nw bg fleet refresh: spoke %s failed: %s", sid, e)
    env = {"status": "SUCCESS", "data": merged, "message": f"{len(merged)} device(s)"}
    try:
        await hub.nw_cache_set_fleet(env)
    except Exception:  # noqa: BLE001
        logger.debug("nw bg fleet cache set failed", exc_info=True)


async def _nw_bg_refresh_device(hub, device_id, endpoint, spoke_id, spoke_cmd,
                                relay_payload, timeout) -> None:
    """Per-device endpoint revalidate: re-run the live spoke fetch and refresh
    the cache so the next cache-first serve is fresh. Best-effort; the on-demand
    poll button + spoke poll telemetry are the primary refreshers."""
    result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                        timeout=timeout)
    data = access.unwrap_spoke(result)
    await hub.nw_cache_set_device(device_id, endpoint, data)



def validate_nw_address(addr):
    """Validate a network device's management address: it must be PRESENT and a
    properly-formatted IPv4 address. Anything else — empty, a hostname, a
    partial address, or a typo'd octet like ``1721.6.1.90`` — is rejected with a
    clear 400 instead of failing opaquely on the spoke (an unresolvable value
    surfaces there as ``Name or service not known``). ``ipaddress.IPv4Address``
    enforces exactly four 0-255 octets and rejects leading-zero octets. Shared
    by the ``/setup/nw-devices`` (admin) and ``/tenant/devices/nw-devices``
    (tenant-admin) CRUD paths so both enforce the same rule."""
    a = str(addr or "").strip()
    if not a:
        raise HTTPException(status_code=400,
                            detail="Management IP address is required")
    try:
        ipaddress.IPv4Address(a)
    except ipaddress.AddressValueError:
        raise HTTPException(
            status_code=400,
            detail=f"'{a}' is not a valid IPv4 address")


def build_scan_target_pool(targets, subnets, cap):
    """Pure IPv4 host-IP pool builder for the network scanner: explicit host IPs
    (``targets``) + expanded CIDRs (``subnets``), deduped, IPv4-only, bounded to
    ``cap`` total hosts. Returns ``(ordered_ips, per_source_counts)``. Large
    prefixes are expanded host-by-host until the cap is hit (a /8 won't blow up
    the scan). Shared by ``_aggregate_scan_targets`` so the risky bounded
    expansion is unit-testable without a spoke."""
    seen = []
    seen_set = set()
    per_source = {}

    def _add(ip):
        ip = str(ip or "").split("/")[0].strip()
        if not ip or ip in seen_set:
            return False
        try:
            if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                return False
        except ValueError:
            return False
        seen_set.add(ip)
        seen.append(ip)
        return True

    c = 0
    for t in (targets or []):
        if len(seen) >= cap:
            break
        if _add(t):
            c += 1
    if c:
        per_source["explicit"] = c

    c = 0
    for s in (subnets or []):
        if len(seen) >= cap:
            break
        try:
            net = ipaddress.ip_network(str(s).strip(), strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        hosts = net.hosts() if net.prefixlen < 31 else iter([net.network_address])
        for host in hosts:
            if len(seen) >= cap:
                break
            if _add(str(host)):
                c += 1
    if c:
        per_source["subnets"] = c
    return seen, per_source


def _nw_norm_mac(mac):
    """Lowercase hex-only MAC for comparison (drops ``:``/``-``/``.``). Empty
    string for anything without 12 hex digits so a blank never false-matches."""
    h = "".join(ch for ch in str(mac or "").lower() if ch in "0123456789abcdef")
    return h if len(h) == 12 else ""


def correlate_nw_records(devices, device_cache, ip=None, mac=None):
    """Pure cross-module stitch for the NW module: given the configured
    ``nw_devices`` list + the hub's per-device cache
    (``{device_id: {arp|macs|interfaces|endpoints: {"data": [...]}}}``), return
    every NW device that KNOWS about ``ip``/``mac`` — either because it IS that
    device (its mgmt address == ip → ``is_self``) or because a cached
    ARP/MAC/endpoint/interface row references the ip/mac (i.e. the host lives on
    that switch, on a specific port/VLAN).

    Used to add an ``nw`` leg to ``/api/device-detail`` so a searched IP is
    stitched to where it physically sits on the switched network. Pure (no hub,
    no I/O) so it is unit-testable without a spoke. Rows are returned verbatim
    (they already carry ``ip``/``mac``/``interface``/``vlan``)."""
    ip = (str(ip).strip() if ip else "") or None
    norm = _nw_norm_mac(mac) if mac else ""

    def _rows(entry, ep):
        env = entry.get(ep)
        data = env.get("data") if isinstance(env, dict) else None
        return data if isinstance(data, list) else []

    def _match(r):
        if ip and str(r.get("ip", "")).strip() == ip:
            return True
        if norm and _nw_norm_mac(r.get("mac", "")) == norm:
            return True
        return False

    hits = []
    for dev in (devices or []):
        if not isinstance(dev, dict):
            continue
        did = dev.get("id")
        entry = (device_cache or {}).get(did) or {}
        is_self = bool(ip and str(dev.get("address", "")).strip() == ip)
        matched = {
            "arp":        [r for r in _rows(entry, "arp") if _match(r)],
            "mac":        [r for r in _rows(entry, "macs") if _match(r)],
            "endpoints":  [r for r in _rows(entry, "endpoints") if _match(r)],
            "interfaces": [r for r in _rows(entry, "interfaces") if _match(r)],
        }
        if is_self or any(matched.values()):
            hits.append({
                "device_id":   did,
                "name":        dev.get("name"),
                "address":     dev.get("address"),
                "object_type": dev.get("object_type"),
                "tenant_id":   dev.get("tenant_id"),
                "is_self":     is_self,
                **matched,
            })
    return hits


def register(app, hub, ctx):
    """Register nw routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin
    _filter_nw = ctx._filter_nw

    def _validate_nw_address(addr):
        return validate_nw_address(addr)

    def _enforce_tenant_bind(request, cfg, kind):
        """Shared add/edit gate for tenant-scoped device/instance creation. A
        tenant-admin may bind ``cfg`` ONLY to a spoke in their own tenant (via
        ``cfg['spoke_id']``) and the record is bound to that tenant; Global Admin
        is unrestricted (record tenant defaults to the spoke's tenant). Plain
        users are rejected. Mutates ``cfg['tenant_id']`` in place. Raises 403 on
        violation."""
        sess = _session_user(request)
        spoke_id = cfg.get("spoke_id")
        if not _is_admin(sess):
            if not _is_tenant_admin(sess):
                raise HTTPException(status_code=403, detail=f"Tenant-admin access required to add a {kind}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403,
                                    detail=f"You can only bind a {kind} to a spoke assigned to your tenant")
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
        elif spoke_id and not cfg.get("tenant_id"):
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

    def _get_nw_spoke(hub):
        """The connected nw spoke id, or raise 503 (single-instance resolver)."""
        return get_spoke_or_503(hub, "nw", "Network Devices")

    def _nw_devices_for_spoke(hub, spoke_id: str):
        """The device slice a spoke should receive (bound-to-it, else unbound)."""
        devices = (hub.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
        if not mine:
            mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
        return mine

    def _project_nw_devices_for_push(devices):
        """Copy device dicts for the spoke payload (creds retained — runtime
        only). Mirrors main.py ``_project_nw_devices``."""
        import copy
        return [copy.deepcopy(d) for d in devices if isinstance(d, dict)]

    async def _nw_push_fleet(hub, spoke_id: str):
        """Re-push the bound device slice to a connected nw spoke."""
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # Overlay any per-device Credential Vault secret (password / enable
        # secret / API token / SNMP community) just before the push, so the
        # plaintext lives only in the vault, not in global_config.
        slice_ = await instance_vault.overlay_many(
            hub, _nw_devices_for_spoke(hub, spoke_id), "nw_devices")
        # Per-tenant poll knobs overlaid on the global defaults for the spoke's
        # owning tenant (see access.nw_poll_cfg_for_tenant).
        poll_cfg = access.nw_poll_cfg_for_tenant(hub, access.nw_spoke_tenant(hub, spoke_id))
        payload = {"devices": _project_nw_devices_for_push(slice_),
                   "shared_tenant_id": access.shared_tenant_id() or "",
                   **poll_cfg}
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _authz_nw_device(request, device_id, write=False):
        """Authorize + classify a per-device nw op by the device's OWNING
        tenant. Returns ``(dev, scope, spoke_id)``. Raises 404 (unknown id) /
        403 (no access). Mirrors ``_authz_firewall`` (firewall.py:17-46).

        ``scope`` folds the caller's tier with the device's tenancy
        (access.read_scope / write_scope): ``"full"`` (admin, or a device
        DEDICATED to the caller's own tenant → whole device), ``"filtered"``
        (a SHARED device → only the caller's tenant subnet slice via
        ``_filter_nw``), ``"deny"`` → 403. ``spoke_id`` resolves from the
        RECORD's ``spoke_id`` (per-tenant spokes), falling back to
        ``get_nw_spoke_for_tenant`` / ``get_nw_spoke_for_shared`` — never an
        unassigned fallback (no cross-tenant leak). Empty ``spoke_id`` → the
        caller raises 503 (device's spoke not connected)."""
        hub = app.state.hub
        devices = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        dev = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        if not dev:
            raise HTTPException(status_code=404, detail="Network device not found")
        sess = _session_user(request)
        tid = dev.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
            raise HTTPException(status_code=403,
                                detail="You do not have access to this network device")
        # Resolve the spoke from the record's spoke_id (per-tenant); if it's
        # unset/disconnected, fall back to the tenant/shared resolver (which
        # returns only a connected, approved, tenant-bound spoke — or None).
        spoke_id = dev.get("spoke_id") or ""
        if (not spoke_id
                or hub._primary_key(spoke_id) not in hub.active_connections):
            spoke_id = (hub.get_nw_spoke_for_shared()
                        if access.tenant_is_shared(tid)
                        else hub.get_nw_spoke_for_tenant(tid)) or ""
        if spoke_id and hub._primary_key(spoke_id) not in hub.active_connections:
            spoke_id = ""
        return dev, scope, spoke_id

    async def _filter_nw_optional(scope, request, data, endpoint, tenant,
                                  dedicated=False):
        """Apply the nw subnet filter ONLY when the reader is scoped or
        acting-as. A ``"full"``-scope reader (admin, or a device DEDICATED to
        the caller's own tenant) with no explicit ``?tenant=`` gets the whole
        device — preserves admin/own-tenant behavior. ``"filtered"`` (shared
        device) or an explicit ``?tenant=`` (admin acting-as) applies
        ``_filter_nw`` (shared → the viewer's session-tenant slice; acting-as
        → the named tenant's slice).

        ``dedicated`` — the device is bound to ONE tenant (not the shared
        tenant). A dedicated device's ENTIRE dataset belongs to that tenant, so
        it is never subnet-filtered: the subnet filter only makes sense on a
        SHARED device where many tenants' clients coexist and each sees only its
        own subnet slice. Without this, a dedicated gateway whose owning tenant
        has no (or non-covering) NetBox prefixes fails closed to an EMPTY view
        even though every record is legitimately theirs (mirrors the own-CPPM
        NAC bypass)."""
        if dedicated:
            return data
        if scope == "full" and not tenant:
            return data
        return await _filter_nw(request, data, endpoint, tenant)

    @app.get("/api/nw/devices")
    async def nw_list_devices(request: Request, tenant: str = None):
        """List the nw fleet, tenant-scoped. Admin → the whole fleet (all
        connected nw spokes). Non-admin → own-tenant + shared devices only
        (the shared-tenant-flag invariant); other-tenant / unassigned devices
        are admin-only. The hub config (``nw_devices``, tenant-stamped) is the
        AUTHORITATIVE visibility gate: live spoke rows are intersected with the
        reader's visible config set so a stale/leaky spoke can't surface a
        device the reader can't see (the cross-tenant leak this closes).

        Cache-first: serves the last-known whole-fleet snapshot tenant-filtered
        (``nw_cache_get_fleet_filtered``) WITHOUT blocking on live SSH — the
        cache is warmed continuously by spoke poll telemetry. When the snapshot
        is aging and a spoke is connected, a single background revalidate
        refreshes it for the next load; ``?refresh=1`` forces a live fetch. A
        cold miss with a connected spoke falls through to a blocking live fetch
        (which also seeds the cache, admin-only). No spoke + no cache → 503.
        ``?tenant=`` is accepted for signature compat (the fleet list is
        inventory, no IP to subnet-filter on)."""
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        # Authoritative visibility: the hub config is the source of truth for
        # the device list (addresses/creds/tenant_id); the spoke adds live
        # reachability. A row is visible iff its tenant_id is admin / shared /
        # the reader's own (spoke_visible_to_session).
        all_devs = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        visible = [d for d in all_devs if isinstance(d, dict)
                   and (is_admin or access.spoke_visible_to_session(sess, d.get("tenant_id", "")))]
        visible_ids = {d.get("id") for d in visible if d.get("id")}

        # The hub config ``name`` is authoritative for the DISPLAY name (it's
        # reconciled to the box's real hostname on each poll —
        # reconcile_nw_device_name). Overlay it onto the served rows so a name
        # reset shows immediately, regardless of what the spoke row / cache
        # still carries. Builds fresh row dicts (never mutates the cache).
        name_by_id = {d.get("id"): str(d.get("name")).strip()
                      for d in visible
                      if d.get("id") and str(d.get("name") or "").strip()}

        # Surface the box's identity datums (serial / base MAC / model / firmware
        # / hostname) captured on each poll, so an operator can positively ID the
        # physical device from the fleet list / detail without opening a session.
        # Pulled from the warm per-device cache (poll → device_info, mirrored to
        # the ``info`` envelope); absent until the device is first polled.
        def _device_identity(did):
            env = hub.nw_cache_get_device(did, "info")
            info = (env or {}).get("data") if isinstance(env, dict) else None
            if not isinstance(info, dict):
                return {}
            out = {}
            for k in ("serial", "mac", "model", "firmware", "hostname"):
                v = info.get(k)
                if v not in (None, ""):
                    out[k] = v
            return out

        info_by_id = {did: _device_identity(did) for did in visible_ids}

        def _overlay_names(env):
            if not isinstance(env, dict):
                return env
            rows = env.get("data")
            if isinstance(rows, list):
                def _merge(r):
                    if not isinstance(r, dict):
                        return r
                    rid = r.get("id")
                    extra = {}
                    if name_by_id.get(rid):
                        extra["name"] = name_by_id[rid]
                    extra.update(info_by_id.get(rid) or {})
                    return {**r, **extra} if extra else r
                env = {**env, "data": [_merge(r) for r in rows]}
            return env

        # Resolve the connected, approved nw spoke(s) to query for live data.
        # Admin → every connected nw spoke (whole fleet per spoke, no tenant
        # filter). Non-admin → the spoke(s) bound to the reader's own tenant(s)
        # + the shared-tenant spoke (shared devices live there); the spoke-side
        # tenant filter returns own+shared from each. No shared tenant → no
        # shared spoke (never the global fallback, which would leak the fleet).
        if is_admin:
            spokes = [s for s in (hub.get_all_spokes_by_type("nw") or [])
                      if s in hub.active_connections
                      and hub.approved_modules.get(s, False)]
            spoke_to_tid = {s: "" for s in spokes}
        else:
            spoke_to_tid = {}
            for t in ((sess or {}).get("user", {}).get("tenants") or []):
                s = hub.get_nw_spoke_for_tenant(t)
                if s:
                    spoke_to_tid[s] = t
            shared_tid = access.shared_tenant_id()
            if shared_tid:
                s = hub.get_nw_spoke_for_shared()
                if s:
                    spoke_to_tid[s] = shared_tid
            spoke_to_tid = {s: t for s, t in spoke_to_tid.items()
                            if s in hub.active_connections
                            and hub.approved_modules.get(s, False)}
            spokes = list(spoke_to_tid)

        # Cache-first: serve the last-known fleet snapshot (tenant-filtered)
        # WITHOUT blocking on live SSH, then revalidate in the background when
        # it's aging and a spoke is up. ``?refresh=1`` forces a live fetch.
        force = _nw_truthy(request.query_params.get("refresh"))
        predicate = (lambda r: is_admin
                     or access.spoke_visible_to_session(sess, r.get("tenant_id", "")))
        cached = None if force else hub.nw_cache_get_fleet_filtered(predicate)
        if cached is not None:
            out = dict(_overlay_names(dict(cached.get("devices") or {})))
            out["cached"] = True
            out["fetched_at"] = cached.get("fetched_at")
            if not spokes:
                # Offline: no live spoke for the reader's slice. The cached rows
                # still carry their LAST up/down, which is now unknowable (the
                # spoke that probes them is gone) — showing it stale would badge
                # a since-crashed box as 'up'. Flip every served row to UNKNOWN
                # (reachable=None → the UI's yellow 'unknown' badge) so the
                # operator sees "can't tell" rather than a stale green. Fresh
                # dicts — never mutate the shared cache.
                rows = out.get("data")
                if isinstance(rows, list):
                    out["data"] = [
                        {**r, "reachable": None, "latency_ms": None}
                        if isinstance(r, dict) else r
                        for r in rows
                    ]
                out["stale"] = True
                out["message"] = (
                    "Network Devices spoke offline — reachability unknown "
                    "(showing last-known inventory)")
            else:
                age = time.time() - float(cached.get("fetched_at") or 0.0)
                if age > _NW_SERVE_MAX_AGE_S:
                    _nw_spawn_refresh("__fleet__", lambda: _nw_bg_refresh_fleet(hub))
            return out

        if not spokes:
            # Cold miss AND no live spoke → nothing to serve.
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")

        # Fan out NW_LIST_DEVICES (admin: {} = whole fleet per spoke; non-admin:
        # {"tenant": tid} = own+shared from that spoke) + merge rows by id.
        merged, seen = [], set()
        for sid in spokes:
            tid = spoke_to_tid.get(sid, "")
            payload = {"tenant": tid} if tid else {}
            try:
                result = await hub.request_response(sid, "NW_LIST_DEVICES", payload,
                                                    timeout=20.0)
                env = access.unwrap_spoke(result)
                rows = env.get("data") if isinstance(env, dict) else None
                if isinstance(rows, list):
                    for r in rows:
                        if isinstance(r, dict) and r.get("id") and r["id"] not in seen:
                            seen.add(r["id"])
                            merged.append(r)
            except Exception as e:
                logger.warning("nw_list_devices: spoke %s fetch failed: %s", sid, e)

        # Authoritative gate: drop any row not in the reader's visible config
        # set (defense-in-depth against a stale/leaky spoke).
        if visible_ids:
            merged = [r for r in merged if r.get("id") in visible_ids]

        env = {"status": "SUCCESS", "data": merged,
               "message": f"{len(merged)} device(s)"}
        # The global cache holds the WHOLE fleet (last admin fetch) so the
        # offline path serves a complete, filterable snapshot — only update it
        # from a whole-fleet (admin) fetch, never a non-admin subset.
        if is_admin:
            try:
                await hub.nw_cache_set_fleet(env)
            except Exception:
                logger.debug("nw_list_devices: cache set failed", exc_info=True)
        return _overlay_names(env)

    @app.get("/api/nw/{device_id}/{endpoint}")
    async def nw_get_device_data(request: Request, device_id: str, endpoint: str,
                                 tenant: str = None):
        """Per-device nw data (info|macs|arp|interfaces|endpoints|vlans),
        tenant-gated. ``_authz_nw_device`` resolves the device record, classifies
        the read scope, and resolves the spoke from the record's ``spoke_id``
        (per-tenant) — 404 unknown, 403 other-tenant/unassigned, 503 spoke down.

        ``endpoint`` selects the device sub-resource → the NW_GET_<X> command.
        Results are subnet-filtered via ``_filter_nw`` ONLY when the reader is
        scoped (shared device → ``"filtered"``) or acting-as (``?tenant=``); a
        ``"full"``-scope reader (admin, or a device dedicated to the caller's
        own tenant) with no explicit tenant gets the whole device (preserves
        admin/own-tenant behavior). MAC/ARP/interfaces carry IPs; info does not.

        Cache-first: serves the last-known raw per-device endpoint envelope
        (scope-filtered) WITHOUT blocking on live SSH — the cache is warmed by
        spoke poll telemetry. When the entry is aging and the spoke is up, a
        single background revalidate refreshes it for the next load;
        ``?refresh=1`` (or the per-device poll button) forces a live fetch. A
        cold miss with a connected spoke falls through to a blocking live fetch
        (which also seeds the cache). The cache is gated by the same
        ``_authz_nw_device`` check, so a non-admin can't fetch another tenant's
        device cache."""
        hub = app.state.hub
        command_map = {
            "info":       "NW_GET_DEVICE_INFO",
            "macs":       "NW_GET_MAC_TABLE",
            "arp":        "NW_GET_ARP",
            "interfaces": "NW_GET_INTERFACES",
            "endpoints":  "NW_GET_ENDPOINTS",  # fused ARP+MAC unique IP/MAC list
            "vlans":      "NW_GET_VLANS",       # per-VLAN rollup
        }
        spoke_cmd = command_map.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported by nw module")
        logger.debug("relay GET /api/nw/%s/%s tenant=%s", device_id, endpoint, tenant)
        dev, scope, spoke_id = _authz_nw_device(request, device_id)
        tid = dev.get("tenant_id", "")
        # A device bound to ONE (non-shared) tenant is DEDICATED: its whole
        # dataset belongs to that tenant, so it is never subnet-filtered (the
        # subnet filter only makes sense on a SHARED device). Without this, a
        # dedicated gateway whose owning tenant has no (or non-covering) NetBox
        # prefixes fails closed to an empty view even under an explicit
        # ``?tenant=`` — mirrors the own-CPPM NAC bypass.
        dedicated = bool(tid) and not access.tenant_is_shared(tid)
        # Defense-in-depth: re-check on the spoke via the tenant filter (the
        # spoke rejects a device whose tenant_id is neither the passed tenant
        # nor the shared tenant — Stage 1).
        relay_payload = {"device_id": device_id}
        if tid:
            relay_payload["tenant"] = tid
        # endpoints/vlans run three sequential SSH gathers (arp+mac+interfaces)
        # on the spoke, so the 5s default relay timeout is far too short — give
        # them room; the single-datum views get a comfortable margin too.
        timeout = 45.0 if endpoint in ("endpoints", "vlans") else 20.0

        # Cache-first: serve the last-known endpoint value WITHOUT blocking on
        # live SSH, then revalidate in the background when it's aging and the
        # spoke is up. ``?refresh=1`` forces a live fetch (cold path below).
        force = _nw_truthy(request.query_params.get("refresh"))
        cached = None if force else hub.nw_cache_get_device(device_id, endpoint)
        if cached is not None:
            filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant, dedicated)
            fetched_at = hub.nw_cache_device_fetched_at(device_id)
            if isinstance(filtered, dict):
                filtered = dict(filtered)
                filtered["cached"] = True
                filtered["fetched_at"] = fetched_at
                if not spoke_id:
                    filtered["stale"] = True
            if spoke_id and (time.time() - fetched_at) > _NW_SERVE_MAX_AGE_S:
                _nw_spawn_refresh(
                    f"{device_id}:{endpoint}",
                    lambda: _nw_bg_refresh_device(hub, device_id, endpoint,
                                                  spoke_id, spoke_cmd, relay_payload, timeout))
            return filtered

        if not spoke_id:
            # Cold miss AND no live spoke → nothing to serve.
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        try:
            result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.nw_cache_set_device(device_id, endpoint, data)
            return await _filter_nw_optional(scope, request, data, endpoint, tenant, dedicated)
        except HTTPException:
            raise
        except Exception as e:
            # A slow/timed-out live fetch shouldn't blank the tab — serve the
            # last-known cached value (marked stale, scope-filtered) if we have
            # one, so a heavy gateway that occasionally overruns still shows data.
            cached = hub.nw_cache_get_device(device_id, endpoint)
            if cached is not None:
                logger.warning("nw_get_device_data live fetch failed (%s/%s: %s)"
                               " — serving cached", device_id, endpoint, e)
                filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant, dedicated)
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
            logger.exception("nw_get_device_data failed (%s/%s)", device_id, endpoint)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/config")
    async def nw_run_config(device_id: str, request: Request):
        """Apply a CLI/REST config snippet to a device. Body:
        ``{"commands": ["...", ...]}``. Returns the spoke's applied/errors lists.

        Tenant-scoped via ``_authz_nw_device(write=True)``: a Global Admin may
        configure any device; a tenant admin may configure devices DEDICATED to
        its own tenant (and, as a shared-infra writer, the shared device) — any
        other/unassigned device is denied. Resolves the spoke from the device
        record's ``spoke_id`` (per-tenant) so a config push lands on the spoke
        that owns the device."""
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        commands = (data or {}).get("commands", []) if isinstance(data, dict) else []
        if not isinstance(commands, list):
            raise HTTPException(status_code=400, detail="commands must be a list")
        dev, _scope, spoke_id = _authz_nw_device(request, device_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NW_RUN_CONFIG",
                                                {"device_id": device_id,
                                                 "commands": commands,
                                                 "tenant": dev.get("tenant_id", "")})
            return access.unwrap_spoke(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_run_config failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/poll")
    async def nw_poll_device(device_id: str, request: Request):
        """POLL NOW for one network device: run a full probe+info+interfaces+
        arp+mac poll on the spoke, then upsert the device + its interfaces into
        NetBox via ``NETBOX_SYNC_NW_DEVICE``. Returns the poll results + a NetBox
        push summary. Driven by the WebUI "Poll Now" button on the Devices table.

        Tenant-scoped via ``_authz_nw_device``: a Global Admin may poll any
        device; a tenant admin may poll devices it can see (own-tenant + shared);
        other/unassigned devices are denied."""
        hub = app.state.hub
        _authz_nw_device(request, device_id, write=False)  # 404/403 by tenant ownership
        try:
            result = await hub.poll_nw_device(device_id)
            # Fold the poll's rich result into the per-device cache so a later
            # page load (spoke offline) still reflects the last probe.
            if isinstance(result, dict):
                await hub.nw_cache_set_poll(device_id, result)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_poll_device failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/nw-devices")
    async def get_nw_devices(request: Request):
        hub = app.state.hub
        devices = hub.state.system_state.get("global_config", {}).get("nw_devices", [])
        # Tenant-scope the device list (shared + own visible; other/unassigned
        # admin-only). Object-level IP filtering + the write gate are unchanged.
        sess = _session_user(request)
        if not _is_admin(sess):
            devices = [d for d in devices
                       if access.spoke_visible_to_session(sess, (d or {}).get("tenant_id", ""))]
        return {"nw_devices": devices}

    @app.get("/setup/nw-poll-config")
    async def get_nw_poll_config(request: Request):
        """Module-level nw poll cadence + anti-stampede knobs. ``default_poll_interval``
        (seconds) is the fallback each nw spoke applies to any device that doesn't
        set its own (device-level always wins); null/absent → the spoke's built-in
        6h. ``poll_jitter_frac`` (0..0.9), ``max_poll_per_tick`` (1..100) and
        ``max_poll_concurrency`` (1..50) tune the spoke's stampede protection;
        null → the spoke's built-in defaults."""
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"default_poll_interval": gc.get("nw_poll_default_interval"),
                "poll_jitter_frac": gc.get("nw_poll_jitter_frac"),
                "max_poll_per_tick": gc.get("nw_poll_max_per_tick"),
                "max_poll_concurrency": gc.get("nw_poll_max_concurrency"),
                "ping_interval": gc.get("nw_ping_interval")}

    @app.post("/setup/nw-poll-config")
    async def set_nw_poll_config(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        raw = data.get("default_poll_interval")
        try:
            val = None if raw in (None, "", "null") else int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="default_poll_interval must be an integer or null")

        def _opt_num(key, cast, lo, hi):
            """Parse an optional numeric knob: null/absent → None (spoke default),
            else cast + clamp to [lo, hi]."""
            v = data.get(key)
            if v in (None, "", "null"):
                return None
            try:
                return max(lo, min(cast(v), hi))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} must be numeric or null")

        jitter = _opt_num("poll_jitter_frac", float, 0.0, 0.9)
        per_tick = _opt_num("max_poll_per_tick", int, 1, 100)
        concurrency = _opt_num("max_poll_concurrency", int, 1, 50)
        # Reachability sweep cadence: 0 disables the ICMP ping sweep, else
        # clamp to a sane [30s, 24h] band; null → the spoke's 5-min default.
        ping_raw = data.get("ping_interval")
        if ping_raw in (None, "", "null"):
            ping_interval = None
        else:
            try:
                ping_interval = int(ping_raw)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400,
                                    detail="ping_interval must be an integer or null")
            if ping_interval != 0:
                ping_interval = max(30, min(ping_interval, 86400))

        gc = hub.state.system_state.get("global_config", {})
        gc["nw_poll_default_interval"] = val
        gc["nw_poll_jitter_frac"] = jitter
        gc["nw_poll_max_per_tick"] = per_tick
        gc["nw_poll_max_concurrency"] = concurrency
        gc["nw_ping_interval"] = ping_interval
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Re-push every connected nw spoke so the new module config takes effect.
        pushed = 0
        for sid in (hub.get_all_spokes_by_type("nw") or []):
            if await _nw_push_fleet(hub, sid):
                pushed += 1
        return {"status": "ok", "default_poll_interval": val,
                "poll_jitter_frac": jitter, "max_poll_per_tick": per_tick,
                "max_poll_concurrency": concurrency,
                "ping_interval": ping_interval, "pushed": pushed}

    @app.get("/setup/nw-netbox-import")
    async def get_nw_netbox_import(request: Request):
        """NetBox→NW import config (NetBox = fleet source of truth): which NetBox
        device roles get imported into the nw fleet, object_type mapping, cadence."""
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"nw_netbox_import": gc.get("nw_netbox_import", {}) or {}}

    @app.post("/setup/nw-netbox-import")
    async def set_nw_netbox_import(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        cfg = data.get("config", data) or {}
        roles = cfg.get("roles")
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "roles": [str(r).strip() for r in (roles or []) if str(r).strip()],
            "object_type_map": dict(cfg.get("object_type_map") or {}),
            "default_object_type": str(cfg.get("default_object_type") or "gateway"),
            "interval": int(cfg.get("interval") or 900),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_netbox_import"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_netbox_import": clean}

    @app.post("/setup/nw-netbox-import/run")
    async def run_nw_netbox_import(request: Request):
        """On-demand 'Import now' — run one NetBox→NW import cycle."""
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            return await hub.run_nw_netbox_import_all()
        except Exception as e:
            logger.exception("run_nw_netbox_import failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Network scan (fingerprint discovery) ────────────────────────────────
    _SCAN_OBJECT_TYPES = ("aos_switch", "cx_switch", "ex_switch", "gateway")

    def _resolve_nw_scan_spoke(hub, sess, tenant_id, requested_spoke_id, *, allow_any=None):
        """The connected nw spoke the scan should run on. Prefer an explicit
        request spoke_id (when connected), else the tenant's nw spoke, else the
        shared nw spoke, else (``allow_any`` — admins only) any connected nw
        spoke. ``allow_any`` defaults to the session's admin status."""
        if allow_any is None:
            allow_any = _is_admin(sess)
        def _up(sid):
            return sid and hub._primary_key(sid) in hub.active_connections
        if requested_spoke_id and _up(requested_spoke_id):
            return requested_spoke_id
        sid = (hub.get_nw_spoke_for_shared() if access.tenant_is_shared(tenant_id)
               else hub.get_nw_spoke_for_tenant(tenant_id)) if tenant_id else None
        if _up(sid):
            return sid
        if allow_any:
            for s in (hub.get_all_spokes_by_type("nw") or []):
                if _up(s) and hub.approved_modules.get(s, False):
                    return s
        return ""

    async def _aggregate_scan_targets(hub, tenant_id, sources, extra_subnets,
                                      extra_targets, cap):
        """Build the candidate host-IP list for a tenant scan.

        Combines (best-effort, each source guarded):
          * explicit ``extra_targets`` (host IPs) and ``extra_subnets`` (CIDRs),
          * NetBox tenant prefixes (``netbox``) expanded to hosts,
          * NAC/DHCP/DNS known host IPs (``nac`` / ``dhcp`` / ``dns``) pulled
            from the tenant's bound spoke and parsed generically for any
            ip/ip_address/address field.
        Deduped, IPv4-only, bounded to ``cap``. Returns ``(targets, per_source)``
        where ``per_source`` counts each source's contribution (for the UI)."""
        sources = set(sources or [])
        seen, per_source = build_scan_target_pool(extra_targets, extra_subnets, cap)
        seen_set = set(seen)

        def _add(ip):
            ip = str(ip or "").split("/")[0].strip()
            if not ip or ip in seen_set or len(seen) >= cap:
                return False
            try:
                if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                    return False
            except ValueError:
                return False
            seen_set.add(ip)
            seen.append(ip)
            return True

        def _expand(cidr):
            n = 0
            try:
                net = ipaddress.ip_network(str(cidr).strip(), strict=False)
            except ValueError:
                return 0
            if not isinstance(net, ipaddress.IPv4Network):
                return 0
            hosts = net.hosts() if net.prefixlen < 31 else iter([net.network_address])
            for host in hosts:
                if len(seen) >= cap:
                    break
                if _add(str(host)):
                    n += 1
            return n

        # NetBox tenant prefixes.
        if "netbox" in sources and tenant_id and len(seen) < cap:
            try:
                prefixes = await access.fetch_tenant_prefixes(hub, tenant_id)
            except Exception:
                prefixes = []
            c = 0
            for p in (prefixes or []):
                if len(seen) >= cap:
                    break
                c += _expand(p)
            if c:
                per_source["netbox"] = c

        # NAC / DHCP / DNS host IPs (generic ip-field parse; fully guarded).
        async def _pull(source, spoke_getter, command, payload=None):
            if source not in sources or len(seen) >= cap:
                return
            try:
                sid = spoke_getter(tenant_id) if tenant_id else None
                if not sid or hub._primary_key(sid) not in hub.active_connections:
                    return
                result = await hub.request_response(sid, command, payload or {}, timeout=30.0)
                data = access.unwrap_spoke(result)
            except Exception as e:
                logger.debug("scan aggregate %s skipped: %s", source, e)
                return
            rows = []
            if isinstance(data, dict):
                for key in ("endpoints", "leases", "records", "data", "results"):
                    if isinstance(data.get(key), list):
                        rows = data[key]
                        break
            elif isinstance(data, list):
                rows = data
            c = 0
            for r in rows:
                if len(seen) >= cap:
                    break
                if not isinstance(r, dict):
                    continue
                ip = r.get("ip") or r.get("ip_address") or r.get("address") or r.get("value")
                if _add(ip):
                    c += 1
            if c:
                per_source[source] = c

        await _pull("nac", hub.get_cppm_spoke_for_tenant, "LIST_ENDPOINTS")
        await _pull("dhcp", hub.get_dhcp_spoke_for_tenant, "DHCP_LIST_LEASES")
        await _pull("dns", hub.get_dns_spoke_for_tenant, "DNS_LIST")

        return seen, per_source

    def _nw_scan_config(hub, tenant_id=None):
        """Effective scan config. Base = global admin ``nw_scan`` (Setup card).
        When ``tenant_id`` is given and that tenant has a per-tenant override
        (``nw_tenant_cfg[tenant]['scan']``), its keys win — so a tenant manages
        its own scan settings without clobbering the shared/global config."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        cfg = dict(gc.get("nw_scan", {}) or {})
        if tenant_id:
            ov = (((gc.get("nw_tenant_cfg") or {}).get(tenant_id) or {}).get("scan") or {})
            for k, v in ov.items():
                if v is not None:
                    cfg[k] = v
        cfg.setdefault("enabled", False)
        cfg.setdefault("crawl", False)
        cfg.setdefault("auto_add", False)
        cfg.setdefault("credential_ids", [])
        cfg.setdefault("ip_sources", ["netbox"])
        cfg.setdefault("tcp_ports", [22, 443, 80, 23])
        cfg.setdefault("try_snmp", True)
        cfg.setdefault("use_nmap", False)
        cfg.setdefault("max_targets", 1024)
        cfg.setdefault("concurrency", 32)
        cfg.setdefault("spoke_id", "")
        return cfg

    @app.get("/setup/nw-scan-config")
    async def get_nw_scan_config(request: Request):
        """Network-scan configuration: whether the nw spoke may scan/crawl, the
        selected scan-credential set ids, IP sources, ports + bounds. Read by the
        WebUI scan card."""
        return {"nw_scan": _nw_scan_config(app.state.hub)}

    @app.post("/setup/nw-scan-config")
    async def set_nw_scan_config(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        data = await request.json()
        cfg = data.get("config", data) or {}
        ports = cfg.get("tcp_ports")
        if isinstance(ports, str):
            ports = [p.strip() for p in ports.split(",") if p.strip()]
        try:
            ports = [int(p) for p in (ports or [22, 443, 80, 23])]
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="tcp_ports must be integers")
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "crawl": bool(cfg.get("crawl", False)),
            "auto_add": bool(cfg.get("auto_add", False)),
            "try_snmp": bool(cfg.get("try_snmp", True)),
            "use_nmap": bool(cfg.get("use_nmap", False)),
            "credential_ids": [str(x) for x in (cfg.get("credential_ids") or []) if str(x).strip()],
            "ip_sources": [str(x) for x in (cfg.get("ip_sources") or ["netbox"]) if str(x).strip()],
            "tcp_ports": ports,
            "max_targets": max(1, min(int(cfg.get("max_targets") or 1024), 4096)),
            "concurrency": max(1, min(int(cfg.get("concurrency") or 32), 128)),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_scan"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_scan": clean}

    def _nw_caller_tenant(sess, req_tenant):
        """Resolve+authorize the tenant a caller may configure. Admin: the named
        tenant or the shared tenant. Tenant-admin: only one of their own tenants.
        Raises 403/400 on violation."""
        req_tenant = str(req_tenant or "").strip()
        if _is_admin(sess):
            return req_tenant or access.shared_tenant_id() or ""
        own = ((sess or {}).get("user", {}).get("tenants")
               or [(sess or {}).get("user", {}).get("tenant_id")])
        own = [t for t in own if t]
        if req_tenant and req_tenant not in own:
            raise HTTPException(status_code=403, detail="You may only configure your own tenant")
        tid = req_tenant or (own[0] if own else "")
        if not tid:
            raise HTTPException(status_code=400, detail="No tenant resolved")
        return tid

    def _nw_scan_schedule(hub, tenant_id):
        """Per-tenant recurring-scan schedule from ``nw_tenant_cfg`` with defaults.
        ``interval_seconds`` 0/absent = off; ``dry_run`` true = preview only (no
        auto-add) even when the scan config allows adding."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        sc = (((gc.get("nw_tenant_cfg") or {}).get(tenant_id) or {}).get("scan_schedule") or {})
        return {
            "enabled": bool(sc.get("enabled", False)),
            "interval_seconds": int(sc.get("interval_seconds") or 0),
            "dry_run": bool(sc.get("dry_run", True)),
        }

    @app.get("/api/nw/tenant-config")
    async def get_nw_tenant_config(request: Request):
        """Tenant-facing NW config surface (Network → Scan tab): effective scan
        settings, poll jitter/caps/cadence, and the recurring-scan schedule for
        the caller's tenant, plus a flag per poll knob showing whether the tenant
        overrides the global admin default."""
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        tid = _nw_caller_tenant(sess, request.query_params.get("tenant"))
        gc = hub.state.system_state.get("global_config", {}) or {}
        poll_ov = (((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("poll") or {})
        eff = access.nw_poll_cfg_for_tenant(hub, tid)
        return {
            "tenant_id": tid,
            "scan": _nw_scan_config(hub, tid),
            "poll": {
                "default_interval": eff["default_poll_interval"],
                "jitter_frac": eff["poll_jitter_frac"],
                "max_per_tick": eff["max_poll_per_tick"],
                "max_concurrency": eff["max_poll_concurrency"],
                # True where the tenant overrides the global admin default.
                "overridden": {k: (poll_ov.get(k) is not None)
                               for k in ("default_interval", "jitter_frac",
                                         "max_per_tick", "max_concurrency")},
            },
            "scan_schedule": _nw_scan_schedule(hub, tid),
        }

    @app.post("/api/nw/tenant-config")
    async def set_nw_tenant_config(request: Request):
        """Persist a tenant's NW overrides. Body: ``tenant`` (admin only),
        ``scan`` (partial scan config), ``poll`` (jitter/caps/cadence; null a key
        to clear the override → inherit global), ``scan_schedule``. Re-pushes the
        tenant's connected nw spoke(s) so poll changes take effect immediately."""
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        data = await request.json()
        tid = _nw_caller_tenant(sess, data.get("tenant"))

        gc = hub.state.system_state.get("global_config", {})
        tmap = dict(gc.get("nw_tenant_cfg") or {})
        cur = dict(tmap.get(tid) or {})

        # ── scan (partial merge over the existing tenant scan override) ──
        if isinstance(data.get("scan"), dict):
            s = data["scan"]
            scan_ov = dict(cur.get("scan") or {})
            for k in ("enabled", "crawl", "auto_add", "try_snmp"):
                if k in s:
                    scan_ov[k] = bool(s[k])
            if "ip_sources" in s:
                scan_ov["ip_sources"] = [str(x) for x in (s["ip_sources"] or []) if str(x).strip()]
            if "credential_ids" in s:
                scan_ov["credential_ids"] = [str(x) for x in (s["credential_ids"] or []) if str(x).strip()]
            if "tcp_ports" in s:
                ports = s["tcp_ports"]
                if isinstance(ports, str):
                    ports = [p.strip() for p in ports.split(",") if p.strip()]
                try:
                    scan_ov["tcp_ports"] = [int(p) for p in (ports or [])]
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="tcp_ports must be integers")
            if "max_targets" in s:
                scan_ov["max_targets"] = max(1, min(int(s["max_targets"] or 1024), 4096))
            if "concurrency" in s:
                scan_ov["concurrency"] = max(1, min(int(s["concurrency"] or 32), 128))
            if "spoke_id" in s:
                scan_ov["spoke_id"] = str(s["spoke_id"] or "").strip()
            cur["scan"] = scan_ov

        # ── poll (null a key → clear override so it inherits the global) ──
        if isinstance(data.get("poll"), dict):
            p = data["poll"]
            poll_ov = dict(cur.get("poll") or {})

            def _num_or_clear(key, cast, lo, hi):
                if key not in p:
                    return
                v = p[key]
                if v in (None, "", "null"):
                    poll_ov.pop(key, None)
                    return
                try:
                    poll_ov[key] = max(lo, min(cast(v), hi))
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail=f"{key} must be numeric or null")

            _num_or_clear("default_interval", int, 0, 604800)
            _num_or_clear("jitter_frac", float, 0.0, 0.9)
            _num_or_clear("max_per_tick", int, 1, 100)
            _num_or_clear("max_concurrency", int, 1, 50)
            cur["poll"] = poll_ov

        # ── scan_schedule ──
        if isinstance(data.get("scan_schedule"), dict):
            ss = data["scan_schedule"]
            sched = dict(cur.get("scan_schedule") or {})
            if "enabled" in ss:
                sched["enabled"] = bool(ss["enabled"])
            if "interval_seconds" in ss:
                try:
                    iv = int(ss["interval_seconds"] or 0)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="interval_seconds must be an integer")
                # 0 = off; otherwise floor at 1h so a tenant can't hammer scans.
                sched["interval_seconds"] = 0 if iv <= 0 else max(3600, iv)
            if "dry_run" in ss:
                sched["dry_run"] = bool(ss["dry_run"])
            cur["scan_schedule"] = sched

        tmap[tid] = cur
        gc["nw_tenant_cfg"] = tmap
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

        # Re-push this tenant's connected nw spoke(s) so poll knobs apply now.
        pushed = 0
        md = hub.state.system_state.get("module_metadata", {}) or {}
        for sid in (hub.get_all_spokes_by_type("nw") or []):
            if (md.get(sid, {}) or {}).get("tenant_id") == tid:
                if await _nw_push_fleet(hub, sid):
                    pushed += 1
        return {"status": "ok", "tenant_id": tid, "pushed": pushed,
                "scan": _nw_scan_config(hub, tid),
                "scan_schedule": _nw_scan_schedule(hub, tid)}

    async def _execute_nw_scan(tenant_id, saved, *, sess, data):
        """Shared scan executor for BOTH the interactive route and the recurring
        scheduler. ``sess`` is the caller session for an interactive scan, or
        ``None`` for a system-initiated (scheduled) scan. Resolves the spoke,
        assembles + vault-overlays the credential sets, aggregates the tenant's
        candidate IPs, runs NW_SCAN on the spoke, then (unless dry-run) auto-adds
        the newly-identified manageable devices to the tenant fleet and re-pushes.

        Credential scoping: admin → any chosen set; tenant-admin → only sets
        visible to their session; system (``sess is None``) → only sets owned by
        this tenant (or the shared tenant). ``allow_any_spoke`` mirrors that —
        only a real admin may fall back to an unbound nw spoke."""
        system = sess is None
        allow_any = (not system) and _is_admin(sess)
        spoke_id = _resolve_nw_scan_spoke(
            hub, sess, tenant_id,
            str(data.get("spoke_id") or saved.get("spoke_id") or "").strip(),
            allow_any=allow_any)
        if not spoke_id:
            if system:
                return {"status": "skipped", "reason": "no nw spoke connected",
                        "tenant": tenant_id, "added": [], "identified": []}
            raise HTTPException(status_code=503, detail="Network Devices spoke not connected")

        # Assemble the candidate credential sets (from the request or saved
        # config), overlaying each set's vault secret just before the push.
        cred_ids = [str(x) for x in (data.get("credential_ids") or saved.get("credential_ids") or [])]
        all_sets = (hub.state.system_state.get("global_config", {}) or {}).get("nw_scan_credentials", []) or []
        chosen = [c for c in all_sets if isinstance(c, dict) and c.get("id") in set(cred_ids)]
        if system:
            shared_tid = access.shared_tenant_id()
            chosen = [c for c in chosen if c.get("tenant_id", "") in (tenant_id, shared_tid)]
        elif not _is_admin(sess):
            chosen = [c for c in chosen
                      if access.spoke_visible_to_session(sess, c.get("tenant_id", ""))]
        if not chosen:
            if system:
                return {"status": "skipped", "reason": "no accessible scan credential set",
                        "tenant": tenant_id, "added": [], "identified": []}
            raise HTTPException(status_code=400,
                                detail="Select at least one accessible scan credential set")
        overlaid = await instance_vault.overlay_many(hub, chosen, "nw_scan_credentials")
        push_creds = [{
            "id": c.get("id"), "name": c.get("name") or c.get("id"),
            "username": c.get("username") or c.get("user") or "",
            "password": c.get("password") or "",
            "enable_secret": c.get("enable_secret") or "",
            "snmp_community": c.get("snmp_community") or "",
        } for c in overlaid]

        ip_sources = data.get("ip_sources") or saved.get("ip_sources") or ["netbox"]
        cap = max(1, min(int(data.get("max_targets") or saved.get("max_targets") or 1024), 4096))
        targets, per_source = await _aggregate_scan_targets(
            hub, tenant_id, ip_sources, data.get("subnets") or [],
            data.get("targets") or [], cap)
        if not targets:
            return {"status": "ok", "message": "No candidate IPs found for this tenant.",
                    "tenant": tenant_id, "targets": 0, "sources": per_source,
                    "identified": [], "added": []}

        options = {
            "tcp_ports": saved.get("tcp_ports") or [22, 443, 80, 23],
            "try_snmp": bool(saved.get("try_snmp", True)),
            "use_nmap": bool(saved.get("use_nmap", False)),
            "concurrency": int(saved.get("concurrency") or 32),
            "crawl": bool(data.get("crawl", saved.get("crawl", False))),
            "max_targets": cap,
            "max_depth": int(data.get("max_depth") or 2),
        }
        try:
            result = await hub.request_response(
                spoke_id, "NW_SCAN",
                {"targets": targets, "credentials": push_creds, "options": options,
                 "tenant": tenant_id},
                timeout=max(60.0, min(len(targets) * 2.0, 900.0)))
            scan = access.unwrap_spoke(result)
        except Exception as e:
            logger.exception("nw scan failed (tenant=%s)", tenant_id)
            if system:
                return {"status": "error", "reason": str(e), "tenant": tenant_id,
                        "added": [], "identified": []}
            raise HTTPException(status_code=500, detail=f"scan failed: {e}")

        identified = (scan or {}).get("identified", []) if isinstance(scan, dict) else []

        # Existing addresses for this tenant (dedup) — an identified device that
        # is already in the fleet (own or shared) is reported but not re-added.
        gc = hub.state.system_state.get("global_config", {})
        devices = gc.get("nw_devices", []) or []
        known = {str((d or {}).get("address", "")).strip()
                 for d in devices if isinstance(d, dict)
                 and (d.get("tenant_id", "") in (tenant_id, access.shared_tenant_id()))}
        by_cred = {c.get("id"): c for c in chosen}

        dry_run = bool(data.get("dry_run", True)) or not bool(
            data.get("auto_add", saved.get("auto_add", False)))
        added, preview = [], []
        for dev in identified:
            addr = str(dev.get("address", "")).strip()
            if not addr or addr in known:
                continue
            cred_set = by_cred.get(dev.get("credential_id")) or (chosen[0] if chosen else {})
            entry = {
                "name": dev.get("hostname") or addr,
                "object_type": dev.get("object_type"),
                "address": addr,
                "os": dev.get("os", ""),
                "method": dev.get("method"),
                "credential_id": dev.get("credential_id"),
            }
            if dev.get("object_type") not in _SCAN_OBJECT_TYPES:
                continue
            if dry_run:
                preview.append(entry)
                continue
            # Auto-add: build a fleet device that reuses the winning credential
            # set's vault reference (so future pushes overlay the same secret).
            new_dev = {
                "id": str(uuid.uuid4()),
                "name": entry["name"],
                "object_type": entry["object_type"],
                "address": addr,
                "transport": "auto",
                "username": cred_set.get("username") or cred_set.get("user") or "",
                "tenant_id": tenant_id,
                "spoke_id": spoke_id,
                "source": "scanned",
            }
            ref = cred_set.get("vault_credential")
            if ref:
                new_dev["vault_credential"] = ref
            devices.append(new_dev)
            known.add(addr)
            added.append(new_dev)

        if added:
            gc["nw_devices"] = devices
            hub.state.system_state["global_config"] = gc
            hub.state._mark_dirty()
            await _nw_push_fleet(hub, spoke_id)

        return {
            "status": "ok",
            "tenant": tenant_id,
            "spoke_id": spoke_id,
            "targets": len(targets),
            "sources": per_source,
            "scanned": (scan or {}).get("scanned", 0) if isinstance(scan, dict) else 0,
            "identified": identified,
            "dry_run": dry_run,
            "preview": preview,
            "added": added,
        }

    async def _run_nw_scheduled_scan(tenant_id):
        """System-initiated recurring scan for one tenant (called by the hub's
        run_nw_scan_schedule_loop). Uses the tenant's saved scan config +
        schedule; ``dry_run`` honors the schedule's preview flag (else the scan
        config's auto_add)."""
        saved = _nw_scan_config(hub, tenant_id)
        sched = _nw_scan_schedule(hub, tenant_id)
        data = {"dry_run": bool(sched.get("dry_run", True)),
                "auto_add": bool(saved.get("auto_add", False))}
        return await _execute_nw_scan(tenant_id, saved, sess=None, data=data)

    # Expose the system scan executor + schedule reader to the hub so the
    # background run_nw_scan_schedule_loop (a mixin method) can drive scans
    # without re-implementing the credential/target/add pipeline.
    hub.run_nw_scheduled_scan = _run_nw_scheduled_scan
    hub.nw_scan_schedule_for_tenant = lambda tid: _nw_scan_schedule(hub, tid)

    @app.post("/setup/nw-scan/run")
    async def run_nw_scan(request: Request):
        """Run a fingerprint scan on the nw spoke and (optionally) auto-add the
        identified manageable devices to the tenant fleet.

        Body (all optional; falls back to the saved ``nw_scan`` config):
          ``tenant``, ``credential_ids``, ``ip_sources``, ``subnets`` (CIDRs),
          ``targets`` (explicit IPs), ``crawl``, ``dry_run`` (default true —
          preview only), ``spoke_id``.

        Tenant-scoped: a tenant-admin scans only their own tenant (targets are
        aggregated from that tenant's inventory + they may only add devices bound
        to their tenant's spoke). Admin may scan any tenant / the shared tenant.
        Devices are added tagged ``source="scanned"`` with the winning scan
        credential's vault reference so future fleet pushes overlay the secret."""
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}

        # Resolve the tenant to scan. A tenant-admin is pinned to their own
        # tenant; an admin may name any tenant (default: the shared tenant).
        req_tenant = str(data.get("tenant") or "").strip()
        if _is_admin(sess):
            tenant_id = req_tenant or access.shared_tenant_id() or ""
        else:
            own = ((sess or {}).get("user", {}).get("tenants")
                   or [(sess or {}).get("user", {}).get("tenant_id")])
            own = [t for t in own if t]
            if req_tenant and req_tenant not in own:
                raise HTTPException(status_code=403, detail="You may only scan your own tenant")
            tenant_id = req_tenant or (own[0] if own else "")
            if not tenant_id:
                raise HTTPException(status_code=400, detail="No tenant to scan")

        # Per-tenant scan config (falls back to the global admin config).
        saved = _nw_scan_config(hub, tenant_id)
        return await _execute_nw_scan(tenant_id, saved, sess=sess, data=data)

    @app.post("/setup/nw-devices")
    async def add_nw_device(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_dev = data.get("device", {})
            if not new_dev.get("name") or not new_dev.get("object_type"):
                raise HTTPException(status_code=400, detail="Missing device name or object_type")
            _validate_nw_address(new_dev.get("address"))
            if new_dev.get("object_type") not in ("aos_switch", "cx_switch",
                                                   "ex_switch", "gateway"):
                raise HTTPException(status_code=400, detail="Invalid object_type")
            _enforce_tenant_bind(request, new_dev, "network device")
            await instance_vault.validate_ref(
                hub, new_dev, _session_user(request),
                is_admin=_is_admin(_session_user(request)), storage_key="nw_devices")
            instance_vault.strip_inline_secrets(new_dev, "nw_devices")
            if "id" not in new_dev:
                new_dev["id"] = str(uuid.uuid4())
            # A manually-added device is nw-owned (not a NetBox import) — tag it so
            # the NetBox→NW import loop never prunes it as a stale netbox record.
            new_dev.setdefault("source", "manual")

            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            devices.append(new_dev)
            global_config["nw_devices"] = devices
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # New device → push the bound slice so the spoke knows about it now.
            spoke_id = new_dev.get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False

            # NetBox is the fleet source of truth: write a manually-added device
            # back to NetBox (dcim.device) so it stays complete. Best-effort — a
            # NetBox miss must not fail the add. Skipped for netbox-imported rows.
            netbox_pushed = False
            if new_dev.get("source") != "netbox":
                try:
                    push, _errs, _slug = await hub.push_nw_device_inventory(new_dev, {}, [])
                    netbox_pushed = str((push or {}).get("status", "")).upper() in ("SUCCESS", "PARTIAL")
                except Exception as e:
                    logger.debug("add_nw_device NetBox write-back skipped: %s", e)
            return {"status": "ok", "device": new_dev, "pushed": pushed,
                    "netbox_pushed": netbox_pushed}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("add_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/nw-devices/{device_id}")
    async def update_nw_device(device_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            idx = next((i for i, d in enumerate(devices)
                        if isinstance(d, dict) and d.get("id") == device_id), None)
            if idx is None:
                raise HTTPException(status_code=404, detail="Network device not found")

            # Validate the effective (post-merge) address BEFORE mutating the
            # stored record, so a rejected edit can't blank a good device.
            effective_addr = (update_data["address"] if "address" in update_data
                              else devices[idx].get("address"))
            _validate_nw_address(effective_addr)

            devices[idx].update(update_data)
            await instance_vault.validate_ref(
                hub, devices[idx], _session_user(request),
                is_admin=_is_admin(_session_user(request)), storage_key="nw_devices")
            instance_vault.strip_inline_secrets(devices[idx], "nw_devices")
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            spoke_id = devices[idx].get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
            if pushed:
                return {"status": "ok",
                        "message": "Network device updated and pushed to spoke.",
                        "pushed": True}
            return {"status": "partial_success",
                    "message": "Configuration saved, but associated spoke is not connected.",
                    "pushed": False}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/nw-devices/{device_id}")
    async def delete_nw_device(device_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        devices = global_config.get("nw_devices", [])
        victim = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        original_len = len(devices)
        devices[:] = [d for d in devices if not (isinstance(d, dict) and d.get("id") == device_id)]
        if len(devices) == original_len:
            raise HTTPException(status_code=404, detail="Network device not found")

        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        # Re-push so the spoke drops the deleted device from its fleet.
        spoke_id = victim.get("spoke_id") if isinstance(victim, dict) else None
        pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
        return {"status": "ok", "message": f"Network device {device_id} deleted.",
                "pushed": pushed}

    # ─── Multi-instance product connections (mirror firewalls) ────────────────
    # NAC / IPAM / LDAP / DNS / DHCP each manage a LIST of connection instances
    # (one per bound spoke) instead of a single config object, so the Setup
    # page can show a table with Add / Edit / Delete like Firewalls.

    async def _push_instance_config(hub, instance: dict, payload_fn, storage_key=None):
        """Send UPDATE_CONFIG to the instance's bound spoke, if connected.
        `payload_fn(instance)` returns the spoke-side config dict (or None for
        save-only products like DNS/DHCP). Returns True when a message was sent."""
        if not payload_fn:
            return False
        spoke_id = instance.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # Overlay a Credential Vault secret (e.g. ClearPass client secret) onto a
        # copy just before projecting the spoke payload — the plaintext is never
        # persisted in global_config, only resolved on demand at push time.
        if storage_key:
            instance = await instance_vault.overlay(hub, instance, storage_key)
        payload = payload_fn(instance)
        if not payload:
            return False
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _instance_crud(route_prefix: str, storage_key: str, payload_fn=None,
                       legacy_key: str = None, legacy_to_instance=None):
        """Register GET/POST/PUT/DELETE /setup/<route_prefix>[/id] for one
        multi-instance product, mirroring the firewalls CRUD. Each instance is
        a dict with an `id` and `spoke_id`; on add/update the config is pushed
        to the bound spoke when `payload_fn` is provided and the spoke is up.

        ``legacy_key``/``legacy_to_instance`` perform a one-shot migration of a
        pre-multi-instance single config (e.g. global_config.cppm / .netbox)
        into the instance list so deployments that configured CPPM/NetBox
        before the refactor still see their server on Setup → NAC /
        IPAM. The migrated entry is deduped by host/url and persisted so it
        becomes a normal editable instance."""
        hub = app.state.hub
        op = route_prefix.replace("-", "_")

        @app.get(f"/setup/{route_prefix}", operation_id=f"list_{op}")
        async def list_instances(request: Request):
            """List instances for this product (NAC/IPAM/Directory); folds in any legacy single-instance config."""
            global_config = hub.state.system_state.get("global_config", {})
            instances = list(global_config.get(storage_key, []))
            if legacy_key and legacy_to_instance:
                legacy = global_config.get(legacy_key)
                if isinstance(legacy, dict) and legacy:
                    inst = legacy_to_instance(legacy)
                    ident = inst.get("host") or inst.get("url") or inst.get("server_url")
                    already = any(
                        (inst.get("host") and i.get("host") == inst.get("host")) or
                        (inst.get("url") and i.get("url") == inst.get("url"))
                        for i in instances if isinstance(i, dict)
                    )
                    if ident and not already:
                        instances.append(inst)
                        global_config[storage_key] = instances
                        # Clear the legacy single-config so deleting the migrated
                        # instance doesn't re-migrate it on the next page load.
                        global_config[legacy_key] = {}
                        hub.state.system_state["global_config"] = global_config
                        hub.state._mark_dirty()
            # Tenant-scope the LIST: a non-admin sees only instances in the shared
            # tenant or their own tenant(s); other-tenant / unassigned instances
            # are admin-only. Object-level filtering + the add/write gates are
            # separate. Admins see all.
            sess = _session_user(request)
            if not _is_admin(sess):
                instances = [i for i in instances
                             if isinstance(i, dict) and access.spoke_visible_to_session(sess, i.get("tenant_id", ""))]
            return {"instances": instances}

        @app.post(f"/setup/{route_prefix}", operation_id=f"add_{op}")
        async def add_instance(request: Request):
            """Add an instance and push its config to the bound spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                data = await request.json()
                new_inst = data.get("instance", {})
                if not new_inst.get("name"):
                    raise HTTPException(status_code=400, detail="Missing instance name")
                _enforce_tenant_bind(request, new_inst, route_prefix.split("-")[0])
                if new_inst.get("spoke_id") and route_prefix in PRODUCT_ROLE:
                    # Auto-load the matching coordinator role if the operator
                    # picked a bare base agent rather than an already-loaded
                    # role sub-spoke — removes the separate manual "Load Role"
                    # step. Resolves to the sub-spoke id actually pushed to.
                    role, module_type = PRODUCT_ROLE[route_prefix]
                    new_inst["spoke_id"] = await ensure_role_loaded(
                        hub, new_inst["spoke_id"], role, module_type)
                # Validate any Credential Vault reference up-front, then strip
                # inline secrets so only the {bucket,name} reference is stored.
                await instance_vault.validate_ref(
                    hub, new_inst, _session_user(request),
                    is_admin=_is_admin(_session_user(request)), storage_key=storage_key)
                instance_vault.strip_inline_secrets(new_inst, storage_key)
                if "id" not in new_inst:
                    new_inst["id"] = str(uuid.uuid4())
                global_config = hub.state.system_state.get("global_config", {})
                instances = global_config.get(storage_key, [])
                instances.append(new_inst)
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                pushed = await _push_instance_config(hub, new_inst, payload_fn, storage_key)
                status = "ok" if pushed else "partial_success"
                msg = "Instance added and pushed to spoke." if pushed else "Instance added; spoke not connected."
                return {"status": status, "message": msg, "pushed": pushed, "instance": new_inst}
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("add_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.put(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"update_{op}")
        async def update_instance(instance_id: str, request: Request):
            """Update an instance and push to its spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                data = await request.json()
                update_data = data.get("config", {})
                global_config = hub.state.system_state.get("global_config", {})
                instances = global_config.get(storage_key, [])
                idx = next((i for i, x in enumerate(instances) if x.get("id") == instance_id), None)
                if idx is None:
                    raise HTTPException(status_code=404, detail="Instance not found")
                old_spoke = instances[idx].get("spoke_id")
                new_spoke = update_data.get("spoke_id")
                if new_spoke and new_spoke != old_spoke and route_prefix in PRODUCT_ROLE:
                    role, module_type = PRODUCT_ROLE[route_prefix]
                    update_data["spoke_id"] = await ensure_role_loaded(hub, new_spoke, role, module_type)
                instances[idx].update(update_data)
                # Validate/strip a Credential Vault reference on the merged record.
                await instance_vault.validate_ref(
                    hub, instances[idx], _session_user(request),
                    is_admin=_is_admin(_session_user(request)), storage_key=storage_key)
                instance_vault.strip_inline_secrets(instances[idx], storage_key)
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                pushed = await _push_instance_config(hub, instances[idx], payload_fn, storage_key)
                if route_prefix in PRODUCT_ROLE and old_spoke and old_spoke != instances[idx].get("spoke_id"):
                    role, _mt = PRODUCT_ROLE[route_prefix]
                    await maybe_unload_orphaned_role(hub, old_spoke, role, instances)
                if pushed:
                    return {"status": "ok", "message": "Instance updated and pushed to spoke.", "pushed": True}
                return {"status": "partial_success", "message": "Instance saved; associated spoke not connected.", "pushed": False}
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("update_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.delete(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"delete_{op}")
        async def delete_instance(instance_id: str):
            """Delete an instance; the spoke keeps its last config until re-pushed."""
            global_config = hub.state.system_state.get("global_config", {})
            instances = global_config.get(storage_key, [])
            deleted = next((x for x in instances if x.get("id") == instance_id), None)
            before = len(instances)
            instances[:] = [x for x in instances if x.get("id") != instance_id]
            if len(instances) == before:
                raise HTTPException(status_code=404, detail="Instance not found")
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            spoke_id = (deleted or {}).get("spoke_id")
            if route_prefix in PRODUCT_ROLE and spoke_id:
                role, _mt = PRODUCT_ROLE[route_prefix]
                await maybe_unload_orphaned_role(hub, spoke_id, role, instances)
            return {"status": "ok", "message": f"Instance {instance_id} deleted."}

    _instance_crud(
        "nac-instances", "nac_instances",
        lambda inst: {
            "host": inst.get("host"),
            "client_id": inst.get("client_id"),
            "client_secret": inst.get("client_secret"),
            "user": inst.get("user"),
            "password": inst.get("password"),
            "verify_ssl": inst.get("verify_ssl", True),
        },
        legacy_key="cppm",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": c.get("host") or "ClearPass",
            "spoke_id": "",
            "host": c.get("host"),
            "client_id": c.get("client_id"),
            "client_secret": c.get("client_secret"),
            "user": c.get("user"),
            "password": c.get("password"),
            "verify_ssl": c.get("verify_ssl", True),
        },
    )
    _instance_crud(
        "ipam-instances", "ipam_instances",
        lambda inst: {"netbox_url": inst.get("url"), "api_token": inst.get("api_token"), "netbox_verify_ssl": inst.get("verify_ssl")},
        legacy_key="netbox",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": "NetBox",
            "spoke_id": "",
            "url": c.get("url") or c.get("netbox_url"),
            "api_token": c.get("api_token") or c.get("token"),
        },
    )
    # Scan credential sets: per-tenant vault-backed SSH/SNMP credentials the
    # fingerprint scanner tries against discovered IPs. Save-only (no
    # payload_fn) — never pushed to a spoke as config; overlaid on demand at
    # scan time by /setup/nw-scan/run.
    _instance_crud("nw-scan-credentials", "nw_scan_credentials")

    @app.post("/setup/ipam/apply-schema", operation_id="ipam_apply_schema")
    async def ipam_apply_schema():
        """Apply the Lab Manager custom-field schema to the connected NetBox.

        Backs the "Apply schema changes" button on the Setup/IPAM NetBox
        instance modal. Sends NETBOX_PROVISION_CUSTOM_FIELDS to the connected
        ipam spoke, which runs the engine's idempotent _ensure_custom_fields
        (force=True) over the shared CUSTOM_FIELDS_SPEC — the same spec
        install.sh provisions on a fresh install, so a manual apply and a
        reinstall produce identical schemas. Re-runnable: never errors when the
        fields are already present (the engine get-or-creates + verifies each
        attachment). Returns the spoke's report
        (status/total/present/created/attached/already_attached/warnings).
        """
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        try:
            # NETBOX_PROVISION_CUSTOM_FIELDS runs _ensure_custom_fields(force=True)
            # over the full CUSTOM_FIELDS_SPEC — get-or-creating each field then
            # verifying/attaching content_types. That is many NetBox API calls
            # (17+ fields × create+attach) and routinely exceeds the 5s default
            # request_response timeout, surfacing as "Timed out waiting for spoke
            # response". Give it a generous window; the UI fires-and-forgets with
            # a "started" toast and shows "completed" when this resolves.
            result = await hub.request_response(spoke_id,
                                                "NETBOX_PROVISION_CUSTOM_FIELDS", {},
                                                timeout=120.0)
            data = _unwrap_spoke(result)
            if data.get("status") not in ("SUCCESS", "PARTIAL"):
                raise HTTPException(status_code=502,
                                    detail=data.get("message", "NetBox provisioning error"))
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ipam_apply_schema failed")
            raise HTTPException(status_code=500, detail=str(e))
    _instance_crud(
        "ldap-instances", "ldap_instances",
        lambda inst: {
            "LDAP_SERVER_URL": inst.get("server_url"),
            "LDAP_BASE_DN": inst.get("base_dn"),
            "LDAP_ADMIN_DN": inst.get("admin_dn"),
            "LDAP_ADMIN_PW": inst.get("admin_pw"),
        },
    )
    _instance_crud("dns-instances", "dns_instances", None)
    _instance_crud("dhcp-instances", "dhcp_instances", None)
