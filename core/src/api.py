"""LM Hub HTTP/WebSocket surface (FastAPI).

This module builds the FastAPI app that serves the Hub WebUI and integration
endpoints, and runs the uvicorn server that hosts it. It owns:

- Sessions & auth — cookie-based login/logout/setup, the in-memory ``_sessions``
  token→session map (persisted to ``sessions.json`` so a logged-in user survives
  a triggered update/restart; see ``_save_sessions``/``_load_sessions``), the
  per-request ``_session_user`` validator, and admin session listing/revocation.
- Tenant cache — per-tenant, per-module prefetched data with a background
  refresh loop and a "drop the cache when no session for a tenant is active"
  rule (``_start_cache_for_tenant``/``_stop_cache_for_tenant``).
- Simulations (cs) relay — mounts the ported Client-Sim operator UI routes
  (``register_simulations_routes``) and relays cs telemetry/events through to
  the LM cs spoke; the spoke is relay-only, so no auto-provisioning logic runs
  here (that brain lives in the pxmx agent, ``pxmx/agent/src/usb_provision.py``).
- Update trigger — ``perform_update`` orchestrates a hub self-update and, on
  success, schedules ``lm-self-restart`` (after flushing sessions to disk).

The app factory is ``create_app(hub)``; the server entrypoint is
``run_api_server``. Audience: Hub developers. For the user-facing manual see
``docs/user_manual.md``; for the REST reference see ``docs/api.md``.

Route map & auth contract
-------------------------

Routes are grouped by feature but NOT in one contiguous block — a top-down
reader encounters them in roughly this order:

  * Setup / spoke approvals / product config (``/setup/*``) — admin-only.
  * NetBox→CPPM IPAM sync (``/api/cppm/sync-endpoints`` etc.) — admin-only.
  * Firewall data + CRUD (``/api/firewall/*``).
  * Multi-instance product CRUD factory (``_instance_crud`` — NAC/IPAM/Directory).
  * CPPM / NAC devices, sessions, logs, roles (``/api/cppm/*``).
  * Device detail + aggregate + pxmx VMs (``/api/device/*``, ``/api/pxmx/*``).
  * Dashboard + global search (``/api/search`` → ``cross_system_search``).
  * Diagnostics + recovery + bug-report (``/api/diagnostics``, ``/api/bug-report``).
  * LDAP relay (``/api/ldap/*``).
  * NetBox data + CRUD (``/api/netbox/*``).
  * Tenants + users (``/setup/tenants``, ``/setup/users``).
  * Auth routes (``/auth/login``, ``/auth/me``, ``/auth/logout``, ``/auth/setup``,
    ``/auth/prefixes``) — defined LATE, near the end of ``create_app``.
  * Admin subnet-filter toggle (``/admin/subnet-filter-config``).
  * Generic Agent API (``/api/agent/*``, ``/api/generic/provision``).
  * DNS relay (``/api/dns/*``).
  * DHCP relay (``/api/dhcp/*``).
  * Cache management (``/admin/cache/*``, ``/auth/cache/*``).
  * Simulations (``/sim/api/*``) — mounted via ``register_simulations_routes``.

Auth (enforced by ``access_control_middleware``): every ``/api/``, ``/setup/``,
``/admin/``, ``/auth/``, ``/sim/api/`` path requires a valid ``lm_session`` cookie
(``_session_user``) except a small public set (``/auth/login``, ``/auth/me``,
``/auth/setup``, ``/status``, ``/sim/api/init``, ``/sim/api/health``).
``/setup/*`` and ``/admin/*`` additionally require an admin session;
``/sim/api/*`` requires the ``cs`` right OR admin. ``?tenant=`` is scoped — a
non-admin user can only request tenants they're authorised for
(``_check_tenant_access``).

The auth/tenant helper closures (``_session_user``, ``_is_admin``,
``_has_cs_access``, ``_check_tenant_access``, ``_resolve_tenant``,
``_effective_tenant*``, ``_filter_session*``) are defined LATE in ``create_app``
(search for ``def _session_user``) but used by routes ~3,500 lines earlier.
Python resolves them at call time, so this works — but a top-down reader hits the
first use long before the definition. Jump to ``def _session_user`` to find them.

Error-response conventions:
  * Spoke down / not connected → ``raise HTTPException(503, "…not connected")``.
    This is the uniform convention for relay GETs (CPPM, firewall, pxmx, NetBox,
    DNS, DHCP, LDAP) — HTTP-level monitors see the 503 directly.
  * Spoke connected but reported an error → ``raise HTTPException(502, "…")``
    (e.g. ``_cppm_unwrap`` raises 502 on a ``status: ERROR`` payload).
  * Success token: ``"ok"`` (``{"status": "ok", "message": "…", "pushed": bool}``
    for config pushes). Use ``"ok"`` for the top-level status of a simple success.
  * ``"partial_success"`` is retained for multi-target / config-push responses where
    the hub saved locally but could not reach a spoke — those also carry a
    ``"pushed": bool`` (and a count where applicable) so a monitor can distinguish
    fully-pushed from partially-pushed. Do NOT rename these to ``"ok"``.
  * Exception: the update-trigger (``/setup/update``) keeps ``"status": "success"``
    because ``webui/update_handler.js`` keys its restart-poll off that literal.
Match these conventions when adding a route; add ``logger.exception(...)`` before
a bare ``raise HTTPException(500, detail=str(e))`` so hub logs capture the trace
(a handful of older sites still lack it — add it when you touch them).
"""

import os
import asyncio
import base64
import subprocess
import json
import time
import uuid
import logging
import hashlib
import secrets
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState
from typing import Any, Dict
# NOTE: any typing name used in an annotation on a nested `def` inside
# create_app() (e.g. ``Dict[str, Any]``) MUST be imported here at module scope.
# Nested-def annotations are evaluated when create_app() runs (at app build),
# NOT at module import, so a missing name raises NameError at startup — the
# .117→.121 regression. ``str | None`` (PEP 604) in nested-def return annotations
# also evaluates at def-time and needs Python 3.10+ (prod is 3.11; the dev box
# is 3.9, so prefer ``Optional[X]`` over ``X | None`` in nested defs).
import uvicorn

logger = logging.getLogger("Hub")

from messaging.protocol import Message, MessageHeader, MessagePayload
from simulations.routes import register_simulations_routes
from simulations.tenant_filter import (filter_items_by_prefixes,
                                       filter_firewall_rules, filter_record_by_prefixes)

import access
# Access-control / tenant-scoping / subnet-filter logic lives in the leaf
# module ``access`` (importable + testable, free of the create_app() nested-def
# annotation trap). api.py depends on access one-way; access never imports api.
# Re-exports keep the ~26 routes calling ``_unwrap_spoke(result)`` and the
# subnet-filter-config routes working with zero call-site churn. The closures
# ``_session_user``/``_is_admin``/``_filter_session*``/``get_netbox_spoke``/
# ``get_tenant_scoping`` are thin shims defined inside create_app() that delegate
# to access.* (search for ``def _session_user``).
_unwrap_spoke = access.unwrap_spoke
_filter_config = access.filter_config
_FILTER_MODULES = access._FILTER_MODULES
_FILTER_DEFAULTS = access._FILTER_DEFAULTS

_SESSION_TTL = 8 * 3600  # 8 hours
_sessions: dict = {}  # token → {user_id, expires, user}


def _sessions_file(hub) -> str:
    """Path to the persisted session store under the hub data dir."""
    return os.path.join(hub.state.data_dir, "sessions.json")


def _save_sessions(hub) -> None:
    """Atomically persist the live session store to disk (best-effort, never raises).

    Writes only the core fields {user_id, expires, user} per token, dropping the
    runtime caches (prefixes/prefixes_at) that ``_resolve_prefixes`` adds — they
    re-populate on demand with their own TTL. Expired tokens are pruned from the
    written copy so the file doesn't grow with stale entries. Surviving a hub
    restart is what keeps a triggered update from logging everyone out: the
    ``lm_session`` cookie is already persistent for 8h, and rehydrating the same
    token→session mapping on startup lets ``/auth/me`` recognise it. A write
    failure logs a warning and degrades to today's in-memory-only behavior.
    """
    try:
        now = time.time()
        pruned: dict = {}
        for token, sess in _sessions.items():
            if not isinstance(sess, dict) or sess.get("expires", 0) < now:
                continue
            pruned[token] = {
                "user_id": sess.get("user_id"),
                "expires": sess.get("expires"),
                "user":    sess.get("user", {}),
            }
        path = _sessions_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(pruned, f)
        os.chmod(tmp, 0o600)  # holds user identities + expiry, not passwords
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("session persist failed: %s", exc)


def _load_sessions(hub) -> None:
    """Rehydrate the in-memory session store from disk on startup (best-effort).

    Drops any entry whose expiry has already passed. Missing/corrupt file →
    leaves ``_sessions`` empty (today's cold-start behavior).
    """
    try:
        path = _sessions_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        now = time.time()
        for token, sess in data.items():
            if not isinstance(token, str) or not isinstance(sess, dict):
                continue
            if sess.get("expires", 0) < now:
                continue
            _sessions[token] = {
                "user_id": sess.get("user_id"),
                "expires": sess.get("expires"),
                "user":    sess.get("user", {}),
            }
        if _sessions:
            logger.info("Restored %d active session(s) from disk", len(_sessions))
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.warning("session load failed (%s): %s — starting empty",
                       getattr(hub.state, "data_dir", "?"), exc)

# ---------------------------------------------------------------------------
# Tenant data cache
# ---------------------------------------------------------------------------
_tenant_cache: dict = {}   # {tenant_id: {module_key: {data, fetched_at}}}
_cache_tasks: dict = {}    # {tenant_id: asyncio.Task}
_cache_status: dict = {}   # {tenant_id: {module_key: "loading"|"ready"|"error"}}
_cache_semaphore = None    # asyncio.Semaphore — gates concurrent tenant preloads

_DEFAULT_CACHE_CONFIG = {
    "rules":           {"enabled": True, "interval": 300, "label": "Firewall Rules"},
    "nat":             {"enabled": True, "interval": 300, "label": "NAT Policies"},
    "dhcp":            {"enabled": True, "interval": 300, "label": "DHCP Leases"},
    "dns":             {"enabled": True, "interval": 300, "label": "DNS Records"},
    "interfaces":      {"enabled": True, "interval": 300, "label": "Interfaces"},
    "cppm_sessions":   {"enabled": True, "interval": 300, "label": "Access Tracker"},
    "cppm_devices":    {"enabled": True, "interval": 300, "label": "Device Database"},
    "netbox_racks":    {"enabled": True, "interval": 300, "label": "Racks"},
    "netbox_devices":  {"enabled": True, "interval": 300, "label": "Devices"},
    "netbox_ips":      {"enabled": True, "interval": 300, "label": "IP Addresses"},
    "netbox_prefixes": {"enabled": True, "interval": 300, "label": "Prefixes"},
    "pxmx_vms":        {"enabled": True, "interval": 300, "label": "Virtual Machines"},
}
_FW_MODULES = {"rules", "nat", "dhcp", "dns", "interfaces"}
_FW_CMD_MAP = {
    "rules":      "OPNSENSE_GET_ALL_RULES",
    "nat":        "OPNSENSE_GET_NAT_POLICIES",
    "dhcp":       "OPNSENSE_GET_DHCP_LEASES",
    "dns":        "OPNSENSE_GET_DNS_RECORDS",
    "interfaces": "GET_INTERFACE_STATUS",
}

# ── Tenant subnet filtering ────────────────────────────────────────────────
# Constants (_FILTER_MODULES / _DEFAULTS), _FW_FILTER_SPEC, and
# _filter_config live in access.py now; re-exported above for the routes
# that read/toggle them (Setup → Simulations). See access.py for the logic.


def _get_cache_config(hub) -> dict:
    stored = hub.state.system_state.get("cache_config", {})
    result = {}
    for key, defaults in _DEFAULT_CACHE_CONFIG.items():
        result[key] = {**defaults, **{k: v for k, v in stored.get(key, {}).items() if k in ("enabled", "interval")}}
    return result

def _get_max_concurrent(hub) -> int:
    return int(hub.state.system_state.get("cache_config", {}).get("max_concurrent_tenants", 3))

def _cache_entry(tenant_id: str, key: str):
    return _tenant_cache.get(tenant_id, {}).get(key)

def _set_cache_entry(tenant_id: str, key: str, data):
    _tenant_cache.setdefault(tenant_id, {})[key] = {"data": data, "fetched_at": time.time()}
    _set_cache_status(tenant_id, key, "ready")

def _set_cache_status(tenant_id: str, key: str, status: str):
    _cache_status.setdefault(tenant_id, {})[key] = status

def _invalidate_tenant_module(tenant_id: str, key: str):
    _tenant_cache.get(tenant_id, {}).pop(key, None)

def _invalidate_module_all_tenants(key: str):
    for t in list(_tenant_cache):
        _tenant_cache[t].pop(key, None)

def _refresh_module_all_tenants(hub, key: str):
    """Drop every tenant's cached entry for ``key`` and re-fetch in the background.

    The common post-write pattern: a spoke mutation invalidates the cached module
    data for all tenants, then kicks a background re-fetch per tenant so the next
    read sees fresh data. Previously this two-step was copy-pasted across the
    NetBox / CPPM / DNS / DHCP write handlers; route it through here instead:
    ``_refresh_module_all_tenants(hub, "netbox_devices")`` replaces
    ``_invalidate_module_all_tenants("netbox_devices")`` + the
    ``for tid in list(_tenant_cache): asyncio.create_task(_fetch_module(hub, tid, "netbox_devices"))``
    loop. (Some call sites intentionally invalidate multiple keys at once — those
    keep calling ``_invalidate_module_all_tenants`` directly.)"""
    _invalidate_module_all_tenants(key)
    for tid in list(_tenant_cache):
        asyncio.create_task(_fetch_module(hub, tid, key))

def _normalize_cached(result):
    if not isinstance(result, dict):
        return result
    if "payload" in result and isinstance(result["payload"], dict):
        return result["payload"].get("data", result)
    if "data" in result:
        return result["data"]
    return result

# _unwrap_spoke now lives in access.py (re-exported above). The previous
# in-tree body was infinite recursion (``return _unwrap_spoke(result)``) — the
# 7bc70c6 doc-pass regression — so all ~26 spoke-data unwrap call sites now
# resolve to the correct access.unwrap_spoke via the module-level alias.

def _hub_msg(spoke_id: str, msg_type: str, data) -> Message:
    """Build a hub-originated Message to a spoke.

    The standard hub→spoke construction: a fresh uuid message_id, current
    timestamp, sender_id ``"hub"``, destination_id ``spoke_id``, and a
    ``MessagePayload(type=msg_type, data=data)``. Replaces the ~11 inline
    ``Message(header=MessageHeader(...), payload=MessagePayload(...))`` blocks
    in the config-push / approval / hostname handlers. No extra header fields
    (correlation_id/priority/ttl) are set by any current call site; extend this
    factory with optional kwargs if a future one needs them."""
    return Message(
        header=MessageHeader(
            message_id=str(uuid.uuid4()),
            timestamp=time.time(),
            sender_id="hub",
            destination_id=spoke_id,
        ),
        payload=MessagePayload(type=msg_type, data=data),
    )

def _nb_slug(hub, tenant_id: str):
    try:
        return (hub.state.get_tenant(tenant_id) or {}).get("netbox_tenant_slug") or None
    except Exception:
        return None

async def _fetch_module(hub, tenant_id: str, module_key: str, fw_id: str = None) -> bool:
    """Fetch one module from its spoke and store in tenant cache."""
    cache_key = f"{module_key}:{fw_id}" if fw_id else module_key
    _set_cache_status(tenant_id, cache_key, "loading")
    try:
        result = None
        if module_key in _FW_MODULES and fw_id:
            firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
            fw = next((f for f in firewalls if f["id"] == fw_id), None)
            if not fw:
                _set_cache_status(tenant_id, cache_key, "error"); return False
            spoke_id = fw.get("spoke_id")
            if not spoke_id or spoke_id not in hub.active_connections:
                _set_cache_status(tenant_id, cache_key, "error"); return False
            result = await hub.request_response(spoke_id, _FW_CMD_MAP[module_key], {})
        elif module_key == "cppm_sessions":
            spoke = hub.get_spoke_by_type("nac")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            result = await hub.request_response(spoke, "CPPM_GET_ACCESS_TRACKER", {})
        elif module_key == "cppm_devices":
            spoke = hub.get_spoke_by_type("nac")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            result = await hub.request_response(spoke, "LIST_ENDPOINTS", {})
        elif module_key in ("netbox_racks", "netbox_devices", "netbox_ips", "netbox_prefixes"):
            spoke = hub.get_spoke_by_type("ipam")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            slug = _nb_slug(hub, tenant_id)
            cmd = {
                "netbox_racks":    "NETBOX_GET_RACKS",
                "netbox_devices":  "NETBOX_GET_DEVICES",
                "netbox_ips":      "NETBOX_GET_IPS",
                "netbox_prefixes": "NETBOX_GET_PREFIXES",
            }[module_key]
            result = await hub.request_response(spoke, cmd, {"tenant": slug} if slug else {})
        elif module_key == "pxmx_vms":
            spoke = hub.get_spoke_by_type("hypervisor")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            cfg = hub.state.get_tenant(tenant_id) or {}
            payload = {"tag_filter": cfg["proxmox_tag"]} if cfg.get("proxmox_tag") else {}
            result = await hub.request_response(spoke, "PXMX_LIST_VMS", payload)

        if result is not None:
            _set_cache_entry(tenant_id, cache_key, _normalize_cached(result))
            return True
        _set_cache_status(tenant_id, cache_key, "error")
        return False
    except Exception as e:
        logger.warning(f"Cache fetch [{tenant_id}][{cache_key}]: {e}")
        _set_cache_status(tenant_id, cache_key, "error")
        return False

async def _preload_all_parallel(hub, tenant_id: str):
    """Parallel-fetch all enabled modules for a tenant, gated by the concurrency semaphore."""
    global _cache_semaphore
    if _cache_semaphore is None:
        _cache_semaphore = asyncio.Semaphore(_get_max_concurrent(hub))
    async with _cache_semaphore:
        config = _get_cache_config(hub)
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        tasks = []
        for module_key, cfg in config.items():
            if not cfg.get("enabled", True):
                continue
            if module_key in _FW_MODULES:
                for fw in firewalls:
                    tasks.append(_fetch_module(hub, tenant_id, module_key, fw_id=fw["id"]))
            else:
                tasks.append(_fetch_module(hub, tenant_id, module_key))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

async def _cache_refresh_loop(hub, tenant_id: str):
    """Background task: initial parallel preload then periodic refresh per module interval."""
    try:
        # Brief delay so the dashboard's own data requests aren't blocked by the
        # initial burst of cache-preload spoke calls.
        await asyncio.sleep(3)
        await _preload_all_parallel(hub, tenant_id)
        while True:
            await asyncio.sleep(30)
            config = _get_cache_config(hub)
            firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
            tasks = []
            for module_key, cfg in config.items():
                if not cfg.get("enabled", True):
                    continue
                interval = cfg.get("interval", 300)
                if module_key in _FW_MODULES:
                    for fw in firewalls:
                        ck = f"{module_key}:{fw['id']}"
                        cached = _cache_entry(tenant_id, ck)
                        if not cached or time.time() - cached["fetched_at"] > interval:
                            tasks.append(_fetch_module(hub, tenant_id, module_key, fw_id=fw["id"]))
                else:
                    cached = _cache_entry(tenant_id, module_key)
                    if not cached or time.time() - cached["fetched_at"] > interval:
                        tasks.append(_fetch_module(hub, tenant_id, module_key))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.warning(f"Cache refresh loop [{tenant_id}] died: {e}")

def _start_cache_for_tenant(hub, tenant_id: str):
    if not tenant_id or tenant_id == "default":
        return
    existing = _cache_tasks.get(tenant_id)
    if existing and not existing.done():
        return  # already running — second user of same tenant shares the cache
    _cache_tasks[tenant_id] = asyncio.create_task(_cache_refresh_loop(hub, tenant_id))
    logger.info(f"[Cache] task started for tenant '{tenant_id}'")

def _stop_cache_for_tenant(tenant_id: str):
    """Drop cache and cancel task only when no active sessions remain for this tenant."""
    if not tenant_id:
        return
    active = sum(
        1 for s in _sessions.values()
        if s.get("user", {}).get("tenant_id") == tenant_id
        and s.get("expires", 0) > time.time()
    )
    if active > 0:
        return
    _tenant_cache.pop(tenant_id, None)
    _cache_status.pop(tenant_id, None)
    task = _cache_tasks.pop(tenant_id, None)
    if task:
        task.cancel()
    logger.info(f"[Cache] cleared for tenant '{tenant_id}' — no active sessions")


def _spoke_payload_or_raise(data):
    """Translate a spoke relay result into the API error contract.

    Spokes return ``{status: "SUCCESS", ...}`` or ``{status: "ERROR",
    message|error}``. The hub relay passes the SUCCESS body through unchanged
    (so existing field access on the caller side is untouched) but a spoke-side
    ERROR is translated to HTTP 502 (Bad Gateway) carrying the spoke's message
    as ``detail`` — the contract every other relay group already follows. A
    non-dict result (raw list / scalar) is returned as-is. Pure → unit-testable;
    the in-``create_app`` ``_relay_spoke`` closure calls this after unwrapping.
    """
    if isinstance(data, dict) and data.get("status") == "ERROR":
        msg = data.get("message") or data.get("error") or "Spoke returned an error"
        raise HTTPException(status_code=502, detail=msg)
    return data


def create_app(hub):
    """Build the FastAPI app for the Hub.

    Mounts CORS, attaches the ``hub`` instance to ``app.state``, rehydrates the
    persisted login sessions from disk (``_load_sessions``), runs the
    anti-lockout admin migration, registers the access-control middleware, the
    Simulations (cs) routes, and all Hub WebUI/integration endpoints. Returns
    the configured app; host it with ``run_api_server``.
    """
    app = FastAPI(title="Lab Manager Hub API")

    # Enable CORS to allow WebUI to connect from different origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach hub instance to app state for access in routes
    app.state.hub = hub

    # Rehydrate login sessions from disk so a user who was logged in before a
    # triggered update/restart stays logged in (the lm_session cookie already
    # persists for 8h; this restores the server-side token→session mapping).
    _load_sessions(hub)

    # Anti-lockout migration: runs on every startup. Ensures the first user is
    # a fully-privileged, protected, tenant-free admin and reconciles the two
    # admin-flag forms (role + boolean) across all admin users so the WebUI
    # "System Admin" checkbox renders correctly and an edit cannot silently
    # demote an admin by dropping one of the two forms.
    if hub.state.ensure_admin_lockout():
        hub.state.save_state()

    @app.middleware("http")
    async def access_control_middleware(request, call_next):
        """Per-request access control.

        Static UI files are always public. Every ``/api/*`` (and ``/sim/api/*``)
        namespace requires a valid ``lm_session`` cookie via ``_session_user``;
        admin-scoped namespaces additionally require an admin session. Short-
        circuits to a 401/403 JSON response when the gate fails, otherwise calls
        the next handler.
        """
        path = request.url.path

        # Only API namespaces require authentication — static UI files are always public.
        _GATED_PREFIXES = ("/api/", "/setup/", "/admin/", "/auth/", "/sim/api/")
        if not any(path.startswith(p) for p in _GATED_PREFIXES) or path == "/status":
            return await call_next(request)

        # Unauthenticated endpoints within gated namespaces
        _PUBLIC = {"/auth/login", "/auth/me", "/auth/setup", "/status",
                   "/sim/api/init", "/sim/api/health"}
        _PUBLIC_GET = {"/setup/appearance"}
        if path in _PUBLIC or (request.method == "GET" and path in _PUBLIC_GET):
            return await call_next(request)

        sess = _session_user(request)
        if not sess:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})

        # /setup/* and /admin/* are admin-only
        if path.startswith("/setup/") or path.startswith("/admin/"):
            if not _is_admin(sess):
                return JSONResponse(status_code=403, content={"detail": "Admin access required"})

        # /sim/api/* (the Simulations module) requires the ``cs`` right OR admin.
        # The frontend hides the Simulations nav on the same right (canSeeModule);
        # this gates the API so a non-authorized user can't reach it directly.
        if path.startswith("/sim/api/"):
            if not (_is_admin(sess) or _has_cs_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Simulations module access required"})

        # Tenant scoping: block requests for a ?tenant= the user isn't authorised for
        tenant = request.query_params.get("tenant")
        if tenant and not _check_tenant_access(sess, tenant):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Not authorized for tenant '{tenant}'"},
            )

        return await call_next(request)

    # ── Error logging (outermost middleware) ────────────────────────────────
    # Wraps every request so that *any* unhandled exception — including ones
    # raised inside access_control_middleware (e.g. session lookup) or during
    # response serialisation, which bypass the per-route try/except — is
    # logged with a full traceback to the hub log and returned as structured
    # JSON. This makes 500s diagnosable from the WebUI / browser console
    # instead of a bare "Internal Server Error" that requires CLI log-tailing.
    @app.middleware("http")
    async def error_logging_middleware(request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:
            logger.exception(
                "Unhandled exception on %s %s", request.method, request.url.path
            )
            return JSONResponse(
                status_code=500,
                content={
                    "detail": str(exc),
                    "type": type(exc).__name__,
                    "path": request.url.path,
                },
            )

    @app.get("/setup/spoke-hosts")
    async def get_spoke_hosts():
        """Return the remote IP for each connected spoke, keyed by module_type.
        Used by the WebUI to auto-populate service URL fields."""
        hub = app.state.hub
        result = {}
        for spoke_id, telemetry in hub.spoke_telemetry.items():
            ip = telemetry.get("remote_ip")
            if not ip:
                continue
            module_type = hub.spoke_module_types.get(spoke_id)
            if module_type:
                result[module_type] = {"ip": ip, "spoke_id": spoke_id}
        return {"hosts": result}

    @app.get("/status")
    async def get_status():
        hub = app.state.hub
        if not getattr(hub, "is_ready", False):
            raise HTTPException(status_code=503, detail="Hub is not yet ready (WebSocket server starting)")
        metrics = await hub.get_system_metrics()
        return {
            "active_connections": list(hub.active_connections.keys()),
            "spoke_module_types": dict(hub.spoke_module_types),
            "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
            "state": hub.state.system_state,
            "metrics": metrics
        }


    @app.get("/vm/{vm_id}/firewall")
    async def get_vm_firewall(vm_id: str):
        hub = app.state.hub

        # 1. Find the IP for this VM from the state manager
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        if not ip:
            raise HTTPException(status_code=404, detail=f"No IP address found for VM {vm_id}")

        # 2. Identify the OPNsense spoke
        opn_spoke = hub.get_spoke_by_type("firewall")

        if not opn_spoke:
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")

        # 3. Use the async bridge to request rules from the spoke
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
            return result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_vm_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Setup: spoke approval / secrets / agents (/setup/spokes/*) ───────────
    @app.post("/setup/spokes/{spoke_id}/reset-secret")
    async def reset_spoke_secret(spoke_id: str):
        hub = app.state.hub
        try:
            hub.key_manager.delete_spoke_key(spoke_id)
            return {"status": "ok", "message": f"Secret for spoke {spoke_id} has been reset. It can now be re-onboarded."}
        except Exception as e:
            logger.exception("reset_spoke_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/spokes/{spoke_id}")
    async def delete_spoke(spoke_id: str):
        """Permanently remove a spoke/generic-agent registration.

        Closes the live WebSocket if the spoke is currently connected (the
        disconnect handler then clears active_connections / spoke_module_types /
        spoke_telemetry), drops the in-memory approval mirror, removes the
        persisted registration + metadata, and wipes the crypto material
        (current key + history). The spoke must fully re-onboard to return.
        """
        hub = app.state.hub
        try:
            ws = hub.active_connections.get(spoke_id)
            if ws is not None:
                try:
                    await ws.close(code=1008, reason="Removed by admin")
                except Exception as e:
                    logger.warning(f"Could not close live WS for {spoke_id} during delete: {e}")
            hub.approved_modules.pop(spoke_id, None)
            hub.state.remove_module(spoke_id)
            hub.key_manager.delete_spoke_key(spoke_id)
            # Drop per-spoke runtime caches (simulations_cache, telemetry,
            # rate_limiters, events, recovery, agent_logs). The disconnect
            # handler only clears active_connections/spoke_module_types, so
            # without this the per-spoke dicts grow unbounded as admins
            # delete/recreate spokes over time. Safe to evict on permanent
            # delete (unlike a transient disconnect, which needs telemetry
            # for the WebUI's DISCONNECTED status + recovery for the watchdog).
            hub._evict_spoke(spoke_id)
            return {"status": "ok", "message": f"Spoke '{spoke_id}' removed."}
        except Exception as e:
            logger.exception("delete_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/rotate-secret")
    async def rotate_spoke_secret(spoke_id: str):
        hub = app.state.hub
        try:
            new_key = hub.key_manager.rotate_key(spoke_id)
            return {"status": "ok", "new_secret": new_key.secret}
        except Exception as e:
            logger.exception("rotate_spoke_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/rotate-key/{spoke_id}")
    async def rotate_key_live(spoke_id: str):
        """
        Generate a new spoke secret and push it to the live spoke in a single call.

        Flow:
          1. Hub generates new secret via key_manager.rotate_key()
          2. Hub sends SPOKE_UPDATE_SESSION_KEY to the spoke over the live WS
          3. Spoke updates self.secret + self.signer, persists to .env, acks
          4. Hub returns the new secret (store it securely; the old one is invalidated)

        If the spoke is not currently connected, the new key is stored and the spoke
        will use it on its next connection (key_manager accepts the new key from then on).
        """
        hub = app.state.hub
        try:
            new_key = hub.key_manager.rotate_key(spoke_id)
            new_secret = new_key.secret

            spoke_conn = hub.active_connections.get(spoke_id)
            if spoke_conn:
                try:
                    result = await hub.request_response(
                        spoke_id, "SPOKE_UPDATE_SESSION_KEY", {"secret": new_secret}
                    )
                    pushed = result.get("status") == "SUCCESS"
                except Exception as push_err:
                    logger.warning(f"Could not push new key to spoke {spoke_id}: {push_err}")
                    pushed = False
            else:
                pushed = False

            return {
                "status":    "ok",
                "spoke_id":  spoke_id,
                "pushed":    pushed,
                "message":   ("New key pushed to live spoke and persisted." if pushed
                               else "New key stored. Spoke will pick it up on next connect."),
            }
        except Exception as e:
            logger.exception("rotate_key_live failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spokes/{spoke_id}/agents")
    async def get_spoke_agents(spoke_id: str):
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])
        agents = [sid for sid in known_spokes if sid != spoke_id]
        return {"spoke_id": spoke_id, "agents": agents}

    @app.post("/setup/spokes/{spoke_id}/agents/{agent_id}/approve")
    async def approve_agent_under_spoke(spoke_id: str, agent_id: str):
        hub = app.state.hub
        try:
            # A Proxmox node agent connects THROUGH the pxmx hypervisor spoke,
            # not directly to the hub, so it must NOT be registered as a
            # hub-direct spoke (known_modules). Doing so made /setup/diagnostics
            # render a bogus OFFLINE spoke row for it — the hub has no
            # WebSocket for the agent, so get_diagnostics() emitted
            # connection_state="OFFLINE"/authenticated=False even though the
            # agent was genuinely connected (its real state lives in the
            # spoke's GET_AGENTS response, shown in the Agents table). Persist
            # the approval flag only, and clean up any prior leak so an
            # already-registered agent stops showing as an offline spoke.
            hub.approved_modules[agent_id] = True
            approved_map = hub.state.system_state.setdefault("approved_modules", {})
            approved_map[agent_id] = True
            known = hub.state.system_state.get("known_modules", [])
            if agent_id in known:
                known.remove(agent_id)
            hub.state.save_state()

            if spoke_id in hub.active_connections:
                msg = _hub_msg(spoke_id, "SPOKE_RELAY", {
                    "target_agent_id": agent_id,
                    "command": "APPROVAL_SUCCESS",
                    "payload": {}
                })
                await hub.send_to_spoke(msg)

            return {"status": "ok", "message": f"Agent {agent_id} approved under spoke {spoke_id}"}
        except Exception as e:
            logger.exception("approve_agent_under_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/pending_spokes")
    async def get_all_spokes_status():
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])
        module_names = hub.state.system_state.get("module_names", {})

        # module_type is held in the live spoke_module_types dict, which is
        # popped on disconnect (main.py disconnect handler) — so an offline
        # spoke reports None and the WebUI can't show its module. Fall back to
        # the spoke_id prefix so the Setup tile still labels offline spokes
        # (opn/cppm/cs/etc.) with their module instead of "—".
        _PREFIX_MODULE = {
            "pxmx": "hypervisor", "opn": "firewall", "cppm": "nac",
            "cs": "simulation", "netbox": "ipam", "ldap": "directory",
            "dns": "dns", "dhcp": "dhcp",
        }

        def _module_type_for(sid: str):
            mt = hub.spoke_module_types.get(sid)
            if mt:
                return mt
            for prefix, fallback in _PREFIX_MODULE.items():
                if sid == prefix or sid.startswith(prefix + "-"):
                    return fallback
            return None

        spokes_status = []
        for sid in known_spokes:
            spokes_status.append({
                "spoke_id": sid,
                "display_name": module_names.get(sid, sid),
                "approved": hub.approved_modules.get(sid, False),
                "module_type": _module_type_for(sid),
            })

        return {"spokes": spokes_status}

    @app.post("/setup/approve_spoke")
    async def approve_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            action = data.get("action", "approve")

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            if action == "unapprove":
                hub.state.register_module(spoke_id, approved=False)
                hub.approved_modules[spoke_id] = False
            else:
                hub.state.register_module(spoke_id, approved=True)
                hub.approved_modules[spoke_id] = True

            # Spoke→tenant binding (admin assigns at approval time). Omitting
            # tenant_id leaves any existing binding untouched.
            tenant_id = data.get("tenant_id")
            if tenant_id is not None:
                hub.state.set_spoke_tenant(spoke_id, tenant_id)

            hub.state.save_state()

            if spoke_id in hub.active_connections:
                if action != "unapprove":
                    # Generate a session secret for the spoke (idempotent — reuses existing key if present)
                    session_secret = hub.key_manager.generate_first_secret(spoke_id)
                    key_msg = _hub_msg(spoke_id, "SPOKE_UPDATE_SESSION_KEY", {"secret": session_secret})
                    await hub.send_to_spoke(key_msg)

                msg_type = "APPROVED" if action != "unapprove" else "DENIED"
                approval_msg = _hub_msg(spoke_id, msg_type, {})
                await hub.send_to_spoke(approval_msg)

                if action != "unapprove":
                    await hub.push_config_to_spoke(spoke_id)

            return {"status": "ok", "message": f"Spoke {spoke_id} {'approved' if action != 'unapprove' else 'un-approved'}."}
        except Exception as e:
            logger.exception("approve_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Product config pairs: cppm/pxmx/ldap/dns/dhcp (/setup/*-config) ───────
    @app.get("/setup/cppm-config")
    async def get_cppm_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("cppm", {})
        return {"config": config}

    @app.post("/setup/cppm-config")
    async def update_cppm_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["cppm"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            cppm_spoke = hub.get_spoke_by_type("nac")
            if cppm_spoke:
                msg = _hub_msg(cppm_spoke, "update_config", config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but CPPM spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_cppm_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── NetBox → CPPM endpoint sync (hub-orchestrated) ──────────────────────
    # On-demand trigger + per-tenant last-sync status for the Setup →
    # Security/NAC "NetBox → ClearPass Endpoint Sync" card. Config (enabled /
    # mode / interval_seconds / daily_time) is stored under
    # global_config["netbox_cppm_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_endpoint_sync_loop) reads that same key.
    def _trigger_endpoint_sync_after_ipam_edit(hub, request: Request,
                                               data: Dict[str, Any] = None):
        """Best-effort: fire a tenant endpoint sync after an IPAM write.

        Resolves the target tenant from the request body's ``tenant`` (the
        per-tenant IPAM scope value → LM tenant id via
        hub.tenant_id_for_ipam_scope, which uses the configured source's scope
        field), falling back to the acting user's tenant. Never raises — a
        sync trigger must not break the IPAM mutation it follows.
        """
        try:
            tid = None
            scope = (data or {}).get("tenant") if isinstance(data, dict) else None
            if scope:
                tid = hub.tenant_id_for_ipam_scope(scope)
            if not tid:
                tid = _resolve_tenant(request, None)
            hub.trigger_endpoint_sync(tid)
        except Exception as e:
            logger.debug("endpoint-sync trigger after IPAM edit skipped: %s", e)

    @app.post("/setup/endpoint-sync/run")
    async def run_endpoint_sync(request: Request):
        """On-demand NetBox → CPPM endpoint sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant; absent →
        all tenants bound to NetBox. Returns per-tenant results + a summary.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_endpoints(target)]
        else:
            results = [await hub.sync_tenant_endpoints(tid)
                       for tid in hub._endpoint_sync_tenants()]
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "tenants": len(results)}}

    @app.get("/setup/endpoint-sync/status")
    async def endpoint_sync_status(request: Request):
        """Per-tenant last-sync status for the Setup → Security/NAC card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_endpoint_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "message": st.get("message", ""),
                "endpoints_total": st.get("endpoints_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
                "skipped_details": st.get("skipped_details", []),
            })
        return {"tenants": tenants}

    @app.get("/setup/endpoint-sync/sources")
    async def endpoint_sync_sources(request: Request):
        """List the available IPAM pull-sources for the sync source selector.

        Driven by Hub.IPAM_SOURCES so adding a product is a one-entry registry
        change and the WebUI dropdown picks it up with no client change.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        active = hub._endpoint_sync_source().get("module_type")
        sources = []
        for name, se in hub.IPAM_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_spoke_by_type(se.get("module_type", "")))})
        return {"active": active, "sources": sources}

    # ── Hypervisor → NetBox VM sync (hub-orchestrated) ───────────────────────
    # On-demand trigger + per-tenant last-sync status for the Setup → IPAM
    # "Hypervisor → NetBox VM Sync" card. Config (enabled / mode /
    # interval_seconds / daily_time) is stored under
    # global_config["pxmx_netbox_vm_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_vm_sync_loop) reads that same key.
    def _trigger_vm_sync_after_pxmx_edit(hub, request: Request,
                                         data: Dict[str, Any] = None):
        """Best-effort: fire a tenant VM sync after a pxmx/hypervisor write.

        Resolves the target tenant from the acting user's session (a VM
        lifecycle action does not carry a per-tenant scope in its body, unlike
        an IPAM edit which carries ``tenant``). Never raises — a sync trigger
        must not break the VM mutation it follows. A superadmin with no tenant
        is a no-op (the scheduled loop covers unbound tenants).
        """
        try:
            tid = _resolve_tenant(request, None)
            hub.trigger_vm_sync(tid)
        except Exception as e:
            logger.debug("vm-sync trigger after pxmx edit skipped: %s", e)

    @app.post("/setup/vm-sync/run")
    async def run_vm_sync(request: Request):
        """On-demand Hypervisor → NetBox VM sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant; absent →
        all tenants bound to a hypervisor source. Returns per-tenant results +
        a summary.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_vms(target)]
        else:
            results = [await hub.sync_tenant_vms(tid)
                       for tid in hub._vm_sync_tenants()]
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors,
                            "deleted": deleted, "tenants": len(results)}}

    @app.get("/setup/vm-sync/status")
    async def vm_sync_status(request: Request):
        """Per-tenant last-VM-sync status for the Setup → IPAM card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_vm_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "vms_total": st.get("vms_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/vm-sync/sources")
    async def vm_sync_sources(request: Request):
        """List the available hypervisor pull-sources for the sync source selector.

        Driven by Hub.HYPERVISOR_SOURCES so adding a product is a one-entry
        registry change and the WebUI dropdown picks it up with no client change.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        active = hub._vm_sync_source().get("module_type")
        sources = []
        for name, se in hub.HYPERVISOR_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_spoke_by_type(se.get("module_type", "")))})
        return {"active": active, "sources": sources}

    @app.get("/setup/pxmx-config")
    async def get_pxmx_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("pxmx", {
            "default_node": "pve",
            "cluster_id": "cluster-1"
        })
        return {"config": config}

    @app.post("/setup/pxmx-config")
    async def update_pxmx_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["pxmx"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            pxmx_spoke = hub.get_spoke_by_type("hypervisor")
            if pxmx_spoke:
                msg = _hub_msg(pxmx_spoke, "update_config", config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but Proxmox spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_pxmx_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/ldap-config")
    async def get_ldap_config():
        """Return the stored LDAP/directory configuration (global_config.ldap)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("ldap", {})
        return {"config": config}

    @app.post("/setup/ldap-config")
    async def update_ldap_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            spoke_config = {
                "LDAP_SERVER_URL": config.get("server_url"),
                "LDAP_BASE_DN": config.get("base_dn"),
                "LDAP_ADMIN_DN": config.get("admin_dn"),
                "LDAP_ADMIN_PW": config.get("admin_pw"),
            }
            spoke_config = {k: v for k, v in spoke_config.items() if v is not None}

            global_config = hub.state.system_state.get("global_config", {})
            global_config["ldap"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            ldap_spoke = hub.get_spoke_by_type("directory")
            if ldap_spoke:
                msg = _hub_msg(ldap_spoke, "UPDATE_CONFIG", spoke_config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "LDAP configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but LDAP spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_ldap_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/dns-config")
    async def get_dns_config():
        """Return the stored DNS/Unbound configuration (global_config.dns)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("dns", {})
        return {"config": config}

    @app.post("/setup/dns-config")
    async def update_dns_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["dns"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            return {"status": "ok"}
        except Exception as e:
            logger.exception("update_dns_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/dhcp-config")
    async def get_dhcp_config():
        """Return the stored DHCP/Kea configuration (global_config.dhcp)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("dhcp", {})
        return {"config": config}

    @app.post("/setup/dhcp-config")
    async def update_dhcp_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["dhcp"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            return {"status": "ok"}
        except Exception as e:
            logger.exception("update_dhcp_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-metadata")
    async def update_spoke_metadata(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            metadata = data.get("metadata", {})

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            known_modules = hub.state.system_state.get("known_modules", [])
            if spoke_id not in known_modules:
                raise HTTPException(status_code=404, detail=f"Spoke '{spoke_id}' not found in known_modules: {known_modules}")

            hub.state.update_module_metadata(spoke_id, metadata)
            hub.state.save_state()

            return {"status": "ok", "message": f"Metadata for spoke {spoke_id} updated."}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Error updating spoke metadata")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spoke-metadata/{spoke_id}")
    async def get_spoke_metadata(spoke_id: str):
        hub = app.state.hub
        metadata = hub.state.system_state.get("module_metadata", {}).get(spoke_id, {})
        if not metadata:
            raise HTTPException(status_code=404, detail="Spoke metadata not found")
        return {"metadata": metadata}

    @app.get("/setup/firewalls")
    async def get_firewalls():
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        return {"firewalls": firewalls}

    @app.get("/api/firewall/{firewall_id}/refresh")
    async def refresh_firewall_cache(firewall_id: str):
        hub = app.state.hub
        logger.info(f"API: Triggering cache refresh for firewall {firewall_id}")
        success = await hub.poll_opnsense_rules(firewall_id=firewall_id)
        if not success:
            logger.error(f"API: Cache refresh failed for firewall {firewall_id}")
            raise HTTPException(status_code=503, detail=f"Failed to refresh cache for firewall {firewall_id} (Spoke not connected or API error)")

        return {"status": "ok", "message": f"Cache for firewall {firewall_id} refreshed successfully!"}

    @app.get("/api/firewall/{firewall_id}/{endpoint}")
    # ── Firewall: data + CRUD (/api/firewall/*) ──────────────────────────────
    # get_firewall_data serves from tenant cache (non-admin) / offline cache /
    # a live spoke round-trip; the CRUD handlers below mutate and refresh.
    async def get_firewall_data(request: Request, firewall_id: str, endpoint: str, tenant: str = None):
        """Live + cached firewall data (rules/interfaces/services/virtual-ip).

        Three return paths: tenant cache hit for non-admins, offline cache when
        the spoke is down, and a live ``request_response`` round-trip. The
        ``endpoint`` arg selects the firewall sub-resource. Results are
        tenant-prefix-filtered via ``_filter_fw`` before return. ``?tenant=``
        scopes the filter to the selected tenant so an admin acting as a tenant
        (via the switcher) sees only that tenant's subnet data across every tab —
        without it, admins bypass the filter (see access.filter_fw)."""
        # see _netbox_list_get (variant: per-model command map + fw_id-scoped cache
        # keys + _filter_fw filter — enough variation to stay inline).
        hub = app.state.hub
        logger.debug("relay %s %s firewall=%s endpoint=%s tenant=%s", request.method, request.url.path, firewall_id, endpoint, tenant)

        # Serve from tenant cache for non-admin users (if module is cached)
        sess = _session_user(request)
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id and endpoint in _FW_MODULES:
                cached = _cache_entry(tenant_id, f"{endpoint}:{firewall_id}")
                if cached:
                    return await _filter_fw(request, cached["data"], endpoint, firewall_id, tenant)

        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")

        model = fw.get("model", "opnsense").lower()
        # Only OPNsense has a spoke that handles these commands. The UI model
        # dropdown also offers pfsense/juniper/fortigate, but no spokes exist
        # for those yet, so an unknown model falls back to the OPNsense command
        # set (parity with the previous behavior for pfsense/fortigate). The
        # former "juniper" entry mapped to JUNIPER_GET_* commands no spoke
        # handles — dead, removed.
        command_map = {
            "opnsense": {
                "rules": "OPNSENSE_GET_ALL_RULES",
                "interfaces": "GET_INTERFACE_STATUS",
                "health": "GET_SYSTEM_HEALTH",
                "dhcp": "OPNSENSE_GET_DHCP_LEASES",
                "nat": "OPNSENSE_GET_NAT_POLICIES",
                "dns": "OPNSENSE_GET_DNS_RECORDS",
                "aliases": "OPNSENSE_GET_ALIASES",
            },
        }

        model_commands = command_map.get(model, command_map.get("opnsense", {}))
        spoke_cmd = model_commands.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported for model {model}")

        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            # Spoke offline — serve last known cache for any authenticated user
            if sess:
                tenant_id = sess.get("user", {}).get("tenant_id")
                if tenant_id:
                    cached = _cache_entry(tenant_id, f"{endpoint}:{firewall_id}")
                    if cached:
                        return await _filter_fw(request, cached["data"], endpoint, firewall_id, tenant)
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")

        try:
            result = await hub.request_response(spoke_id, spoke_cmd, {})
            data = {}
            if isinstance(result, dict):
                if "data" in result:
                    data = result["data"]
                elif "payload" in result and isinstance(result["payload"], dict):
                    data = result["payload"].get("data", {})
                else:
                    data = result
            else:
                data = result
            return await _filter_fw(request, data, endpoint, firewall_id, tenant)
        except Exception as e:
            logger.error(f"Error fetching {endpoint} for firewall {firewall_id}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    async def _fw_spoke_cmd(hub, firewall_id: str, command: str, data: dict):
        """Helper: resolve firewall spoke and send a command, return result."""
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")
        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")
        try:
            result = await hub.request_response(spoke_id, command, data)
            if isinstance(result, dict):
                payload = result.get("payload", result)
                if isinstance(payload, dict) and "data" in payload:
                    return payload
                return result
            return result
        except Exception as e:
            logger.exception("_fw_spoke_cmd failed")
            raise HTTPException(status_code=500, detail=str(e))

    async def _fw_write(hub, firewall_id: str, command: str, data: dict, module_key: str):
        """Send a firewall write command and refresh the affected module in all tenant caches."""
        result = await _fw_spoke_cmd(hub, firewall_id, command, data)
        for tid in list(_tenant_cache):
            _invalidate_tenant_module(tid, f"{module_key}:{firewall_id}")
            asyncio.create_task(_fetch_module(hub, tid, module_key, fw_id=firewall_id))
        return result

    @app.post("/api/firewall/{firewall_id}/rules")
    async def add_firewall_rule(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_RULE", {"rule": data.get("rule", data)}, "rules")

    @app.delete("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def delete_firewall_rule(firewall_id: str, rule_id: str):
        hub = app.state.hub
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_RULE", {"rule_id": rule_id}, "rules")

    @app.put("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def edit_firewall_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_RULE", {"uuid": rule_id, "rule": data.get("rule", data)}, "rules")

    @app.post("/api/firewall/{firewall_id}/aliases")
    async def add_firewall_alias(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_ADD_ALIAS", data)

    @app.delete("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def delete_firewall_alias(firewall_id: str, alias_id: str):
        hub = app.state.hub
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_DEL_ALIAS", {"uuid": alias_id})

    @app.put("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def edit_firewall_alias(firewall_id: str, alias_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_EDIT_ALIAS", {"uuid": alias_id, **data})

    @app.post("/api/firewall/{firewall_id}/nat")
    async def add_nat_rule(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_NAT_RULE", data, "nat")

    @app.delete("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def delete_nat_rule(firewall_id: str, rule_id: str):
        hub = app.state.hub
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_NAT_RULE", {"nat_type": "d_nat", "uuid": rule_id}, "nat")

    @app.put("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def edit_nat_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_NAT_RULE", {"uuid": rule_id, **data}, "nat")

    @app.post("/api/firewall/{firewall_id}/dns")
    async def add_dns_record(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_DNS_RECORD", data, "dns")

    @app.delete("/api/firewall/{firewall_id}/dns/{record_id}")
    async def delete_dns_record(firewall_id: str, record_id: str):
        hub = app.state.hub
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_DNS_RECORD", {"uuid": record_id}, "dns")

    @app.put("/api/firewall/{firewall_id}/dns/{record_id}")
    async def edit_dns_record(firewall_id: str, record_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_DNS_RECORD", {"uuid": record_id, **data}, "dns")

    @app.post("/setup/firewalls")
    async def add_firewall(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_fw = data.get("firewall", {})
            if not new_fw.get("name") or not new_fw.get("model"):
                raise HTTPException(status_code=400, detail="Missing firewall name or model")

            if "id" not in new_fw:
                new_fw["id"] = str(uuid.uuid4())

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])
            firewalls.append(new_fw)
            global_config["firewalls"] = firewalls
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "ok", "firewall": new_fw}
        except Exception as e:
            logger.exception("add_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/firewalls/{firewall_id}")
    async def update_firewall(firewall_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])

            fw_index = next((i for i, fw in enumerate(firewalls) if fw["id"] == firewall_id), None)
            if fw_index is None:
                raise HTTPException(status_code=404, detail="Firewall not found")

            firewalls[fw_index].update(update_data)
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            spoke_id = firewalls[fw_index].get("spoke_id")
            if spoke_id and spoke_id in hub.active_connections:
                msg = _hub_msg(spoke_id, "UPDATE_CONFIG", firewalls[fw_index])
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Firewall configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but associated spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/firewalls/{firewall_id}")
    async def delete_firewall(firewall_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        firewalls = global_config.get("firewalls", [])

        original_len = len(firewalls)
        firewalls[:] = [fw for fw in firewalls if fw["id"] != firewall_id]

        if len(firewalls) == original_len:
            raise HTTPException(status_code=404, detail="Firewall not found")

        hub.state.system_state["global_config"] = global_config
        hub.state.save_state()
        return {"status": "ok", "message": f"Firewall {firewall_id} deleted."}

    # ─── Multi-instance product connections (mirror firewalls) ────────────────
    # NAC / IPAM / LDAP / DNS / DHCP each manage a LIST of connection instances
    # (one per bound spoke) instead of a single config object, so the Setup
    # page can show a table with Add / Edit / Delete like Firewalls.

    async def _push_instance_config(hub, instance: dict, payload_fn):
        """Send UPDATE_CONFIG to the instance's bound spoke, if connected.
        `payload_fn(instance)` returns the spoke-side config dict (or None for
        save-only products like DNS/DHCP). Returns True when a message was sent."""
        if not payload_fn:
            return False
        spoke_id = instance.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            return False
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
        before the refactor still see their server on Setup → Security/NAC /
        IPAM. The migrated entry is deduped by host/url and persisted so it
        becomes a normal editable instance."""
        hub = app.state.hub
        op = route_prefix.replace("-", "_")

        @app.get(f"/setup/{route_prefix}", operation_id=f"list_{op}")
        async def list_instances():
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
                        hub.state.save_state()
            return {"instances": instances}

        @app.post(f"/setup/{route_prefix}", operation_id=f"add_{op}")
        async def add_instance(request: Request):
            """Add an instance and push its config to the bound spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                data = await request.json()
                new_inst = data.get("instance", {})
                if not new_inst.get("name"):
                    raise HTTPException(status_code=400, detail="Missing instance name")
                if "id" not in new_inst:
                    new_inst["id"] = str(uuid.uuid4())
                global_config = hub.state.system_state.get("global_config", {})
                instances = global_config.get(storage_key, [])
                instances.append(new_inst)
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state.save_state()
                pushed = await _push_instance_config(hub, new_inst, payload_fn)
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
                instances[idx].update(update_data)
                hub.state.system_state["global_config"] = global_config
                hub.state.save_state()
                pushed = await _push_instance_config(hub, instances[idx], payload_fn)
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
            before = len(instances)
            instances[:] = [x for x in instances if x.get("id") != instance_id]
            if len(instances) == before:
                raise HTTPException(status_code=404, detail="Instance not found")
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            return {"status": "ok", "message": f"Instance {instance_id} deleted."}

    _instance_crud(
        "nac-instances", "nac_instances",
        lambda inst: {
            "host": inst.get("host"),
            "client_id": inst.get("client_id"),
            "client_secret": inst.get("client_secret"),
            "user": inst.get("user"),
            "password": inst.get("password"),
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
        },
    )
    _instance_crud(
        "ipam-instances", "ipam_instances",
        lambda inst: {"netbox_url": inst.get("url"), "api_token": inst.get("api_token")},
        legacy_key="netbox",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": "NetBox",
            "spoke_id": "",
            "url": c.get("url") or c.get("netbox_url"),
            "api_token": c.get("api_token") or c.get("token"),
        },
    )
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

    @app.get("/cppm/refresh")
    async def refresh_cppm_cache():
        hub = app.state.hub
        logger.info("API: Triggering CPPM cache refresh")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected for refresh")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_REFRESH_CACHE", {})
            return result
        except Exception as e:
            logger.error(f"API: Error refreshing CPPM cache: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/test-auth")
    async def test_cppm_auth():
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "TEST_AUTH", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.exception("test_cppm_auth failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/probe")
    async def probe_cppm(path: str, method: str = "GET"):
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "PROBE_API", {"path": path, "method": method})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.exception("probe_cppm failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/cppm/health")
    async def get_cppm_health():
        hub = app.state.hub
        logger.info("API: Requesting CPPM health")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_SYSTEM_HEALTH", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received CPPM health: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM health: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _device_tenant_slug(d: dict) -> str:
        """A device's tenant = its NetBox_Tenant_Slug (or Tenant_Slug) endpoint
        attribute — the value the endpoint sync writes. Empty when untagged."""
        attrs = (d.get("attributes") if isinstance(d, dict) else None) or {}
        return attrs.get("NetBox_Tenant_Slug") or attrs.get("Tenant_Slug") or ""

    def _filter_devices_by_tenant(data, scope: str):
        """Tag-based tenant filter for the Device Database list. Keeps only
        devices tagged with this IPAM scope (the logged-in user's tenant).
        More authoritative than the subnet filter — a device tagged for tenant
        X belongs to X regardless of its IP — so a non-admin sees only their own
        tenant's devices. No scope (admin, or tenant not bound to NetBox) →
        unchanged. Preserves the response shape (status/devices/total)."""
        if not scope:
            return data
        if not isinstance(data, dict):
            return data
        devices = data.get("devices")
        if not isinstance(devices, list):
            return data
        kept = [d for d in devices if isinstance(d, dict) and _device_tenant_slug(d) == scope]
        out = dict(data)
        out["devices"] = kept
        out["total"] = len(kept)
        return out

    # ── CPPM / NAC: devices, sessions, logs, roles (/api/cppm/*) ─────────────
    # ClearPass REST ``filter`` is exact-equality only (no SQL-LIKE), so the
    # device/session list handlers do an exact MAC/IP filter first then a bounded
    # client-side substring scan (see cppm/src/queries.py SEARCH_SCAN_CAP).
    @app.get("/api/cppm/devices")
    async def get_cppm_devices(request: Request, tenant: str = None):
        hub = app.state.hub
        # see _netbox_list_get (variant: admin/multi-tenant live path runs FIRST,
        # then non-admin cache path; _filter_tenant + tag filter — inline).
        # Relay trace (DEBUG so polled reads don't flood INFO): records the
        # tenant scope + that we entered the relay. Established convention —
        # every relay GET (CPPM, NetBox, pxmx, DNS, DHCP, LDAP, firewall
        # live-fetch) carries this one-liner so a slow/failed spoke round-trip
        # is traceable from logs even on the happy path (error paths already log).
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        sess = _session_user(request)
        # Tag-based tenant filter: keep only devices tagged with the effective
        # tenant's IPAM scope (NetBox_Tenant_Slug / Tenant_Slug). The effective
        # tenant is the selected one (?tenant=) for admins / multi-tenant
        # switches — clamped for non-admins — falling back to the session tenant
        # when nothing is selected. scope=None (admin, no selection, or tenant
        # not bound to NetBox) → no-op; the subnet filter is the backstop.
        if tenant and _effective_tenant(request, tenant):
            scope = _effective_tenant_slug(request, tenant)
        elif sess and not _is_admin(sess):
            tid = sess.get("user", {}).get("tenant_id")
            scope = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug") or None if tid else None
        else:
            scope = None
        tf = lambda d: _filter_devices_by_tenant(d, scope)

        if tenant and _effective_tenant(request, tenant):
            cppm_spoke = hub.get_spoke_by_type("nac")
            if not cppm_spoke:
                raise HTTPException(status_code=503, detail="No CPPM spoke connected")
            try:
                result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
                return await _filter_tenant(request, tf(_cppm_unwrap(result)), "nac", ["ip"], tenant)
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"API: Error fetching CPPM devices: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id:
                cached = _cache_entry(tenant_id, "cppm_devices")
                if cached:
                    return await _filter_session(request, tf(cached["data"]), "nac", ["ip"])
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            if sess:
                tenant_id = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tenant_id, "cppm_devices") if tenant_id else None
                if cached:
                    return await _filter_session(request, tf(cached["data"]), "nac", ["ip"])
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
            return await _filter_session(request, tf(_cppm_unwrap(result)), "nac", ["ip"])
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"API: Error fetching CPPM devices: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/unknown-devices")
    async def get_cppm_unknown_devices(request: Request, tenant: str = None):
        """Endpoints not assigned to any tenant (no NetBox_Tenant_Slug /
        Tenant_Slug attribute) — the 'Unknown Devices' tab. Subnet-scoped by the
        selected tenant so a tenant sees untagged devices on their own network;
        an admin with no tenant selected sees every untagged endpoint."""
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
            data = _cppm_unwrap(result)
            # Keep only untagged endpoints (assigned to no tenant).
            if isinstance(data, dict) and isinstance(data.get("devices"), list):
                untagged = [d for d in data["devices"] if isinstance(d, dict) and not _device_tenant_slug(d)]
                data = {**data, "devices": untagged, "total": len(untagged)}
            elif isinstance(data, list):
                data = [d for d in data if isinstance(d, dict) and not _device_tenant_slug(d)]
            return await _filter_tenant(request, data, "nac", ["ip"], tenant)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"API: Error fetching CPPM unknown devices: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _norm_mac(m: str) -> str:
        return m.lower().replace(":", "").replace("-", "").replace(".", "") if m else ""

    @app.get("/api/device-detail")
    async def get_device_detail(q: str = None, mac: str = None, ip: str = None, hostname: str = None):
        """Fan-out device lookup across all modules by MAC, IP, or hostname.

        Queries every connected spoke type (CPPM endpoints/sessions, NetBox IPs,
        OPNsense DHCP leases + firewall rules, pxmx VMs) for a match, de-dupes,
        and returns the merged record. Consumer: the WebUI device dashboard
        (``showDeviceDashboard`` in ``WebUI/main.js``). NOTE: the inner OPNsense
        loop sets ``rules_data`` from a lease-IP match even when the rules call
        itself failed — the success condition is intentionally tied to finding a
        DHCP lease, so read that block twice before changing it."""
        import asyncio as _asyncio, re as _re
        hub = app.state.hub

        mac = (mac or "").strip() or None
        ip = (ip or "").strip() or None
        hostname = (hostname or "").strip() or None

        if q and not (mac or ip or hostname):
            q = q.strip()
            if _re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', q):
                mac = q
            elif _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', q):
                ip = q
            else:
                hostname = q

        async def safe(coro):
            try:
                return await coro
            except Exception as e:
                return {"error": str(e)}

        async def req(spoke, cmd, data):
            if not spoke:
                return None
            r = await hub.request_response(spoke, cmd, data)
            d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
            return d

        spoke_nac  = hub.get_spoke_by_type("nac")
        fw_spokes  = hub.get_all_spokes_by_type("firewall") or []
        spoke_ipam = hub.get_spoke_by_type("ipam")
        spoke_pxmx = hub.get_spoke_by_type("hypervisor")
        spoke_ldap = hub.get_spoke_by_type("directory")

        tasks: dict = {}
        search_q = mac or ip or hostname or ""

        if spoke_nac:
            if mac:
                tasks["nac_ep"]   = safe(req(spoke_nac, "GET_ENDPOINT_DETAIL", {"mac": mac}))
                tasks["nac_sess"] = safe(req(spoke_nac, "GET_DEVICE_SESSIONS", {"mac": mac}))
            elif ip or hostname:
                tasks["nac_sess"] = safe(req(spoke_nac, "SEARCH_SESSIONS", {"q": ip or hostname}))

        for fw in fw_spokes:
            tasks["dhcp"] = safe(req(fw, "OPNSENSE_GET_DHCP_LEASES", {}))
            break

        if spoke_ipam and search_q:
            tasks["netbox"] = safe(req(spoke_ipam, "NETBOX_SEARCH", {"q": search_q}))
        if spoke_pxmx and (ip or hostname):
            tasks["proxmox"] = safe(req(spoke_pxmx, "SEARCH_VMS", {"q": ip or hostname}))
        if spoke_ldap and (hostname or ip):
            tasks["ldap"] = safe(req(spoke_ldap, "SEARCH_USERS", {"q": hostname or ip}))

        gathered = await _asyncio.gather(*tasks.values())
        data = dict(zip(tasks.keys(), gathered))

        identity = {"mac": mac, "ip": ip, "hostname": hostname}

        # Process DHCP — find lease by MAC or IP
        dhcp_result = None
        if "dhcp" in data and isinstance(data["dhcp"], list):
            norm_mac = _norm_mac(mac) if mac else None
            for lease in data["dhcp"]:
                if norm_mac and _norm_mac(lease.get("mac", "")) == norm_mac:
                    dhcp_result = lease
                    break
                if ip and lease.get("ip") == ip:
                    dhcp_result = lease
                    break
            if dhcp_result:
                identity["ip"]       = identity["ip"] or (dhcp_result.get("ip") if dhcp_result.get("ip") != "unknown" else None)
                identity["mac"]      = identity["mac"] or (dhcp_result.get("mac") if dhcp_result.get("mac") != "unknown" else None)
                identity["hostname"] = identity["hostname"] or (dhcp_result.get("hostname") if dhcp_result.get("hostname") not in ("unknown", "") else None)

        # Process NAC
        nac_result = None
        nac_ep = data.get("nac_ep") or {}
        nac_sess = data.get("nac_sess") or {}
        if isinstance(nac_ep, dict) and nac_ep.get("status") == "SUCCESS":
            nac_result = {**nac_ep, "sessions": nac_sess.get("sessions", []) if isinstance(nac_sess, dict) else []}
            identity["ip"]       = identity["ip"] or nac_ep.get("ip") or None
            identity["hostname"] = identity["hostname"] or nac_ep.get("hostname") or None
        elif isinstance(nac_sess, dict) and nac_sess.get("sessions"):
            nac_result = {"sessions": nac_sess["sessions"]}

        nb_results  = (data.get("netbox") or {}).get("results", []) if isinstance(data.get("netbox"), dict) else []
        px_results  = (data.get("proxmox") or {}).get("results", []) if isinstance(data.get("proxmox"), dict) else []
        ld_results  = (data.get("ldap") or {}).get("results", []) if isinstance(data.get("ldap"), dict) else []

        return {
            "identity": identity,
            "nac":      nac_result,
            "dhcp":     dhcp_result,
            "netbox":   nb_results,
            "proxmox":  px_results,
            "ldap":     ld_results,
        }

    @app.get("/api/cppm/device-enrich")
    async def get_cppm_device_enrich(request: Request, mac: str, tenant: str = None):
        """Fetch CPPM endpoint detail and enrich missing fields from DHCP leases."""
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        fw_spokes = hub.get_all_spokes_by_type("firewall") or []

        ep: dict = {}
        if cppm_spoke:
            try:
                raw = await hub.request_response(cppm_spoke, "GET_ENDPOINT_DETAIL", {"mac": mac})
                ep = _cppm_unwrap(raw) if isinstance(raw, dict) else {}
            except Exception:
                pass

        sources: dict = {}
        if ep.get("ip"):
            sources["ip"] = "ClearPass"
        if ep.get("hostname"):
            sources["hostname"] = "ClearPass"

        norm_target = _norm_mac(mac)
        for spoke_id in fw_spokes:
            try:
                dhcp_raw = await hub.request_response(spoke_id, "OPNSENSE_GET_DHCP_LEASES", {})
                leases = dhcp_raw.get("payload", {}).get("data", []) if isinstance(dhcp_raw, dict) else []
                if not isinstance(leases, list):
                    continue
                lease = next((l for l in leases if _norm_mac(l.get("mac", "")) == norm_target), None)
                if lease:
                    if not ep.get("ip") and lease.get("ip") and lease["ip"] != "unknown":
                        ep["ip"] = lease["ip"]
                        sources["ip"] = "DHCP"
                    if not ep.get("hostname") and lease.get("hostname") and lease["hostname"] not in ("unknown", ""):
                        ep["hostname"] = lease["hostname"]
                        sources["hostname"] = "DHCP"
                    if ep.get("ip") and ep.get("hostname"):
                        break
            except Exception:
                pass

        ep["sources"] = sources
        # Gate the single endpoint record by tenant subnet (returns {} if the
        # resolved IP is concrete and off the tenant's prefixes). Honors the
        # selected tenant for admins / multi-tenant switches.
        return await _gate_record_tenant(request, ep, "nac", ["ip"], tenant) or {}

    @app.get("/api/cppm/device-sessions")
    async def get_cppm_device_sessions(request: Request, mac: str, tenant: str = None):
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "GET_DEVICE_SESSIONS", {"mac": mac})
            return await _filter_tenant(request, _cppm_unwrap(result), "nac", ["ip"], tenant)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_device_sessions failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/roles")
    async def get_cppm_roles():
        """List ClearPass roles from the NAC spoke (unfiltered relay)."""
        hub = app.state.hub
        logger.debug("relay GET /api/cppm/roles")
        logger.info("API: Requesting CPPM roles")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ROLES", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM roles: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/logs")
    async def get_cppm_logs(request: Request, start: str, end: str, tenant: str = None):
        """Fetch ClearPass audit logs between start/end; subnet-filtered per tenant."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        logger.info(f"API: Requesting CPPM logs from {start} to {end}")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "GET_LOGS", {"start": start, "end": end})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return await _filter_tenant(request, data, "nac", ["ip", "nas_ip_address"], tenant)
        except Exception as e:
            logger.error(f"API: Error fetching CPPM logs: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _cppm_unwrap(result):
        """Extract spoke payload data and raise HTTPException if spoke reported an error."""
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        if isinstance(data, dict) and data.get("status") == "ERROR":
            raise HTTPException(status_code=502, detail=data.get("message", "CPPM API error"))
        return data

    @app.get("/api/cppm/sessions")
    async def get_cppm_sessions(request: Request, limit: int = 200, offset: int = 0,
                                tenant: str = None):
        """List ClearPass access-tracker sessions; admin/multi-tenant switches go
        live, non-admins get the tenant cache; spoke-down falls back to cache."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        sess = _session_user(request)
        # see _netbox_list_get (variant: admin/multi-tenant live path FIRST, then
        # non-admin cache; _filter_tenant — inline, mirrors get_cppm_devices).
        # Admin / multi-tenant switch: scope by the selected tenant's prefixes
        # (explicit_tenant). Without a selection, non-admins keep session-tenant
        # scoping via the cache path below.
        if tenant and _effective_tenant(request, tenant):
            cppm_spoke = hub.get_spoke_by_type("nac")
            if not cppm_spoke:
                raise HTTPException(status_code=503, detail="No CPPM spoke connected")
            try:
                result = await hub.request_response(cppm_spoke, "CPPM_GET_ACCESS_TRACKER", {"limit": limit, "offset": offset})
                return await _filter_tenant(request, _cppm_unwrap(result), "nac", ["ip"], tenant)
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("get_cppm_sessions failed")
                raise HTTPException(status_code=500, detail=str(e))
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id:
                cached = _cache_entry(tenant_id, "cppm_sessions")
                if cached:
                    return await _filter_session(request, cached["data"], "nac", ["ip"])
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            if sess:
                tenant_id = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tenant_id, "cppm_sessions") if tenant_id else None
                if cached:
                    return await _filter_session(request, cached["data"], "nac", ["ip"])
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_ACCESS_TRACKER", {"limit": limit, "offset": offset})
            return await _filter_session(request, _cppm_unwrap(result), "nac", ["ip"])
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_sessions failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/nac-status")
    async def get_cppm_nac_status():
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_NAC_STATUS", {})
            return _cppm_unwrap(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_nac_status failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/vm/{vm_id}/details")
    async def get_vm_details(vm_id: str):
        hub = app.state.hub
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        details = {
            "vm_id": vm_id,
            "ip": ip,
            "metadata": res_info,
            "proxmox": {"status": "OFFLINE"},
            "opnsense": {"status": "OFFLINE", "rules": [], "dhcp": None},
            "cppm": {"status": "OFFLINE", "policy": "Unknown"}
        }

        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if pxmx_spoke:
            px_res_raw = await hub.request_response(pxmx_spoke, "GET_VM_INFO", {"vm_id": vm_id})
            px_res = px_res_raw.get("payload", {}).get("data", {}) if isinstance(px_res_raw, dict) else {}
            details["proxmox"] = px_res if px_res.get("status") == "SUCCESS" else {"status": "ERROR", "error": px_res.get("message", "Unknown error")}

        opn_spokes = hub.get_all_spokes_by_type("firewall")
        if opn_spokes and ip:
            rules_data = None
            lease = None

            for spoke_id in opn_spokes:
                try:
                    rules_raw = await hub.request_response(spoke_id, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
                    dhcp_raw = await hub.request_response(spoke_id, "OPNSENSE_GET_DHCP_LEASES", {})

                    rules_res = rules_raw.get("payload", {}).get("data", {}) if isinstance(rules_raw, dict) else {}
                    dhcp_res = dhcp_raw.get("payload", {}).get("data", []) if isinstance(dhcp_raw, dict) else []

                    if rules_res.get("status") == "SUCCESS" and rules_res.get("rules"):
                        rules_data = rules_res
                        break

                    if isinstance(dhcp_res, list):
                        lease = next((l for l in dhcp_res if l.get("ip") == ip), None)
                        if lease:
                            rules_data = rules_res
                            break
                except Exception as e:
                    logger.error(f"Error querying OPNsense spoke {spoke_id} for VM {vm_id}: {e}")

            if rules_data:
                details["opnsense"] = {
                    "status": "ONLINE",
                    "rules": rules_data.get("rules", []),
                    "dhcp": lease
                }
            else:
                details["opnsense"] = {"status": "OFFLINE", "rules": [], "dhcp": None}

        cppm_spoke = hub.get_spoke_by_type("nac")
        if cppm_spoke and ip:
            cppm_res_raw = await hub.request_response(cppm_spoke, "CPPM_GET_POLICY_BY_IP", {"ip": ip})
            cppm_res = cppm_res_raw.get("payload", {}).get("data", {}) if isinstance(cppm_res_raw, dict) else {}
            details["cppm"] = cppm_res if cppm_res.get("status") == "SUCCESS" else {"status": "ERROR", "error": cppm_res.get("message", "Unknown error")}

        return details

    @app.get("/api/aggregate/opnsense")
    async def aggregate_opnsense():
        hub = app.state.hub
        opn_spokes = hub.get_all_spokes_by_type("firewall")

        async def _one(sid):
            try:
                # Health + interface status are independent — fetch both at once
                # per spoke, and all spokes run concurrently so the dashboard
                # latency is one round-trip, not N×2.
                health_raw, int_raw = await _asyncio.gather(
                    hub.request_response(sid, "GET_SYSTEM_HEALTH", {}),
                    hub.request_response(sid, "GET_INTERFACE_STATUS", {}),
                )
                health_data = health_raw.get("payload", {}).get("data", {}) if isinstance(health_raw, dict) else {}
                int_data = int_raw.get("payload", {}).get("data", {}) if isinstance(int_raw, dict) else {}
                return {"spoke_id": sid, "spoke_online": True,
                        "health": health_data, "interfaces": int_data, "status": "ONLINE"}
            except Exception as e:
                return {"spoke_id": sid, "spoke_online": False, "status": "ERROR", "error": str(e)}

        results = await _asyncio.gather(*(_one(sid) for sid in opn_spokes))
        return {"hosts": list(results)}

    @app.get("/api/aggregate/proxmox")
    async def aggregate_proxmox():
        hub = app.state.hub
        pxmx_spokes = hub.get_all_spokes_by_type("hypervisor")

        async def _one(sid):
            try:
                res_raw = await hub.request_response(sid, "GET_VM_INFO", {"vm_id": "all"})
                res_data = res_raw.get("payload", {}).get("data", {}) if isinstance(res_raw, dict) else {}
                return {"spoke_id": sid, "spoke_online": True, "data": res_data, "status": "ONLINE"}
            except Exception as e:
                return {"spoke_id": sid, "spoke_online": False, "status": "ERROR", "error": str(e)}

        results = await _asyncio.gather(*(_one(sid) for sid in pxmx_spokes))
        return {"hosts": list(results)}

    @app.get("/api/pxmx/agent-install-cmd")
    async def get_pxmx_agent_install_cmd(request: Request):
        """Return a ready-to-paste install command for the pxmx node agent."""
        import socket as _socket
        host = request.headers.get("host", "").split(":")[0] or _socket.gethostbyname(_socket.gethostname())
        cmd = (
            f"curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh "
            f"| sudo bash -s -- "
            f"--spoke-url ws://{host}:8766 "
            f"--id pxmx-agent-$(hostname)"
        )
        return {"cmd": cmd, "spoke_url": f"ws://{host}:8766"}

    @app.get("/api/pxmx/agents")
    async def get_pxmx_agents():
        hub = app.state.hub
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            return {"agents": [], "pending_agents": [], "spoke_connected": False}
        try:
            result = await hub.request_response(pxmx_spoke, "GET_AGENTS", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # Merge in stored per-agent config: display name + Client Simulation mode.
            # `agent_config` is the new home; `agent_display_names` is a read fallback.
            agent_cfg = hub.state.system_state.get("agent_config", {})
            names = hub.state.system_state.get("agent_display_names", {})
            now = time.time()
            for a in data.get("agents", []):
                aid = a["agent_id"]
                cfg = agent_cfg.get(aid, {})
                if cfg.get("display_name"):
                    a["display_name"] = cfg["display_name"]
                elif aid in names:
                    a["display_name"] = names[aid]
                if cfg.get("client_simulation"):
                    a["client_simulation"] = cfg["client_simulation"]
                # Hub-tracked per-agent heartbeat (keyed spoke_id:agent_id, fed
                # by the pxmx spoke relaying AGENT_HEARTBEAT up). Surfaces in
                # System → Diagnostics alongside the spoke heartbeats; falls
                # back to RED/never when the hub has never seen the agent beat.
                hb_key = f"{pxmx_spoke}:{aid}"
                hb_last = hub.heartbeat.last_seen.get(hb_key)
                a["heartbeat_age_s"] = max(0, int(now - hb_last)) if isinstance(hb_last, (int, float)) else None
                a["heartbeat_status"] = str(hub.heartbeat.get_status(hb_key).value)
            return data
        except Exception as e:
            logger.exception("get_pxmx_agents failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/agents/{agent_id}/revoke")
    async def revoke_pxmx_agent(agent_id: str):
        hub = app.state.hub
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            raise HTTPException(status_code=503, detail="Hypervisor spoke not connected")
        try:
            result = await hub.request_response(pxmx_spoke, "SPOKE_RELAY", {
                "target_agent_id": agent_id,
                "command": "REVOKE_AGENT",
            })
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            if data.get("status") != "SUCCESS":
                raise HTTPException(status_code=502, detail=data.get("message", "Relay failed"))
            return {"status": "ok", "message": f"Agent '{agent_id}' disconnected"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("revoke_pxmx_agent failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/agents/{agent_id}/rename")
    async def rename_pxmx_agent(agent_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        display_name = (data.get("display_name") or "").strip()
        if not display_name:
            raise HTTPException(status_code=400, detail="display_name required")
        hub.state.system_state.setdefault("agent_display_names", {})[agent_id] = display_name
        hub.state.save_state()
        return {"status": "ok", "message": f"Agent '{agent_id}' renamed to '{display_name}'"}

    @app.get("/api/pxmx/agents/{agent_id}/config")
    async def get_pxmx_agent_config(agent_id: str):
        """Return the stored per-agent config (display name + Client Simulation mode)."""
        hub = app.state.hub
        cfg = hub.state.system_state.get("agent_config", {}).get(agent_id, {})
        # Fall back to the legacy display-name override if agent_config has none yet.
        if not cfg.get("display_name"):
            legacy = hub.state.system_state.get("agent_display_names", {}).get(agent_id)
            if legacy:
                cfg = dict(cfg)
                cfg["display_name"] = legacy
        return {"config": cfg}

    @app.post("/api/pxmx/agents/{agent_id}/config")
    async def set_pxmx_agent_config(agent_id: str, request: Request):
        """Persist per-agent config (display name + Client Simulation mode) and push
        the client_simulation config down to the agent via the pxmx spoke.
        Reuses the spoke's SET_AGENT_CONFIG command, which persists in the spoke and
        re-pushes UPDATE_CONFIG to the agent on reconnect (see proxmox_spoke.py:55-64)."""
        hub = app.state.hub
        try:
            data = await request.json()
            display_name = (data.get("display_name") or "").strip() or None
            cs = data.get("client_simulation") or {}
            cs_cfg = {
                "enabled": bool(cs.get("enabled")),
                "tenant_id": (cs.get("tenant_id") or "").strip() or None,
            }

            # Persist (merge with any existing entry so partial updates keep fields).
            store = hub.state.system_state.setdefault("agent_config", {})
            entry = dict(store.get(agent_id, {}))
            if display_name:
                entry["display_name"] = display_name
            entry["client_simulation"] = cs_cfg
            store[agent_id] = entry
            hub.state.save_state()

            # Best-effort push to a live agent. SET_AGENT_CONFIG persists spoke-side
            # even when the agent is offline, so a failure here just means the agent
            # picks up the config on its next connect/reconnect.
            pushed = False
            pxmx_spoke = hub.get_spoke_by_type("hypervisor")
            if pxmx_spoke:
                try:
                    res = await hub.request_response(pxmx_spoke, "SET_AGENT_CONFIG", {
                        "agent_id": agent_id,
                        "config": {"client_simulation": cs_cfg},
                    })
                    rdata = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
                    pushed = rdata.get("status") == "SUCCESS"
                except Exception as e:
                    logger.info(f"SET_AGENT_CONFIG push for '{agent_id}' failed (will re-push on reconnect): {e}")

            return {
                "status": "ok" if pushed else "partial_success",
                "message": ("Config saved and pushed to agent." if pushed
                            else "Config saved; agent will receive it on next connect/reconnect."),
                "pushed": pushed,
                "config": store[agent_id],
            }
        except Exception as e:
            logger.exception("set_pxmx_agent_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/agents/{agent_id}/cs-command")
    async def pxmx_agent_cs_command(agent_id: str, request: Request):
        """Admin/debug: send a Client-Simulation fast command to a Proxmox agent
        — start/stop/reboot/snapshot_vm, the start_vms/stop_vms/snapshot_vms
        batches, unlock_template, clear_provision_lock, clear_usb_quarantine.

        Relays through the pxmx spoke as SPOKE_RELAY {command: CS_COMMAND}; the
        agent returns SUCCESS or ERROR (a cs_guard refusal — e.g. vmid below the
        90000 floor or a protected container — comes back as ERROR with the
        guard's message). Sync only: long ops (delete/reclone/reseed/backup) are
        not exposed here (they'd exceed the spoke's 15s relay window)."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        action = (body.get("action") or "").strip()
        if not action:
            raise HTTPException(status_code=400, detail="missing 'action'")
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            raise HTTPException(status_code=503, detail="hypervisor spoke not connected")
        try:
            result = await hub.request_response(pxmx_spoke, "SPOKE_RELAY", {
                "target_agent_id": agent_id,
                "command": "CS_COMMAND",
                "data": body,
            })
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"CS command relay failed: {e}")

    @app.delete("/api/pxmx/agents/{agent_id}")
    async def delete_pxmx_agent(agent_id: str):
        """Remove a Proxmox node agent: best-effort disconnect of a live agent
        (relayed through the hypervisor spoke) plus removal of any persisted
        display-name override. If the agent is already dead / the hypervisor
        spoke is offline, the relay is skipped and we still clear the override."""
        hub = app.state.hub
        relayed = False
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if pxmx_spoke:
            try:
                result = await hub.request_response(pxmx_spoke, "SPOKE_RELAY", {
                    "target_agent_id": agent_id,
                    "command": "REVOKE_AGENT",
                })
                data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
                relayed = data.get("status") == "SUCCESS"
            except Exception as e:
                # Agent may already be disconnected — non-fatal for a delete.
                logger.info(f"Revoke relay for delete of agent '{agent_id}' skipped/failed (may be dead): {e}")
        names = hub.state.system_state.get("agent_display_names", {})
        if agent_id in names:
            names.pop(agent_id, None)
            hub.state.save_state()
        msg = ("Agent disconnected and removed." if relayed else "Agent removed (was not connected).")
        return {"status": "ok", "message": msg}

    @app.get("/api/pxmx/nodes")
    async def get_pxmx_nodes():
        hub = app.state.hub
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            return {"nodes": [], "spoke_connected": False}
        try:
            result = await hub.request_response(pxmx_spoke, "GET_NODE_STATS", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.exception("get_pxmx_nodes failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── pxmx / Proxmox: VMs + agent commands (/api/pxmx/*) ───────────────────
    @app.get("/api/pxmx/vms")
    async def get_pxmx_vms(request: Request, agent_id: str = None, tenant: str = None):
        """
        Aggregate VM/CT list from all connected pxmx agents.
        Each VM includes unique_id ("<cluster>/<node>/<vmid>"), agent_id, cluster, node, vmid.
        Pass ?agent_id=<id> to scope to a single agent.
        Pass ?tenant=<id> to filter by that tenant's proxmox_tag setting AND to
        subnet-filter the returned VMs by that tenant's NetBox prefixes (each VM
        carries an ``ips`` list; VMs whose ``ips`` all fall outside the tenant's
        prefixes are dropped). The subnet filter is applied on all three return
        paths (tenant cache hit / spoke-down cache / live) via
        ``_filter_tenant`` so an admin acting as a tenant sees only that
        tenant's VMs — the toggle is the ``hypervisor`` subnet-filter module.
        """
        hub = app.state.hub
        # see _netbox_list_get (variant: hypervisor spoke, proxmox_tag payload, and
        # a non-503 spoke-down shape {vms:[], spoke_connected:False} — inline).
        logger.debug("relay %s %s tenant=%s agent_id=%s", request.method, request.url.path, tenant, agent_id)
        sess = _session_user(request)
        if not agent_id and not tenant and sess and not _is_admin(sess):
            tid = sess.get("user", {}).get("tenant_id")
            if tid:
                cached = _cache_entry(tid, "pxmx_vms")
                if cached:
                    return await _filter_tenant(request, cached["data"], "hypervisor", ["ips"], tenant)
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            if sess:
                tid = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tid, "pxmx_vms") if tid else None
                if cached:
                    return await _filter_tenant(request, cached["data"], "hypervisor", ["ips"], tenant)
            return {"vms": [], "spoke_connected": False}
        try:
            scoping = get_tenant_scoping(hub, _resolve_tenant(request, tenant))
            payload: dict = {}
            if agent_id:
                payload["agent_id"] = agent_id
            if scoping.get("proxmox_tag"):
                payload["tag_filter"] = scoping["proxmox_tag"]
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_VMS", payload)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return await _filter_tenant(request, data, "hypervisor", ["ips"], tenant)
        except Exception as e:
            logger.exception("get_pxmx_vms failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/console")
    async def pxmx_create_console(request: Request):
        """Hypervisors view VNC console — create a console session for a VM.

        Body: ``{unique_id, vmid, node, type}``. Mints a one-shot ``session_id``
        + ``ws_token`` and tells the pxmx spoke→agent to open a Proxmox
        vncwebsocket locally (agent-terminates-WSS) and relay frames over the
        existing WS legs. Admin-only (VM console is privileged). The browser
        then connects to ``/ws/console/{session_id}?token=<ws_token>`` for the
        noVNC byte relay. Fire-and-forget VNC_START — the agent emits
        VNC_READY/VNC_ERROR up, which the browser WS picks up."""
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        try:
            body = await request.json()
        except Exception:
            body = {}
        unique_id = str((body or {}).get("unique_id", "")).strip()
        parts = unique_id.split("/")
        if len(parts) < 3:
            raise HTTPException(status_code=400, detail="invalid unique_id (expect <cluster>/<node>/<vmid>)")
        cluster, node, vmid_s = parts[0], parts[1], parts[2]
        try:
            vmid = int(vmid_s)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid vmid in unique_id")
        hub = app.state.hub
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            raise HTTPException(status_code=503, detail="Hypervisor spoke not connected")
        session_id = str(uuid.uuid4())
        ws_token = secrets.token_urlsafe(32)
        tenant_id = sess.get("tenant_id") or ""
        hub.register_vnc_session(session_id, {
            "spoke_id": pxmx_spoke,
            "tenant_id": tenant_id,
            "ws_token": ws_token,
            "vmid": vmid,
            "node": node,
            "unique_id": unique_id,
        })
        try:
            await hub.send_to_spoke_command(pxmx_spoke, "VNC_START", {
                "session_id": session_id,
                "unique_id": unique_id,
                "vmid": vmid,
                "node": node,
                "type": str((body or {}).get("type", "qemu")),
            })
        except Exception as e:
            hub.unregister_vnc_session(session_id)
            logger.exception("pxmx_create_console VNC_START failed")
            raise HTTPException(status_code=502, detail=f"failed to start console: {e}")
        return {"session_id": session_id, "ws_token": ws_token, "expires_in": 60}

    @app.websocket("/ws/console/{session_id}")
    async def pxmx_console_ws(websocket: WebSocket, session_id: str):
        """Browser↔Proxmox VNC byte relay (agent-terminates-WSS).

        Auth: the single-use ``ws_token`` query param must match the session
        record minted by ``pxmx_create_console``. Two relay tasks:
        ``browser_to_spoke`` sends raw bytes to the agent as VNC_FRAME_DOWN
        (fire-and-forget); ``spoke_to_browser`` sends queued Proxmox frames
        (VNC_FRAME_UP) to the browser as bytes, and handles control tuples
        (VNC_READY / VNC_ERROR / VNC_DISCONNECT) from _handle_agent_relay_up.
        On any exit, sends VNC_DISCONNECT down so the agent closes the Proxmox
        WSS and drops the session."""
        token = websocket.query_params.get("token") or ""
        hub = app.state.hub
        sess = hub.get_vnc_session(session_id)
        if not sess or sess.get("ws_token") != token:
            await websocket.accept()
            await websocket.close(code=4401, reason="invalid or expired console session")
            return
        spoke_id = sess["spoke_id"]
        queue = sess["queue"]
        await websocket.accept()
        relay_tasks: list = []
        try:
            async def browser_to_spoke():
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        raise WebSocketDisconnect(code=msg.get("code", 1000))
                    raw = msg.get("bytes")
                    if raw is None:
                        text = msg.get("text")
                        if not text:
                            continue
                        raw = text.encode()
                    await hub.send_to_spoke_command(spoke_id, "VNC_FRAME_DOWN", {
                        "session_id": session_id,
                        "data": base64.b64encode(raw).decode(),
                    })

            async def spoke_to_browser():
                while True:
                    item = await queue.get()
                    if isinstance(item, (bytes, bytearray)):
                        await websocket.send_bytes(bytes(item))
                    elif isinstance(item, tuple) and item:
                        kind = item[0]
                        if kind == "error":
                            await websocket.close(code=1011, reason=str(item[1]))
                            return
                        # "ready" → no-op (RFB just starts); "disconnect" → close
                        return
                    else:
                        return

            relay_tasks = [asyncio.create_task(browser_to_spoke()),
                           asyncio.create_task(spoke_to_browser())]
            done, pending = await asyncio.wait(relay_tasks,
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*relay_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (WebSocketDisconnect, asyncio.CancelledError)):
                    raise exc
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.warning("console ws %s relay failed: %s", session_id, exc)
        finally:
            hub.unregister_vnc_session(session_id)
            try:
                await hub.send_to_spoke_command(spoke_id, "VNC_DISCONNECT",
                                                {"session_id": session_id})
            except Exception:
                pass
            for task in relay_tasks:
                if not task.done():
                    task.cancel()
            if relay_tasks:
                await asyncio.gather(*relay_tasks, return_exceptions=True)
            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close()
                except Exception:
                    pass

    @app.post("/api/pxmx/vm-action")
    async def pxmx_vm_action(request: Request):
        """Hypervisors view VM lifecycle: start/stop/reboot/snapshot (ANY vmid).

        Body: ``{unique_id, vmid, node, type, action, snapshot_name?}``. Routes to
        the pxmx spoke's ``PXMX_VM_ACTION`` (unguarded — the agent's cs_guard sim
        90000 floor does NOT apply, so real tenant VMs at arbitrary vmids work).
        Admin-only: VM control is a privileged action. ``timeout=35`` covers a
        slow ``qm stop``/``snapshot`` (spoke→agent window is 30s)."""
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        try:
            body = await request.json()
        except Exception:
            body = {}
        action = str((body or {}).get("action", "")).lower()
        if action not in ("start", "stop", "reboot", "restart", "snapshot"):
            raise HTTPException(status_code=400, detail=f"unknown action: {action}")
        hub = app.state.hub
        pxmx_spoke = hub.get_spoke_by_type("hypervisor")
        if not pxmx_spoke:
            raise HTTPException(status_code=503, detail="Hypervisor spoke not connected")
        payload = {
            "unique_id": body.get("unique_id", ""),
            "vmid": body.get("vmid"),
            "node": body.get("node", ""),
            "type": body.get("type", "qemu"),
            "action": action,
            "snapshot_name": body.get("snapshot_name"),
        }
        try:
            result = await hub.request_response(pxmx_spoke, "PXMX_VM_ACTION", payload, timeout=35.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # Best-effort: a VM lifecycle change (start/stop/restart/snapshot)
            # may change the NetBox VM-record view (status at minimum), so re-sync
            # the acting tenant's VMs to NetBox when the VM sync is enabled.
            _trigger_vm_sync_after_pxmx_edit(hub, request, body)
            return data
        except Exception as e:
            logger.exception("pxmx_vm_action failed")
            raise HTTPException(status_code=500, detail=str(e))
        """Per-tenant aggregate counts across all connected spokes, scoped by
        the tenant's netbox_tenant_slug / proxmox_tag. Returns
        {devices, vms, sessions, prefixes, ips_used}. Shared by the single-tenant
        dashboard summary and the admin all-tenants overview so both show
        identical numbers for a given tenant."""
        import asyncio as _asyncio
        nb_slug  = scoping["netbox_tenant_slug"] or None
        pxmx_tag = scoping["proxmox_tag"]        or None

        spoke_ipam       = hub.get_spoke_by_type("ipam")
        spoke_hypervisor = hub.get_spoke_by_type("hypervisor")
        spoke_nac        = hub.get_spoke_by_type("nac")

        async def _req(spoke, cmd, payload=None):
            if not spoke:
                return {}
            try:
                timeout = 30.0 if isinstance(cmd, str) and cmd.startswith("NETBOX_") else 5.0
                r = await hub.request_response(spoke, cmd, payload or {}, timeout=timeout)
                return r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
            except Exception:
                return {}

        devices_r, prefixes_r, ips_r, vms_r, sessions_r = await _asyncio.gather(
            _req(spoke_ipam, "NETBOX_GET_DEVICES", {"tenant": nb_slug}),
            _req(spoke_ipam, "NETBOX_GET_PREFIXES", {"tenant": nb_slug}),
            _req(spoke_ipam, "NETBOX_GET_IPS",     {"tenant": nb_slug}),
            _req(spoke_hypervisor, "PXMX_LIST_VMS",
                 {"tag_filter": pxmx_tag} if pxmx_tag else {}),
            _req(spoke_nac, "CPPM_GET_ACCESS_TRACKER", {}),
        )

        devices  = len(devices_r.get("devices",   []))
        prefixes = len(prefixes_r.get("prefixes", []))
        ips_used = len(ips_r.get("ip_addresses",  []))
        all_vms  = vms_r.get("vms", [])
        sessions_list = sessions_r.get("sessions", sessions_r.get("data", []))
        # Scope the VM + active-session counts by the tenant's subnets so the
        # dashboard matches the (tenant-scoped) hypervisor + Access Tracker
        # views, not the global totals. No prefixes (unbound tenant) or the
        # module's subnet-filter toggle off → global count. VMs filter on their
        # ``ips`` list (a VM with no concrete IPs, e.g. stopped, is shown — can't
        # filter, err on showing).
        sess_prefixes = await _resolve_prefixes_for_tenant(hub, scoping.get("tenant_id"))
        if sess_prefixes and _filter_enabled(hub, "hypervisor"):
            all_vms = filter_items_by_prefixes(all_vms, sess_prefixes, ["ips"])
        if sess_prefixes:
            sessions_list = filter_items_by_prefixes(sessions_list, sess_prefixes, ["ip"])
        vms      = sum(1 for v in all_vms if v.get("status") == "running")
        sessions = len(sessions_list)

        return {
            "devices":   devices,
            "vms":       vms,
            "sessions":  sessions,
            "prefixes":  prefixes,
            "ips_used":  ips_used,
        }

    @app.get("/api/dashboard/summary")
    async def dashboard_summary(request: Request, tenant: str = None):
        """
        Aggregate counts for the active tenant across all connected spokes.
        Returns: devices (NetBox), vms (Proxmox running), sessions (CPPM), prefixes, ips_used.
        All counts are scoped by the tenant's netbox_tenant_slug / proxmox_tag.
        """
        hub = app.state.hub
        scoping = get_tenant_scoping(hub, _resolve_tenant(request, tenant))
        counts = await _compute_tenant_counts(hub, scoping)
        return {"tenant": scoping["tenant_id"], **counts}

    # Admin all-tenants overview: memoized 60s so repeated renders don't re-fan-out.
    _all_tenants_summary_cache: dict = {"ts": 0.0, "data": None}

    @app.get("/api/dashboard/all-tenants")
    async def dashboard_all_tenants(request: Request, refresh: int = 0):
        """Admin-only: one row per tenant with the same counts as the
        single-tenant summary, fanned out in parallel (bounded) and memoized
        for 60s. ``?refresh=1`` bypasses the memo. ``default`` is excluded
        (unscoped — its counts would be global/all and misleading)."""
        import asyncio as _asyncio, time as _time
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        if not refresh and _all_tenants_summary_cache["data"] is not None \
                and (_time.time() - _all_tenants_summary_cache["ts"]) < 60:
            return _all_tenants_summary_cache["data"]

        tenants = hub.state.tenant_state.get("tenants", {})
        tids = [tid for tid in tenants.keys() if tid != "default"]

        sem = _asyncio.Semaphore(5)

        async def _one(tid):
            cfg = tenants.get(tid) or {}
            scoping = get_tenant_scoping(hub, tid)
            async with sem:
                counts = await _compute_tenant_counts(hub, scoping)
            return {
                "id":          tid,
                "name":        cfg.get("name") or tid,
                "slug":        cfg.get("netbox_tenant_slug") or tid,
                "description": cfg.get("description", ""),
                **counts,
            }

        rows = await _asyncio.gather(*[_one(tid) for tid in tids], return_exceptions=True)
        out = []
        for tid, row in zip(tids, rows):
            if isinstance(row, Exception):
                logger.warning(f"all-tenants counts for '{tid}' failed: {row}")
                cfg = tenants.get(tid) or {}
                out.append({
                    "id": tid, "name": cfg.get("name") or tid,
                    "slug": cfg.get("netbox_tenant_slug") or tid,
                    "description": cfg.get("description", ""),
                    "devices": 0, "vms": 0, "sessions": 0, "prefixes": 0, "ips_used": 0,
                })
            else:
                out.append(row)
        out.sort(key=lambda r: r["name"].lower())
        data = {"tenants": out}
        _all_tenants_summary_cache["ts"] = _time.time()
        _all_tenants_summary_cache["data"] = data
        return data

    @app.get("/api/search")
    # ── Dashboard + global search (/api/search, /api/dashboard) ──────────────
    # cross_system_search fans `q` to every spoke type (NETBOX/VMs/SESSIONS/
    # USERS/DHCP); matching is spoke-side. See docs/architecture.md search table
    # and memory `global-device-search-fanout`.
    async def cross_system_search(request: Request, q: str, tenant: str = None):
        """
        Fan-out search across all connected spoke types.
        Each spoke's results are tagged with source= so the UI can group them.

        Query type detection:
          - IP / prefix: contains '.' or ':' (IPv4/IPv6/CIDR)
          - MAC: matches hex pairs separated by : or -
          - Name / hostname / username: everything else
        """
        import re, asyncio as _asyncio
        hub = app.state.hub
        if not q or not q.strip():
            raise HTTPException(status_code=400, detail="q must not be empty")

        resolved = _resolve_tenant(request, tenant)
        scoping = get_tenant_scoping(hub, resolved)
        payload = {"q": q.strip(), "tenant": scoping["netbox_tenant_slug"] or resolved}

        async def _call(spoke, cmd):
            if not spoke:
                return []
            try:
                r = await hub.request_response(spoke, cmd, payload)
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                return d.get("results", []) if isinstance(d, dict) else []
            except Exception as e:
                return [{"source": cmd, "type": "error", "name": str(e)}]

        spoke_ipam       = hub.get_spoke_by_type("ipam")
        spoke_hypervisor = hub.get_spoke_by_type("hypervisor")
        spoke_nac        = hub.get_spoke_by_type("nac")
        spoke_directory  = hub.get_spoke_by_type("directory")
        spoke_firewall   = hub.get_spoke_by_type("firewall")

        tasks = [
            _call(spoke_ipam,       "NETBOX_SEARCH"),
            _call(spoke_hypervisor, "SEARCH_VMS"),
            _call(spoke_nac,        "SEARCH_SESSIONS"),
            _call(spoke_directory,  "SEARCH_USERS"),
            _call(spoke_firewall,   "SEARCH_DHCP"),
        ]
        all_results = await _asyncio.gather(*tasks)
        merged = [item for sublist in all_results for item in sublist]

        # Categorise for the UI
        is_ip  = bool(re.match(r'^[\d:.]+(/\d+)?$', q.strip()))
        is_mac = bool(re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', q.strip()))
        return {
            "query":       q,
            "query_type":  "ip" if is_ip else ("mac" if is_mac else "name"),
            "total":       len(merged),
            "results":     merged,
            "spokes_queried": {
                "ipam":       spoke_ipam is not None,
                "hypervisor": spoke_hypervisor is not None,
                "nac":        spoke_nac is not None,
                "directory":  spoke_directory is not None,
                "firewall":   spoke_firewall is not None,
            },
        }

    @app.get("/setup/debug-mode")
    async def get_debug_mode():
        hub = app.state.hub
        enabled = hub.state.get_global_config().get("debug_mode", False)
        return {"enabled": enabled}

    @app.post("/setup/debug-mode")
    async def toggle_debug_mode(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            enabled = data.get("enabled", False)

            global_config = hub.state.get_global_config()
            global_config["debug_mode"] = enabled
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            await hub.broadcast_log_level(enabled)

            return {"status": "ok", "enabled": enabled}
        except Exception as e:
            logger.exception("toggle_debug_mode failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/docs/{section}")
    async def get_docs(section: str):
        try:
            readme_path = os.path.join(os.path.dirname(__file__), "../../README.md")
            if not os.path.exists(readme_path):
                raise HTTPException(status_code=404, detail="README.md documentation not found")

            with open(readme_path, "r") as f:
                content = f.read()

            marker = "### \U0001f4d6 Help:"
            sections = content.split(marker)

            for s in sections[1:]:
                lines = s.split('\n')
                header = lines[0].strip()
                if header == section:
                    body = '\n'.join(lines[1:]).strip()
                    return {"content": body}

            raise HTTPException(status_code=404, detail=f"Help section '{section}' not found in documentation.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading documentation section {section}: {e}")
            raise HTTPException(status_code=500, detail=f"Error retrieving documentation: {str(e)}")

    @app.get("/setup/appearance")
    async def get_appearance():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("appearance", {
            "primary_color": "#01A982",
            "navy_color": "#263040",
            "logo_url": "hpe-svg",
            "logo_url_right": "hpe-svg",
            "show_logo_left": True,
            "show_logo_right": True
        })
        return {"config": config}

    @app.post("/setup/appearance")
    async def update_appearance(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["appearance"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "ok", "message": "Appearance settings updated."}
        except Exception as e:
            logger.exception("update_appearance failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/logs/all")
    async def get_all_logs():
        hub = app.state.hub
        return hub.collect_all_logs()

    @app.get("/setup/logs")
    async def get_hub_logs():
        hub = app.state.hub
        try:
            log_path = "/var/log/lm/hub.log"
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    file_lines = f.readlines()
                return {"logs": [l.strip() for l in file_lines[-500:]]}
            # No file — fall back to in-memory deque (deques don't support slicing)
            mem_logs = list(hub.logs)[-500:] if hasattr(hub, "logs") else []
            return {"logs": [str(l) for l in mem_logs]}
        except Exception as e:
            logger.error(f"Error reading hub logs: {e}")
            try:
                mem_logs = list(hub.logs)[-500:] if hasattr(hub, "logs") else []
                return {"logs": [str(l) for l in mem_logs]}
            except Exception:
                return {"logs": []}

    @app.get("/setup/logs/{module}")
    async def get_module_logs(module: str):
        hub = app.state.hub
        try:
            if module == "errors":
                # Error Log tab: every error-level line across all sources
                # (hub deque, agent_logs, /var/log/lm/*.log), one list.
                return hub.collect_error_logs()

            if module == "agents":
                flat = []
                for agent_id, logs in hub.agent_logs.items():
                    for line in logs:
                        flat.append(f"[{agent_id}] {line}")
                return {"logs": flat[-500:]}

            # Map WebUI module keys → actual log filenames under /var/log/lm/
            log_name_map = {
                "opn":    "lm-opnsense",
                "pxmx":   "lm-pxmx",
                "cppm":   "lm-cppm",
                "cs":     "lm-cs",
                "ldap":   "lm-ldap",
                "netbox": "lm-netbox-spoke",
                "dns":    "lm-dns",
                "dhcp":   "lm-dhcp",
            }
            filename = log_name_map.get(module, f"lm-{module}")

            log_path = f"/var/log/lm/{filename}.log"
            if not os.path.exists(log_path):
                raise HTTPException(status_code=404, detail=f"Log file for {module} not found at {log_path}.")

            with open(log_path, "r") as f:
                logs = f.readlines()

            return {"logs": [log.strip() for log in logs[-500:]]}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading logs for {module}: {e}")
            raise HTTPException(status_code=500, detail=f"Permission or I/O error reading {log_path}: {str(e)}")

    @app.get("/setup/api-probe")
    async def probe_spoke_api(spoke_id: str, path: str):
        hub = app.state.hub
        if spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Spoke {spoke_id} not connected")

        try:
            result = await hub.request_response(spoke_id, "PROBE_API", {"path": path})
            return result
        except Exception as e:
            logger.exception("probe_api failed (spoke=%s path=%s)", spoke_id, path)
            raise HTTPException(status_code=500, detail=f"Probe failed: {str(e)}")


    # ── Diagnostics + bug-report (/setup/diagnostics, /api/bug-report/*) ───────
    @app.get("/setup/diagnostics")
    async def get_diagnostics():
        """Per-spoke + hub diagnostic snapshot for the WebUI Diagnostics card.

        Assembles, for each known spoke: connection status, heartbeat age + RED
        flag, watchdog/recovery state, flapping detection, version skew vs the
        hub, and CS telemetry presence; plus hub-side metrics. Consumer: the
        WebUI Diagnostics view (``loadDiagnostics`` in ``WebUI/main.js``).
        Read-only aggregate — does NOT mutate state or send to spokes. The
        heartbeat 300s RED threshold is load-bearing for the watchdog (see
        ``messaging/heartbeat.py`` and ``main.py`` ``run_spoke_recovery_loop``)."""
        hub = app.state.hub
        metrics = await hub.get_system_metrics()
        diagnostics = []
        known_spokes = hub.state.system_state.get("known_modules", [])

        # Resolved up-front so per-spoke version_skew can be computed in the loop.
        hub_version = await hub.get_local_version()
        now = time.time()

        for sid in known_spokes:
            ws = hub.active_connections.get(sid)
            telemetry = hub.spoke_telemetry.get(sid, {})
            events = hub.get_spoke_events(sid, limit=50)

            # Flapping detector: count connect/close cycles in the last 5 min.
            # A "flap" is a connection_closed / connection_error / auth_failed
            # event — i.e. the spoke reached the hub then dropped. Many of
            # these in a short window with intervening auth_attempt/connected
            # events is the flapping signature (spoke process is alive and
            # retrying, but never holds the connection).
            recent = [e for e in events if now - e["ts"] <= 300]
            flap_drops = sum(1 for e in recent if e["event"] in
                             ("connection_closed", "connection_error",
                              "auth_failed", "mutual_auth_failed", "mutual_auth_timeout"))
            flapping = flap_drops >= 3

            # Heartbeat age: seconds since the last inbound heartbeat frame, or
            # None if the spoke has never heartbeated. get_status() already
            # classifies GREEN/YELLOW/RED from this; surfacing the raw age lets
            # the UI show "last seen 312s ago" rather than just a colored dot.
            last_seen = hub.heartbeat.last_seen.get(sid)
            heartbeat_age_s = None
            if isinstance(last_seen, (int, float)):
                heartbeat_age_s = max(0, int(now - last_seen))

            # Watchdog recovery state (run_spoke_recovery_loop). Empty dict when
            # the spoke has never been stranded/recovered. The WebUI renders a
            # badge + attempt counter + last action/error from this; bugfixer
            # also reads it via GET_SPOKE_STATUS to suppress/escalate.
            rec = hub.spoke_recovery.get(sid, {}) or {}

            spoke_version = hub.spoke_versions.get(sid, "unknown")
            # version_skew: True when the spoke is connected AND reports a
            # version different from the hub. "unknown" / disconnected spokes
            # are not skewed (we just don't know).
            version_skew = (
                spoke_version not in ("unknown", None, "")
                and hub_version not in ("unknown", None, "")
                and str(spoke_version) != str(hub_version)
            )

            diagnostics.append({
                "spoke_id": sid,
                "display_name": hub.state.get_module_name(sid),
                "authenticated": sid in hub.active_connections,
                "approved": hub.approved_modules.get(sid, False),
                "heartbeat_status": hub.heartbeat.get_status(sid),
                "heartbeat_age_s": heartbeat_age_s,
                "connection_state": ws.state if ws else "OFFLINE",
                "version": spoke_version,
                "version_skew": version_skew,
                "hub_version": hub_version,
                "last_attempt": telemetry.get("last_attempt"),
                "last_status": telemetry.get("status", "UNKNOWN"),
                "last_error": telemetry.get("error"),
                "flapping": flapping,
                "recent_drops": flap_drops,
                "events": events,
                "cpu_util": telemetry.get("cpu_util"),
                "mem_util": telemetry.get("mem_util"),
                # Watchdog recovery (see run_spoke_recovery_loop). in_progress =
                # hub is actively restarting the unit (backoff); gave_up = a
                # restart structurally can't fix it (e.g. venv missing) and
                # bugfixer has/will be handed off; manual_pause = admin paused.
                "recovery": {
                    "attempts": rec.get("attempts", 0),
                    "in_progress": bool(rec.get("in_progress", False)),
                    "gave_up": bool(rec.get("gave_up", False)),
                    "manual_pause": bool(rec.get("manual_pause", False)),
                    "last_action": rec.get("last_action", ""),
                    "last_error": rec.get("last_error", ""),
                    "last_crash_sig": rec.get("last_crash_sig", ""),
                    "next_retry_ts": rec.get("next_retry_ts", 0),
                    "last_attempt_ts": rec.get("last_attempt_ts", 0),
                },
                # Client-Sim combined spoke: module type, tenant binding, and
                # whether the latest CS_TELEMETRY frame is cached.
                "module_type": hub.spoke_module_types.get(sid, ""),
                "tenant_id": hub.state.get_spoke_tenant(sid),
                "cs_telemetry_cached": sid in hub.simulations_cache,
                "cs_telemetry_ts": (hub.simulations_cache.get(sid, {}) or {}).get("timestamp"),
            })

        webui_version = "unknown"
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../ui/VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../../../GitHub/webui/VERSION")
            with open(version_path, "r") as f:
                webui_version = f.read().strip()
        except Exception:
            pass

        return {
            "spokes": diagnostics,
            "hub_version": hub_version,
            "webui_version": webui_version,
            "system": metrics
        }

    @app.post("/setup/spoke/{spoke_id}/recovery")
    async def set_spoke_recovery_pause(spoke_id: str, request: Request):
        """Manual override for the spoke-recovery watchdog.

        Body: {"pause": true|false}. Pausing sets manual_pause so the watchdog
        stops restart attempts for this spoke (one of the give-up triggers);
        resuming clears it so recovery resumes. This is the "Manual override
        flag" surfaced as a per-row Pause/Resume button in the Diagnostics view.
        Admin-gated automatically by the /setup/ prefix in access_control_middleware.
        """
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        pause = bool(data.get("pause", False))

        st = hub.spoke_recovery.setdefault(spoke_id, {"attempts": 0})
        if pause:
            st["manual_pause"] = True
            st["in_progress"] = False
            action, event = "paused", "recovery_paused"
            hub.record_spoke_event(spoke_id, "recovery_paused", "manual pause set via WebUI")
            logger.info(f"[recovery] spoke_id={spoke_id} action=paused reason=manual_override")
        else:
            st["manual_pause"] = False
            # Resume: reset attempts/backoff so recovery fires on the next tick
            # rather than waiting out a stale next_retry_ts.
            st["attempts"] = 0
            st["next_retry_ts"] = 0
            st["gave_up"] = False
            action, event = "resumed", "recovery_resumed"
            hub.record_spoke_event(spoke_id, "recovery_resumed", "manual pause cleared via WebUI")
            logger.info(f"[recovery] spoke_id={spoke_id} action=resumed reason=manual_override")
        return {"status": "ok", "spoke_id": spoke_id, "paused": pause}

    @app.post("/api/bug-report")
    async def file_bug_report(request: Request):
        """File a Bug from the WebUI footer button.

        Body: {explanation, severity, console_logs, html, screenshot, context}.
        The hub stores the full artifacts (console/HTML/screenshot) under
        data_dir/bugs/<id>/ and logs a short greppable [bug-report] marker so
        bugfixer's scan_bugs finds it. The marker line carries only the id +
        a summary — the large payloads never go into the hub log. Any
        authenticated user can file (the /api/ prefix is auth-gated but not
        admin-only, unlike /setup/). bugfixer later files a clean-body GitHub
        issue and pulls these artifacts from the hub for fix context.
        """
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        if not isinstance(data, dict) or not str(data.get("explanation") or "").strip():
            raise HTTPException(status_code=400, detail="Missing explanation")

        try:
            explanation = str(data.get("explanation") or "")
            # Capture-integrity receipt line (before store): shows whether the
            # WebUI actually captured console/html/screenshot, so a "no issue in
            # GitHub" trace can rule out a missing payload upstream of storage.
            shot = data.get("screenshot")
            if isinstance(shot, str) and shot.startswith("data:"):
                shot_kind = "png" if "image/png" in shot.split(",", 1)[0] else "jpg"
            else:
                shot_kind = "none"
            logger.info(
                f"[bug-report] received explanation={len(explanation)} chars "
                f"console={len(str(data.get('console_logs') or ''))} "
                f"html={len(str(data.get('html') or ''))} screenshot={shot_kind}"
            )
            rid = hub._store_bug_report(data)
            if not rid:
                logger.error("bug-report: _store_bug_report returned no id (data keys=%s)", list(data.keys()))
                raise HTTPException(status_code=500, detail="Failed to store bug report")
            sev = str(data.get("severity") or "medium")
            ctx = data.get("context") or {}
            view = ctx.get("currentView") if isinstance(ctx, dict) else ""
            # Short marker — flows through HubLogHandler -> self.logs ->
            # /var/log/lm/hub.log -> GET_LOGS -> bugfixer scan_bugs. No base64.
            logger.info(
                f"[bug-report] id={rid} severity={sev} view={view} "
                f"summary={explanation[:80]!r}"
            )
            return {"status": "ok", "id": rid}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"[bug-report] /api/bug-report failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    # Bug Reports log view (admin-only, like the rest of /setup/): lists filed
    # reports and serves the full artifacts (console/HTML/screenshot) for an
    # expandable detail modal. Reuses the hub's _list_bug_reports /
    # _get_bug_report helpers so the UI and bugfixer see the same data.
    @app.get("/setup/bug-reports")
    async def list_bug_reports():
        hub = app.state.hub
        reports = hub._list_bug_reports()
        reports.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return {"reports": reports}

    @app.get("/setup/bug-reports/{rid}")
    async def get_bug_report(rid: str):
        hub = app.state.hub
        rep = hub._get_bug_report(rid)
        if not rep:
            raise HTTPException(status_code=404, detail="Bug report not found")
        return rep

    # ── LDAP relay (/api/ldap/*) ──────────────────────────────────────────────
    async def get_ldap_spoke(hub):
        spoke_id = hub.get_spoke_by_type("directory")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        return spoke_id

    @app.get("/api/ldap/ous")
    async def get_ldap_ous():
        """List LDAP OUs from the directory spoke."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/ous")
        try:
            result = await hub.request_response(spoke_id, "LIST_OUS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_ldap_ous failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/ous")
    async def create_ldap_ou(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_OU", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_ou failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/ous")
    async def update_ldap_ou(request: Request):
        """Rename an OU (dn + new name → modrdn on the spoke)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn") or not data.get("name"):
                raise HTTPException(status_code=400, detail="dn and name are required")
            result = await hub.request_response(spoke_id, "UPDATE_OU", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_ou failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/users")
    async def get_ldap_users():
        """List LDAP users from the directory spoke."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/users")
        try:
            result = await hub.request_response(spoke_id, "LIST_USERS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_ldap_users failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_USER", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/users")
    async def update_ldap_user(request: Request):
        """Update a user's attributes (first/last/email) and optionally rename uid."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn"):
                raise HTTPException(status_code=400, detail="dn is required")
            result = await hub.request_response(spoke_id, "UPDATE_USER", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/groups")
    async def get_ldap_groups():
        """List LDAP groups from the directory spoke."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/groups")
        try:
            result = await hub.request_response(spoke_id, "LIST_GROUPS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_ldap_groups failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_GROUP", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/groups")
    async def update_ldap_group(request: Request):
        """Rename a group (dn + new name → modrdn on the spoke)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn") or not data.get("name"):
                raise HTTPException(status_code=400, detail="dn and name are required")
            result = await hub.request_response(spoke_id, "UPDATE_GROUP", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/group")
    async def add_ldap_user_to_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "ADD_USER_TO_GROUP", data)
            return result
        except Exception as e:
            logger.exception("add_ldap_user_to_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/users/group")
    async def remove_ldap_user_from_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "REMOVE_USER_FROM_GROUP", data)
            return result
        except Exception as e:
            logger.exception("remove_ldap_user_from_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/entity")
    async def delete_ldap_entity(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "DELETE_ENTITY", data)
            return result
        except Exception as e:
            logger.exception("delete_ldap_entity failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/password")
    async def set_ldap_user_password(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "SET_PASSWORD", data)
            return result
        except Exception as e:
            logger.exception("set_ldap_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── NetBox setup config ───────────────────────────────────────────────────

    # Shims delegating to access.* — bodies live in access.py (importable,
    # testable, free of the nested-def annotation trap). Routes keep calling
    # get_netbox_spoke(hub) / get_tenant_scoping(hub, tid) unchanged.
    def get_netbox_spoke(hub):
        return access.get_netbox_spoke(hub)

    def get_tenant_scoping(hub, tenant_id: str = None) -> dict:
        return access.get_tenant_scoping(hub, tenant_id)

    @app.get("/setup/netbox-config")
    async def get_netbox_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("netbox", {})
        return {"config": config}

    @app.post("/setup/netbox-config")
    async def update_netbox_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["netbox"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            spoke_id = get_netbox_spoke(hub)
            if spoke_id:
                msg = _hub_msg(spoke_id, "UPDATE_CONFIG", {"netbox_url": config.get("url"), "api_token": config.get("api_token")})
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Config saved and pushed to NetBox spoke.", "pushed": True}
            return {"status": "partial_success", "message": "Config saved; NetBox spoke not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_netbox_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── NetBox data API ────────────────────────────────────────────────────────

    async def _netbox_list_get(request, tenant, cache_key, cmd, slice_query, subnet_fields, route_name):
        """Cache→spoke→offline GET for the NetBox list handlers (racks/devices/
        prefixes/ips). Non-admin cache hit (when no slice param or tenant is
        selected) → cached data; spoke down → offline cache fallback; otherwise a
        live spoke round-trip with the resolved tenant slug. ``slice_query`` is the
        dict of non-tenant slice params (site/rack/prefix/device); ``subnet_fields``
        is None for raw data or a list like ``["prefix"]`` to apply the subnet
        filter to both cached and live data. Handlers that can't share this
        helper (get_firewall_data, get_cppm_devices/sessions, get_pxmx_vms)
        inline the same cache→spoke→offline shape with a
        ``# see _netbox_list_get (variant: …)`` cross-ref."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s %s", request.method, request.url.path, tenant, slice_query)
        sess = _session_user(request)
        cache_bypass = bool(tenant) or any(v for v in slice_query.values())
        if not cache_bypass and sess and not _is_admin(sess):
            tid = sess.get("user", {}).get("tenant_id")
            if tid:
                cached = _cache_entry(tid, cache_key)
                if cached:
                    data = cached["data"]
                    if subnet_fields:
                        return await _filter_session(request, data, "netbox", subnet_fields)
                    return data
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            if sess:
                tid = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tid, cache_key) if tid else None
                if cached:
                    data = cached["data"]
                    if subnet_fields:
                        return await _filter_session(request, data, "netbox", subnet_fields)
                    return data
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            scoping = get_tenant_scoping(hub, _resolve_tenant(request, tenant))
            payload = dict(slice_query)
            payload["tenant"] = scoping["netbox_tenant_slug"] or None
            result = await hub.request_response(spoke_id, cmd, payload)
            data = _unwrap_spoke(result)
            if subnet_fields:
                return await _filter_session(request, data, "netbox", subnet_fields)
            return data
        except Exception as e:
            logger.exception(route_name + " failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/health")
    async def netbox_health():
        """NetBox spoke reachability + API-token validity probe (10s timeout)."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_HEALTH", {}, timeout=10.0)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_health failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/sites")
    async def netbox_get_sites():
        """List NetBox sites (admin sees all; unfiltered spoke round-trip)."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_GET_SITES", {})
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_get_sites failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/racks")
    async def netbox_get_racks(request: Request, site: str = None, tenant: str = None):
        """List NetBox racks, optionally scoped by site; non-admins get the
        tenant cache, admins/multi-tenant switches go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_racks", "NETBOX_GET_RACKS",
                                      {"site": site}, None, "netbox_get_racks")

    @app.post("/api/netbox/racks")
    async def netbox_add_rack(request: Request):
        """Create a NetBox rack; invalidates the racks cache on success."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "NETBOX_ADD_RACK", data)
            _refresh_module_all_tenants(hub, "netbox_racks")
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_add_rack failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/netbox/racks/{rack_id}")
    async def netbox_update_rack(rack_id: int, request: Request):
        """Update a NetBox rack; invalidates the racks cache on success."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            data["rack_id"] = rack_id
            result = await hub.request_response(spoke_id, "NETBOX_UPDATE_RACK", data)
            _refresh_module_all_tenants(hub, "netbox_racks")
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_update_rack failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/netbox/racks/{rack_id}")
    async def netbox_delete_rack(rack_id: int):
        """Delete a NetBox rack; invalidates the racks cache on success."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_DELETE_RACK", {"rack_id": rack_id})
            _refresh_module_all_tenants(hub, "netbox_racks")
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_delete_rack failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/devices")
    async def netbox_get_devices(request: Request, site: str = None, rack: str = None, tenant: str = None):
        """List NetBox devices, optionally scoped by site/rack; non-admins get the
        tenant cache, admins/multi-tenant switches go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_devices", "NETBOX_GET_DEVICES",
                                      {"site": site, "rack": rack}, None, "netbox_get_devices")

    @app.post("/api/netbox/devices")
    async def netbox_add_device(request: Request):
        """Create a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "NETBOX_ADD_DEVICE", data)
            _refresh_module_all_tenants(hub, "netbox_devices")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, data)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_add_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/claim-device/options")
    async def netbox_claim_device_options(request: Request):
        """Picklists (sites, device types, device roles, tenants) for the
        Claim-an-unknown-device form. Non-admins see only their own allowed
        tenants in the tenant list; admins see all."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_GET_DEVICE_FORM_OPTIONS", {})
            out = _unwrap_spoke(result)
            sess = _session_user(request)
            if sess and not _is_admin(sess) and isinstance(out, dict):
                user = sess.get("user", {}) or {}
                allowed_ids = user.get("tenants") or []
                if not allowed_ids and user.get("tenant_id"):
                    allowed_ids = [user.get("tenant_id")]
                allowed = set()
                for tid in allowed_ids:
                    s = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug")
                    if s:
                        allowed.add(s)
                out = dict(out)
                out["tenants"] = [t for t in (out.get("tenants") or []) if t.get("slug") in allowed]
            return out
        except Exception as e:
            logger.exception("netbox_claim_device_options failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/netbox/claim-device")
    async def netbox_claim_device(request: Request):
        """Claim a CPPM unknown (untagged) endpoint into NetBox: create a
        tenant-owned device and attach the endpoint's IP as its primary IPv4.
        The spoke does the create; on success we invalidate the device caches
        and trigger an endpoint sync so the matching ClearPass endpoint is
        tagged with the tenant and leaves 'Unknown Devices'.

        Security: a non-admin may only claim into one of their own tenants
        (matched by NetBox tenant slug); any other slug → 403. Admins may claim
        into any tenant."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        requested_slug = (str(data.get("tenant") or "").strip()) or None

        sess = _session_user(request)
        if sess and not _is_admin(sess):
            user = sess.get("user", {}) or {}
            allowed_ids = user.get("tenants") or []
            if not allowed_ids and user.get("tenant_id"):
                allowed_ids = [user.get("tenant_id")]
            allowed = set()
            for tid in allowed_ids:
                s = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug")
                if s:
                    allowed.add(s)
            if not requested_slug or requested_slug not in allowed:
                raise HTTPException(status_code=403, detail="Not authorized to claim into that tenant")

        payload = {
            "name": data.get("name", ""),
            "device_type": data.get("device_type", ""),
            "role": data.get("role", ""),
            "site": data.get("site", ""),
            "tenant": requested_slug or "",
            "status": data.get("status", "active"),
            "description": data.get("description", ""),
            "ip": data.get("ip", ""),
            "mac": data.get("mac", ""),
            "dns_name": data.get("dns_name", ""),
        }
        try:
            result = await hub.request_response(spoke_id, "NETBOX_CLAIM_DEVICE", payload)
            result = _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_claim_device failed")
            raise HTTPException(status_code=500, detail=str(e))
        if isinstance(result, dict) and result.get("status") == "SUCCESS":
            _invalidate_module_all_tenants("netbox_devices")
            _invalidate_module_all_tenants("cppm_devices")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, {"tenant": requested_slug} if requested_slug else None)
        return result

    @app.delete("/api/netbox/devices/{device_id}")
    async def netbox_delete_device(device_id: int, request: Request):
        """Delete a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_DELETE_DEVICE", {"device_id": device_id})
            _refresh_module_all_tenants(hub, "netbox_devices")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, None)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_delete_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/netbox/devices/{device_id}")
    async def netbox_update_device(device_id: int, request: Request):
        """Update a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            data["device_id"] = device_id
            result = await hub.request_response(spoke_id, "NETBOX_UPDATE_DEVICE", data)
            _refresh_module_all_tenants(hub, "netbox_devices")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, data)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_update_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/prefixes")
    async def netbox_get_prefixes(request: Request, site: str = None, tenant: str = None):
        """List NetBox prefixes (subnet-filtered), optionally scoped by site;
        non-admins get the tenant cache, admins go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_prefixes", "NETBOX_GET_PREFIXES",
                                      {"site": site}, ["prefix"], "netbox_get_prefixes")

    @app.post("/api/netbox/prefixes")
    async def netbox_allocate_prefix(request: Request):
        """Allocate a NetBox prefix; invalidates the prefix + IP caches (30s timeout)."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "NETBOX_ALLOCATE_PREFIX", data, timeout=30.0)
            _refresh_module_all_tenants(hub, "netbox_prefixes")
            _refresh_module_all_tenants(hub, "netbox_ips")
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_allocate_prefix failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/netbox/prefixes/{prefix_id}")
    async def netbox_update_prefix(prefix_id: int, request: Request):
        """Update a NetBox prefix; invalidates the prefix cache on success."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            data["prefix_id"] = prefix_id
            result = await hub.request_response(spoke_id, "NETBOX_UPDATE_PREFIX", data)
            _refresh_module_all_tenants(hub, "netbox_prefixes")
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_update_prefix failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/netbox/prefixes/{prefix_id}")
    async def netbox_delete_prefix(prefix_id: int):
        """Delete a NetBox prefix; invalidates the prefix + IP caches on success."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_DELETE_PREFIX", {"prefix_id": prefix_id})
            _refresh_module_all_tenants(hub, "netbox_prefixes")
            _refresh_module_all_tenants(hub, "netbox_ips")
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_delete_prefix failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/available-subnets")
    async def netbox_find_available_subnets(request: Request, near: str = None,
                                             prefix_length: int = None,
                                             hosts: int = None, count: int = 20,
                                             exact: str = None):
        """Find the closest free subnets of a requested size to ``near``.

        Free = no tenant-assigned NetBox prefix overlaps it; search is RFC1918.
        Size may be given as ``prefix_length`` or as ``hosts`` (host count →
        smallest mask that fits). ``exact`` is tried first when given. Response
        is only free CIDRs (no other tenants' data), so it is safe for non-admins."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        if not near:
            raise HTTPException(status_code=400, detail="'near' CIDR is required")
        try:
            payload: dict = {"near": near, "count": int(count)}
            if prefix_length is not None:
                prefix_length = int(prefix_length)
                if not 22 <= prefix_length <= 30:
                    raise HTTPException(status_code=400,
                                        detail="subnet size must be between /22 and /30 (up to a /22)")
                payload["prefix_length"] = prefix_length
            elif hosts is not None:
                payload["hosts"] = int(hosts)
            if exact:
                payload["exact"] = exact
            result = await hub.request_response(spoke_id, "NETBOX_FIND_AVAILABLE_PREFIXES",
                                                 payload, timeout=30.0)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_find_available_subnets failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/netbox/subnet-assign")
    async def netbox_assign_subnet(request: Request):
        """Assign a chosen free subnet to a tenant (the picker "Assign" action).

        Tenant is enforced server-side: a non-admin can only assign to their
        own tenant (any ``tenant`` in the body is ignored); an admin may target
        any tenant or leave it unassigned. Forwards NETBOX_CLAIM_PREFIX, which
        reassigns an existing unassigned prefix or creates a new one."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            body = await request.json()
            prefix = body.get("prefix")
            if not prefix:
                raise HTTPException(status_code=400, detail="'prefix' is required")
            if _is_admin(sess):
                tenant = body.get("tenant")
            else:
                tenant = get_tenant_scoping(hub, _resolve_tenant(request, None))["netbox_tenant_slug"] or None
            payload = {
                "prefix": prefix,
                "tenant": tenant,
                "description": body.get("description", ""),
                "site": body.get("site"),
                "status": body.get("status", "active"),
            }
            result = await hub.request_response(spoke_id, "NETBOX_CLAIM_PREFIX", payload, timeout=30.0)
            data = _unwrap_spoke(result)
            if isinstance(data, dict) and data.get("status") == "SUCCESS":
                _refresh_module_all_tenants(hub, "netbox_prefixes")
                _refresh_module_all_tenants(hub, "netbox_ips")
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_assign_subnet failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/ips")
    async def netbox_get_ips(request: Request, prefix: str = None, device: str = None, tenant: str = None):
        """List NetBox IP addresses (subnet-filtered), optionally scoped by
        prefix/device; non-admins get the tenant cache, admins go live
        (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_ips", "NETBOX_GET_IPS",
                                      {"prefix": prefix, "device": device}, ["address"], "netbox_get_ips")

    @app.post("/api/netbox/ips")
    async def netbox_allocate_ip(request: Request):
        """Allocate a NetBox IP address; invalidates the IP cache and triggers an endpoint sync (30s timeout)."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "NETBOX_ALLOCATE_IP", data, timeout=30.0)
            _refresh_module_all_tenants(hub, "netbox_ips")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, data)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_allocate_ip failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/netbox/ips/{ip_id}")
    async def netbox_release_ip(ip_id: int, request: Request):
        """Release a NetBox IP back to the pool; invalidates the IP cache and triggers an endpoint sync."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_RELEASE_IP", {"ip_id": ip_id})
            _refresh_module_all_tenants(hub, "netbox_ips")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, None)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_release_ip failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/netbox/ips/{ip_id}")
    async def netbox_update_ip(ip_id: int, request: Request):
        """Update a NetBox IP address; invalidates the IP cache and triggers an endpoint sync."""
        hub = app.state.hub
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            data = await request.json()
            data["ip_id"] = ip_id
            result = await hub.request_response(spoke_id, "NETBOX_UPDATE_IP_ADDR", data)
            _refresh_module_all_tenants(hub, "netbox_ips")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, data)
            return _unwrap_spoke(result)
        except Exception as e:
            logger.exception("netbox_update_ip failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Update trigger + module install (/setup/update, /setup/modules/*) ─────
    @app.post("/setup/update")
    async def trigger_update(request: Request):
        hub = app.state.hub
        force_param = request.query_params.get("force", "false")
        force = force_param.lower() == "true"
        logger.info(f"API: Triggering update with force={force} (param: {force_param})")
        success = await hub.perform_update(force=force)
        if isinstance(success, dict):
            if success.get("status") == "success":
                return {"status": "success", "message": success["message"]}
            elif success.get("status") == "checked":
                # Hub is already current; spoke updates were triggered. This is a
                # success outcome, not an error — returning 200 avoids the UI
                # prefixing the message with "Critical Error:".
                return {"status": "checked", "message": success["message"]}
            elif success.get("status") == "no_update":
                return {"status": "no_update", "message": success["message"]}
            else:
                logger.error("update-trigger: perform_update returned unexpected status=%s", success.get("status"))
                raise HTTPException(status_code=500, detail=success.get("message", "Update failed"))
        elif success:
            return {"status": "success", "message": "Update triggered. The server is restarting..."}
        else:
            logger.error("update-trigger: perform_update returned falsy success (force=%s)", force)
            raise HTTPException(status_code=500, detail="Update failed. Check Hub logs.")

    @app.post("/setup/update/spokes")
    async def trigger_spoke_updates(request: Request):
        """Send SPOKE_UPDATE to all approved spokes without restarting the Hub.

        Called by BugFixer immediately after pushing a fix to GitHub so all deployed
        services pull the latest code before the QA service runs its test suite.
        Returns 200 with a summary once all SPOKE_UPDATE messages have been queued
        (spoke restarts happen asynchronously — poll GET /status for reconnection).
        """
        hub = app.state.hub
        logger.info("API: /setup/update/spokes — queuing SPOKE_UPDATE for all approved spokes")
        result = await hub.update_spokes_only()
        return result

    @app.get("/setup/modules")
    async def get_modules():
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        is_single_server = global_config.get("single_server_mode", False)

        modules = {
            "cppm":     {"path": "cppm/install.sh",              "installed": False},
            "cs":       {"path": "cs/install_cs.sh",             "installed": False},
            "dhcp":     {"path": "dhcp/install_dhcp.sh",         "installed": False},
            "dns":      {"path": "dns/install_dns.sh",           "installed": False},
            "ldap":     {"path": "ldap/install_ldap.sh",         "installed": False},
            "netbox":   {"path": "netbox/install.sh",            "installed": False},
            "opnsense": {"path": "opnsense/install_opnsense.sh", "installed": False},
            "pxmx":     {"path": "pxmx/install_pxmx.sh",        "installed": False},
        }

        for mod in modules:
            if any(mod in sid for sid in hub.active_connections):
                modules[mod]["installed"] = True

        return {
            "single_server_mode": is_single_server,
            "modules": modules
        }

    @app.post("/setup/install-module")
    async def install_module(request: Request):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        if not global_config.get("single_server_mode", False):
            raise HTTPException(status_code=403, detail="On-demand installation is only supported in single-server mode.")

        try:
            data = await request.json()
            module_id = data.get("module_id")
            custom_spoke_id = data.get("spoke_id")
            display_name = data.get("display_name")

            if not module_id:
                raise HTTPException(status_code=400, detail="Missing module_id")

            modules = {
                "cppm":     "cppm/install.sh",
                "cs":       "cs/install_cs.sh",
                "dhcp":     "dhcp/install_dhcp.sh",
                "dns":      "dns/install_dns.sh",
                "ldap":     "ldap/install_ldap.sh",
                "netbox":   "netbox/install.sh",
                "opnsense": "opnsense/install_opnsense.sh",
                "pxmx":     "pxmx/install_pxmx.sh",
            }

            script_path = modules.get(module_id)
            if not script_path:
                raise HTTPException(status_code=404, detail="Module not found")

            hub_url = f"ws://{hub.host}:{hub.port}"

            spoke_id = custom_spoke_id if custom_spoke_id else f"{module_id}-spoke-1"

            hub.state.register_module(spoke_id, approved=False, display_name=display_name or spoke_id)
            hub.known_modules = hub.state.system_state["known_modules"]

            first_secret = hub.key_manager.generate_first_secret(spoke_id)

            subprocess.Popen(
                ["bash", script_path, "--hub", hub_url, "--id", spoke_id,
                 "--secret", first_secret, "--all-prereqs"],
                shell=False,
                cwd=os.path.join(os.path.dirname(__file__), "../../.."),
            )

            return {"status": "ok", "message": f"Installation of {module_id} triggered for {spoke_id} in background."}
        except Exception as e:
            logger.exception("install_module failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-name")
    async def rename_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            new_name = data.get("display_name")
            new_hostname = data.get("hostname")

            if not spoke_id or not new_name:
                raise HTTPException(status_code=400, detail="Missing spoke_id or display_name")

            known_modules = hub.state.system_state.get("known_modules", [])
            if spoke_id not in known_modules:
                raise HTTPException(status_code=404, detail="Spoke not found")

            hub.state.set_module_name(spoke_id, new_name)
            hub.state.save_state()

            if new_hostname:
                if spoke_id in hub.active_connections:
                    msg = _hub_msg(spoke_id, "SPOKE_SET_HOSTNAME", {"hostname": new_hostname})
                    await hub.send_to_spoke(msg)
                    hostname_status = "Hostname update triggered."
                else:
                    hostname_status = "Spoke not connected; hostname update will be queued."
                    msg = _hub_msg(spoke_id, "SPOKE_SET_HOSTNAME", {"hostname": new_hostname})
                    await hub.mailbox.push(msg, hub.send_to_spoke)
            else:
                hostname_status = ""

            return {"status": "ok", "message": f"Spoke {spoke_id} renamed to {new_name}. {hostname_status}".strip()}
        except Exception as e:
            logger.exception("rename_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Tenants + users (/setup/tenants/*, /setup/users/*) ───────────────────
    @app.get("/setup/tenants")
    async def get_tenants():
        hub = app.state.hub
        tenants = hub.state.tenant_state.get("tenants", {})
        tenant_list = [
            {
                "id": tid,
                "name": cfg.get("name") or tid,
                "slug": cfg.get("netbox_tenant_slug") or tid,
                "netbox_id": cfg.get("netbox_id"),
                "description": cfg.get("description", ""),
            }
            for tid, cfg in tenants.items()
        ]
        if "default" not in [t["id"] for t in tenant_list]:
            tenant_list.insert(0, {"id": "default", "name": "Default", "slug": "default", "netbox_id": None, "description": ""})
        return {"tenants": tenant_list}

    @app.post("/setup/sync-tenants")
    async def sync_tenants_from_netbox():
        """Pull tenants from NetBox and upsert them into hub tenant state."""
        hub = app.state.hub
        spoke_id = hub.get_spoke_by_type("ipam")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_GET_TENANTS", {})
            data = _unwrap_spoke(result)
            nb_tenants = data.get("tenants", [])
            if data.get("status") != "SUCCESS":
                raise HTTPException(status_code=502, detail=data.get("message", "NetBox error"))

            added, updated = [], []
            existing_ids = set(hub.state.tenant_state.get("tenants", {}).keys())
            nb_slugs = {t["slug"] for t in nb_tenants}

            for t in nb_tenants:
                slug = t["slug"]
                exists = slug in existing_ids
                cfg = hub.state.get_tenant(slug) or {}
                hub.state.update_tenant(slug, {
                    "name": t["name"],
                    "netbox_tenant_slug": slug,
                    "netbox_id": t["id"],
                    "description": t.get("description", ""),
                    **{k: v for k, v in cfg.items() if k not in ("name", "netbox_tenant_slug", "netbox_id", "description")},
                })
                (updated if exists else added).append(slug)

            hub.state.save_state()
            return {
                "status": "ok",
                "added": added, "updated": updated,
                "message": f"Synced {len(nb_tenants)} tenant(s) from NetBox: {len(added)} added, {len(updated)} updated",
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("sync_tenants_from_netbox failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/tenants/{tenant_id}")
    async def get_tenant_details(tenant_id: str):
        hub = app.state.hub
        logger.info(f"API: Fetching details for tenant {tenant_id}")
        tenant = hub.state.get_tenant(tenant_id)
        if tenant is None:
            logger.warning(f"API: Tenant {tenant_id} not found in state.")
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        return {"tenant_id": tenant_id, "config": tenant}

    @app.get("/api/tenant/scoping")
    async def get_current_tenant_scoping(tenant: str = None):
        """Returns the active tenant's spoke-scoping config (netbox slug, proxmox tag, ldap base DN)."""
        hub = app.state.hub
        return get_tenant_scoping(hub, tenant)

    @app.post("/setup/tenants")
    async def create_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id")
            if not tenant_id:
                raise HTTPException(status_code=400, detail="Missing tenant_id")

            hub.state.update_tenant(tenant_id, {})
            hub.state.save_state()
            return {"status": "ok", "message": f"Tenant {tenant_id} created."}
        except Exception as e:
            logger.exception("create_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/tenant")
    async def update_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id", "default")
            config = data.get("config", {})

            hub.state.update_tenant(tenant_id, config)

            if config.get("active"):
                hub.state.set_active_tenant(tenant_id)

            hub.state.save_state()

            return {"status": "ok", "message": f"Tenant {tenant_id} updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")

    @app.post("/setup/generate-secret")
    async def generate_secret(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            secret = hub.key_manager.generate_first_secret(spoke_id)
            return {"spoke_id": spoke_id, "secret": secret}
        except Exception as e:
            logger.exception("generate_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/assign-tenant")
    async def assign_user_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            tenant_id = data.get("tenant_id")

            if not user_id or not tenant_id:
                raise HTTPException(status_code=400, detail="Missing user_id or tenant_id")

            if not hub.state.get_tenant(tenant_id):
                raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

            users = hub.state.system_state.get("users", {})
            if users.get(user_id, {}).get("protected"):
                raise HTTPException(status_code=403, detail="The protected admin account cannot be assigned to a tenant")

            hub.state.assign_user_to_tenant(user_id, tenant_id)
            return {"status": "ok", "message": f"User {user_id} assigned to tenant {tenant_id}"}
        except Exception as e:
            logger.exception("assign_user_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/remove-tenant")
    async def remove_user_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            tenant_id = data.get("tenant_id")

            if not user_id or not tenant_id:
                raise HTTPException(status_code=400, detail="Missing user_id or tenant_id")

            hub.state.remove_user_from_tenant(user_id, tenant_id)
            return {"status": "ok", "message": f"User {user_id} removed from tenant {tenant_id}"}
        except Exception as e:
            logger.exception("remove_user_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    def _hash_password(password: str) -> str:
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return f"{salt}${dk.hex()}"

    def _verify_password(password: str, stored: str) -> bool:
        try:
            salt, dk_hex = stored.split("$", 1)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
            return secrets.compare_digest(dk.hex(), dk_hex)
        except Exception:
            return False

    @app.get("/setup/users")
    async def get_users():
        hub = app.state.hub
        raw = hub.state.system_state.get("users", {})
        # Strip password hashes before returning
        safe = {uid: {k: v for k, v in u.items() if k != "password_hash"} for uid, u in raw.items()}
        return {"users": safe}

    @app.post("/setup/users")
    async def update_user(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            permissions = data.get("permissions", {})
            password = data.get("password", "")
            auth_type = data.get("auth_type", "local")
            tenant_id = data.get("tenant_id")

            if not user_id:
                raise HTTPException(status_code=400, detail="Missing user_id")

            users = hub.state.system_state.setdefault("users", {})
            existing = users.get(user_id, {})

            # Create vs edit: the WebUI "Add New User" flow sends create=true.
            # Reject an already-existing user_id on create so the modal can't
            # silently upsert — and demote — an existing user (e.g. reusing a
            # non-protected admin's id with System Admin unchecked). The edit
            # modal does not send create, so edits still upsert as before.
            if data.get("create") and user_id in users:
                raise HTTPException(status_code=409, detail="User already exists")

            # Anti-lockout: protected account cannot be demoted or assigned to a tenant
            if existing.get("protected"):
                permissions = existing.get("permissions", {"role": "admin"})
                tenant_id = None  # ignore any tenant assignment attempt

            # Keep the two admin-flag forms (role + boolean) in sync on every
            # write so the WebUI "System Admin" checkbox and _is_admin() never
            # diverge — a role-only admin would otherwise show unchecked and an
            # edit could drop the role, silently demoting the user.
            _p = permissions or {}
            if _p.get("admin") or _p.get("role") == "admin":
                permissions = {**_p, "admin": True, "role": "admin"}

            entry = {
                **existing,
                "permissions": permissions,
                "auth_type": auth_type,
                "updated_at": time.time(),
            }
            if password:
                entry["password_hash"] = _hash_password(password)
            if tenant_id:
                entry.setdefault("tenants", [])
                if tenant_id not in entry["tenants"]:
                    entry["tenants"].append(tenant_id)
            users[user_id] = entry
            hub.state.save_state()

            return {"status": "ok", "message": f"User {user_id} updated."}
        except Exception as e:
            logger.exception("update_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/{user_id}/set-password")
    async def set_user_password(user_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            password = data.get("password", "")
            if not password:
                raise HTTPException(status_code=400, detail="Password required")
            users = hub.state.system_state.get("users", {})
            if user_id not in users:
                raise HTTPException(status_code=404, detail="User not found")
            users[user_id]["password_hash"] = _hash_password(password)
            hub.state.save_state()
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("set_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Auth / tenant helper closures ────────────────────────────────────────
    # Thin shims over access.* — the real logic (session/auth, tenant scoping,
    # prefix resolution, subnet filtering) lives in the leaf module ``access``
    # (importable, testable, free of the nested-def annotation trap that caused
    # the .117→.121 startup regression). Kept as closures so the ~185 routes
    # keep calling the same bare names — _session_user(req), _is_admin(sess),
    # _filter_session(req, data, "nac", ["ip"]), … — with zero call-site churn.
    # They capture the live _sessions module global and the hub arg; everything
    # else flows from access. Shim signatures intentionally carry NO annotations
    # (trivial delegators) so no typing name can ever be evaluated at def-time;
    # the real type hints live in access.py under ``from __future__ import
    # annotations``. Defined late, as before, so routes above resolve them at
    # call time; register_simulations_routes below receives them as callables.
    def _session_user(request):
        return access.session_user(_sessions, request)

    def _is_admin(sess):
        return access.is_admin(sess)

    def _has_cs_access(sess):
        return access.has_cs_access(sess)

    def _check_tenant_access(sess, tenant_id):
        return access.check_tenant_access(sess, tenant_id)

    def _resolve_tenant(request, explicit=None):
        return access.resolve_tenant(_sessions, request, explicit)

    async def _fetch_tenant_prefixes(hub, tenant_id):
        return await access.fetch_tenant_prefixes(hub, tenant_id)

    async def _resolve_prefixes(hub, sess):
        return await access.resolve_prefixes(hub, sess)

    def _effective_tenant(request, explicit=None):
        return access.effective_tenant(_sessions, request, explicit)

    def _effective_tenant_slug(request, explicit=None):
        return access.effective_tenant_slug(hub, _sessions, request, explicit)

    async def _resolve_prefixes_for_tenant(hub, tenant_id):
        return await access.resolve_prefixes_for_tenant(hub, tenant_id)

    def _filter_enabled(hub, module):
        return access.filter_enabled(hub, module)

    async def _filter_session(request, data, module, ip_fields):
        return await access.filter_session(hub, _sessions, request, data, module, ip_fields)

    async def _filter_fw(request, data, endpoint, firewall_id=None, explicit_tenant=None):
        return await access.filter_fw(hub, _sessions, request, data, endpoint, firewall_id, explicit_tenant)

    async def _gate_record(request, record, module, ip_fields):
        return await access.gate_record(hub, _sessions, request, record, module, ip_fields)

    async def _filter_tenant(request, data, module, ip_fields, explicit_tenant=None):
        return await access.filter_tenant(hub, _sessions, request, data, module, ip_fields, explicit_tenant)

    async def _gate_record_tenant(request, record, module, ip_fields, explicit_tenant=None):
        return await access.gate_record_tenant(hub, _sessions, request, record, module, ip_fields, explicit_tenant)

    # ── Simulations module (ported Client-Sim UI) ───────────────────────────
    # Registered after the auth helpers above so the /sim routes can reuse them.
    register_simulations_routes(app, app.state.hub, _session_user, _resolve_tenant,
                                _is_admin, _check_tenant_access, _sessions,
                                _has_cs_access)

    # ── Auth routes (/auth/login, /auth/me, /auth/logout, /auth/setup) ────────
    @app.post("/auth/login")
    async def local_login(request: Request):
        """Authenticate a local user and set the ``lm_session`` cookie.

        Verifies the password against the stored hash, mints a 32-byte session
        token (8h TTL, persisted via ``_save_sessions`` so it survives a hub
        restart), and kicks background cache preload for each tenant the user
        belongs to. Returns the user record (user_id, permissions, tenants) with
        HTTP 200; 401 on bad credentials, 400 on missing fields."""
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("username", "").strip()
            password = data.get("password", "")
            if not user_id or not password:
                raise HTTPException(status_code=400, detail="username and password required")
            users = hub.state.system_state.get("users", {})
            user = users.get(user_id)
            if not user or not user.get("password_hash"):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            if not _verify_password(password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            # Always read the live record so migrations/admin changes take effect on next login
            perms   = user.get("permissions", {})
            tenants = user.get("tenants", [])
            protected = user.get("protected", False)
            # Protected accounts have no tenant assignment regardless of stored value
            if protected:
                tenants = []
            tenant_id = tenants[0] if tenants else None
            token = secrets.token_urlsafe(32)
            user_data = {
                "user_id":    user_id,
                "auth_type":  user.get("auth_type", "local"),
                "permissions": perms,
                "tenants":    tenants,
                "tenant_id":  tenant_id,
                "protected":  protected,
            }
            _sessions[token] = {
                "user_id": user_id,
                "expires": time.time() + _SESSION_TTL,
                "user":    user_data,
            }
            _save_sessions(hub)
            resp = JSONResponse({"status": "ok", **user_data})
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
            )
            # Kick off background cache preload for every tenant this user belongs to
            for tid in tenants:
                _start_cache_for_tenant(hub, tid)
            return resp
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("local_login failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/auth/me")
    async def auth_me(request: Request):
        """Return the current user, or 401 ``{first_run}`` when unauthenticated.

        Re-reads the live user record each call so permission/tenant changes
        made after login take effect without a re-login, and keeps the session
        in sync. ``first_run=true`` (no users defined yet) tells the WebUI to
        show the initial setup flow instead of the login form."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            users = hub.state.system_state.get("users", {})
            return JSONResponse(
                status_code=401,
                content={"authenticated": False, "first_run": len(users) == 0},
            )
        # Always read permissions and tenants from the live user record so that
        # changes made after login (migrations, admin edits) are reflected immediately
        # without requiring a logout/login cycle.
        user_id = sess.get("user_id") or sess["user"].get("user_id")
        live = hub.state.system_state.get("users", {}).get(user_id, {})
        merged = {
            **sess["user"],
            "permissions": live.get("permissions", sess["user"].get("permissions", {})),
            "tenants":     live.get("tenants",     sess["user"].get("tenants", [])),
            "tenant_id":   live.get("tenants", [sess["user"].get("tenant_id")])[0]
                           if live.get("tenants") else None,
            "protected":   live.get("protected", False),
        }
        # Keep session in sync so middleware checks stay consistent
        sess["user"] = merged
        return {"status": "ok", **merged}

    @app.post("/auth/logout")
    async def auth_logout(request: Request):
        """Drop the ``lm_session`` token, clear the cookie, and stop the
        background cache task for the user's tenant when no other sessions
        for it remain. Persists the session store so the revocation survives
        a restart."""
        token = request.cookies.get("lm_session")
        sess = _sessions.pop(token, None)
        tenant_id = (sess or {}).get("user", {}).get("tenant_id")
        _save_sessions(app.state.hub)
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie("lm_session")
        if tenant_id:
            _stop_cache_for_tenant(tenant_id)
        return resp

    @app.post("/auth/setup")
    async def first_run_setup(request: Request):
        """Create the first admin account. Only works when no users exist."""
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        if users:
            raise HTTPException(status_code=403, detail="Setup already complete — log in with an existing account")
        try:
            data = await request.json()
            username = data.get("username", "").strip()
            password = data.get("password", "")
            if not username or not password:
                raise HTTPException(status_code=400, detail="username and password required")
            if len(password) < 8:
                raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
            entry = {
                "auth_type": "local",
                "password_hash": _hash_password(password),
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "protected": True,  # anti-lockout: this account cannot be deleted or demoted
                "updated_at": time.time(),
            }
            hub.state.system_state.setdefault("users", {})[username] = entry
            hub.state.save_state()
            token = secrets.token_urlsafe(32)
            _sessions[token] = {
                "user_id": username,
                "expires": time.time() + _SESSION_TTL,
                "user": {
                    "user_id": username,
                    "auth_type": "local",
                    "permissions": {"role": "admin", "admin": True},
                    "tenants": [],
                    "tenant_id": None,
                    "protected": True,
                },
            }
            _save_sessions(hub)
            resp = JSONResponse({
                "status": "ok",
                "user_id": username,
                "auth_type": "local",
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "tenant_id": None,
                "protected": True,
            })
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
            )
            return resp
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("first_run_setup failed")
            raise HTTPException(status_code=500, detail=str(e))

    # _PREFIX_CACHE_TTL moved to access.py (access._PREFIX_CACHE_TTL); the
    # session-prefix cache TTL is now owned by access.resolve_prefixes.

    @app.get("/auth/prefixes")
    async def get_session_prefixes(request: Request, tenant: str = None):
        """Return the IP prefixes for the current session user's tenant.

        NetBox-derived and session-cached (5 min). Used by the UI to filter all
        module views (firewall rules, NAC sessions, etc.) AND by the server-side
        subnet filter — both share prefix resolution so the UI and the API
        enforcement agree. ``?tenant=`` scopes prefixes to the selected tenant
        (an admin acting as a tenant via the switcher, or a multi-tenant user
        switching to an allowed one); without it, the session tenant is used
        (admins get [] so the client-side filter stays a no-op for them).
        """
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        hub = app.state.hub
        if tenant:
            tid = _effective_tenant(request, tenant)
            prefixes = await _resolve_prefixes_for_tenant(hub, tid) if tid else []
        else:
            tid = sess.get("user", {}).get("tenant_id")
            prefixes = await _resolve_prefixes(hub, sess)
        resp = {"prefixes": prefixes}
        # Surface why a non-admin might have no prefixes (helps debugging the
        # "tenant sees everything" symptom). Admins get [] intentionally.
        if not prefixes and not _is_admin(sess):
            if not tid:
                resp["warning"] = "No tenant assigned to this user"
            elif not get_tenant_scoping(hub, tid).get("netbox_tenant_slug"):
                resp["warning"] = "No NetBox tenant slug configured for this tenant"
            elif not get_netbox_spoke(hub):
                resp["warning"] = "NetBox spoke not connected"
        return resp

    # ── Admin: per-module subnet-filter toggle ──────────────────────────────
    # Middleware already 403s non-admins on /admin/* (api.py:274); the explicit
    # _is_admin check is defense-in-depth and matches the other /admin routes.
    @app.get("/admin/subnet-filter-config")
    async def get_filter_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        return {"modules": _filter_config(app.state.hub),
                "defaults": dict(zip(_FILTER_MODULES,
                                     (_FILTER_DEFAULTS.get(m, False) for m in _FILTER_MODULES)))}

    @app.put("/admin/subnet-filter-config")
    async def set_filter_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        data = await request.json()
        incoming = data.get("modules") or {}
        stored = {}
        for m in _FILTER_MODULES:
            if m in incoming:
                stored[m] = bool(incoming[m])
        app.state.hub.state.system_state["subnet_filter_modules"] = stored
        app.state.hub.state.save_state()
        return {"status": "ok", "modules": _filter_config(app.state.hub)}

    @app.delete("/setup/users/{user_id}")
    async def delete_user(user_id: str):
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        if user_id not in users:
            raise HTTPException(status_code=404, detail="User not found")
        if users[user_id].get("protected"):
            raise HTTPException(status_code=403, detail="This account is protected and cannot be deleted")
        del users[user_id]
        hub.state.save_state()
        return {"status": "ok", "message": f"User {user_id} deleted."}

    @app.get("/setup/github-repos")
    async def get_github_repos():
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://api.github.com/users/lbockenstedt/repos")
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail="Failed to fetch repos from GitHub")
                repos = resp.json()
                return {
                    "repos": [
                        {"name": r["name"], "url": r["clone_url"], "description": r["description"]}
                        for r in repos
                    ]
                }
        except Exception as e:
            logger.exception("get_github_repos failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/github-branches/{repo}")
    async def get_github_branches(repo: str):
        try:
            import httpx
            if "/" not in repo:
                repo_full = f"lbockenstedt/{repo}"
            else:
                repo_full = repo

            async with httpx.AsyncClient() as client:
                resp = await client.get(f"https://api.github.com/repos/{repo_full}/branches")
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch branches for {repo_full}")
                branches = resp.json()
                return {
                    "branches": [b["name"] for b in branches]
                }
        except Exception as e:
            logger.exception("get_github_branches failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/config")
    async def get_global_config():
        hub = app.state.hub
        return {"global_config": hub.state.system_state.get("global_config", {})}

    @app.post("/setup/config")
    async def update_global_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            gc = hub.state.system_state.setdefault("global_config", {})
            gc.update(config)
            hub.state.save_state()

            return {"status": "ok", "message": "Global configuration updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")


    @app.post("/api/generic/provision")
    async def provision_generic_agent(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            agent_id = data.get("agent_id")
            module_id = data.get("module_id")
            repo_url = data.get("repo_url")
            custom_spoke_id = data.get("spoke_id")
            display_name = data.get("display_name")

            if not agent_id or not module_id or not repo_url:
                raise HTTPException(status_code=400, detail="Missing agent_id, module_id, or repo_url")

            if agent_id not in hub.active_connections:
                raise HTTPException(status_code=503, detail=f"Generic agent {agent_id} not connected")

            spoke_id = custom_spoke_id if custom_spoke_id else f"{module_id}-spoke-1"

            hub.state.register_module(spoke_id, approved=False, display_name=display_name or spoke_id)
            hub.known_modules = hub.state.system_state["known_modules"]

            secret = hub.key_manager.generate_first_secret(spoke_id)
            hub_secret = hub.key_manager.hub_secret

            provision_data = {
                "module_id": module_id,
                "repo_url": repo_url,
                "hub_url": f"ws://{hub.host}:{hub.port}",
                "spoke_id": spoke_id,
                "secret": secret,
                "hub_secret": hub_secret
            }

            result = await hub.request_response(agent_id, "PROVISION_MODULE", provision_data)
            return result
        except Exception as e:
            logger.error(f"Provisioning failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    # ─── Generic Agent API ────────────────────────────────────────────────────

    @app.get("/api/agents")
    async def list_agents():
        """List all connected generic agents and their active roles."""
        hub = app.state.hub
        agents = []
        for sid, mtype in hub.spoke_module_types.items():
            if mtype == "agent" and sid in hub.active_connections:
                agents.append({"spoke_id": sid, "module_type": mtype})
        return {"agents": agents}

    @app.post("/api/agent/{spoke_id}/command")
    async def send_agent_command(spoke_id: str, request: Request):
        """Send any command to a connected generic agent."""
        hub = app.state.hub
        if spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Agent {spoke_id} not connected")
        try:
            data = await request.json()
            command = data.get("command")
            payload = data.get("data", {})
            if not command:
                raise HTTPException(status_code=400, detail="command is required")
            result = await hub.request_response(spoke_id, command, payload)
            return result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("send_agent_command failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/agent/{spoke_id}/load-role")
    async def load_agent_role(spoke_id: str, request: Request):
        """
        Morph a generic agent into a specific role (dns, dhcp, …).
        The agent installs required packages, loads the role, and re-registers
        its module_type so hub APIs can route to it.
        """
        hub = app.state.hub
        if spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Agent {spoke_id} not connected")
        try:
            data   = await request.json()
            role   = data.get("role")
            config = data.get("config", {})
            if not role:
                raise HTTPException(status_code=400, detail="role is required")
            result = await hub.request_response(spoke_id, "LOAD_ROLE", {"role": role, "config": config})
            payload = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # Update hub's module_type index so routing picks up the new type immediately
            if isinstance(payload, dict) and payload.get("status") == "SUCCESS":
                new_mtype = payload.get("module_type")
                if new_mtype:
                    hub.spoke_module_types[spoke_id] = new_mtype
                    logger.info("Agent %s morphed to module_type %s", spoke_id, new_mtype)
            return payload
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("load_agent_role failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── DNS API ──────────────────────────────────────────────────────────────

    def _get_dns_spoke(hub):
        spoke_id = hub.get_spoke_by_type("dns")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="DNS spoke not connected")
        return spoke_id

    async def _relay_spoke(spoke_id, command, payload=None, log_name=""):
        """Relay ``command`` to a spoke and return its SUCCESS payload.

        Shared core of every DNS/DHCP relay handler (10 routes were near-
        identical get-spoke → request_response → unwrap → except→500 blocks).
        The spoke contract is ``{status: "SUCCESS", ...}`` / ``{status:
        "ERROR", message|error}``; previously the hub passed an ERROR payload
        back at HTTP 200, which was the last residual hold-out from the API
        error-contract migration (every other spoke-relay group raises on
        spoke-down). An upstream that responded with an error is now translated
        to HTTP 502 (Bad Gateway) carrying the spoke's message as ``detail``,
        matching the NetBox/CPPM relay contract. The success body — the spoke's
        full SUCCESS dict — is returned verbatim so existing field access
        (``data["records"]`` / ``data["subnets"]`` …) is unchanged. Spoke-down
        (503) is raised by the ``_get_*_spoke`` caller before we run.
        """
        hub = app.state.hub
        try:
            result = await hub.request_response(spoke_id, command, payload or {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return _spoke_payload_or_raise(data)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("%s relay failed", log_name or command)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/dns/records")
    async def dns_list_records():
        """List all DNS records from the Unbound spoke (unfiltered relay)."""
        logger.debug("relay GET /api/dns/records")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_LIST", log_name="dns_list_records")

    @app.post("/api/dns/record")
    async def dns_add_record(request: Request):
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_ADD", await request.json(), log_name="dns_add_record")

    @app.delete("/api/dns/record")
    async def dns_delete_record(request: Request):
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_DELETE", await request.json(), log_name="dns_delete_record")

    @app.put("/api/dns/record")
    async def dns_update_record(request: Request):
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_UPDATE", await request.json(), log_name="dns_update_record")

    @app.get("/api/dns/status")
    async def dns_status():
        """Unbound service status / health from the DNS spoke."""
        logger.debug("relay GET /api/dns/status")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_STATUS", log_name="dns_status")

    @app.post("/api/dns/sync")
    async def dns_sync_from_netbox():
        """
        Fetch all IPs with a dns_name from NetBox and sync them to Unbound.
        Requires both NetBox spoke and DNS spoke to be connected.
        """
        import asyncio as _asyncio
        hub = app.state.hub
        nb_spoke  = get_netbox_spoke(hub)
        dns_spoke = hub.get_spoke_by_type("dns")
        if not nb_spoke:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        if not dns_spoke:
            raise HTTPException(status_code=503, detail="DNS spoke not connected")
        try:
            ips_raw = await hub.request_response(nb_spoke, "NETBOX_GET_IPS", {})
            ips_data = ips_raw.get("payload", {}).get("data", ips_raw) if isinstance(ips_raw, dict) else {}
            ip_list = ips_data.get("ip_addresses", [])
            records = []
            for entry in ip_list:
                dns_name = entry.get("dns_name") or ""
                address  = (entry.get("address") or "").split("/")[0]
                if dns_name and address:
                    records.append({"name": dns_name, "type": "A", "value": address, "ttl": 300})
            result = await hub.request_response(dns_spoke, "DNS_SYNC", {"records": records})
            return {
                "status": "ok",
                "records_synced": len(records),
                "spoke_result": result.get("payload", {}).get("data", result) if isinstance(result, dict) else result,
            }
        except Exception as e:
            logger.exception("dns_sync_from_netbox failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── DHCP API ─────────────────────────────────────────────────────────────

    def _get_dhcp_spoke(hub):
        spoke_id = hub.get_spoke_by_type("dhcp")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="DHCP spoke not connected")
        return spoke_id

    @app.get("/api/dhcp/subnets")
    async def dhcp_list_subnets():
        """List DHCP subnets configured on the Kea spoke (unfiltered relay)."""
        logger.debug("relay GET /api/dhcp/subnets")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_SUBNETS", log_name="dhcp_list_subnets")

    @app.get("/api/dhcp/leases")
    async def dhcp_list_leases(request: Request, subnet: str = None):
        """List DHCP leases (optionally per-subnet); subnet-filtered before return."""
        logger.debug("relay %s %s subnet=%s", request.method, request.url.path, subnet)
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_LEASES", {"subnet": subnet}, log_name="dhcp_list_leases")
        return await _filter_session(request, data, "dhcp", ["ip", "address"])

    @app.post("/api/dhcp/reservation")
    async def dhcp_add_reservation(request: Request):
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_ADD_RES", await request.json(), log_name="dhcp_add_reservation")

    @app.get("/api/dhcp/reservations")
    async def dhcp_list_reservations():
        """List DHCP reservations from the Kea spoke (unfiltered relay)."""
        logger.debug("relay GET /api/dhcp/reservations")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_RES", log_name="dhcp_list_reservations")

    @app.put("/api/dhcp/reservation")
    async def dhcp_update_reservation(request: Request):
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_UPDATE_RES", await request.json(), log_name="dhcp_update_reservation")

    @app.delete("/api/dhcp/reservation")
    async def dhcp_delete_reservation(request: Request):
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_DEL_RES", await request.json(), log_name="dhcp_delete_reservation")

    @app.get("/api/dhcp/status")
    async def dhcp_status():
        """Kea DHCP4 service status / health from the DHCP spoke."""
        logger.debug("relay GET /api/dhcp/status")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_STATUS", log_name="dhcp_status")

    @app.post("/api/dhcp/sync")
    async def dhcp_sync_from_netbox():
        """
        Fetch NetBox prefixes and IP-to-MAC reservations, sync to Kea DHCP4.
        """
        hub = app.state.hub
        nb_spoke   = get_netbox_spoke(hub)
        dhcp_spoke = hub.get_spoke_by_type("dhcp")
        if not nb_spoke:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        if not dhcp_spoke:
            raise HTTPException(status_code=503, detail="DHCP spoke not connected")
        try:
            import asyncio as _asyncio
            prefixes_raw, ips_raw = await _asyncio.gather(
                hub.request_response(nb_spoke, "NETBOX_GET_PREFIXES", {}),
                hub.request_response(nb_spoke, "NETBOX_GET_IPS", {}),
            )
            pfx_data = prefixes_raw.get("payload", {}).get("data", prefixes_raw) if isinstance(prefixes_raw, dict) else {}
            ips_data  = ips_raw.get("payload", {}).get("data", ips_raw) if isinstance(ips_raw, dict) else {}

            subnets = []
            for p in pfx_data.get("prefixes", []):
                prefix_str = p.get("prefix", "")
                if not prefix_str:
                    continue
                subnets.append({
                    "subnet":      prefix_str,
                    "description": p.get("description", ""),
                    "gateway":     p.get("custom_fields", {}).get("gateway", ""),
                    "dns_servers": p.get("custom_fields", {}).get("dns_servers", "").split(",")
                                   if p.get("custom_fields", {}).get("dns_servers") else [],
                    "pools":       [],
                })

            reservations = []
            for ip in ips_data.get("ip_addresses", []):
                mac = (ip.get("custom_fields") or {}).get("mac_address", "")
                address = (ip.get("address") or "").split("/")[0]
                if mac and address:
                    reservations.append({
                        "ip":       address,
                        "mac":      mac,
                        "hostname": ip.get("dns_name", ""),
                        "subnet":   "",
                    })

            result = await hub.request_response(dhcp_spoke, "DHCP_SYNC", {
                "subnets":      subnets,
                "reservations": reservations,
            })
            return {
                "status": "ok",
                "subnets_synced":       len(subnets),
                "reservations_synced":  len(reservations),
                "spoke_result": result.get("payload", {}).get("data", result) if isinstance(result, dict) else result,
            }
        except Exception as e:
            logger.exception("dhcp_sync_from_netbox failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Cache management (/admin/cache/*, /setup/cache-config) ───────────────

    @app.get("/auth/cache-status")
    async def get_my_cache_status(request: Request):
        """Returns cache loading status for the current session's tenant (used by footer indicator)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        tenant_id = sess.get("user", {}).get("tenant_id")
        if not tenant_id:
            return {"status": {}, "all_ready": True, "tenant_id": None}
        config = _get_cache_config(hub)
        status = _cache_status.get(tenant_id, {})
        enabled_modules = {k for k, v in config.items() if v.get("enabled", True)}
        loading = [k for k, v in status.items() if v == "loading"]
        all_ready = not loading and bool(status)
        return {
            "status": status,
            "loading": loading,
            "all_ready": all_ready,
            "tenant_id": tenant_id,
            "labels": {k: _DEFAULT_CACHE_CONFIG[k.split(":")[0]]["label"]
                       for k in status if k.split(":")[0] in _DEFAULT_CACHE_CONFIG},
        }

    @app.get("/admin/sessions")
    async def admin_get_sessions(request: Request):
        now = time.time()
        active = []
        pruned = False
        for token, sess in list(_sessions.items()):
            if sess["expires"] < now:
                _sessions.pop(token, None)
                pruned = True
                continue
            u = sess.get("user", {})
            p = u.get("permissions", {})
            active.append({
                "user_id":    sess.get("user_id", u.get("user_id", "?")),
                "is_admin":   bool(p.get("admin") or p.get("role") == "admin"),
                "tenants":    u.get("tenants", []),
                "expires_in": int(sess["expires"] - now),
                "token_hint": token[:8] + "…",
            })
        if pruned:
            _save_sessions(app.state.hub)
        active.sort(key=lambda s: s["user_id"])
        return {"sessions": active, "count": len(active)}

    @app.delete("/admin/sessions/{token_hint}")
    async def admin_revoke_session(token_hint: str, request: Request):
        for token in list(_sessions.keys()):
            if token.startswith(token_hint.rstrip("…")):
                _sessions.pop(token, None)
                _save_sessions(app.state.hub)
                return {"status": "ok", "message": "Session revoked"}
        raise HTTPException(status_code=404, detail="Session not found")

    @app.get("/admin/cache/config")
    async def admin_get_cache_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        cfg = _get_cache_config(hub)
        return {
            "config": cfg,
            "max_concurrent_tenants": _get_max_concurrent(hub),
            "labels": {k: v["label"] for k, v in _DEFAULT_CACHE_CONFIG.items()},
        }

    @app.put("/admin/cache/config")
    async def admin_update_cache_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        data = await request.json()
        stored = hub.state.system_state.get("cache_config", {})
        for key, vals in data.get("config", {}).items():
            stored.setdefault(key, {}).update({k: v for k, v in vals.items() if k in ("enabled", "interval")})
        if "max_concurrent_tenants" in data:
            stored["max_concurrent_tenants"] = int(data["max_concurrent_tenants"])
        hub.state.system_state["cache_config"] = stored
        hub.state.save_state()
        return {"status": "ok"}

    @app.post("/admin/cache/purge")
    async def admin_purge_cache(request: Request, tenant: str = None):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        if tenant:
            _tenant_cache.pop(tenant, None)
            _cache_status.pop(tenant, None)
            task = _cache_tasks.pop(tenant, None)
            if task: task.cancel()
            _start_cache_for_tenant(hub, tenant)
        else:
            tenants_to_rewarm = list(_tenant_cache.keys())
            _tenant_cache.clear()
            _cache_status.clear()
            for tid, task in list(_cache_tasks.items()):
                task.cancel()
            _cache_tasks.clear()
            for tid in tenants_to_rewarm:
                _start_cache_for_tenant(hub, tid)
        return {"status": "ok", "tenant": tenant or "all"}

    @app.get("/admin/cache/status")
    async def admin_cache_status(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        summary = {}
        for tid, modules in _cache_status.items():
            summary[tid] = {
                "modules": modules,
                "fetched_at": {k: _tenant_cache.get(tid, {}).get(k, {}).get("fetched_at")
                               for k in modules},
                "task_alive": tid in _cache_tasks and not _cache_tasks[tid].done(),
            }
        return {"tenants": summary, "max_concurrent": _get_max_concurrent(hub)}

    @app.post("/auth/cache/refresh")
    async def refresh_my_cache(request: Request, module: str = None):
        """Any authenticated user can trigger a refresh of their tenant's cache modules."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        tenant_id = sess.get("user", {}).get("tenant_id")
        if not tenant_id:
            return {"status": "ok", "message": "No tenant assigned"}
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        if module:
            base = module.split(":")[0]
            if base in _FW_MODULES:
                tasks = [_fetch_module(hub, tenant_id, base, fw_id=fw["id"]) for fw in firewalls]
            else:
                tasks = [_fetch_module(hub, tenant_id, base)]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            await _preload_all_parallel(hub, tenant_id)
        return {"status": "ok", "tenant_id": tenant_id}

    # --- Static File Serving ---
    ui_path = os.path.join(os.path.dirname(__file__), "../../WebUI")

    if os.path.exists(ui_path):
        @app.get("/{full_path:path}")
        async def serve_ui(full_path: str):
            file_path = os.path.join(ui_path, full_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                response = FileResponse(file_path)
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response

            index_html_path = os.path.join(ui_path, "index.html")
            if os.path.exists(index_html_path):
                response = FileResponse(index_html_path)
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response

            raise HTTPException(status_code=404, detail="UI index.html not found in WebUI folder")
    else:
        @app.get("/")
        async def root():
            return {"message": "Hub API is running. UI folder not found. Please check repository structure."}

    return app

def run_api_server(hub, port=8000):
    """Build the app and run the uvicorn server that hosts the Hub HTTP/WS surface.

    Blocks the caller; this is the Hub's main long-running coroutine host.
    """
    app = create_app(hub)
    uvicorn.run(app, host="0.0.0.0", port=port)