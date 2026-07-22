"""Simulations (cs) HTTP/WebSocket routes — the ported Client-Sim operator UI.

Mounted under ``/sim`` and ``/sim/api`` by ``register_simulations_routes``
(called from ``api.create_app``). Provides the cs health/auth endpoints, the
tenant-subnet-filtered dashboard/clients/sims/proxmox/central views (shaped by
``SimulationsService``), the global + per-tenant USB device/ignore lists, the
admin tenant/user lists, the telemetry WebSocket (fed by
``SimulationsBroadcaster``), and the config-push path back to the cs spoke.
Audience: Hub developers; endpoint reference in ``docs/api.md`` (Simulations
section). This is the LM-side port of the legacy solutions-hpe Client-Sim UI.
"""

from fastapi import WebSocket, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Any, Dict, Optional
import asyncio
import configparser
from datetime import datetime, timezone
import hmac
import inspect
import json
import logging
import re
from .service import SimulationsService, _PASS, _FAIL
from .aruba import test_central_from_config, get_central_available_from_config, browse_all_from_config
from .sim_quota import validate_sim_quotas, sim_quota_catalog_from_ini, available_sims_from_ini
from . import sim_quota
from . import email_report
from . import github_config_client
from access import safe_external_url, host_resolves_external, has_edit_access
from urllib.parse import urlsplit

logger = logging.getLogger("SimRoutes")

# Pure helpers + the short-TTL caches live in helpers.py; imported back so
# behavior is unchanged (the route handlers mutate the cache dicts in place
# via these references). main.py also imports _normalize_usb_vidpids/
# _normalize_usb_ignored from simulations.routes, so they must stay resolvable
# here.
from .helpers import (  # noqa: F401
    _SIM_QUOTA_CATALOG_TTL_S, _sim_quota_catalog_cache,
    _invalidate_sim_quota_catalog,
    _PXMX_SITE_MAP_TTL_S, _pxmx_site_map_cache, _invalidate_pxmx_site_map,
    _parse_ini_sections, _now_iso,
    _USB_VIDPID_RE, _USB_TYPES,
    _normalize_usb_vidpids, _normalize_usb_ignored, _coerce_vidpid_items,
    _HUB_CONFIG_LIST_KEYS, _HUB_CONFIG_VIDPID_OBJ_KEY,
    _split_delim, _coerce_to_list, _hub_config_list_value,
    normalize_hub_config_lists,
    _usb_dev_vidpid, _reclassify_host_usb, _usb_keys_summary,
    _usb_structure_dump, _usb_provisioning_status_payload,
    _cached_command_queue,
)


def _compute_stale_push(eff_quotas: list, spoke_counts: dict) -> list:
    """Flag effective quotas whose spoke-side count lags the hub's applied count.

    ``spoke_counts`` maps ``quota_dedup_key`` → the count the spoke's engine is
    actually running with (from the spoke's own effective set). A quota that
    **matches** (sc == hc) is current. A quota the spoke has at a **different**
    count is a stale push. A quota **missing** from the spoke (sc is None — the
    push never landed) is the starkest case: the engine never tries to fill it,
    so it reads 0/target with no eligibility explanation — flag it as
    spoke_count 0 + ``missing=True`` instead of silently skipping it (the old
    ``sc is not None`` guard hid exactly this case). A quota with hub count 0
    that's also absent/0 on the spoke is not flagged (nothing to push)."""
    out: list = []
    for q in eff_quotas or []:
        k = sim_quota.quota_dedup_key(q)
        sc = spoke_counts.get(k)
        hc = int(q.get("count") or 0)
        sc_num = 0 if sc is None else sc
        if sc_num != hc and (sc_num > 0 or hc > 0):
            out.append({"key": k, "spoke_count": sc_num,
                        "hub_count": hc, "missing": sc is None})
    return out


def register_simulations_routes(app, hub, session_user_fn, resolve_tenant_fn,
                                  is_admin_fn, check_tenant_access_fn=None, sessions=None,
                                  has_cs_access_fn=None, is_tenant_admin_fn=None):
    """
    Registers the simulation API and WebSocket routes.

    The full auth-helper set (session_user, resolve_tenant, is_admin,
    check_tenant_access, sessions, has_cs_access) is accepted so the
    tenant-scoped access checks can be wired in as the stubbed handlers are
    filled out. resolve_tenant_fn, is_admin_fn and has_cs_access_fn are used
    today (the latter gates /sim/ws on the ``cs`` right); the rest are accepted
    (and default to None) so the call site in api.py create_app() — which
    passes all of them — does not raise a TypeError at app-build time, which
    would prevent the FastAPI app (and thus the WebUI/API) from starting.
    """

    async def get_tenant_id(request: Request):
        # Honor the frontend's ?tenant_id= (sim-views.js csTenant() — the LM
        # tenant selector) and the LM-wide ?tenant=, falling back to the
        # session's tenant_id. Without this, admin sessions (no tenant_id on
        # the session) resolve to None and every /sim/api/aggregate/* route
        # returns an empty result set even when CS spokes are connected.
        # resolve_tenant_fn is a sync helper (_resolve_tenant); await only if a
        # caller ever passes an async resolver (awaiting a plain str raises
        # TypeError -> 500 on every aggregate route).
        explicit = (request.query_params.get("tenant_id")
                    or request.query_params.get("tenant"))
        if explicit:
            # The http middleware only enforces ?tenant=, not ?tenant_id=, so
            # gate the explicit tenant here to prevent cross-tenant reads.
            sess = session_user_fn(request)
            if check_tenant_access_fn and not check_tenant_access_fn(sess, explicit):
                raise HTTPException(status_code=403,
                                    detail=f"Not authorized for tenant '{explicit}'")
            tid = explicit
        else:
            tid = resolve_tenant_fn(request)
        if inspect.isawaitable(tid):
            tid = await tid
        return tid

    # ── Auth adapters ───────────────────────────────────────────────────
    # LM owns authentication via the lm_session cookie. These endpoints map the
    # LM session into the shapes the ported cs webui-hub frontend expects at
    # boot (see cs/webui-hub/app/main.py and routers/auth.py). The cs login
    # screen is never the entry path — the frontend's hub_token gate is cleared
    # by the sim_shim.js seeding a vestigial token, after which loadUserContext()
    # hits /sim/api/auth/me below.

    @app.get("/sim/api/init")
    async def sim_api_init():
        """cs /api/init contract: mode + versions. Public (in api.py _PUBLIC)."""
        return {"mode": "hub", "app_version": "1.00", "installer_version": "1.00"}

    @app.get("/sim/api/health")
    async def sim_api_health():
        """cs /api/health contract. Public (in api.py _PUBLIC)."""
        import os
        sha = os.getenv("APP_VERSION", "dev")
        branch = os.getenv("APP_BRANCH", "local")
        return {"status": "ok", "version": sha, "branch": branch, "sha": sha}

    @app.get("/sim/api/auth/providers")
    async def sim_auth_providers():
        """Cosmetic auth-provider list (LM controls auth; cs login form is unreachable)."""
        # LM controls auth; the cs login form is unreachable. Contents are
        # cosmetic — mirror cs routers/auth.py:9-10,46-52.
        return {"providers": ["password", "oidc", "ldap", "radius", "tacacs"],
                "active": ["password"]}

    def _tenant_name(tid: str) -> str:
        """Return a tenant's display name, falling back to its id."""
        tenant = hub.state.get_tenant(tid) if tid else None
        return (tenant or {}).get("name") or tid

    def _user_tenants(sess) -> list:
        """Tenant ids this session user acts on. Admins see all tenants."""
        if not sess:
            return []
        if is_admin_fn(sess):
            all_tenants = (hub.state.tenant_state or {}).get("tenants", {})
            return list(all_tenants.keys())
        return list(sess.get("user", {}).get("tenants", []) or [])

    @app.get("/sim/api/auth/me")
    async def sim_auth_me(request: Request):
        """Map the LM session into the cs UserResponse shape
        {id, username, is_superadmin, tenant_roles:[{tenant_id, role, tenant_name}]}.
        Cookie-gated by access_control_middleware (not in _PUBLIC)."""
        sess = session_user_fn(request)
        if not sess:
            return JSONResponse(status_code=401, content={"authenticated": False})
        user = sess.get("user", {})
        user_id = user.get("user_id") or sess.get("user_id") or "unknown"
        is_superadmin = bool(is_admin_fn(sess))
        # A tenant Admin admins the tenants in its user.tenants list; a Global
        # Admin admins every tenant. is_superadmin (top-level) stays Global-only
        # so the cs superadmin dashboard remains a Global-Admin surface.
        is_tadm = bool(is_tenant_admin_fn(sess)) if is_tenant_admin_fn else False
        role = "admin" if (is_superadmin or is_tadm) else "member"
        tenant_roles = [
            {"tenant_id": tid, "role": role, "tenant_name": _tenant_name(tid)}
            for tid in _user_tenants(sess)
        ]
        return {
            "id": user_id,
            "username": user_id,
            "is_superadmin": is_superadmin,
            "tenant_roles": tenant_roles,
        }

    def _require_admin(request: Request):
        """Raise 403 unless the request's session is an admin; return the admin session."""
        sess = session_user_fn(request)
        if not sess or not is_admin_fn(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        return sess

    def _require_tenant_admin_or_admin(request: Request):
        """Onboarding-PSK / tenant-admin operation gate.

        A Global Admin (``is_admin_fn``) may manage any tenant's PSKs; a tenant
        Admin (``is_tenant_admin_fn``) may manage PSKs only for a tenant in their
        ``user.tenants`` (the ``Depends(get_tenant_id)`` + ``check_tenant_access``
        tenant-scoping enforces that downstream). A plain ``cs``-righted user is
        blocked — retrieving/generating onboarding PSKs is an admin operation
        (it lets the holder enroll a rogue spoke into the tenant). Returns the
        session.
        """
        sess = session_user_fn(request)
        if not sess or not (is_admin_fn(sess) or (is_tenant_admin_fn and is_tenant_admin_fn(sess))):
            raise HTTPException(status_code=403, detail="Admin access required")
        return sess

    @app.get("/sim/api/superadmin/tenants")
    async def sim_superadmin_tenants(request: Request):
        """cs /superadmin/tenants contract: list of {id, name, ...}. Admin-only.
        Feeds the superadmin dashboard tenant rows (app.js loadUserContext)."""
        _require_admin(request)
        tenants = (hub.state.tenant_state or {}).get("tenants", {})
        rows = []
        for tid, t in tenants.items():
            t = t or {}
            rows.append({"id": tid, "name": t.get("name") or tid, **t})
        return rows

    @app.get("/sim/api/superadmin/users")
    async def sim_superadmin_users(request: Request):
        """cs /superadmin/users contract (subset): list of users with
        tenant_roles, so buildTenantUserCounts (app.js:8743) works. Admin-only."""
        _require_admin(request)
        users = hub.state.system_state.get("users", {})
        rows = []
        for uid, u in users.items():
            u = u or {}
            rows.append({
                "id": uid,
                "tenant_roles": [
                    {"tenant_id": tid, "role": "member", "tenant_name": _tenant_name(tid)}
                    for tid in (u.get("tenants", []) or [])
                ],
            })
        return rows

    # ── superadmin global USB dongle-type approval (applies to all tenants) ──
    # Mirrors cs source superadmin.py:589-658. A platform-wide certified/ignored
    # list is merged with each tenant's list (see _effective_usb_*) and pushed
    # to every tenant's spoke, so approving a dongle type once applies globally.
    @app.get("/sim/api/superadmin/global-usb-vidpids")
    async def sim_get_global_usb_vidpids(request: Request):
        """Admin-only: return the platform-wide certified USB device list."""
        _require_admin(request)
        return {"usb_vidpids": await store.get_global_usb_vidpids()}

    @app.put("/sim/api/superadmin/global-usb-vidpids")
    async def sim_put_global_usb_vidpids(request: Request):
        """Replace the platform-wide certified list, then push the effective
        (global+tenant) list to every tenant's spoke."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        devices = _normalize_usb_vidpids((body or {}).get("usb_vidpids"))
        await store.set_global_usb_vidpids(devices)
        pushed = await _push_usb_to_all_tenants()
        return {"status": "saved", "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.get("/sim/api/superadmin/global-usb-ignored-vidpids")
    async def sim_get_global_usb_ignored(request: Request):
        """Admin-only: return the platform-wide ignored USB VID:PID list."""
        _require_admin(request)
        return {"usb_vidpids": await store.get_global_usb_ignored_vidpids()}

    @app.put("/sim/api/superadmin/global-usb-ignored-vidpids")
    async def sim_put_global_usb_ignored(request: Request):
        """Replace the platform-wide ignored list, then push the effective
        (global+tenant) ignored list to every tenant's spoke."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        vidpids = _normalize_usb_ignored((body or {}).get("usb_vidpids"))
        await store.set_global_usb_ignored_vidpids(vidpids)
        pushed = await _push_usb_to_all_tenants()
        return {"status": "saved", "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.get("/sim/api/superadmin/global-t1-pci-vidpids")
    async def sim_get_global_t1_pci(request: Request):
        """Admin-only: platform-wide T1 PCI-passthrough VID:PID list."""
        _require_admin(request)
        return {"vidpids": await store.get_global_t1_pci_vidpids()}

    @app.put("/sim/api/superadmin/global-t1-pci-vidpids")
    async def sim_put_global_t1_pci(request: Request):
        """Replace the platform-wide T1 PCI list, then push the effective
        (global+tenant) list to every tenant's spoke."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        vidpids = _normalize_usb_ignored((body or {}).get("vidpids"))
        await store.set_global_t1_pci_vidpids(vidpids)
        pushed = await _push_usb_to_all_tenants()
        return {"status": "saved", "pushed_to_spokes": pushed}

    @app.get("/sim/api/superadmin/global-t3-pci-vidpids")
    async def sim_get_global_t3_pci(request: Request):
        """Admin-only: platform-wide T3 PCI-passthrough VID:PID list."""
        _require_admin(request)
        return {"vidpids": await store.get_global_t3_pci_vidpids()}

    @app.put("/sim/api/superadmin/global-t3-pci-vidpids")
    async def sim_put_global_t3_pci(request: Request):
        """Replace the platform-wide T3 PCI list, then push the effective
        (global+tenant) list to every tenant's spoke."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        vidpids = _normalize_usb_ignored((body or {}).get("vidpids"))
        await store.set_global_t3_pci_vidpids(vidpids)
        pushed = await _push_usb_to_all_tenants()
        return {"status": "saved", "pushed_to_spokes": pushed}

    @app.get("/sim/api/superadmin/discovered-usb-vidpids")
    async def sim_get_discovered_usb(request: Request):
        """Approval queue: every unique VID:PID seen in spoke telemetry across
        all tenants, annotated with where it was seen and whether it is already
        globally certified. Superadmin certifies/ignores from here."""
        _require_admin(request)
        return {"devices": await _discovered_usb()}

    @app.get("/sim/api/superadmin/tenants/usb")
    async def sim_superadmin_tenants_usb(request: Request):
        """Admin USB overview: the platform-wide (global) certified/ignored
        lists PLUS each tenant's own certified/ignored lists, side by side.
        Feeds the Setup → Simulations admin page. Global approve/ignore acts via
        the existing /sim/api/superadmin/global-usb-* PUT routes; per-tenant
        certify/ignore acts via POST /sim/api/{tenant}/usb-vidpids?tenant_id=<id>.
        """
        _require_admin(request)
        tenants = (hub.state.tenant_state or {}).get("tenants", {}) or {}
        rows = []
        for tid in _all_tenant_ids():
            t = tenants.get(tid) or {}
            hc = await store.get_hub_config(tid)
            cfg = hc.get("hub_config") or {}
            rows.append({
                "id": tid,
                "name": t.get("name") or tid,
                "certified": _normalize_usb_vidpids(cfg.get("usb_vidpids")),
                "ignored": _normalize_usb_ignored(cfg.get("usb_ignored_vidpids")),
            })
        return {
            "global": {
                "certified": await store.get_global_usb_vidpids(),
                "ignored": await store.get_global_usb_ignored_vidpids(),
            },
            "tenants": rows,
        }

    @app.get("/sim/api/superadmin/dhcp-status")
    async def sim_superadmin_dhcp_status(request: Request):
        """Admin DHCP overview: each tenant's cs-spoke Kea DHCP status block,
        projected from the cached CS_TELEMETRY payload (no spoke round-trip).
        Each spoke's ``dhcp`` block (built by ``cs/lm-spoke/src/dhcp_status.py``
        and carried on the 10 s telemetry frame) is ``{installed, running, iface,
        subnet, pool_start, pool_end, pool_size, leases_used, leases_free,
        utilization_pct, leases[], ...}``. A spoke that isn't running the cs
        Kea instance reports ``installed: false``; an offline cs spoke simply has
        no ``dhcp`` key → empty. Feeds the Setup → Simulations "DHCP Server" card.
        """
        _require_admin(request)
        rows = []
        for tid in _all_tenant_ids():
            tname = ((hub.state.tenant_state or {}).get("tenants", {}) or {}) \
                .get(tid, {}).get("name") or tid
            spokes = []
            for sid, data in _tenant_cache(tid).items():
                spokes.append({
                    "spoke_id": sid,
                    "spoke_name": data.get("spoke_name") or sid,
                    "dhcp": data.get("dhcp") or {},
                })
            rows.append({"tenant_id": tid, "tenant_name": tname, "spokes": spokes})
        return {"tenants": rows}

    # --- API Routes ---
    # Ordering: literal-first-segment routes (aggregate/*, spokes/*, checks,
    # tenant/*, hub/*) are registered BEFORE any {tenant}/... param route so the
    # param route can't shadow them. The {tenant} path segment is cosmetic —
    # every handler scopes to the session-resolved tenant_id.

    service = SimulationsService(hub)
    store = hub.simulations_store

    class _PushResult(int):
        """An ``int`` (spoke-pushed count) that also remembers whether the push
        was delivered live or queued for later. Behaves exactly like the plain
        ``0``/``1`` every call site already used — JSON-encodes as a bare
        number, works in ``if pushed`` / arithmetic — so none of the ~16
        call sites need to change how they use the count itself. They only
        need to opt in to reading ``.queued``/``.message`` where they want to
        tell the caller the change is delayed rather than already live."""
        def __new__(cls, count: int, queued: bool = False, message: str = ""):
            obj = int.__new__(cls, count)
            obj.queued = queued
            obj.message = message
            return obj

    async def _push_config(tenant_id: str, payload: dict) -> "_PushResult":
        """Best-effort CS_CONFIG_UPDATE push to ALL of the tenant's Client-Sim
        spokes. Returns a _PushResult whose int value is the NUMBER of spokes
        the config reached (0 if none connected/assigned; N if pushed to N
        spokes — a tenant with 3 bound cs spokes gets 3, not 1) and ``.queued``
        is True when ANY delivery was queued rather than live. The spoke-side
        CSBridge routes CS_CONFIG_UPDATE through server._apply_hub_config,
        which handles central_api/central_config/notifications/
        sim_conf_override/user_conf_override/relay_onboarding_psk + the
        HUB_CONFIG_OWNED_KEYS.

        Uses push_or_queue_to_spoke (not a bare request_response) so a spoke
        that's approved+bound but momentarily unreachable — mid self-update
        restart, brief reconnect blip — gets this queued for delivery the
        moment it reconnects instead of silently reporting "0 spokes pushed"
        for what looked like a fine, connected spoke a few seconds earlier.
        A queued push still counts toward the total: it WILL apply, just not
        this instant.

        Fans out to every spoke from hub.get_client_sim_spokes (the plural
        helper that respects tenant binding — a tenant with several bound cs
        spokes gets the config on ALL of them, not just ``bound[0]``); falls
        back to the singular get_client_sim_spoke on an older hub build without
        it. Pushes CONCURRENTLY so a slow/queued spoke doesn't serialise the
        fan-out (3 spokes = one ~5s round-trip, not three)."""
        # Never let a hub-config push carry a TENANT-ONLY vid:pid list. The
        # global USB/PCI approvals live in a SEPARATE store (not in the tenant's
        # hub_config), so a raw hub-config Save/reset/patch would push the
        # tenant-only usb_vidpids and OVERWRITE the effective (global+tenant) list
        # the spoke already stored — silently evicting a globally-certified dongle
        # from the spoke → agent, so it never provisions ("global dongle not
        # grabbed" bug). Whenever any of these lists is present in the payload,
        # replace it with the EFFECTIVE merged list (same union the global-approval
        # and reconnect pushes already use). Idempotent for _push_usb_to_tenant
        # (which already sent effective). Payloads without these keys are untouched.
        if isinstance(payload, dict) and any(
                k in payload for k in ("usb_vidpids", "usb_ignored_vidpids",
                                       "t1_pci_vidpids", "t3_pci_vidpids")):
            payload = dict(payload)
            if "usb_vidpids" in payload:
                payload["usb_vidpids"] = json.dumps(await _effective_usb_vidpids(tenant_id))
            if "usb_ignored_vidpids" in payload:
                payload["usb_ignored_vidpids"] = json.dumps(await _effective_usb_ignored(tenant_id))
            if "t1_pci_vidpids" in payload:
                payload["t1_pci_vidpids"] = json.dumps(await _effective_t1_pci(tenant_id))
            if "t3_pci_vidpids" in payload:
                payload["t3_pci_vidpids"] = json.dumps(await _effective_t3_pci(tenant_id))
        # Prefer the plural helper (reaches every bound cs spoke); fall back to
        # the singular one on an older hub build without it.
        spoke_ids: list = []
        get_spokes = getattr(hub, "get_client_sim_spokes", None)
        if callable(get_spokes):
            try:
                spoke_ids = list(get_spokes(tenant_id) or [])
            except Exception:
                spoke_ids = []
        if not spoke_ids:
            get_spoke = getattr(hub, "get_client_sim_spoke", None)
            if callable(get_spoke):
                try:
                    sid = get_spoke(tenant_id)
                except Exception:
                    sid = None
                if sid:
                    spoke_ids = [sid]
        if not spoke_ids:
            return _PushResult(0)
        # Always refresh the spoke's in-memory github_config (the Source-of-Truth
        # push token) so a spoke that restarted AFTER the key was installed — and
        # before the operator re-saved the GitHub creds — still has the token when
        # it commits+pushes THIS edit. github_config is in-memory-only on the
        # spoke (never persisted), so without this re-delivery a post-restart conf
        # edit silently writes a local hub-override and never pushes — the "old
        # GitHub version on sync" symptom. Don't override an explicit caller value
        # (the clear route sends github_config=None to wipe the spoke's copy).
        if "github_config" not in payload:
            try:
                payload = {**payload,
                           "github_config": await store.get_github_config(tenant_id)}
            except Exception as exc:  # noqa: BLE001 — best-effort, never block the push
                logger.debug("CS_CONFIG_UPDATE: github_config merge for %s failed: %s",
                             tenant_id, exc)
        # ── Hub is the config authority; an ATTACHED spoke is a FOLLOWER ──────
        # For a CONFIG-DELIVERY push (sim/user override text, or an explicit
        # config_source), tell the spoke to run as a follower so it serves the
        # hub-delivered files as its WHOLE config — the hub is the sole GitHub
        # client (simulations/github_config_client.py). The mode comes from
        # _spoke_config_source: 'hub' once the hub actually HAS the tenant's
        # config (hub-owned, or github pulled into the store), else a short-lived
        # 'github' bootstrap so the spoke isn't handed an EMPTY whole-config
        # before the hub's first pull lands (it keeps self-pulling until then).
        # When 'hub', strip the PAT — a follower must never push/pull GitHub
        # (belt-and-suspenders atop config_source='hub'). Non-config pushes
        # (USB/quotas) are left untouched; standalone (no-hub) spokes are never
        # reached here and self-manage via their own repo_sync + creds.
        if any(k in payload for k in
               ("sim_conf_override", "user_conf_override", "config_source")):
            try:
                _src = await _spoke_config_source(tenant_id)
            except Exception:  # noqa: BLE001 — never block the push on the mode calc
                _src = "hub"
            payload = dict(payload)
            payload["config_source"] = _src
            if _src == "hub":
                _gc = payload.get("github_config")
                if isinstance(_gc, dict) and _gc.get("github_token"):
                    payload["github_config"] = {k: v for k, v in _gc.items()
                                                if k != "github_token"}
        # Drain-aware push preferred: when a bound cs spoke is mid self-update
        # (draining — about to os._exit + relaunch, or already restarting), a
        # live request_response hangs to its 5s timeout when the spoke drops its
        # WS mid-reply (the "Request Timeout: [CS_CONFIG_UPDATE] ... after 5.0s"
        # burst during an Update fan-out — _push_spoke_update already marks the
        # spoke draining the instant it sends SPOKE_UPDATE, but a CONCURRENT
        # config write that fans out here used to ignore that and live-attempt
        # anyway). _drain_aware_config_push short-circuits on drain state and
        # queues straight to the durable mailbox (no 5s hang, no ERROR log); it
        # falls through to a normal live-attempt + queue-on-unreachable push
        # otherwise. Same path push_cs_hub_config + cs_bridge SET_AGENT_CONFIG
        # already use. Falls back to push_or_queue_to_spoke on an older hub
        # build without the drain-aware helper, then to a bare request_response.
        drain_aware = getattr(hub, "_drain_aware_config_push", None)
        push = getattr(hub, "push_or_queue_to_spoke", None)

        # Tenant-wide split: when a tenant has SEVERAL cs spokes, a quota/placement
        # target N is apportioned across them so the tenant TOTAL is N (not N on
        # each spoke). The split is PROPORTIONAL to each spoke's pool size (from
        # telemetry) via largest-remainder, so a bigger spoke takes a bigger share
        # and small spokes aren't over-asked; falls back to even when telemetry is
        # absent. Each spoke fills its share from its own clients; Quota State sums
        # the ledgers back to N.
        #
        # ANTI-AFFINITY (design §0): a quota TIED TO AN ALERT is split EVENLY
        # (round-robin), NOT by pool size — 10 clients across 3 servers → 4/3/3.
        # That way losing one server still leaves the alert firing from the others,
        # instead of a big spoke holding all of an alert's traffic. The +1
        # remainder rotates per-quota (by a stable checksum of its key) so it's not
        # always the same spoke carrying the extra across many alerts.
        # Per-site apportionment: a site-scoped quota is split ONLY across the
        # spokes that actually hold clients for that site (each spoke's
        # CS_TELEMETRY ``pool_by_site``), not every bound cs spoke. A bound
        # spoke whose clients are all elsewhere no longer reserves a share it
        # can never fill — the old even/total-pool split under-filled the
        # tenant total whenever the tenant had a bound spoke that didn't serve
        # the site (the MIA target divided across a DAL-only spoke too). Alert-
        # tied quotas stay EVEN among the site-eligible spokes (fault tolerance:
        # lose one, the others still carry the alert); presence/untethered
        # quotas stay PROPORTIONAL to the per-site pool. Falls back to the
        # legacy even/total-pool split when no telemetry places the site on any
        # spoke (cold cache / just-connected spoke) — never worse than today.
        try:
            _csc = await store.get_central_sites_config(tenant_id) or {}
            _alias_groups = _alias_groups_from_csc(_csc)
        except Exception:  # noqa: BLE001
            _alias_groups = []

        def _site_aliases(site) -> Optional[set]:
            """The quota's site resolved to its co-referring alias set (cell →
            wsite → central_site, transitively) so a "MIA" quota matches a
            spoke reporting "MIA-PSK" clients. None for an empty/global site →
            the quota is eligible on every spoke."""
            site = str(site or "").strip()
            if not site:
                return None
            aliases = {site.lower()}
            try:
                changed = True
                while changed:
                    changed = False
                    for g in _alias_groups:
                        if (aliases & g) and not (g <= aliases):
                            aliases |= g
                            changed = True
            except Exception:  # noqa: BLE001
                pass
            return aliases

        def _spoke_pool_by_site(sid: str) -> dict:
            try:
                return (getattr(hub, "simulations_cache", {}).get(sid) or {}).get("pool_by_site") or {}
            except Exception:  # noqa: BLE001
                return {}

        _k = len(spoke_ids)
        _idx_of = {sid: i for i, sid in enumerate(spoke_ids)}

        def _spoke_weight(sid: str) -> int:
            try:
                return len((getattr(hub, "simulations_cache", {}).get(sid) or {}).get("clients") or [])
            except Exception:  # noqa: BLE001
                return 0
        _weights = [_spoke_weight(s) for s in spoke_ids]
        if sum(_weights) <= 0:
            _weights = [1] * _k

        def _site_weights(aliases) -> list:
            """Per-spoke weight for a site-scoped quota: the count of that
            spoke's pool clients whose physical site is in the alias set. None
            aliases (global quota) → the spoke's whole online pool (_weights)."""
            if aliases is None:
                return list(_weights)
            ws = []
            for sid in spoke_ids:
                bs = _spoke_pool_by_site(sid)
                n = sum(int(v) for s, v in bs.items()
                        if str(s).strip().lower() in aliases)
                ws.append(n)
            return ws

        def _apportion_w(total, idx: int, weights, rotate: int = 0) -> int:
            total = int(total or 0)
            tw = sum(weights) or 1
            raw = [total * w / tw for w in weights]
            shares = [int(x) for x in raw]
            rem = total - sum(shares)
            # Primary: largest fractional remainder. Secondary tie-break: spokes
            # starting at `rotate` (round-robin), so an even split's extra client
            # lands on a different server for each alert.
            order = sorted(range(_k),
                           key=lambda j: (raw[j] - shares[j], -((j - rotate) % _k)),
                           reverse=True)
            for i in order[:max(0, rem)]:
                shares[i] += 1
            return shares[idx]

        def _quota_rotate(q: dict) -> int:
            key = f"{q.get('alert_type', 'alert')}:{q.get('alert_id', '')}:{q.get('site', '')}"
            return sum(key.encode()) % _k if _k else 0

        def _payload_for(sid: str) -> dict:
            if _k <= 1:
                return payload
            idx = _idx_of.get(sid, 0)
            p = dict(payload)
            if isinstance(payload.get("effective_sim_quotas"), list):
                out = []
                for q in payload["effective_sim_quotas"]:
                    site_w = _site_weights(_site_aliases(q.get("site")))
                    if q.get("alert_id"):
                        # Alert-tied: EVEN among site-eligible spokes (1 each),
                        # so losing one doesn't drop the alert. Fall back to
                        # even-across-all when no telemetry places the site.
                        w = [1 if x > 0 else 0 for x in site_w]
                        if sum(w) == 0:
                            w = [1] * _k
                    else:
                        # Presence / untethered: proportional to the per-site
                        # pool. Fall back to total-pool when no site telemetry.
                        w = site_w
                        if sum(w) <= 0:
                            w = _weights
                    out.append({**q, "count": _apportion_w(q.get("count") or 0, idx,
                                                           w, _quota_rotate(q))})
                p["effective_sim_quotas"] = out
            if isinstance(payload.get("ssid_placement"), dict):
                out_place = {}
                for site, pc in payload["ssid_placement"].items():
                    if not isinstance(pc, dict):
                        out_place[site] = pc
                        continue
                    site_w = _site_weights(_site_aliases(site))
                    w = site_w if sum(site_w) > 0 else _weights
                    out_place[site] = {**pc, "targets": {
                        c: _apportion_w(n or 0, idx, w) for c, n in (pc.get("targets") or {}).items()}}
                p["ssid_placement"] = out_place
            return p

        async def _one(sid: str):
            """Push to one spoke. Returns (1, queued, msg) on delivery (live OR
            queued — a queued push still counts, it WILL apply on reconnect),
            (0, False, '') on transport failure."""
            payload = _payload_for(sid)
            if callable(drain_aware):
                try:
                    outcome = await drain_aware(sid, "CS_CONFIG_UPDATE", payload, timeout=30.0)
                    queued = bool(outcome.get("queued"))
                    msg = str(outcome.get("message", "") or "")
                    if queued:
                        logger.info("CS_CONFIG_UPDATE for %s queued (%s): %s", sid,
                                    "draining" if outcome.get("draining")
                                    else "spoke unreachable",
                                    outcome.get("message") or "")
                    return 1, queued, msg
                except Exception as exc:
                    logger.warning("CS_CONFIG_UPDATE push to %s failed: %s", sid, exc)
                    return 0, False, ""
            if not callable(push):
                # Fallback for an older hub build without either helper.
                try:
                    await hub.request_response(sid, "CS_CONFIG_UPDATE", payload, timeout=30.0)
                    return 1, False, ""
                except Exception as exc:
                    logger.warning("CS_CONFIG_UPDATE push to %s failed: %s", sid, exc)
                    return 0, False, ""
            try:
                outcome = await push(sid, "CS_CONFIG_UPDATE", payload, timeout=30.0)
                queued = bool(outcome.get("queued"))
                msg = str(outcome.get("message", "") or "")
                if queued:
                    logger.info("CS_CONFIG_UPDATE for %s queued (spoke unreachable): %s",
                               sid, outcome.get("message"))
                return 1, queued, msg
            except Exception as exc:
                logger.warning("CS_CONFIG_UPDATE push to %s failed: %s", sid, exc)
                return 0, False, ""

        results = await asyncio.gather(*[_one(sid) for sid in spoke_ids])
        pushed = sum(r[0] for r in results)
        any_queued = any(r[1] for r in results)
        queued_msgs = [f"{sid}: {r[2]}" for sid, r in zip(spoke_ids, results)
                       if r[1] and r[2]]
        return _PushResult(pushed, queued=any_queued,
                          message="; ".join(queued_msgs) if any_queued else "")


    async def _cs_forward(tenant_id: str, cmd_type: str, payload: dict,
                          timeout: float = 15.0) -> dict:
        """Forward a CS_* command to the tenant's Client-Sim spoke and unwrap the
        reply the way the command-queue routes do. Raises HTTPException on
        refusal (spoke returns status=ERROR) or transport failure. Returns the
        spoke's data dict on success."""
        sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
        if not sid:
            raise HTTPException(status_code=503, detail="Client-Sim spoke not connected")
        try:
            result = await hub.request_response(sid, cmd_type, payload, timeout=timeout)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"{cmd_type} failed: {exc}")
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        if isinstance(data, dict) and data.get("status") == "ERROR":
            msg = str(data.get("message") or "refused")
            # A request/agent TIMEOUT ("Timed out waiting for spoke response" /
            # "Agent response timeout") is a stalled/busy spoke, NOT a safeguard
            # refusal — surface 504 so the UI reads "spoke busy/timeout" instead
            # of a misleading 403 "forbidden". Real refusals (protected vmid /
            # below the sim floor) stay 403.
            ml = msg.lower()
            code = 504 if ("timed out" in ml or "timeout" in ml) else 403
            raise HTTPException(status_code=code, detail=msg)
        return data if isinstance(data, dict) else {"status": "SUCCESS", "result": data}

    async def _cs_forward_all(tenant_id: str, cmd_type: str, payload: dict,
                              timeout: float = 15.0) -> list:
        """Forward a CS_* command to EVERY Client-Sim spoke bound to the tenant,
        concurrently. Returns ``[(spoke_id, data|None)]`` — a failed/absent spoke
        yields None so callers merge what they got (tenant-wide aggregation for a
        multi-spoke tenant, e.g. cs-svr-02/03/04). Empty list = no spokes."""
        sids: list = []
        get_spokes = getattr(hub, "get_client_sim_spokes", None)
        if callable(get_spokes):
            try:
                sids = list(get_spokes(tenant_id) or [])
            except Exception:  # noqa: BLE001
                sids = []
        if not sids:
            sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
            sids = [sid] if sid else []

        async def _one(sid: str):
            try:
                result = await hub.request_response(sid, cmd_type, payload, timeout=timeout)
                data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
                return (sid, data if isinstance(data, dict) else None)
            except Exception as exc:  # noqa: BLE001
                logger.info("_cs_forward_all(%s): %s failed on %s: %s", tenant_id, cmd_type, sid, exc)
                return (sid, None)
        if not sids:
            return []
        return list(await asyncio.gather(*[_one(s) for s in sids]))

    def _tenant_cache(tenant_id: str) -> dict:
        """The merged CS_TELEMETRY cache for the tenant's spokes (read-only)."""
        out = {}
        for sid, data in (getattr(hub, "simulations_cache", {}) or {}).items():
            try:
                if hub.state.get_spoke_tenant(sid) != tenant_id:
                    continue
            except Exception:
                continue
            out[sid] = data or {}
        return out

    def _patch_cached_client_overrides(tenant_id: str, hostname: str, overrides: dict) -> None:
        """Patch the tenant's cached client's ``overrides`` in simulations_cache
        immediately after an override write. The Clients view is served from this
        cache (CS_TELEMETRY), which only refreshes every ~10s — so without this
        patch a just-pruned/updated override reads STALE until the next frame,
        making a removed override reappear when the user navigates back in. The
        spoke returns its POST-PRUNE overrides; we mirror them so the next read is
        correct. Best-effort; the authoritative telemetry frame overwrites it."""
        hostname = str(hostname or "")
        ov = dict(overrides or {})
        for sid, data in (getattr(hub, "simulations_cache", {}) or {}).items():
            try:
                if hub.state.get_spoke_tenant(sid) != tenant_id:
                    continue
            except Exception:
                continue
            for c in (data.get("clients") or []):
                if isinstance(c, dict) and (c.get("hostname") == hostname or c.get("id") == hostname):
                    c["overrides"] = dict(ov)

    # ── Per-user sim overrides → user-overrides.conf [username] (model A) ──────
    # A dashboard per-client sim toggle now writes a per-USER override (username =
    # hostname minus the trailing "-N") into user-overrides.conf and goes through
    # the SAME source-of-truth push as the Config Editor: hub-owned in Hub mode,
    # committed+pushed to GitHub when a token is configured, 403 in GitHub
    # read-only. Replaces the hidden per-client registry layer; the legacy
    # registry override is cleared on write so nothing double-applies.
    _CS_SIM_FLAGS = {'assoc_fail', 'auth_fail', 'dhcp_fail', 'dns_fail', 'download',
                     'iperf', 'kill_switch', 'ping_test', 'port_flap', 'ssidpw_fail',
                     'www_traffic'}

    def _username_for(hostname: str) -> str:
        """Mirror sim_config.username_for: hostname minus the trailing '-N'."""
        h = str(hostname or "").strip()
        return h.split("-", 1)[0] if "-" in h else h

    async def _current_user_overrides_text(tenant_id: str) -> str:
        """Effective user-overrides.conf text (repo base + hub override), read
        live from the spoke; falls back to the hub-owned override content when
        the spoke is offline so an edit never starts from a blank file."""
        try:
            data = await _cs_forward(tenant_id, "CS_GET_CONFIG", {}, timeout=6.0)
            if isinstance(data, dict) and data.get("user_overrides") is not None:
                return data.get("user_overrides") or ""
        except HTTPException:
            pass
        try:
            return await store.get_user_overrides_content(tenant_id)
        except Exception:  # noqa: BLE001
            return ""

    def _edit_user_override_flags(text, username, flags, clear):
        """Return user-overrides.conf text with the [username] section's SIM
        flags updated. clear=True with empty flags removes ALL sim flags from the
        section; clear=True with flags removes just those; otherwise each flag is
        set on/off. Non-sim keys (wsite/ssid/sim_phy/…) are preserved."""
        import io
        p = configparser.ConfigParser()
        p.optionxform = str
        try:
            p.read_string(text or "")
        except Exception:  # noqa: BLE001 — start clean on a malformed file
            p = configparser.ConfigParser(); p.optionxform = str
        if clear and not flags:
            if p.has_section(username):
                for k in list(p.options(username)):
                    if k in _CS_SIM_FLAGS:
                        p.remove_option(username, k)
        else:
            if not p.has_section(username):
                p.add_section(username)
            for k, v in (flags or {}).items():
                if clear:
                    if p.has_option(username, k):
                        p.remove_option(username, k)
                else:
                    on = str(v).strip().lower() in ("on", "true", "1", "yes")
                    p.set(username, k, "on" if on else "off")
        if p.has_section(username) and not p.options(username):
            p.remove_section(username)
        buf = io.StringIO()
        p.write(buf)
        return buf.getvalue()

    def _patch_cached_client_config(tenant_id: str, username: str, flags: dict) -> None:
        """Patch effective_config[flag] for every cached client of `username` so a
        just-set per-user override shows immediately (before the ~10s telemetry
        frame). Best-effort; the authoritative frame overwrites it."""
        for sid, data in (getattr(hub, "simulations_cache", {}) or {}).items():
            try:
                if hub.state.get_spoke_tenant(sid) != tenant_id:
                    continue
            except Exception:  # noqa: BLE001
                continue
            for c in (data.get("clients") or []):
                if not isinstance(c, dict):
                    continue
                if _username_for(c.get("hostname") or c.get("id") or "") != username:
                    continue
                cfg = c.get("config")
                if not isinstance(cfg, dict):
                    cfg = {}
                    c["config"] = cfg
                for k, v in (flags or {}).items():
                    cfg[k] = "on" if str(v).strip().lower() in ("on", "true", "1", "yes") else "off"

    async def _write_user_override(tenant_id, hostname, flags, clear):
        """Set/clear a per-user sim override in user-overrides.conf and push it via
        the source-of-truth flow. Also clears the legacy per-client registry
        override so the old hidden layer never double-applies."""
        source = await _require_config_writable(tenant_id)   # 403 if github + no key
        username = _username_for(hostname)
        flags = {k: v for k, v in (flags or {}).items() if k in _CS_SIM_FLAGS}
        cur = await _current_user_overrides_text(tenant_id)
        new_text = _edit_user_override_flags(cur, username, flags, clear)
        await store.set_user_overrides_content(tenant_id, new_text)
        # Human edit (per-user override toggle) → the HUB commits it to GitHub,
        # since the follower spoke no longer does. Best-effort; still fans out.
        if source == "github":
            await _commit_config_to_github(
                tenant_id, github_config_client.USER_OVERRIDES_PATH, new_text,
                "Update user-overrides.conf (per-user override) via Lab Manager")
        pushed = await _push_config(tenant_id,
                                    {"user_conf_override": new_text, "config_source": source})
        if not clear and flags:
            _patch_cached_client_config(tenant_id, username, flags)   # instant feedback
        try:
            await _cs_forward(tenant_id, "CS_CLEAR_CLIENT_OVERRIDES", {"hostname": hostname})
        except HTTPException:
            pass
        _patch_cached_client_overrides(tenant_id, hostname, {})
        return {"saved": True, "username": username, "source": source,
                "pushed_to_spokes": pushed}

    # ── platform-wide USB approval helpers (superadmin global + effective merge) ──
    # Mirrors the cs source: global (superadmin) USB certified/ignored lists are
    # merged with each tenant's lists into an "effective" set that is pushed to
    # spokes, so a globally-approved dongle type applies to every tenant.
    def _all_tenant_ids() -> list:
        tenants = (hub.state.tenant_state or {}).get("tenants", {}) or {}
        return list(tenants.keys())

    async def _effective_usb_vidpids(tenant_id: str) -> list:
        """Merged certified list = global + tenant (dedup by vidpid, global
        first). Returns {vidpid,type,label} dicts — the cs-spoke push shape."""
        out: list = []
        seen: set = set()
        for d in await store.get_global_usb_vidpids():
            vp = str(d.get("vidpid", "")).strip().lower()
            if vp and vp not in seen:
                seen.add(vp)
                out.append({"vidpid": vp, "type": str(d.get("type") or "wireless"),
                            "label": str(d.get("label") or vp)})
        if tenant_id:
            hc = await store.get_hub_config(tenant_id)
            for d in _normalize_usb_vidpids((hc.get("hub_config") or {}).get("usb_vidpids")):
                if d["vidpid"] not in seen:
                    seen.add(d["vidpid"])
                    out.append(d)
        return out

    async def _effective_usb_ignored(tenant_id: str) -> list:
        """Merged ignored list = global + tenant (sorted bare vidpid strings)."""
        s: set = set(await store.get_global_usb_ignored_vidpids())
        if tenant_id:
            hc = await store.get_hub_config(tenant_id)
            s.update(_normalize_usb_ignored((hc.get("hub_config") or {}).get("usb_ignored_vidpids")))
        return sorted(s)

    async def _effective_t1_pci(tenant_id: str) -> list:
        """Merged T1 PCI VID:PID list = global ∪ tenant (sorted bare strings)."""
        s: set = set(await store.get_global_t1_pci_vidpids())
        if tenant_id:
            hc = await store.get_hub_config(tenant_id)
            s.update(_normalize_usb_ignored((hc.get("hub_config") or {}).get("t1_pci_vidpids")))
        return sorted(s)

    async def _effective_t3_pci(tenant_id: str) -> list:
        """Merged T3 PCI VID:PID list = global ∪ tenant (sorted bare strings)."""
        s: set = set(await store.get_global_t3_pci_vidpids())
        if tenant_id:
            hc = await store.get_hub_config(tenant_id)
            s.update(_normalize_usb_ignored((hc.get("hub_config") or {}).get("t3_pci_vidpids")))
        return sorted(s)

    async def _push_usb_to_tenant(tenant_id: str) -> int:
        """Push the effective (global+tenant) USB certified/ignored + T1/T3 PCI
        tier lists to the tenant's cs speak. Returns spokes pushed (0 or 1)."""
        cert = await _effective_usb_vidpids(tenant_id)
        ign = await _effective_usb_ignored(tenant_id)
        t1 = await _effective_t1_pci(tenant_id)
        t3 = await _effective_t3_pci(tenant_id)
        return await _push_config(tenant_id, {
            "usb_vidpids": json.dumps(cert),
            "usb_ignored_vidpids": json.dumps(ign),
            "t1_pci_vidpids": json.dumps(t1),
            "t3_pci_vidpids": json.dumps(t3),
        })

    async def _discovered_usb() -> list:
        """Aggregate every unique VID:PID seen across all tenants' cached
        telemetry plus tenant-certified/ignored lists. Mirrors cs source
        store.get_discovered_usb_vidpids. Each entry: {vidpid, name,
        seen_on:[{tenant_name,spoke_name}], is_global, is_global_ignored,
        locally_ignored}. Sorted by vidpid — feeds the superadmin approval
        queue (Setup → Simulations → Global USB Approvals)."""
        g_cert: set = set()
        for d in await store.get_global_usb_vidpids():
            vp = str(d.get("vidpid", "")).strip().lower()
            if vp:
                g_cert.add(vp)
        g_ign: set = set(await store.get_global_usb_ignored_vidpids())
        discovered: dict = {}

        def _ensure(vp: str, name: str = "", locally_ignored: bool = False) -> None:
            e = discovered.get(vp)
            if e is None:
                discovered[vp] = {"vidpid": vp, "name": name or "",
                                  "seen_on": [], "is_global": vp in g_cert,
                                  "is_global_ignored": vp in g_ign,
                                  "locally_certified": [],
                                  "locally_ignored": locally_ignored}
            else:
                if not e["name"] and name:
                    e["name"] = name
                if locally_ignored:
                    e["locally_ignored"] = True

        for tid in _all_tenant_ids():
            tname = _tenant_name(tid)
            hc = await store.get_hub_config(tid)
            cfg = hc.get("hub_config") or {}
            for d in _normalize_usb_vidpids(cfg.get("usb_vidpids")):
                vp = d["vidpid"]
                if vp in g_cert:
                    continue
                _ensure(vp, d.get("label") or "")
                entry = {"tenant_name": tname, "spoke_name": "(tenant certified)"}
                if entry not in discovered[vp]["seen_on"]:
                    discovered[vp]["seen_on"].append(entry)
                # Record the tenant (with id) that locally certified this device so
                # the superadmin can un-approve it per-tenant from the discovered row.
                if not any(c.get("tenant_id") == tid for c in discovered[vp]["locally_certified"]):
                    discovered[vp]["locally_certified"].append({"tenant_id": tid, "tenant_name": tname})
            for vp in _normalize_usb_ignored(cfg.get("usb_ignored_vidpids")):
                if vp in g_ign:
                    continue
                _ensure(vp, "", locally_ignored=True)
                entry = {"tenant_name": tname, "spoke_name": "(tenant ignored)"}
                if entry not in discovered[vp]["seen_on"]:
                    discovered[vp]["seen_on"].append(entry)

        cache = getattr(hub, "simulations_cache", {}) or {}
        for sid, data in cache.items():
            try:
                tid = hub.state.get_spoke_tenant(sid)
            except Exception:
                tid = None
            if not tid:
                continue
            data = data or {}
            sname = data.get("spoke_name") or sid
            tname = _tenant_name(tid)
            px = data.get("proxmox") or {}
            raw: list = []
            for k in ("present_usb", "unknown_usb", "usb_state"):
                v = px.get(k) if isinstance(px, dict) else None
                if isinstance(v, list):
                    raw.extend(v)
            v = data.get("usb_devices")
            if isinstance(v, list):
                raw.extend(v)
            for dev in raw:
                if not isinstance(dev, dict):
                    continue
                vp = str(dev.get("vidpid", "")).strip().lower()
                if not vp:
                    continue
                _ensure(vp, dev.get("name") or dev.get("product") or "")
                entry = {"tenant_name": tname, "spoke_name": sname}
                if entry not in discovered[vp]["seen_on"]:
                    discovered[vp]["seen_on"].append(entry)

        return sorted(discovered.values(), key=lambda d: d["vidpid"])

    async def _push_usb_to_all_tenants() -> int:
        """Push the effective USB list to every tenant's cs speak. Used after a
        global certified/ignored change so all tenants pick up the new devices.
        Fanned out concurrently across tenants (the per-spoke push inside is
        already concurrent); returns the total pushed. Any error propagates as
        before (gather re-raises the first exception)."""
        counts = await asyncio.gather(
            *[_push_usb_to_tenant(tid) for tid in _all_tenant_ids()]
        )
        return sum(counts)

    # ── Sim-Quota effective merge + push ─────────────────────────────────────
    async def _effective_sim_quotas(tenant_id: str) -> list:
        """Merge platform-wide default sim quotas with the tenant's overrides,
        enabled-only (per-alert: tenant wins if it declares any enabled row for
        that alert, else the global default applies). The cs spoke's
        SimQuotaEngine consumes this list. Pure merge in sim_quota.merge_effective_quotas."""
        from .sim_quota import merge_effective_quotas, resolve_effective_quotas, SIM_META
        try:
            t_csc = await store.get_central_sites_config(tenant_id) or {}
        except Exception:  # noqa: BLE001
            t_csc = {}
        # A tenant may opt OUT of the platform-wide quota defaults (Config → Sim
        # Quotas → "Ignore global quotas"): then only its own enabled rows apply.
        if t_csc.get("ignore_global_quotas"):
            base = resolve_effective_quotas(t_csc.get("sim_quotas"), list(SIM_META.keys()))
        else:
            try:
                g_defaults = await store.get_sim_quota_defaults()
            except Exception:  # noqa: BLE001
                g_defaults = []
            base = merge_effective_quotas(g_defaults, t_csc.get("sim_quotas"))
        # Adaptive targets MUST be applied in BOTH branches — the controller ramps
        # state.target from csc.sim_quotas regardless of ignore_global_quotas, so
        # skipping apply here (the old early-return) left count pinned at the min
        # floor while the controller maxed its target and reported "at max, still
        # not firing" — a false alarm: the engine only ever ran the floor.
        return await _apply_adaptive_targets(tenant_id, base)

    def _adaptive_is_on(q: dict) -> bool:
        return sim_quota.adaptive_is_on(q)

    def _adaptive_key(q: dict) -> str:
        return sim_quota.adaptive_key(q)

    async def _apply_adaptive_targets(tenant_id: str, quotas: list) -> list:
        """Replace an adaptive quota's ``count`` with the controller's current
        target (stored state; the controller loop advances it), lifted by the
        effective learned operating point for the alert (max of this tenant's
        learning-ON stable learned_op and the global published value). A quota
        with no controller state yet seeds from that op (or ``min``)."""
        try:
            state = await store.get_adaptive_state(tenant_id)
        except Exception:  # noqa: BLE001
            state = {}
        try:
            global_lv = await store.get_global_learned_values()
        except Exception:  # noqa: BLE001
            global_lv = {}
        return sim_quota.apply_adaptive_targets(quotas, state, global_lv)

    async def _spoke_effective_counts(tenant_id: str) -> dict:
        """Per-quota effective count as the cs spoke's engine is ACTUALLY running
        it (vs the hub's pushed target) — ``{dedup_key: count}``. Gathered by
        forwarding ``CS_GET_SIM_QUOTA_STATE`` to every cs spoke and reducing each
        reply's ``effective`` list. Empty when no spokes reply (spoke down or no
        cs spoke bound). The first spoke's count wins per key (the effective set
        is pushed tenant-wide, so every spoke reports the same count for a key);
        mirrors the reduction in ``get_sim_quota_state``."""
        counts: dict = {}
        try:
            results = await _cs_forward_all(tenant_id, "CS_GET_SIM_QUOTA_STATE",
                                            {}, timeout=10.0)
        except Exception:  # noqa: BLE001
            return counts
        for _sid, data in results:
            if not isinstance(data, dict):
                continue
            for q in (data.get("effective") or []):
                if isinstance(q, dict):
                    counts.setdefault(sim_quota.quota_dedup_key(q),
                                      int(q.get("count") or 0))
        return counts

    def _ceil(x: float) -> int:
        return sim_quota.ceil_to_int(x)

    def _adaptive_step(st: dict, q: dict, firing, now: float,
                       applied_op: Optional[int] = None) -> dict:
        return sim_quota.adaptive_step(st, q, firing, now, applied_op)

    def _alias_groups_from_csc(csc: dict) -> list:
        """Build the "groups" of co-referring site identifiers from a tenant's
        central_sites_config: each ssid_matrix cell, each site_link, and each
        site_mappings pair contributes the SET of its site-ish field values.
        Pure (no I/O) so a sweep can compute it ONCE per tenant and pass it to
        every _alert_firing call instead of re-reading csc + rebuilding per
        quota. The transitive fixpoint over these groups still runs per-quota in
        _alert_firing (it depends on the quota's own site)."""
        _FIELDS = ("name", "cell", "site", "wsite", "central_site")
        groups: list = []
        for cd in (csc.get("ssid_matrix") or []):
            g = {str(cd.get(f) or "").strip().lower() for f in _FIELDS}
            g.discard("")
            if g:
                groups.append(g)
        for lk in (csc.get("site_links") or []):
            g = {str(lk.get(f) or "").strip().lower() for f in _FIELDS}
            g.discard("")
            if g:
                groups.append(g)
        for wk, cv in (csc.get("site_mappings") or {}).items():
            g = {str(wk).strip().lower(), str(cv or "").strip().lower()}
            g.discard("")
            if g:
                groups.append(g)
        return groups

    async def _alert_firing(tenant_id: str, q: dict, alias_groups: Optional[list] = None):
        """Is this quota's alert firing at its site?

        Reads the SAME per-site check status the dashboard already computed — the
        hub's 5-min Central poller for centralized tenants (``central_hub_status``)
        plus relayed spoke telemetry for distributed ones — so the Engine and the
        dashboard Checks view can NEVER disagree, and NO extra Central API call is
        made. This is a cheap in-memory read, so the controller may call it as
        often as it runs; the Central poll itself stays on its own 5-min cadence.

        INVERTED semantics (see central_hub_poller): a check status of "ok" means
        the expected error IS present, i.e. the alert IS firing. Returns True when
        firing at a matching site, False when the check is present but definitively
        not firing, and None when the signal is unavailable (check not found, or
        only an unknown/pending status) so the controller HOLDS instead of ramping.

        Historically this made its own browse_all_from_config call and scanned only
        ``browse["alerts"]`` (never insights) with a separate site matcher — so an
        alert the dashboard showed firing was invisible to the Engine, which then
        ramped to max forever. Reading the dashboard value removes that whole
        second code path.
        """
        alert_id = str(q.get("alert_id") or "").strip().lower()
        if not alert_id:
            return None
        # Every (status_map, site_mappings) the dashboard has for this tenant.
        blocks = []
        hub_central = service._hub_central(tenant_id)               # centralized
        hub_present = isinstance(hub_central, dict)
        if hub_present:
            blocks.append((hub_central.get("status") or {},
                           hub_central.get("site_mappings") or {}))
        spokes = list(service._spokes_for_tenant(tenant_id))        # distributed
        for _sid, data in spokes:
            central = (data or {}).get("central") or {}
            blocks.append((central.get("status") or {},
                           central.get("site_mappings") or {}))
        # No early-return on empty blocks: always fall through to the diag so
        # "engine sees NO dashboard status for this tenant" is visible in the log
        # (hub_status=False spokes=0) rather than silently producing no diag line.
        # Resolve the quota's site to the wsite / central_site aliases the status
        # map is keyed by: a cell-scoped quota (MIA-ACD) must match its physical
        # wsite (MIA) and linked central_site (Miami); an empty site = global →
        # match every wsite.
        # A quota's site can be a cell name, a wsite code, a link name, or a
        # central_site — and the chain is multi-hop (cell "MIA-ACD" → wsite "MIA"
        # → central_site "Miami", the form the poller keys status by). Fold the
        # co-referring "groups" into the alias set TRANSITIVELY (fixpoint) so any
        # hop is reachable. ``alias_groups`` is computed ONCE per sweep by the
        # controller/learner loops (from the csc they already read) and passed in
        # to avoid re-reading csc + rebuilding groups per quota; when absent (any
        # other caller), read + build here so behavior is identical.
        site = str(q.get("site") or "").strip()
        aliases = set()
        if site:
            aliases.add(site.lower())
            try:
                groups = alias_groups
                if groups is None:
                    csc = await store.get_central_sites_config(tenant_id) or {}
                    groups = _alias_groups_from_csc(csc)
                # Fixpoint: union any group that shares a member with the alias set,
                # repeating until nothing new is added (bounded by len(groups)).
                changed = True
                while changed:
                    changed = False
                    for g in groups:
                        if (aliases & g) and not (g <= aliases):
                            aliases |= g
                            changed = True
            except Exception:  # noqa: BLE001
                pass
        # Look the alert up in the dashboard status. "ok" (in _PASS) = firing.
        firing = None
        saw_fail = False
        matched_status = None
        seen_cids: set = set()   # every check id available at the matched site(s)
        for status_map, site_mappings in blocks:
            for wsite, checks_map in (status_map or {}).items():
                if not isinstance(checks_map, dict):
                    continue
                if aliases:
                    wkey = str(wsite).strip().lower()
                    csite = str(site_mappings.get(wsite) or "").strip().lower()
                    if wkey not in aliases and csite not in aliases:
                        continue
                for cid, info in checks_map.items():
                    seen_cids.add(str(cid))
                    if str(cid).strip().lower() != alert_id:
                        continue
                    s = (info.get("status") if isinstance(info, dict) else info) or ""
                    sl = str(s).strip().lower()
                    matched_status = sl
                    if sl in _PASS:
                        firing = True         # error present at a matching site → firing
                    elif sl in _FAIL and firing is None:
                        saw_fail = True       # present, definitively not firing
        # Only report "not firing" when the dashboard definitively says so;
        # otherwise hold (None) rather than ramp on an unclear/absent signal.
        if firing is None and saw_fail:
            firing = False
        # DIAG: what the Engine looked for vs what the dashboard status held.
        #  - status_wsites = every site key the dashboard status is keyed by (with
        #    its central_site). If none of these appear in `aliases`, the quota's
        #    site didn't resolve to the status's key form (add the missing hop /
        #    the site-link's Central Site).
        #  - alert_id NOT in cids_at_site → name/format mismatch with the check id.
        #  - present but firing False → the dashboard has it not-ok at that site.
        status_wsites = sorted({
            f"{w}→{(smap or {}).get(w)}"
            for stat, smap in blocks for w in (stat or {})
        })
        # DEBUG: fires once PER ALERT PER POLL — a per-cycle diagnostic, not an
        # operational event. At INFO it floods the Hub log (and read like debug);
        # keep it at DEBUG so it only surfaces with debug logging enabled.
        logger.debug("engine-firing diag [%s]: alert_id=%r site=%r hub_status=%s spokes=%d "
                     "aliases=%s matched_status=%r → firing=%s; status_wsites=%s cids_at_site=%s",
                     tenant_id, alert_id, site or "(global)", hub_present, len(spokes),
                     sorted(aliases), matched_status, firing, status_wsites, sorted(seen_cids))
        return firing

    async def _reconcile_push_tenant(tenant_id: str) -> bool:
        """Re-push the tenant's effective sim quotas when the cs spoke's
        effective set is missing or count-mismatched vs the hub's. Returns True
        when a re-push was sent.

        This is the self-heal for a spoke that missed a push while continuously
        online: the adaptive controller only re-pushes on state change, so a
        spoke whose adaptive state is stable AND that missed an earlier push
        (briefly disconnected with a mailbox delivery that didn't land, or the
        push fired before it connected) stays stale forever — the engine keeps
        topping up to the stale set and the row reads 0/target with no
        eligibility explanation. Also covers non-adaptive fixed-count quotas
        (WPA/Max-Assoc) that the adaptive controller skips entirely. The
        diagnostic behind the decision is ``_compute_stale_push`` (shipped with
        the Quota State view); this is the actuator that actually re-feeds the
        spoke. Called every 45s from the adaptive controller loop (A) AND every
        15m from a dedicated backstop loop (B)."""
        try:
            eff = await _effective_sim_quotas(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("reconcile-push [%s] effective read failed: %s",
                         tenant_id, exc)
            return False
        if not eff:
            return False  # tenant has no quotas — no forward, no push
        try:
            spoke_counts = await _spoke_effective_counts(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("reconcile-push [%s] spoke counts read failed: %s",
                         tenant_id, exc)
            return False
        stale = _compute_stale_push(eff, spoke_counts)
        if not stale:
            return False
        logger.info(
            "reconcile-push [%s]: %d stale quota(s) — re-pushing: %s",
            tenant_id, len(stale),
            ", ".join(
                f"{s['key']} spoke={s['spoke_count']} hub={s['hub_count']}"
                f"{'(missing)' if s['missing'] else ''}" for s in stale))
        try:
            await _push_sim_quotas(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("reconcile-push [%s] re-push failed: %s",
                           tenant_id, exc)
            return False
        return True

    async def _run_adaptive_controller() -> None:
        """One controller pass over every tenant's adaptive quotas — advance the
        target and re-push when it moves. Small (per-quota state).

        For each alert, ``applied_op`` = max(this tenant's learning-ON stable
        rows' learned_op, the global published value). Learning-ON rows run the
        full thermostat (the lab); learning-OFF rows are up-only consumers that
        seed/lift from ``applied_op``. Only learning-ON rows down-ratchet — a
        consumer never risks stopping its alert."""
        import time as _t
        from .sim_quota import normalize_quota, _alert_key
        now = _t.time()
        try:
            global_lv = await store.get_global_learned_values()
        except Exception:  # noqa: BLE001
            global_lv = {}
        for tid in _all_tenant_ids():
            try:
                csc = await store.get_central_sites_config(tid) or {}
                # (A) Reconcile-pass each 45s tick: re-push effective quotas when
                # the spoke's effective set is missing/mismatched vs the hub's,
                # regardless of adaptive state. The adaptive push below only fires
                # on state change, so a stable-but-stale spoke (missed a push while
                # online) would never self-heal. Runs for EVERY tenant — including
                # non-adaptive fixed-count quotas (WPA/Max-Assoc) the `if not
                # adaptive: continue` below would otherwise skip. When this tick
                # ALSO moves adaptive state, both pushes fire: this one carries
                # the pre-step effective set, the `if changed:` push carries the
                # post-step target — the second wins, which is correct.
                await _reconcile_push_tenant(tid)
                # Resolve the tenant's site-alias groups ONCE for the whole sweep
                # (was re-read + rebuilt inside _alert_firing per quota).
                alias_groups = _alias_groups_from_csc(csc)
                all_q = [normalize_quota(r) for r in (csc.get("sim_quotas") or [])]
                adaptive = [q for q in all_q if q.get("enabled") and _adaptive_is_on(q)]
                # DIAG: does the controller even reach _alert_firing for this tenant?
                # total_quotas>0 but adaptive=0 = quotas aren't adaptive (min==max /
                # disabled) → no firing eval → an "underfilled" row is a fixed-count
                # pool-fill issue, not a firing issue.
                logger.info("adaptive-controller diag [%s]: total_quotas=%d adaptive=%d %s",
                            tid, len(all_q), len(adaptive),
                            [f"{q.get('alert_id')}@{q.get('site')} min={q.get('min')} "
                             f"max={q.get('max')} learn={q.get('learning')}" for q in adaptive])
                if not adaptive:
                    continue
                state = await store.get_adaptive_state(tid)
                # applied_op per alert = max(own learning-ON stable learned_op, global op)
                applied_op: dict = {}
                for q in adaptive:
                    if not q.get("learning"):
                        continue
                    st = state.get(_adaptive_key(q)) or {}
                    if st.get("phase") == "stable" and st.get("learned_op") is not None:
                        ak = _alert_key(q)
                        val = int(st["learned_op"])
                        if ak not in applied_op or val > applied_op[ak]:
                            applied_op[ak] = val
                for ak, gv in (global_lv or {}).items():
                    if not isinstance(gv, dict):
                        continue
                    gop = gv.get("op")
                    if gop is None:
                        continue
                    try:
                        gval = int(gop)
                    except (TypeError, ValueError):
                        continue
                    if ak not in applied_op or gval > applied_op[ak]:
                        applied_op[ak] = gval
                changed = False
                live = set()
                # Known-good capture: the learned simulation.conf knobs live in
                # the knob-learner state (same _adaptive_key), and the per-alert
                # known-good snapshot + the global pending-approval queue are read
                # once per sweep and written back if they change.
                knob_state = await store.get_knob_learn_state(tid)
                known_good = await store.get_known_good(tid)
                pending = await store.get_global_learned_pending()
                kg_changed = False
                pending_changed = False
                for q in adaptive:
                    k = _adaptive_key(q); live.add(k)
                    firing = await _alert_firing(tid, q, alias_groups)
                    before = dict(state.get(k) or {})
                    after = _adaptive_step(before, q, firing, now,
                                            applied_op.get(_alert_key(q)))
                    if after != before:
                        state[k] = after; changed = True
                    # Record the known-good when a learning-ON quota is stable —
                    # count + the knobs it took + how long. Per ALERT (shared
                    # across sites); the higher learned count wins. Only when the
                    # snapshot actually changes, and only propose to the global
                    # pending queue when it differs from the approved global value
                    # (admin still has to approve before it seeds every tenant).
                    if (q.get("learning") and after.get("phase") == "stable"
                            and after.get("learned_op") is not None):
                        _knobs = (knob_state.get(k) or {}).get("values") or {}
                        kg = sim_quota.known_good_from_state(q, after, _knobs)
                        if kg:
                            ak = _alert_key(q)
                            prev = known_good.get(ak) or {}
                            if (int(kg["count"]) != int(prev.get("count", 0))
                                    or (kg.get("knobs") or {}) != (prev.get("knobs") or {})):
                                known_good[ak] = kg
                                kg_changed = True
                                _gap = (global_lv or {}).get(ak) or {}
                                if int(_gap.get("op", -1)) != int(kg["count"]):
                                    pending[ak] = {
                                        "count": kg["count"], "floor": after.get("floor"),
                                        "knobs": kg.get("knobs") or {},
                                        "time_to_stable_s": kg.get("time_to_stable_s"),
                                        "source_tenant": tid, "proposed_at": now}
                                    pending_changed = True
                for k in list(state.keys()):
                    if k not in live:
                        state.pop(k, None); changed = True
                if changed:
                    await store.set_adaptive_state(tid, state)
                    await _push_sim_quotas(tid)
                if kg_changed:
                    await store.set_known_good(tid, known_good)
                if pending_changed:
                    await store.set_global_learned_pending(pending)
            except Exception as exc:  # noqa: BLE001
                logger.warning("adaptive controller (%s): %s", tid, exc)

    async def _adaptive_controller_loop() -> None:
        """Periodic adaptive-quota controller sweep. Started from main.py."""
        while True:
            try:
                await _run_adaptive_controller()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a sweep must not kill the loop
                logger.warning("adaptive controller loop: %s", exc)
            await asyncio.sleep(45)

    # Expose the loop so the Hub's startup can schedule it (a running event loop
    # isn't guaranteed at route-registration time).
    try:
        hub._adaptive_controller_loop = _adaptive_controller_loop
    except Exception:  # noqa: BLE001
        pass

    async def _reconcile_push_loop() -> None:
        """Periodic backstop (B): re-push effective sim quotas for any tenant
        whose spoke-side effective set has drifted from the hub's. Decoupled
        from the adaptive controller so it still self-heals a stable-but-stale
        spoke even when the 45s controller's per-tenant try/except skips a
        tenant or the controller loop itself is stalled. 15-min cadence — the
        45s controller also runs a reconcile pass each tick (A); this is the
        safety net, not the primary path. Started from main.py."""
        while True:
            try:
                for tid in _all_tenant_ids():
                    await _reconcile_push_tenant(tid)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a sweep must not kill the loop
                logger.warning("reconcile-push loop: %s", exc)
            await asyncio.sleep(900)

    try:
        hub._reconcile_push_loop = _reconcile_push_loop
    except Exception:  # noqa: BLE001
        pass

    # Expose the per-tenant actuator alongside the loop — gives the Hub a
    # callable seam (and a unit-test hook) without reaching into the closure.
    try:
        hub._reconcile_push_tenant = _reconcile_push_tenant
    except Exception:  # noqa: BLE001
        pass

    # ── config-value learner (knob-floor search over simulation.conf knobs) ──
    # A SECOND control axis, orthogonal to the count controller above. Where the
    # adaptive controller tunes how MANY clients run a sim, this tunes how HARD
    # each one hits — the sim's [simulation] intensity knobs (SIM_KNOBS) — by a
    # coordinate-descent search that ratchets one knob at a time DOWN to the
    # floor that still fires the alert. State lives in a separate store key
    # (knob_learn_state) so the two never clobber each other, and is keyed by the
    # same alert_type:alert_id:site (`_adaptive_key`). Reuses `_alert_firing`.
    # The pure floor-search step lives in sim_quota.knob_step (shared with the cs
    # twin + unit-tested); the sweep below drives it with the live firing signal.

    async def _knob_overrides_for_tenant(tenant_id: str) -> dict:
        """The tenant-wide ``[simulation]`` knob values the learner currently
        wants delivered = per-knob MIN across all this tenant's ``learn_knobs``
        quota states (most conservative floor when several quotas tune the same
        global knob). Empty when nothing is learning."""
        from .sim_quota import normalize_quota, knobs_for_sim
        try:
            csc = await store.get_central_sites_config(tenant_id) or {}
            learn = [q for q in (normalize_quota(r) for r in (csc.get("sim_quotas") or []))
                     if q.get("enabled") and q.get("learn_knobs") and knobs_for_sim(q.get("sim_id"))]
            if not learn:
                return {}
            state = await store.get_knob_learn_state(tenant_id)
        except Exception:  # noqa: BLE001
            return {}
        out: dict = {}
        for q in learn:
            vals = (state.get(_adaptive_key(q)) or {}).get("values") or {}
            for kk, vv in vals.items():
                try:
                    iv = int(vv)
                except (TypeError, ValueError):
                    continue
                out[kk] = iv if kk not in out else min(out[kk], iv)
        return out

    async def _run_knob_learner() -> None:
        """One learner pass over every tenant's ``learn_knobs`` quotas — advance
        the floor search and re-push the delivered knob values when they move."""
        import time as _t
        from .sim_quota import normalize_quota, knobs_for_sim, knob_step
        now = _t.time()
        for tid in _all_tenant_ids():
            try:
                csc = await store.get_central_sites_config(tid) or {}
                learn = [q for q in (normalize_quota(r) for r in (csc.get("sim_quotas") or []))
                         if q.get("enabled") and q.get("learn_knobs") and knobs_for_sim(q.get("sim_id"))]
                if not learn:
                    continue
                # Site-alias groups resolved ONCE for the sweep (see controller).
                alias_groups = _alias_groups_from_csc(csc)
                state = await store.get_knob_learn_state(tid)
                changed = False
                live = set()
                for q in learn:
                    k = _adaptive_key(q); live.add(k)
                    firing = await _alert_firing(tid, q, alias_groups)
                    before = dict(state.get(k) or {})
                    after = knob_step(before, knobs_for_sim(q.get("sim_id")), firing, now)
                    if after != before:
                        state[k] = after; changed = True
                for k in list(state.keys()):
                    if k not in live:
                        state.pop(k, None); changed = True
                if changed:
                    await store.set_knob_learn_state(tid, state)
                    await _push_sim_quotas(tid)
            except Exception as exc:  # noqa: BLE001
                logger.warning("knob learner (%s): %s", tid, exc)

    async def _knob_learner_loop() -> None:
        """Periodic knob-floor learner sweep. Started from main.py."""
        while True:
            try:
                await _run_knob_learner()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a sweep must not kill the loop
                logger.warning("knob learner loop: %s", exc)
            await asyncio.sleep(45)

    try:
        hub._knob_learner_loop = _knob_learner_loop
    except Exception:  # noqa: BLE001
        pass

    async def _sim_shareable(tenant_id: str = "") -> dict:
        """The GLOBAL (all-tenant) per-simulation shareable/stackable overrides
        (authoritative — a sim set non-shareable can NEVER be stacked by any
        tenant's quota engine). Edited on Setup → Simulations → Sim Quotas and
        stored under the store's ``__global__`` key. The ``tenant_id`` arg is
        accepted (call sites pass it) but ignored — sharing is platform-wide."""
        try:
            return await store.get_sim_shareable_global()
        except Exception:  # noqa: BLE001
            return {}

    async def _record_alert_insight_history(browse: dict) -> None:
        """Upsert the alerts/insights from a browse result into the shared history.
        Best-effort: swallows everything so recording can never break a browse."""
        try:
            if not isinstance(browse, dict):
                return
            items: list = []
            for a in (browse.get("alerts") or []):
                ident = str((a.get("name") or a.get("category") or "")).strip()
                if ident:
                    items.append({"type": "alert", "id": ident, "name": a.get("name") or ident,
                                  "site": a.get("site") or "",
                                  # Rich browse objects carry these; the poller path
                                  # doesn't. Recorded to enrich the global catalog.
                                  "category": a.get("category") or "",
                                  "severity": a.get("severity") or "",
                                  "device_type": a.get("device_type") or a.get("deviceType") or ""})
            for i in (browse.get("insights") or []):
                ident = str((i.get("name") or i.get("category") or "")).strip()
                if ident:
                    items.append({"type": "insight", "id": ident, "name": i.get("name") or ident,
                                  "site": i.get("site") or "",
                                  "category": i.get("category") or "",
                                  "severity": i.get("severity") or "",
                                  "device_type": i.get("device_type") or i.get("deviceType") or ""})
            if items:
                await store.record_alert_insight_seen(items)
        except Exception:  # noqa: BLE001
            pass

    async def _alert_insight_catalog() -> tuple[list, list]:
        """The shared alert/insight history split into (alerts, insights), each a
        list of {id, name, site} sorted by display name — the option source for
        every Sim-Quota "Alert / Insight ID" picker (tenant + system defaults)."""
        try:
            hist = await store.get_alert_insight_history()
        except Exception:  # noqa: BLE001
            hist = []
        def _sort(rows):
            return sorted(
                [{"id": h.get("id"), "name": h.get("name") or h.get("id"), "site": h.get("site") or ""}
                 for h in rows if h.get("id")],
                key=lambda r: str(r.get("name") or r.get("id") or "").lower(),
            )
        alerts = _sort([h for h in hist if h.get("type") == "alert"])
        insights = _sort([h for h in hist if h.get("type") == "insight"])
        return alerts, insights

    async def _sim_na(tenant_id: str = "") -> dict:
        """The GLOBAL per-simulation N/A (does-not-apply) UI hide map — used only
        to hide sims from the Setup → Simulations Sharing tile. Stored under the
        store's ``__global__`` key. ``tenant_id`` accepted but ignored."""
        try:
            return await store.get_sim_na_global()
        except Exception:  # noqa: BLE001
            return {}

    async def _pool_config(tenant_id: str) -> dict:
        """The tenant's pool / SSID config, pulled from central_sites_config and
        flattened into the CS_CONFIG_UPDATE keys the spoke applies (see
        docs/simulation-pool-and-quota-design.md). Missing keys are omitted so a
        tenant that hasn't configured pools pushes nothing extra."""
        try:
            csc = await store.get_central_sites_config(tenant_id) or {}
        except Exception:  # noqa: BLE001
            csc = {}
        out: dict = {}
        if isinstance(csc.get("site_source"), str):
            out["site_source"] = csc["site_source"]
        if isinstance(csc.get("randomizable_sims"), list):
            out["randomizable_sims"] = csc["randomizable_sims"]
        if isinstance(csc.get("random_pool"), dict):
            out["random_pool"] = csc["random_pool"]
        if isinstance(csc.get("ssid_matrix"), list):
            out["ssid_matrix"] = csc["ssid_matrix"]
        if isinstance(csc.get("ssid_placement"), dict):
            out["ssid_placement"] = csc["ssid_placement"]
        if isinstance(csc.get("ssid_weights"), list):
            out["ssid_weights"] = csc["ssid_weights"]
        # Ambient distribution (HUB mode): ambient_pct is the LEVEL (% of fleet
        # ambient-active); ambient_control=on adds relative per-sim weights
        # (ambient_weights) that split the active clients and per-site load weights
        # (ambient_site_weights) that scale a site's level.
        if csc.get("ambient_pct") is not None:
            try:
                out["ambient_pct"] = max(0, min(100, int(csc["ambient_pct"])))
            except (TypeError, ValueError):
                pass
        if csc.get("ambient_control") is not None:
            out["ambient_control"] = bool(csc.get("ambient_control"))
        if isinstance(csc.get("ambient_weights"), dict):
            out["ambient_weights"] = csc["ambient_weights"]
        # Per-site load weight (relative, default 1) — folded into the served
        # ambient level on the spoke so a site weighted 3 gets 3x the load of one
        # weighted 1.
        if isinstance(csc.get("ambient_site_weights"), dict):
            out["ambient_site_weights"] = csc["ambient_site_weights"]
        # ignored_hostnames lives in the Hub Config card (tenant hub_config), but
        # the spoke's _apply_hub_config drops that copy — ride it on the pool push
        # (always applied) so the quota engine's exclude list reaches the spoke
        # regardless of the hub-source-of-truth toggle.
        try:
            hc = await store.get_hub_config(tenant_id) or {}
            ih = hc.get("ignored_hostnames")
            if isinstance(ih, list) and ih:
                out["ignored_hostnames"] = ih
        except Exception:  # noqa: BLE001
            pass
        # Dongle-quarantine exclusion sims: a per-tenant csc ``qt_exclude_sims``
        # overrides the platform-wide default; the spoke's SimQuotaEngine reads
        # the resolved set from its central_sites_config (the engine defaults to
        # the locked set when neither is set, so this is purely an admin override).
        try:
            t_qt = csc.get("qt_exclude_sims")
            if isinstance(t_qt, list):
                out["qt_exclude_sims"] = [str(s) for s in t_qt if str(s).strip()]
            else:
                g_qt = await store.get_qt_exclude_sims()
                if g_qt:
                    out["qt_exclude_sims"] = g_qt
        except Exception:  # noqa: BLE001
            pass
        return out

    async def _push_sim_quotas(tenant_id: str) -> int:
        """Push the tenant's effective sim quotas + per-sim shareable overrides +
        pool/SSID config to its cs spoke(s) as a CS_CONFIG_UPDATE the
        SimQuotaEngine reconciles against."""
        return await _push_config(tenant_id, {
            "effective_sim_quotas": await _effective_sim_quotas(tenant_id),
            "sim_shareable": await _sim_shareable(tenant_id),
            "sim_knob_overrides": await _knob_overrides_for_tenant(tenant_id),
            **await _pool_config(tenant_id),
        })

    async def _push_sim_quotas_all_tenants() -> int:
        """Re-push effective sim quotas to every tenant after a global-defaults
        change (Setup → Simulations → Sim Quotas). Fanned out concurrently across
        tenants (per-spoke push inside is already concurrent); returns the total
        pushed. Any error propagates as before (gather re-raises)."""
        counts = await asyncio.gather(
            *[_push_sim_quotas(tid) for tid in _all_tenant_ids()]
        )
        return sum(counts)

    # Expose the per-tenant push as a callable seam on the Hub (on-demand
    # re-push + a unit-test hook for the per-site apportionment in _push_config).
    try:
        hub._push_sim_quotas = _push_sim_quotas
    except Exception:  # noqa: BLE001
        pass

    # ── aggregate reads (literal "aggregate" first segment) ────────────────
    @app.get("/sim/api/aggregate/dashboard")
    async def get_dashboard(tenant_id: str = Depends(get_tenant_id)):
        return await service.get_dashboard_data(tenant_id)

    @app.get("/sim/api/aggregate/clients")
    async def get_clients(tenant_id: str = Depends(get_tenant_id)):
        return await service.get_clients_data(tenant_id)

    @app.get("/sim/api/aggregate/simulations")
    async def get_simulations(tenant_id: str = Depends(get_tenant_id)):
        return await service.get_simulations_data(tenant_id)

    @app.get("/sim/api/aggregate/proxmox")
    async def get_proxmox(request: Request, tenant_id: str = Depends(get_tenant_id)):
        data = await service.get_proxmox_data(tenant_id)
        # Apply the effective USB certified/ignored sets (global + this tenant)
        # server-side so the tenant UI reflects admin/tenant decisions even
        # before the spoke re-filters its own telemetry: ignored devices are
        # hidden, certified devices no longer show as "to be certified", and each
        # certified device is tagged with its approval scope (global/local).
        ign = set(await _effective_usb_ignored(tenant_id))
        g_cert = {str(d.get("vidpid", "")).strip().lower(): str(d.get("type") or "wireless")
                  for d in await store.get_global_usb_vidpids() if d.get("vidpid")}
        hc = await store.get_hub_config(tenant_id)
        t_cert = {e["vidpid"]: str(e.get("type") or "wireless") for e in
                  _normalize_usb_vidpids((hc.get("hub_config") or {}).get("usb_vidpids"))}
        if ign or g_cert or t_cert:
            data["hosts"] = [_reclassify_host_usb(h, ign, g_cert, t_cert)
                             for h in (data.get("hosts") or [])]
        # Admin-only sidecar: where USB data lives in each cached cs spoke
        # payload, so a missing USB count can be diagnosed from the VM Server
        # page itself (no separate request). Keys + lengths only, never values.
        try:
            sess = session_user_fn(request)
            if is_admin_fn(sess):
                data["_usb_debug"] = [
                    {"spoke_id": sid, "online": hub._primary_key(sid) in getattr(hub, "active_connections", {}),
                     **_usb_structure_dump(raw)}
                    for sid, raw in service._spokes_for_tenant(tenant_id)
                ]
        except Exception:
            pass
        return data

    @app.get("/sim/api/aggregate/proxmox-debug")
    async def get_proxmox_debug(request: Request, tenant_id: str = Depends(get_tenant_id)):
        """Admin-only raw-structure dump of the cached CS_TELEMETRY payloads for
        the tenant's cs spokes, to localize a missing USB count in the VM Server
        Overview / USB tab. Returns keys + USB field locations/lengths only —
        NEVER values (a CS payload may carry Proxmox tokens in other frames)."""
        _require_admin(request)
        return {
            "tenant_id": tenant_id,
            "spokes": [
                {"spoke_id": sid,
                 "online": hub._primary_key(sid) in getattr(hub, "active_connections", {}),
                 **_usb_structure_dump(raw)}
                for sid, raw in service._spokes_for_tenant(tenant_id)
            ],
        }

    @app.get("/sim/api/aggregate/central")
    async def get_central(tenant_id: str = Depends(get_tenant_id)):
        return await service.get_central_data(tenant_id)

    @app.get("/sim/api/aggregate/central-health")
    async def get_central_health(request: Request, tenant_id: str = Depends(get_tenant_id)):
        """30-day per-check health history (green/yellow/red). Default: DAILY
        summaries for every check ({site:{check_id:[{d,o,w,e,n}]}}) — the strip.
        With ?site=&check= → that check's raw HOURLY buckets ([{h,o,w,e,n}]) for
        the on-hover breakdown. Merges the centralized hub-poller history with any
        DISTRIBUTED spoke's relayed daily summary (central_status.health); hourly for
        a distributed check is fetched on demand from the owning spoke (CS_GET_HEALTH)."""
        poller = getattr(hub, "central_hub_poller", None)
        health = getattr(poller, "_health", None)
        site = request.query_params.get("site")
        check = request.query_params.get("check")
        if site and check:
            hourly = health.hourly(tenant_id, site, check) if health else []
            if not hourly:  # distributed → ask the owning spoke
                try:
                    r = await _cs_forward(tenant_id, "CS_GET_HEALTH",
                                          {"site": site, "check": check}, timeout=10.0)
                    hourly = (r or {}).get("hourly") or []
                except Exception:  # noqa: BLE001 — no spoke / offline → empty
                    pass
            return {"hourly": hourly}
        from .central_hub_poller import success_from_daily
        daily = dict(health.summary(tenant_id)) if health else {}
        success = dict(health.success_stats(tenant_id)) if health else {}
        # Merge relayed spoke health (distributed-mode tenants).
        for _sid, data in service._spokes_for_tenant(tenant_id):
            sp = ((data or {}).get("central") or {}).get("health") or {}
            for site_name, checks in sp.items():
                daily.setdefault(site_name, {}).update(checks)
        # Success-% per check (ok / graded over 24h·7d·4w). Hub-poller history is
        # hourly-accurate; distributed checks (only in `daily`) fall back to their
        # daily buckets so every rendered check gets a score.
        for site_name, checks in daily.items():
            for cid, dlist in (checks or {}).items():
                if success.get(site_name, {}).get(cid) is None:
                    success.setdefault(site_name, {})[cid] = success_from_daily(dlist)
        return {"daily": daily, "success": success}

    @app.get("/sim/api/aggregate/central-status")
    async def get_central_status(tenant_id: str = Depends(get_tenant_id)):
        data = await service.get_central_status_data(tenant_id)
        # Merge hub-owned central config (mode + cluster creds) from the store so
        # the Central tab's form populates.
        cc = await store.get_central_config(tenant_id)
        if isinstance(cc, dict):
            data["hub_central_config"] = {k: v for k, v in cc.items() if k != "mode"}
            if cc.get("mode"):
                data["mode"] = cc["mode"]
        return data

    @app.get("/sim/api/aggregate/central-browse")
    async def get_central_browse(tenant_id: str = Depends(get_tenant_id)):
        """FULL Central inventory (all sites / alerts / insights / clients),
        on-demand, for the Central → Sites/Alerts/Clients tabs — independent of
        site_mappings (which only scope the background Checks poller). Forwards
        CS_CENTRAL_BROWSE to the tenant's cs spoke (which holds the full Aruba
        client + caches). Returns an empty set + warning when the spoke is not
        connected (a centralized-only tenant has no spoke to browse from yet).

        Mode-aware, matching test-central / available-checks: in **centralized**
        processing mode the HUB holds the creds and runs browse_all itself (the
        spoke is a telemetry relay and has no Aruba client); in **distributed**
        mode it forwards CS_CENTRAL_BROWSE to the spoke. Without the centralized
        branch, a centralized tenant's creds validated (Test Central) but the
        Sites/Alerts/Clients tabs asked a credential-less spoke and got
        'Central not configured'."""
        modes = await store.get_processing_modes(tenant_id)
        if store.central_api_is_centralized(modes):  # unset defaults to centralized
            cc = await store.get_central_config(tenant_id)
            result = await browse_all_from_config(cc or {})
        else:
            try:
                result = await _cs_forward(tenant_id, "CS_CENTRAL_BROWSE", {}, timeout=30.0)
            except HTTPException as exc:
                return {"status": "SUCCESS", "sites": [], "alerts": [], "insights": [],
                        "clients": [], "devices_by_site": {}, "clients_by_site": {},
                        "warning": f"Central browse unavailable: {exc.detail}"}
        # Record every alert/insight name we just saw into the SHARED (all-tenant +
        # system-defaults) history so the Sim-Quota ID picker can offer it later,
        # even after it clears. Best-effort — never let it break the browse.
        await _record_alert_insight_history(result)
        return result

    @app.get("/sim/api/aggregate/api-server")
    async def get_api_server(tenant_id: str = Depends(get_tenant_id)):
        return await service.get_api_server_data(tenant_id)

    # ── aggregate actions ──────────────────────────────────────────────────
    @app.post("/sim/api/aggregate/central")
    async def save_central(request: Request, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        mode = body.get("mode")
        hub_cc = body.get("hub_central_config") or {}
        cfg = dict(hub_cc)
        if mode:
            cfg["mode"] = mode
        # SSRF guard: ``cluster_url`` is the host the hub POSTs the Aruba
        # ``client_id``/``client_secret`` to (classic mode) and GETs monitoring
        # data from. This route is reachable by any cs-righted tenant user (NOT
        # just admins), so without a guard a tenant user can point the hub's
        # outbound HTTP at an internal host / cloud-metadata endpoint and have
        # the hub exfiltrate the stored Central creds there. Confine it to a
        # public HTTPS host, and DNS-resolve it to block rebinding to an
        # internal IP after the save. ``new_central`` mode uses a fixed HPE
        # token URL and ignores cluster_url, so only validate when present.
        cluster_url = (cfg.get("cluster_url") or "").strip()
        if cluster_url:
            if not safe_external_url(cluster_url, require_https=True):
                raise HTTPException(
                    status_code=400,
                    detail="cluster_url must be a public https:// URL "
                           "(internal hosts, IP literals, and plain http are blocked).",
                )
            host = urlsplit(cluster_url).hostname
            if host and not await asyncio.to_thread(host_resolves_external, host):
                raise HTTPException(
                    status_code=400,
                    detail="cluster_url resolves to an internal address — "
                           "DNS rebinding to a private/loopback host is blocked.",
                )
        # Central poll interval (seconds). Optional; coerce + floor at 60s here so
        # a bad value can't be stored (the poller also floors defensively).
        if "poll_interval_s" in cfg:
            try:
                cfg["poll_interval_s"] = max(60, int(cfg["poll_interval_s"] or 300))
            except (TypeError, ValueError):
                cfg["poll_interval_s"] = 300
        # Client-count CHECK thresholds (Dashboard Checks colouring, Setup →
        # Central API). Coerce + clamp so a bad value can't be stored; the pollers
        # (_cc_thresholds) also clamp defensively on read. error can't sit below
        # warn (red before amber). die_off_pct=0 disables the sustained-die-off rule.
        if isinstance(cfg.get("cc_thresholds"), dict):
            _t = cfg["cc_thresholds"]

            def _cnum(val, dflt, lo, hi):
                try:
                    return max(lo, min(hi, float(val)))
                except (TypeError, ValueError):
                    return dflt

            _warn = _cnum(_t.get("warn_pct"), 20.0, 0.0, 100.0)
            _err = _cnum(_t.get("error_pct"), 50.0, 0.0, 100.0)
            if _err < _warn:
                _err = _warn
            cfg["cc_thresholds"] = {
                "warn_pct": _warn,
                "error_pct": _err,
                "die_off_pct": _cnum(_t.get("die_off_pct"), 20.0, 0.0, 100.0),
                "min_peak": int(_cnum(_t.get("min_peak"), 5, 1, 1_000_000)),
            }
        await store.set_central_config(tenant_id, cfg)
        # Push ``cfg`` (NOT ``hub_cc``): cfg carries ``mode`` on top of the
        # cluster creds, and the spoke's poller (_build_config) needs ``mode`` to
        # pick classic vs new_central. Pushing hub_cc dropped mode, so the spoke
        # defaulted to classic regardless of the operator's choice.
        pushed = await _push_config(tenant_id, {"central_config": cfg})
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.post("/sim/api/aggregate/config-push")
    async def config_push(request: Request, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        cfg = body.get("config") if isinstance(body, dict) else body
        pushed = await _push_config(tenant_id, {"config": cfg or {}})
        return {"pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    # ── spokes / checks (literal first segment) ────────────────────────────
    @app.get("/sim/api/spokes/diag")
    async def get_spokes_diag(tenant_id: str = Depends(get_tenant_id)):
        """Live, cache-derived diag per spoke for the tenant (replaces the former
        store.get_spokes_diag call that AttributeErrored)."""
        out = []
        for sid, data in (getattr(hub, "simulations_cache", {}) or {}).items():
            try:
                if hub.state.get_spoke_tenant(sid) != tenant_id:
                    continue
            except Exception:
                continue
            out.append({
                "spoke_id": sid,
                "spoke_name": (data or {}).get("spoke_name") or sid,
                "online": hub._primary_key(sid) in getattr(hub, "active_connections", {}),
                "last_seen": (data or {}).get("timestamp"),
                "telemetry_keys": sorted((data or {}).keys()),
            })
        return {"tenant_id": tenant_id, "spokes": out}

    # Spoke-id prefix → module-type fallback (mirrors api.py:509-513) so an
    # offline spoke with no persisted module_type still shows a readable type.
    _TYPE_PREFIX = {
        "pxmx": "hypervisor", "opn": "firewall", "cppm": "nac",
        "cs": "simulation", "netbox": "ipam", "ldap": "directory",
        "dns": "dns", "dhcp": "dhcp", "nw": "nw",
    }

    def _spoke_type(sid: str, live_types: dict, meta: dict) -> str:
        t = live_types.get(sid) or (meta or {}).get("module_type")
        if t:
            return t
        for pfx, typ in _TYPE_PREFIX.items():
            if sid.startswith(pfx):
                return typ
        return ""

    # Module types that count as a "Simulation" spoke for this module's
    # Spoke Management screen: the live registered "Client-Sim" (webui-spoke
    # relay) and "simulation" (legacy lm-spoke), plus the bare "cs" label.
    _SIM_TYPES = {"Client-Sim", "simulation", "cs"}

    def _is_sim_spoke(sid: str, live_types: dict, meta: dict) -> bool:
        t = _spoke_type(sid, live_types, meta)
        return bool(t) and t in _SIM_TYPES

    @app.get("/sim/api/spokes")
    async def get_spokes_list(request: Request, tenant_id: str = Depends(get_tenant_id)):
        """Spoke Management list: every known spoke with its module type,
        connection/approval state, tenant binding, and (for cs spokes) VM
        count. Tenant-scoped: non-admins see only their own tenant's approved
        spokes; admins see all spokes (approved + pending, bound + unbound) so
        they can assign the unbound ones. VM count is read from the
        simulations_cache (the cached CS_TELEMETRY relay payload)."""
        sess = session_user_fn(request)
        admin = bool(sess and is_admin_fn(sess))
        user_tenants = _user_tenants(sess)
        meta = hub.state.system_state.get("module_metadata", {}) or {}
        approved = hub.state.get_approved_modules()
        live_types = getattr(hub, "spoke_module_types", {}) or {}
        conns = getattr(hub, "active_connections", {}) or {}
        cache = getattr(hub, "simulations_cache", {}) or {}
        out = []
        for sid, m in meta.items():
            m = m or {}
            # This is the Simulations module's Spoke Management screen — only
            # Simulation spokes belong here. Other module types (pxmx/netbox/
            # opn/…) are managed from their own modules' screens.
            if not _is_sim_spoke(sid, live_types, m):
                continue
            t_id = m.get("tenant_id")
            if not admin:
                # Non-admin: only their own tenant's approved spokes.
                if t_id not in user_tenants or not approved.get(hub._primary_key(sid), False):
                    continue
            vm_count = None
            cdata = cache.get(sid) or {}
            hosts = cdata.get("proxmox_hosts") or []
            if hosts:
                vm_count = sum(int((h.get("proxmox") or {}).get("vm_count") or 0)
                               for h in hosts)
            elif isinstance(cdata.get("proxmox"), dict) and \
                    cdata["proxmox"].get("vm_count") is not None:
                vm_count = cdata["proxmox"].get("vm_count")
            if vm_count is None:
                # No Proxmox HOST inventory relayed (e.g. no pxmx agent reporting
                # VMs), but a Client-Sim spoke's sim clients each run in a VM — so
                # fall back to the registered sim-client count instead of blanking
                # the column when clients clearly exist.
                clients = cdata.get("clients")
                if isinstance(clients, list):
                    vm_count = len(clients)
            out.append({
                "spoke_id": sid,
                "display_name": m.get("display_name") or sid,
                "module_type": _spoke_type(sid, live_types, m),
                "connected": hub._primary_key(sid) in conns,
                "approved": bool(approved.get(hub._primary_key(sid), False)),
                "tenant_id": t_id,
                "vm_count": vm_count,
            })
        out.sort(key=lambda s: s["spoke_id"])
        return {"tenant_id": tenant_id, "spokes": out}

    @app.get("/sim/api/checks")
    async def get_checks():
        return []

    # ── tenant-scoped config (literal "tenant" first segment) ──────────────
    @app.get("/sim/api/tenant/{tenant}/hypervisors-config")
    async def get_hypervisors_config(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Setup → Hypervisors config (backup/snapshot/per-host/confirm)."""
        return {"hypervisors_config": await store.get_hypervisors_config(tenant_id)}

    @app.put("/sim/api/tenant/{tenant}/hypervisors-config")
    async def set_hypervisors_config(request: Request, tenant: str,
                                     tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        cfg = body.get("hypervisors_config") if isinstance(body, dict) else None
        if not isinstance(cfg, dict):
            raise HTTPException(status_code=400, detail="missing hypervisors_config")
        await store.set_hypervisors_config(tenant_id, cfg)
        return {"saved": True}

    @app.get("/sim/api/tenant/{tenant}/hypervisor-storages")
    async def list_hypervisor_storages(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Live backup-storage list per host: fan PXMX_LIST_STORAGE out to every
        hypervisor/simulation spoke so the Setup dropdown offers real Proxmox
        storages (content=backup). Best-effort — a spoke that errors/omits it
        just contributes nothing. Returns {hosts:[{hostname, storages:[...]}]}."""
        out: List[Dict[str, Any]] = []
        seen_hosts = set()
        for sid in (hub.get_all_spokes_by_type("hypervisor")
                    + hub.get_all_spokes_by_type("simulation")):
            if sid in seen_hosts:
                continue
            seen_hosts.add(sid)
            try:
                r = await hub.request_response(sid, "PXMX_LIST_STORAGE", {}, timeout=15.0)
                data = r.get("payload", {}).get("data", {}) if isinstance(r, dict) else {}
                for h in (data.get("hosts") or []):
                    if isinstance(h, dict) and h.get("hostname"):
                        # Forward storage_types (name→type, e.g. pbs/dir/nfs/zfs)
                        # so the WebUI can filter non-file storages (PBS excluded
                        # from "Back up to Hub": vzdump-to-PBS isn't a streamable
                        # .vma.zst). Older agents without storage_types → {} .
                        out.append({"hostname": h["hostname"],
                                    "storages": h.get("storages") or [],
                                    "storage_types": h.get("storage_types") or {}})
            except Exception as e:  # noqa: BLE001
                logger.debug("PXMX_LIST_STORAGE %s failed: %s", sid, e)
        return {"hosts": out}

    @app.get("/sim/api/tenant/{tenant}/hub-config")
    async def get_hub_config(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        return await store.get_hub_config(tenant_id)

    @app.put("/sim/api/tenant/{tenant}/hub-config")
    async def set_hub_config(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        enabled = bool(body.get("hub_config_enabled", False))
        hc = body.get("hub_config") or {}
        # Normalize Setup/Proxmox list fields: the WebUI sends comma/space-
        # delimited text for usb_vidpids / usb_ignored_vidpids / t1/t3_pci_vidpids
        # / ignored_hostnames; downstream expects lists. Preserve usb_vidpids
        # type/label from the currently-stored entry (fetch it here).
        try:
            stored = await store.get_hub_config(tenant_id)
        except Exception:
            stored = None
        stored_hc = (stored and stored.get("hub_config")) or {}
        hc = normalize_hub_config_lists(hc, stored_hc)
        await store.set_hub_config(tenant_id, enabled, hc)
        pushed = await _push_config(tenant_id, hc if enabled else {}) if enabled else 0
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.post("/sim/api/tenant/{tenant}/hub-config/reset")
    async def reset_hub_config(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Reset the tenant's Setup/Proxmox knobs to factory defaults (the
        ``_DEFAULT_HUB_CONFIG`` the cs speak ``_DEFAULTS`` mirror), preserving
        certified/ignored USB vidpids + ignored hostnames. Tenant-scoped — only
        this tenant's hub_config is touched. Pushes the reset config to the
        tenant's spoke when hub-as-source-of-truth is enabled so the spoke's
        settings clear to defaults too (the payload carries an explicit value
        for every owned knob so the spoke's set-present-only apply clears old
        user values)."""
        result = await store.reset_hub_config(tenant_id)
        pushed = await _push_config(tenant_id, result["hub_config"]) \
            if result["hub_config_enabled"] else 0
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False)),
                "hub_config_enabled": result["hub_config_enabled"],
                "hub_config": result["hub_config"]}

    @app.get("/sim/api/tenant/{tenant}/onboarding-psk")
    async def get_psks(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        _require_tenant_admin_or_admin(request)
        return {"psks": await store.get_psks(tenant_id)}

    @app.post("/sim/api/tenant/{tenant}/onboarding-psk")
    async def gen_psk(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        _require_tenant_admin_or_admin(request)
        import secrets as _secrets
        psk = _secrets.token_urlsafe(24)
        await store.add_psk(tenant_id, psk)
        pushed = await _push_config(tenant_id, {"relay_onboarding_psk": psk})
        return {"psk": psk, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.delete("/sim/api/tenant/{tenant}/onboarding-psk")
    async def revoke_psk(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        _require_tenant_admin_or_admin(request)
        body = await request.json()
        psk = body.get("psk") if isinstance(body, dict) else None
        removed = await store.remove_psk(tenant_id, psk) if psk else False
        # Rotate the spoke's PSK away from the revoked value.
        pushed = await _push_config(tenant_id, {"relay_onboarding_psk": ""}) if removed else 0
        return {"removed": removed, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.post("/sim/api/tenant/{tenant}/spokes/{spoke_id}/claim")
    async def claim_spoke(request: Request, tenant: str, spoke_id: str,
                         tenant_id: str = Depends(get_tenant_id)):
        """Claim an unapproved/unbound spoke for the caller's tenant by
        presenting the tenant's onboarding PSK — the PSK self-provisioning
        fallback for a spoke that already connected WITHOUT a PSK (so it is
        pending admin approval). Tenant-scoped: a non-admin may only claim for
        a tenant they belong to (enforced by get_tenant_id's access check);
        admins may claim for any tenant. The PSK is validated against the same
        onboarding_psks store the /onboarding-psk routes manage, then the spoke
        is approved + tenant-bound and (if connected) pushed its session key +
        APPROVED + config so it begins operating immediately."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        psk = str((body or {}).get("onboarding_psk") or "").strip()
        if not psk:
            raise HTTPException(status_code=400, detail="onboarding_psk required")
        if not spoke_id:
            raise HTTPException(status_code=400, detail="spoke_id required")
        # Only a Simulation spoke may be claimed from this (Simulations) screen.
        # A non-sim spoke connecting with this tenant's PSK would otherwise get
        # bound as if it were a Client-Sim spoke.
        live_types = getattr(hub, "spoke_module_types", {}) or {}
        spoke_meta = (hub.state.system_state.get("module_metadata", {}) or {}).get(spoke_id) or {}
        if not _is_sim_spoke(spoke_id, live_types, spoke_meta):
            raise HTTPException(status_code=409, detail="Only a Simulation spoke can be claimed here.")
        try:
            psks = await store.get_psks(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("claim_spoke: PSK read failed for tenant %s: %s", tenant_id, exc)
            raise HTTPException(status_code=500, detail="PSK store unavailable")
        if not psks or not any(hmac.compare_digest(str(p), psk) for p in psks):
            raise HTTPException(status_code=403, detail="Invalid onboarding PSK")
        try:
            await hub.approve_and_bind_spoke(spoke_id, tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("claim_spoke: approve_and_bind failed for %s: %s", spoke_id, exc)
            raise HTTPException(status_code=500, detail=str(exc))
        logger.info("Spoke %s claimed for tenant %s via PSK.", spoke_id, tenant_id)
        return {"status": "success", "spoke_id": spoke_id, "tenant_id": tenant_id}

    # ── spoke management parity (Wave 6) — admin-only {tenant}-first routes ──
    # label / assigned-site / approve / config-patch / delete / config-diag.
    @app.patch("/sim/api/{tenant}/spokes/{spoke_id}/label")
    async def cs_spoke_set_label(request: Request, tenant: str, spoke_id: str,
                                  tenant_id: str = Depends(get_tenant_id)):
        _require_admin(request)
        body = await request.json()
        label = (body or {}).get("label")
        if not label or not str(label).strip():
            raise HTTPException(status_code=400, detail="label required")
        hub.state.set_module_name(spoke_id, str(label).strip())
        hub.state._mark_dirty()
        return {"saved": True, "spoke_id": spoke_id, "label": str(label).strip()}

    @app.patch("/sim/api/{tenant}/spokes/{spoke_id}/assigned-site")
    async def cs_spoke_set_assigned_site(request: Request, tenant: str, spoke_id: str,
                                          tenant_id: str = Depends(get_tenant_id)):
        _require_admin(request)
        body = await request.json()
        site = (body or {}).get("site", "")
        hub.state.update_module_metadata(spoke_id, {"assigned_site": site or ""})
        hub.state._mark_dirty()
        return {"saved": True, "spoke_id": spoke_id, "assigned_site": site or ""}

    @app.post("/sim/api/{tenant}/spokes/{spoke_id}/approve")
    async def cs_spoke_approve(request: Request, tenant: str, spoke_id: str,
                                tenant_id: str = Depends(get_tenant_id)):
        _require_admin(request)
        raw = await request.body()
        body = {}
        if raw:
            try:
                import json as _json
                body = _json.loads(raw)
            except Exception:
                body = {}
        action = (body or {}).get("action", "approve")
        approved = action != "unapprove"
        hub.state.register_module(spoke_id, approved=approved)
        hub.approved_modules[hub._primary_key(spoke_id)] = approved
        if (body or {}).get("tenant_id"):
            hub.state.set_spoke_tenant(spoke_id, body["tenant_id"])
        await hub.state.save_state_now()
        return {"saved": True, "spoke_id": spoke_id, "approved": approved}

    @app.patch("/sim/api/{tenant}/spokes/{spoke_id}/config")
    async def cs_spoke_patch_config(request: Request, tenant: str, spoke_id: str,
                                     tenant_id: str = Depends(get_tenant_id)):
        _require_admin(request)
        body = await request.json()
        cfg = (body or {}).get("config") or {}
        if not isinstance(cfg, dict):
            raise HTTPException(status_code=400, detail="config must be an object")
        pushed = await _push_config(tenant_id, cfg)
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.delete("/sim/api/spokes/{spoke_id}")
    async def cs_spoke_delete(request: Request, spoke_id: str,
                              tenant_id: str = Depends(get_tenant_id)):
        _require_admin(request)
        # Close the live WS (if any) then drop registration + metadata + keys.
        ws = hub.active_connections.get(hub._primary_key(spoke_id))
        if ws is not None:
            try:
                await ws.close(code=1008, reason="Removed by admin")
            except Exception as exc:
                logger.warning("cs_spoke_delete: close WS %s failed: %s", spoke_id, exc)
        try:
            hub.state.remove_module(spoke_id)
        except Exception as exc:
            logger.warning("cs_spoke_delete: remove_module %s failed: %s", spoke_id, exc)
        try:
            hub.key_manager.delete_spoke_key(hub._primary_key(spoke_id))
        except Exception as exc:
            logger.warning("cs_spoke_delete: delete_spoke_key %s failed: %s", spoke_id, exc)
        return {"removed": True, "spoke_id": spoke_id}

    @app.get("/sim/api/{tenant}/spokes/{spoke_id}/config-diag")
    async def cs_spoke_config_diag(tenant: str, spoke_id: str,
                                   tenant_id: str = Depends(get_tenant_id)):
        # Desired (store-pushed) vs applied (last relayed telemetry) for a spoke.
        diag = {"spoke_id": spoke_id, "tenant_id": tenant_id}
        try:
            diag["applied_config"] = await service.get_spoke_config(tenant_id, spoke_id)
        except Exception as exc:
            diag["applied_config"] = None
            diag["applied_error"] = str(exc)
        cache = getattr(hub, "simulations_cache", {}) or {}
        entry = cache.get(spoke_id) or {}
        diag["last_seen"] = entry.get("last_seen")
        diag["telemetry_keys"] = sorted(list(entry.keys())) if isinstance(entry, dict) else []
        return diag

    # ── scheduled email health report (Setup → Notifications → Email Reports) ──
    _EMAIL_REPORT_DEFAULTS = {
        "enabled": False,
        "sections": {"checks": True, "clients": True},
        "schedule": {"freq": "weekly", "dow": 0, "dom": 1, "hour": 7},
        "recipients": [],
    }

    # ── Reports: a global LIST of emailed reports (each with a target tenant) ──
    # Global Admin sees/manages all; a non-admin (reports right) sees only reports
    # for their own tenant and can only create for it. Stored in global_config via
    # email_report.get_reports / save_reports.
    import uuid as _uuid

    def _user_tenant(sess):
        u = (sess or {}).get("user", {}) or {}
        return u.get("tenant_id") or ((u.get("tenants") or [None])[0])

    def _clean_report(body, sess, existing=None):
        sch = body.get("schedule") or {}
        freq = str(sch.get("freq", "weekly"))
        tenant = str(body.get("tenant") or "default")
        if not is_admin_fn(sess):
            tenant = _user_tenant(sess) or "default"  # non-admin can only target own
        return {
            "id": (existing or {}).get("id") or _uuid.uuid4().hex[:12],
            "name": (str(body.get("name") or "Report").strip() or "Report")[:80],
            "tenant": tenant,
            "sections": {"checks": bool((body.get("sections") or {}).get("checks", True)),
                         "clients": bool((body.get("sections") or {}).get("clients", True))},
            "recipients": [str(r).strip() for r in (body.get("recipients") or []) if str(r).strip()][:20],
            "schedule": {
                "freq": freq if freq in ("daily", "weekly", "monthly") else "weekly",
                "dow": max(0, min(6, int(sch.get("dow", 0) or 0))),
                "dom": max(1, min(28, int(sch.get("dom", 1) or 1))),
                "hour": max(0, min(23, int(sch.get("hour", 7) or 7))),
            },
            "enabled": bool(body.get("enabled")),
            "last_sent": (existing or {}).get("last_sent"),
        }

    def _may_touch(sess, rep):
        return is_admin_fn(sess) or (rep.get("tenant") == _user_tenant(sess))

    @app.get("/api/reports/list")
    async def list_reports(request: Request, tenant: str = None):
        sess = session_user_fn(request)
        reports = email_report.get_reports(hub)
        if not is_admin_fn(sess):
            tid = _user_tenant(sess)
            reports = [r for r in reports if r.get("tenant") == tid]
        elif tenant and tenant != "default":
            # Admin + a specific tenant on the picker → scope the view to it (the
            # non-admin filter above stays the security floor; this is view scope).
            reports = [r for r in reports if r.get("tenant") == tenant]
        return {"reports": reports}

    @app.get("/api/reports/tenants")
    async def reports_tenants(request: Request):
        """Tenants selectable as a report's dashboard (admin: all; else own only)."""
        sess = session_user_fn(request)
        tenants = hub.state.tenant_state.get("tenants", {}) or {}
        out = [{"id": tid, "name": (cfg or {}).get("name") or tid} for tid, cfg in tenants.items()]
        if "default" not in [t["id"] for t in out]:
            out.insert(0, {"id": "default", "name": "Default"})
        if not is_admin_fn(sess):
            mine = _user_tenant(sess)
            out = [t for t in out if t["id"] == mine]
        return {"tenants": out}

    @app.post("/api/reports")
    async def create_report(request: Request):
        sess = session_user_fn(request)
        body = await request.json()
        reports = email_report.get_reports(hub)
        rep = _clean_report(body if isinstance(body, dict) else {}, sess)
        reports.append(rep)
        email_report.save_reports(hub, reports)
        return {"saved": True, "report": rep}

    @app.put("/api/reports/{rid}")
    async def update_report(rid: str, request: Request):
        sess = session_user_fn(request)
        body = await request.json()
        reports = email_report.get_reports(hub)
        for i, r in enumerate(reports):
            if r.get("id") == rid:
                if not _may_touch(sess, r):
                    raise HTTPException(status_code=403, detail="Not authorized for this report")
                reports[i] = _clean_report(body if isinstance(body, dict) else {}, sess, r)
                email_report.save_reports(hub, reports)
                return {"saved": True, "report": reports[i]}
        raise HTTPException(status_code=404, detail="Report not found")

    @app.delete("/api/reports/{rid}")
    async def delete_report(rid: str, request: Request):
        sess = session_user_fn(request)
        reports = email_report.get_reports(hub)
        keep, removed = [], False
        for r in reports:
            if r.get("id") == rid:
                if not _may_touch(sess, r):
                    raise HTTPException(status_code=403, detail="Not authorized for this report")
                removed = True
                continue
            keep.append(r)
        if removed:
            email_report.save_reports(hub, keep)
        return {"removed": removed}

    @app.post("/api/reports/{rid}/test")
    async def test_report(rid: str, request: Request):
        sess = session_user_fn(request)
        rep = next((r for r in email_report.get_reports(hub) if r.get("id") == rid), None)
        if not rep:
            raise HTTPException(status_code=404, detail="Report not found")
        if not _may_touch(sess, rep):
            raise HTTPException(status_code=403, detail="Not authorized for this report")
        try:
            await email_report.send_now(hub, rep.get("tenant") or "default", rep)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"Send failed: {exc}")
        return {"sent": True, "to": rep.get("recipients") or []}

    # ── realtime alert rules (per-tenant; the AlertEngine matches on these) ──
    from alert_engine import SOURCES as _ALERT_SOURCES

    def _clean_rule(body, existing=None):
        src = str(body.get("source") or "")
        src = src if src in _ALERT_SOURCES else _ALERT_SOURCES[0]
        return {
            "id": (existing or {}).get("id") or _uuid.uuid4().hex[:12],
            "name": (str(body.get("name") or "").strip() or src)[:80],
            "source": src,
            "recipients": [str(r).strip() for r in (body.get("recipients") or []) if str(r).strip()][:20],
            "enabled": bool(body.get("enabled", True)),
            # 'human' = formatted dashboard-style email; 'raw' = JSON body for automation.
            "format": "raw" if str(body.get("format") or "human").lower() == "raw" else "human",
        }

    @app.get("/api/alerts/rules")
    async def list_alert_rules(tenant_id: str = Depends(get_tenant_id)):
        return {"rules": await store.get_alert_rules(tenant_id), "sources": list(_ALERT_SOURCES)}

    @app.post("/api/alerts/rules")
    async def create_alert_rule(request: Request, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        rules = await store.get_alert_rules(tenant_id)
        rule = _clean_rule(body if isinstance(body, dict) else {})
        rules.append(rule)
        await store.set_alert_rules(tenant_id, rules)
        return {"saved": True, "rule": rule}

    @app.put("/api/alerts/rules/{rid}")
    async def update_alert_rule(rid: str, request: Request, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        rules = await store.get_alert_rules(tenant_id)
        for i, r in enumerate(rules):
            if r.get("id") == rid:
                rules[i] = _clean_rule(body if isinstance(body, dict) else {}, r)
                await store.set_alert_rules(tenant_id, rules)
                return {"saved": True, "rule": rules[i]}
        raise HTTPException(status_code=404, detail="Rule not found")

    @app.delete("/api/alerts/rules/{rid}")
    async def delete_alert_rule(rid: str, tenant_id: str = Depends(get_tenant_id)):
        rules = await store.get_alert_rules(tenant_id)
        keep = [r for r in rules if r.get("id") != rid]
        removed = len(keep) != len(rules)
        if removed:
            await store.set_alert_rules(tenant_id, keep)
        return {"removed": removed}

    @app.post("/api/alerts/rules/{rid}/test")
    async def test_alert_rule(rid: str, tenant_id: str = Depends(get_tenant_id)):
        rule = next((r for r in await store.get_alert_rules(tenant_id) if r.get("id") == rid), None)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        recips = rule.get("recipients") or []
        if not recips:
            raise HTTPException(status_code=400, detail="This rule has no recipients")
        import notifications as _n
        _src = str(rule.get("source") or "").replace("<", "").replace(">", "")
        _tid = str(tenant_id).replace("<", "").replace(">", "")
        ok = await _n.send_email(
            hub, f"[LM TEST] alert rule '{rule.get('name')}'",
            f"Test alert for source '{_src}' (tenant {_tid}).",
            to_emails=recips,
            html=f"<p>Test alert for <b>{_src}</b> (tenant {_tid}).</p>")
        if not ok:
            raise HTTPException(status_code=400, detail="Send failed — check Setup → Notifications")
        return {"sent": True, "to": recips}

    # ── hub tenant processing-modes (literal "hub" first segment) ──────────
    @app.patch("/sim/api/hub/tenants/{tenant}/processing-modes")
    async def set_processing_mode(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        feature, value = next(iter(body.items())) if body else (None, None)
        if not feature:
            raise HTTPException(status_code=400, detail="missing feature")
        await store.set_processing_mode(tenant_id, feature, value)
        # central_api maps to the spoke's central_api.mode; other features are
        # hub-stored only for now.
        payload: dict = {}
        if feature == "central_api" and value:
            payload = {"central_api": {"mode": "central" if value == "centralized" else "classic"}}
        pushed = await _push_config(tenant_id, payload) if payload else 0
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    # ── {tenant}/... param routes (registered last) ────────────────────────
    @app.get("/sim/api/{tenant}/spokes/{spoke_id}/config")
    async def get_spoke_config(tenant: str, spoke_id: str, tenant_id: str = Depends(get_tenant_id)):
        return await service.get_spoke_config(tenant_id, spoke_id)

    # ── Kill switch (global sim emergency stop) ───────────────────────────────
    # The legacy cs webui-spoke had a prominent kill-switch banner + one-click
    # toggle; the new arch buried kill_switch as a Sim Config field. These give
    # the hub a read + toggle that forward to the spoke's CS_GET_KILL_SWITCH /
    # CS_KILL_SWITCH (engine.set_kill_switch persists kill_switch.txt + short-
    # circuits every sim iteration to KILLED).
    @app.get("/sim/api/{tenant}/kill-switch")
    async def cs_get_kill_switch(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
        if not sid:
            return {"kill_switch": None, "spoke_connected": False}
        try:
            result = await hub.request_response(sid, "CS_GET_KILL_SWITCH", {}, timeout=4.0)
        except Exception:
            return {"kill_switch": None, "spoke_connected": False}
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        ks = data.get("kill_switch") if isinstance(data, dict) else None
        return {"kill_switch": bool(ks), "spoke_connected": True}

    @app.post("/sim/api/{tenant}/kill-switch")
    async def cs_set_kill_switch(request: Request, tenant: str,
                                 tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        on = bool(body.get("on")) if isinstance(body, dict) else False
        return await _cs_forward(tenant_id, "CS_KILL_SWITCH", {"on": on})

    # ── Demo scenarios (named per-client failure presets, TTL + auto-expiry) ──
    # Ports the legacy cs webui-spoke demo system: trigger a named failure
    # (dns_fail/dhcp_fail/assoc_fail/auth_fail/ssidpw_fail/port_flap) on one
    # client for 120 min, or ``normal`` to clear. The override is ephemeral +
    # in-memory on the spoke (layered on top of persisted overrides at config
    # delivery), so it expires or clears back to the operator's prior setting.
    @app.post("/sim/api/{tenant}/demo/client/{hostname}/scenario")
    async def cs_demo_set_scenario(request: Request, tenant: str, hostname: str,
                                   tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        scenario = str(body.get("scenario") or "").strip() if isinstance(body, dict) else ""
        if not scenario:
            raise HTTPException(status_code=400, detail="missing 'scenario'")
        return await _cs_forward(tenant_id, "CS_DEMO_SCENARIO",
                                 {"hostname": hostname, "scenario": scenario,
                                  "triggered_by": str(body.get("triggered_by") or "")})

    @app.delete("/sim/api/{tenant}/demo/client/{hostname}/scenario")
    async def cs_demo_clear_scenario(tenant: str, hostname: str,
                                     tenant_id: str = Depends(get_tenant_id)):
        return await _cs_forward(tenant_id, "CS_DEMO_CLEAR", {"hostname": hostname})

    @app.get("/sim/api/{tenant}/demo/active")
    async def cs_demo_active(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        try:
            return await _cs_forward(tenant_id, "CS_GET_DEMO_ACTIVE", {})
        except HTTPException:
            return {"active": [], "spoke_connected": False}

    @app.get("/sim/api/{tenant}/demo/scenarios")
    async def cs_demo_scenarios(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        # The scenario catalog is static; fall back to the canon if the spoke is
        # offline so the UI's dropdown still populates. (Mirrors
        # cs/lm-spoke/src/demo_scenarios.build_scenarios — kept in sync.)
        _flags = ("dns_fail", "dhcp_fail", "assoc_fail", "auth_fail",
                  "ssidpw_fail", "port_flap")
        _canon = {"normal": {f: "off" for f in _flags}}
        for f in _flags:
            _canon[f] = {x: ("on" if x == f else "off") for x in _flags}
        try:
            return await _cs_forward(tenant_id, "CS_GET_DEMO_SCENARIOS", {})
        except HTTPException:
            return {"status": "SUCCESS", "scenarios": _canon}

    # ── per-client override Control Panel (ports the legacy cs webui-spoke) ──
    # Live sim-flag toggles per client + Apply / Clear / Apply-to-ALL, forwarded
    # to the spoke's CS_GET/SET/CLEAR/SET_ALL_CLIENT_OVERRIDES handlers (which
    # wrap the persisted ClientRegistry store — sticky across reconnects/reboots,
    # unlike the ephemeral demo flags). "control-all" is registered BEFORE the
    # {hostname} route so Starlette doesn't capture it as a hostname.
    @app.post("/sim/api/{tenant}/clients/control-all")
    async def cs_control_all(request: Request, tenant: str,
                             tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        overrides = body.get("overrides") if isinstance(body, dict) else None
        if not isinstance(overrides, dict):
            overrides = {k: v for k, v in (body or {}).items()
                         if isinstance(body, dict)}
        return await _cs_forward(tenant_id, "CS_SET_ALL_CLIENT_OVERRIDES",
                                 {"overrides": overrides})

    # "Purge Clients" — drop every registered client on the tenant's cs spoke
    # (memory + clients.json on disk). Registered BEFORE the {hostname}/control
    # routes so Starlette doesn't capture a bare collection DELETE as a
    # hostname. After the spoke confirms, clear the hub's cached `clients` for
    # that spoke so the next /aggregate/clients renders empty immediately
    # (the next CS_TELEMETRY at ~10s repopulates it if clients beacon back).
    @app.delete("/sim/api/{tenant}/clients")
    async def cs_purge_clients(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        result = await _cs_forward(tenant_id, "CS_PURGE_CLIENTS", {})
        try:
            sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
            cache = getattr(hub, "simulations_cache", None)
            if sid and isinstance(cache, dict) and isinstance(cache.get(sid), dict):
                cache[sid].pop("clients", None)
        except Exception:
            pass
        return result

    @app.delete("/sim/api/proxmox/host/{hostname}")
    async def cs_delete_proxmox_host(hostname: str, request: Request,
                                     tenant_id: str = Depends(get_tenant_id)):
        """Remove a Proxmox host row from the VM Server view + clear its cached
        data. For an intentionally shut-down host that otherwise lingers as a STALE
        row. Clears the hub's cached ``proxmox_hosts`` entry for this host across the
        tenant's cs spokes (immediate UI removal) and best-effort tells the owning
        spoke to drop it from ``proxmox_states`` so it isn't re-relayed. Works even
        if the spoke is offline (cache clear still applies)."""
        _require_admin(request)
        hn = (hostname or "").strip()
        if not hn:
            raise HTTPException(status_code=400, detail="hostname required")
        removed = 0
        cleared_sids = []
        cache = getattr(hub, "simulations_cache", None)
        if isinstance(cache, dict):
            for sid, cdata in list(cache.items()):
                if not isinstance(cdata, dict):
                    continue
                try:
                    if hub.state.get_spoke_tenant(sid) != tenant_id:
                        continue
                except Exception:
                    pass
                touched = False
                ph = cdata.get("proxmox_hosts")
                if isinstance(ph, list):
                    new_ph = [h for h in ph
                              if str((h or {}).get("hostname", "")).strip() != hn]
                    if len(new_ph) != len(ph):
                        cdata["proxmox_hosts"] = new_ph
                        removed += len(ph) - len(new_ph)
                        touched = True
                # Prune the flat single-host mirrors that belong to this host too.
                for k in ("proxmox_vms", "usb_devices"):
                    lst = cdata.get(k)
                    if isinstance(lst, list):
                        pruned = [x for x in lst
                                  if str((x or {}).get("_agent_hostname")
                                         or (x or {}).get("node", "")).strip() != hn]
                        if len(pruned) != len(lst):
                            cdata[k] = pruned
                            touched = True
                if touched:
                    cleared_sids.append(sid)
        # Best-effort: tell the connected cs spoke(s) to drop it from proxmox_states
        # so it doesn't re-appear on the next relay. Spoke offline → skip silently.
        forwarded = False
        try:
            sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
            if sid:
                await hub.request_response(sid, "CS_PURGE_HOST", {"hostname": hn}, timeout=8.0)
                forwarded = True
        except Exception:
            pass
        return {"status": "ok", "removed": removed, "spoke_notified": forwarded,
                "message": (f"Removed host {hn}"
                            + ("" if forwarded else " (spoke offline — cache cleared; "
                               "it will reappear only if a spoke relays it again)"))}

    @app.delete("/sim/api/{tenant}/clients/overrides")
    async def cs_clear_all_client_overrides(tenant: str,
                                            tenant_id: str = Depends(get_tenant_id)):
        """Bulk-clear the legacy per-client REGISTRY override layer on the spoke.

        Model A moved per-user overrides to ``user-overrides.conf``, but stale
        registry overrides (set via the old Control Panel, a prior bulk set, or
        a since-removed SimQuotaEngine assignment that didn't revert) persist in
        the spoke's ``clients.json`` and are baked into ``[username]`` by
        ``/api/config`` (client_api.py:304-313) — invisible in the User
        Overrides card (which reads user-overrides.conf) and in the Control
        Panel (cs_get_client_control reads the same). This wipes them for every
        registered client so the served ``simulation.conf`` drops the stale
        ``[username]`` sim flags on the next client fetch. Mirrors the per-host
        CS_CLEAR_CLIENT_OVERRIDES but fan-out to all clients in one shot."""
        result = await _cs_forward(tenant_id, "CS_CLEAR_ALL_CLIENT_OVERRIDES", {})
        # Mirror the clear into the hub cache so the Clients tab sim bars drop
        # the flags before the next ~10s telemetry frame (otherwise a stale
        # override reappears until the frame lands).
        try:
            for _sid, data in (getattr(hub, "simulations_cache", {}) or {}).items():
                try:
                    if hub.state.get_spoke_tenant(_sid) != tenant_id:
                        continue
                except Exception:  # noqa: BLE001
                    continue
                for c in (data.get("clients") or []):
                    if isinstance(c, dict):
                        c.pop("overrides", None)
        except Exception:  # noqa: BLE001
            pass
        return result

    @app.get("/sim/api/{tenant}/clients/{hostname}/control")
    async def cs_get_client_control(tenant: str, hostname: str,
                                    tenant_id: str = Depends(get_tenant_id)):
        # Model A: per-client sim overrides live in user-overrides.conf
        # [username], so seed the control panel from there (the same place the
        # toggles write) rather than the legacy per-client registry.
        username = _username_for(hostname)
        try:
            text = await _current_user_overrides_text(tenant_id)
            p = configparser.ConfigParser()
            p.optionxform = str
            try:
                p.read_string(text or "")
            except Exception:  # noqa: BLE001
                p = None
            ov = {}
            if p is not None and p.has_section(username):
                for k in p.options(username):
                    if k in _CS_SIM_FLAGS:
                        ov[k] = p.get(username, k)
            return {"status": "SUCCESS", "hostname": hostname,
                    "username": username, "overrides": ov}
        except Exception:  # noqa: BLE001
            return {"status": "SUCCESS", "hostname": hostname, "overrides": {}}

    @app.post("/sim/api/{tenant}/clients/{hostname}/control")
    async def cs_set_client_control(request: Request, tenant: str, hostname: str,
                                    tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        overrides = body.get("overrides") if isinstance(body, dict) else None
        if not isinstance(overrides, dict):
            # Also accept the flags inline ({"dns_fail":"on",...}) for parity with
            # the spoke's HTTP client_api endpoint.
            overrides = {k: v for k, v in (body or {}).items()
                         if isinstance(body, dict)}
        # Model A: write a per-USER override to user-overrides.conf (visible in
        # the Config Editor; synced to GitHub when a token is configured).
        return await _write_user_override(tenant_id, hostname, overrides, clear=False)

    @app.delete("/sim/api/{tenant}/clients/{hostname}/control")
    async def cs_clear_client_control(tenant: str, hostname: str,
                                      tenant_id: str = Depends(get_tenant_id)):
        return await _write_user_override(tenant_id, hostname, {}, clear=True)

    # ── per-host USB VMID overrides ─────────────────────────────────────────
    # Optional per-host vmid_start/vmid_end/vm_set_override that override the
    # global VMID range for one proxmox host. The pxmx agent derives each host's
    # batch from its hostname suffix by default; these let the cs speak pin a
    # specific host's range instead. Persisted by the cs spoke (cs_settings.json
    # ``host_usb_overrides``); the hub only forwards. Gated by the cs module
    # access right via the http access_control_middleware (same as /clients/*).
    @app.get("/sim/api/{tenant}/cs/host-usb-override")
    async def cs_get_host_usb_overrides(tenant: str,
                                        tenant_id: str = Depends(get_tenant_id)):
        return await _cs_forward(tenant_id, "CS_GET_HOST_USB_OVERRIDES", {})

    @app.post("/sim/api/{tenant}/cs/host-usb-override/{hostname}")
    async def cs_set_host_usb_override(request: Request, tenant: str, hostname: str,
                                       tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        knobs = body.get("knobs") if isinstance(body, dict) else None
        if not isinstance(knobs, dict):
            # Accept the knobs inline ({"vmid_start":91000,"vmid_end":91999}).
            knobs = {k: v for k, v in (body or {}).items() if isinstance(body, dict)}
        return await _cs_forward(tenant_id, "CS_SET_HOST_USB_OVERRIDE",
                                 {"hostname": hostname, "knobs": knobs})

    @app.delete("/sim/api/{tenant}/cs/host-usb-override/{hostname}")
    async def cs_clear_host_usb_override(tenant: str, hostname: str,
                                         tenant_id: str = Depends(get_tenant_id)):
        return await _cs_forward(tenant_id, "CS_CLEAR_HOST_USB_OVERRIDE",
                                 {"hostname": hostname})

    @app.get("/sim/api/{tenant}/config/simulation-conf")
    async def get_sim_conf(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        # The spoke's actual simulation.conf content, relayed in telemetry.
        sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
        data = (getattr(hub, "simulations_cache", {}) or {}).get(sid, {}) if sid else {}
        return {"content": data.get("sim_conf_content") or "", "sha": ""}

    @app.put("/sim/api/{tenant}/config/simulation-conf")
    async def put_sim_conf(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        content = body.get("content", "") if isinstance(body, dict) else ""
        source = await _require_config_writable(tenant_id)  # 403 if github + no key
        await store.set_sim_conf_content(tenant_id, content)
        # Hub is the sole GitHub client: on a GitHub-managed tenant the HUB
        # commits+pushes this edit to the repo (the spoke is a follower and no
        # longer pushes). Best-effort — a GitHub failure still saves + fans out.
        if source == "github":
            await _commit_config_to_github(
                tenant_id, github_config_client.SIM_CONF_PATH, content,
                "Update simulation.conf via Lab Manager")
        _invalidate_sim_quota_catalog(tenant_id)  # sims/sites derive from this
        pushed = await _push_config(tenant_id, {"sim_conf_override": content})
        # Re-merge + re-push effective quotas so a config change that removes a
        # sim primitive re-validates the tenant's quotas against SIM_META (a
        # quota pointing at a now-unknown sim is dropped) and the spoke
        # reconciles against the refreshed list.
        try:
            qpushed = await _push_sim_quotas(tenant_id)
        except Exception:  # noqa: BLE001
            qpushed = 0
        return {"saved": True, "synced_spokes": pushed, "quota_spokes": qpushed,
                "source": source}

    @app.get("/sim/api/{tenant}/clients/sim-overrides")
    async def get_client_overrides(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        return await store.get_user_overrides(tenant_id)

    # ── Simulations Config tab (legacy solutions-hpe/client-sim port) ──────────
    # A structured editor for simulation.conf (sections [simulation]/[server]/
    # [address]/[s0]–[s9]) and user-overrides.conf (per-user sections). The hub
    # is the source of truth for hub-owned config: edits save as the hub-managed
    # override (``sim_conf_override`` / ``user_conf_override`` INI text →
    # CS_CONFIG_UPDATE → spoke writes configs/hub-*-overrides.conf → merged on
    # top of the repo base files by sim_config.load_configs). The spoke's
    # CS_GET_CONFIG returns the MERGED effective config, which is what the
    # editor reads back on Refresh (so the UI shows what's actually in effect,
    # not just the override layer).

    @app.get("/sim/api/{tenant}/config/simulation-conf-parsed")
    async def get_sim_conf_parsed(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Structured simulation.conf view — ``{sections: {section: {k:v}}}``.

        The HUB is the config authority: it pulls simulation.conf from GitHub
        (or owns it in Hub mode) into the store, so the editor shows that stored
        config DIRECTLY — the value pulled from GitHub / hub-owned — with no
        dependency on a spoke round-trip that can return blank. Falls back to the
        spoke's merged effective config only when the hub store is still empty
        (the brief pre-first-pull bootstrap for a github tenant). ``source`` says
        which: ``hub`` (authoritative store) | ``spoke`` (bootstrap fallback).
        """
        raw = (await store.get_sim_conf_content(tenant_id)) or ""
        source = "hub"
        try:
            mode = "hub" if (await store.get_source_of_truth(tenant_id)) == "hub" else "github"
        except Exception:  # noqa: BLE001
            mode = "github"
        if not raw.strip():
            # Hub store empty (github tenant not yet pulled) — ask the spoke for
            # its current effective config so the editor still renders.
            try:
                data = await _cs_forward(tenant_id, "CS_GET_CONFIG", {}, timeout=6.0)
                _sr = (data or {}).get("simulation_conf", "") if isinstance(data, dict) else ""
                if (_sr or "").strip():
                    raw = _sr
                    source = "spoke"
            except HTTPException as exc:
                logger.info("sim-conf-parsed: hub store empty + CS_GET_CONFIG failed (%s)", exc.detail)
        # Distinguish a truly-offline spoke from one that IS connected but whose
        # live CS_GET_CONFIG round-trip failed/timed out (e.g. its event loop was
        # momentarily busy) — the editor mislabeled the latter as "spoke offline".
        spoke_connected = False
        try:
            _sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
            spoke_connected = bool(_sid and hub._primary_key(_sid) in getattr(hub, "active_connections", {}))
        except Exception:
            spoke_connected = False
        return {"sections": _parse_ini_sections(raw), "raw": raw,
                "mode": mode, "source": source,
                "spoke_connected": spoke_connected,
                "fetched_at": _now_iso()}

    @app.get("/sim/api/{tenant}/config/user-overrides-conf")
    async def get_user_overrides_conf(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Raw user-overrides.conf for the per-user editor.

        The HUB is the config authority: show the stored user_overrides_content
        (pulled from GitHub / hub-owned) DIRECTLY. Falls back to the spoke's
        effective user_overrides only when the hub store is still empty AND the
        tenant hasn't been pulled yet (an empty store is otherwise the real value
        — user-overrides.conf is commonly empty). ``source``: ``hub`` | ``spoke``.
        """
        content = (await store.get_user_overrides_content(tenant_id)) or ""
        source = "hub"
        try:
            mode = "hub" if (await store.get_source_of_truth(tenant_id)) == "hub" else "github"
        except Exception:  # noqa: BLE001
            mode = "github"
        if not content.strip() and not (await store.get_sim_conf_content(tenant_id) or "").strip():
            # Nothing pulled yet (bootstrap) — ask the spoke so the editor renders.
            try:
                data = await _cs_forward(tenant_id, "CS_GET_CONFIG", {}, timeout=6.0)
                _uo = (data or {}).get("user_overrides", "") if isinstance(data, dict) else ""
                if (_uo or "").strip():
                    content = _uo
                    source = "spoke"
            except HTTPException as exc:
                logger.info("user-overrides-conf: hub store empty + CS_GET_CONFIG failed (%s)", exc.detail)
        return {"content": content, "mode": mode, "source": source,
                "fetched_at": _now_iso()}

    @app.put("/sim/api/{tenant}/config/user-overrides-conf")
    async def put_user_overrides_conf(request: Request, tenant: str,
                                      tenant_id: str = Depends(get_tenant_id)):
        """Save the full user-overrides.conf override + push to the spoke.

        Validates the INI parses (422 on a malformed file) before persisting or
        pushing, mirroring the spoke-side ``sim_config.validate_ini_text`` gate.
        """
        body = await request.json()
        content = (body.get("content", "") if isinstance(body, dict) else "") or ""
        source = await _require_config_writable(tenant_id)  # 403 if github + no key
        # Validate parse before saving so a bad edit doesn't overwrite the canon.
        if content.strip() and not _parse_ini_sections(content):
            raise HTTPException(status_code=422, detail="Invalid INI: could not parse user-overrides.conf")
        await store.set_user_overrides_content(tenant_id, content)
        # Hub is the sole GitHub client: commit the edit to the repo on a
        # GitHub-managed tenant (best-effort; the spoke no longer pushes).
        if source == "github":
            await _commit_config_to_github(
                tenant_id, github_config_client.USER_OVERRIDES_PATH, content,
                "Update user-overrides.conf via Lab Manager")
        pushed = await _push_config(tenant_id, {"user_conf_override": content})
        # Per-user wsite/sim-flag overrides shift a quota's site pool + sim
        # eligibility, so re-merge + re-push effective quotas (the spoke
        # reconciles against the refreshed list).
        try:
            qpushed = await _push_sim_quotas(tenant_id)
        except Exception:  # noqa: BLE001
            qpushed = 0
        return {"saved": True, "synced_spokes": pushed, "quota_spokes": qpushed,
                "source": source}

    @app.get("/sim/api/{tenant}/settings")
    async def get_settings(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        settings = await store.get_settings(tenant_id)
        # Never echo the password (legacy plaintext smtp_pass or the Fernet
        # ciphertext) to the UI — surface a has_password flag instead.
        notif = dict(settings.get("notifications") or {})
        has_pw = bool(notif.get("smtp_password_enc") or notif.get("smtp_pass"))
        for _k in ("smtp_pass", "smtp_password", "smtp_password_enc"):
            notif.pop(_k, None)
        notif["has_password"] = has_pw
        settings["notifications"] = notif
        return settings

    @app.post("/sim/api/{tenant}/settings/notifications")
    async def set_notifications(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        cfg = body if isinstance(body, dict) else {}
        # The hub sends this tenant's spoke out-of-contact alerts itself, using
        # the hub's global notifications config (provider / ACS creds /
        # from_email — see Hub → Setup → Notifications). The tenant only
        # supplies a recipient list; nothing is pushed to the spoke and no
        # sender creds are stored here (the spoke-sent email path is retired).
        # Legacy sender-config fields already on disk are preserved untouched
        # (non-destructive) in case the spoke-sent path is ever revived.
        cur = await store.get_notifications(tenant_id) or {}
        stored = dict(cur)
        stored["to_emails"] = cfg.get("to_emails")
        await store.set_notifications(tenant_id, stored)
        return {"saved": True}

    @app.get("/sim/api/{tenant}/spokes")
    async def list_spokes(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        return []

    # ── Client-Simulation command queue (D2) ───────────────────────────────
    # The cs UI (and any LM-native UI) enqueues VM actions here; the hub's
    # CSBridgePoller (gateway/cs_bridge.py) polls the cs spoke's inbox and
    # relays each command to the unified pxmx agent as CS_COMMAND, then acks
    # the terminal result. Body: {action, args?|<inline vmid...>, target?, type?}.
    @app.post("/sim/api/{tenant}/proxmx/command")
    async def cs_enqueue_command(request: Request, tenant: str,
                                 tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        action = str(body.get("action") or "").strip()
        if not action:
            raise HTTPException(status_code=400, detail="missing 'action'")
        sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
        if not sid:
            raise HTTPException(status_code=503, detail="Client-Sim spoke not connected")
        # Accept either an explicit "args" object or inline fields
        # ({action:"start_vm", vmid:90050}) — the legacy cs UI posts the latter.
        if isinstance(body.get("args"), dict):
            args = body["args"]
        else:
            args = {k: v for k, v in body.items() if k not in ("action", "target", "type")}
        payload = {"target": body.get("target") or "proxmox",
                   "action": action, "args": args, "type": body.get("type")}
        try:
            result = await hub.request_response(sid, "CS_QUEUE_COMMAND", payload, timeout=5.0)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"enqueue failed: {exc}")
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        if isinstance(data, dict) and data.get("status") == "ERROR":
            # Safeguard refusal (protected vmid / below sim floor) → 403.
            raise HTTPException(status_code=403, detail=data.get("message", "refused"))
        return data

    @app.get("/sim/api/{tenant}/proxmx/commands")
    async def cs_list_commands(tenant: str, tenant_id: str = Depends(get_tenant_id),
                               live: bool = False):
        sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
        if not sid:
            return {"commands": [], "spoke_connected": False}
        # Serve from the cached CS_TELEMETRY payload (the cs spoke includes its
        # command queue in every ~10s telemetry frame) so the VM Server →
        # Command Queue view loads instantly instead of a live 15s
        # request_response that stalls when the spoke is busy. The WebUI passes
        # live=1 after a Send/Delete/Clear (the spoke just responded, so the
        # round-trip is fast) to reflect the mutation immediately; cold start
        # (no cached queue yet) also falls back to the live fetch.
        if not live:
            cq = _cached_command_queue(hub, sid)
            if cq is not None:
                return {"commands": cq, "spoke_connected": True}
        try:
            result = await hub.request_response(sid, "CS_GET_COMMANDS", {}, timeout=15.0)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"list failed: {exc}")
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        return data if isinstance(data, dict) else {"commands": []}

    @app.get("/sim/api/{tenant}/cs-bridge-status")
    async def cs_bridge_status(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Per-agent CS-bridge state for the WebUI "CS Bridge Status" panel —
        lets an Azure-hub operator diagnose 'why isn't svr-02 deleting' (is the
        bridge reaching it? are commands re-queued or failing?) without SSH.
        Reads the CSBridgePoller instance stored on the hub by
        run_cs_bridge_loop. Returns {} if the bridge hasn't started yet."""
        bridge = getattr(hub, "cs_bridge", None)
        if bridge is None or not hasattr(bridge, "status_snapshot"):
            return {"agents": [], "available": False}
        try:
            snap = bridge.status_snapshot()
        except Exception as exc:  # noqa: BLE001 — never 500 the panel
            return {"agents": [], "available": False, "error": str(exc)}
        snap["available"] = True
        return snap

    # ── VM Server fleet operations + per-spoke actions (Wave 1) ──────────────
    # All forward to the cs spoke via CS_QUEUE_COMMAND (the spoke's CSBridge
    # dispatches fleet types through _apply_relay_command_batch and plain VM
    # actions through _queue_command). Spoke-connected status errors → 503.

    @app.post("/sim/api/{tenant}/spokes/{spoke_id}/proxmox-command")
    async def cs_spoke_proxmox_command(request: Request, tenant: str, spoke_id: str,
                                        tenant_id: str = Depends(get_tenant_id)):
        """Per-spoke/per-VM action. Body: {action, args?, target?}. ``target``
        defaults to the spoke's primary proxmox hostname (resolved from the
        cached telemetry) so the UI can address a host by spoke_id alone."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        # Default host for items that don't specify their own target.
        def _default_target():
            cache = _tenant_cache(tenant_id).get(spoke_id, {})
            px = cache.get("proxmox") or {}
            node = (px.get("node") or {}) if isinstance(px, dict) else {}
            return (node.get("hostname") or "proxmox") if isinstance(node, dict) else "proxmox"
        # Bulk path: an ``items`` list queues MANY VM commands in ONE forward to the
        # spoke (the UI groups a multi-VM action by spoke and sends one call each),
        # instead of one WS round-trip per VM. Each item keeps its own target so
        # VMs route to their own host.
        items = body.get("items")
        if isinstance(items, list) and items:
            norm = []
            for it in items:
                if not isinstance(it, dict):
                    continue
                iact = str(it.get("action") or "").strip()
                if not iact:
                    continue
                norm.append({
                    "target": it.get("target") or _default_target(),
                    "action": iact,
                    "args": it.get("args") if isinstance(it.get("args"), dict) else {},
                    "type": it.get("type"),
                })
            if not norm:
                raise HTTPException(status_code=400, detail="no valid items")
            return await _cs_forward(tenant_id, "CS_QUEUE_COMMAND", {"items": norm})
        action = str(body.get("action") or "").strip()
        if not action:
            raise HTTPException(status_code=400, detail="missing 'action'")
        args = body.get("args") if isinstance(body.get("args"), dict) else \
            {k: v for k, v in body.items() if k not in ("action", "target", "type")}
        target = body.get("target") or _default_target()
        payload = {"target": target, "action": action, "args": args, "type": body.get("type")}
        return await _cs_forward(tenant_id, "CS_QUEUE_COMMAND", payload)

    @app.post("/sim/api/{tenant}/vm-console")
    async def cs_vm_console(request: Request, tenant: str,
                            tenant_id: str = Depends(get_tenant_id)):
        """VNC console for a cs sim VM — the cs-VM-Server-table analogue of
        ``/api/pxmx/console``. Body: ``{spoke_id, vmid, node, agent_id?, type?}``.

        cs sim VMs are qemu VMs on Proxmox hosts whose pxmx agents dial the
        cs spoke (not the pxmx hypervisor spoke), so this mints a one-shot
        ``session_id`` + ``ws_token`` and sends ``VNC_START`` to the cs spoke
        that owns the VM — which relays it to its pxmx agent
        (``handlers_agents.py`` VNC_START: resolves the agent from ``node``/
        ``cluster`` against its connected agents, opens the Proxmox
        vncwebsocket, returns the ticket = the RFB password). The browser then
        connects to the SAME spoke-agnostic ``/ws/console/{session_id}?token=…``
        byte relay the pxmx console uses; only the registered ``spoke_id``
        differs (cs spoke vs pxmx hypervisor spoke).

        Auth mirrors the pxmx console: Global Admin → any VM; otherwise a
        write-user/tenant-admin (``has_edit_access`` — console is control-tier)
        AND the spoke must be bound to the session's tenant. ``tenant_id`` is
        already session-authorized by ``get_tenant_id``; the spoke-binding check
        is the per-VM ownership gate (a cs spoke is single-tenant, so a VM on a
        spoke bound to the session's tenant is the session's VM)."""
        import uuid as _uuid
        import secrets as _secrets
        sess = session_user_fn(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        spoke_id = str(body.get("spoke_id") or "").strip()
        try:
            vmid = int(body.get("vmid"))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="invalid vmid")
        node = str(body.get("node") or "").strip()
        agent_id = str(body.get("agent_id") or "").strip()
        vm_type = str(body.get("type") or "qemu")
        # The cs spokes visible to this tenant (bound + an UNASSIGNED spoke the
        # tenant implicitly claims — see get_client_sim_spokes). A multi-spoke
        # tenant (cs-svr-02/03/04) MUST route VNC_START to the spoke whose agent
        # owns the VM's host, so the body's spoke_id (the VM's owning spoke,
        # supplied by the VM table row) is preferred; it must be one of the
        # tenant's spokes or the request is foreign → 403 (not a silent fallback
        # to the primary, which would route to the wrong host and 502).
        tenant_spokes = []
        get_spokes = getattr(hub, "get_client_sim_spokes", None)
        if callable(get_spokes):
            try:
                tenant_spokes = list(get_spokes(tenant_id) or [])
            except Exception:  # noqa: BLE001
                tenant_spokes = []
        if not is_admin_fn(sess):
            if not has_edit_access(sess):
                raise HTTPException(status_code=403, detail="Edit access required for VM console")
            # Per-VM ownership: the VM's spoke must be one of the session
            # tenant's cs spokes (get_tenant_id already authorized the tenant for
            # the session; this confirms the VM's spoke is one of that tenant's,
            # including a claimable unassigned spoke). A foreign spoke_id → 403.
            if not spoke_id or spoke_id not in tenant_spokes:
                raise HTTPException(status_code=403,
                                    detail="not authorized for this VM's tenant")
        else:
            # Admin: prefer the body's spoke_id when it's a connected cs spoke
            # (any tenant); else fall back to the tenant's primary cs spoke.
            if spoke_id and spoke_id not in tenant_spokes:
                all_cs = []
                get_all = getattr(hub, "get_all_spokes_by_type", None)
                if callable(get_all):
                    try:
                        all_cs = list(get_all("Client-Sim")
                                      or get_all("simulation") or [])
                    except Exception:  # noqa: BLE001
                        all_cs = []
                if spoke_id not in all_cs:
                    spoke_id = ""
            if not spoke_id:
                spoke_id = (hub.get_client_sim_spoke(tenant_id)
                            if hasattr(hub, "get_client_sim_spoke") else None) or ""
            if not spoke_id:
                raise HTTPException(status_code=503, detail="Client-Sim spoke not connected")
        session_id = str(_uuid.uuid4())
        ws_token = _secrets.token_urlsafe(32)
        hub.register_vnc_session(session_id, {
            "spoke_id": spoke_id,
            "tenant_id": tenant_id,
            "ws_token": ws_token,
            "vmid": vmid,
            "node": node,
        })
        # unique_id shape <cluster>/<node>/<vmid> — the cs spoke's VNC_START
        # handler reads only the cluster (split('/')[0]) to match a connected
        # agent's cluster_name; node is matched separately against hostname, so
        # a cs VM (which may not carry a cluster) uses node as the cluster
        # fallback. node is the authoritative agent-resolver here.
        unique_id = f"{node or 'cs'}/{node or 'cs'}/{vmid}"
        try:
            vnc_res = await hub.request_response(spoke_id, "VNC_START", {
                "session_id": session_id,
                "unique_id": unique_id,
                "vmid": vmid,
                "node": node,
                "type": vm_type,
                "agent_id": agent_id,
                "target_agent_id": agent_id,
            }, timeout=50.0)
        except Exception as e:
            hub.unregister_vnc_session(session_id)
            logger.exception("cs_vm_console VNC_START failed")
            raise HTTPException(status_code=502, detail=f"failed to start console: {e}")
        # Peel the relay envelope to the status-bearing dict (mirrors
        # pxmx_create_console's unwrap — spoke→agent may nest payload.data twice).
        for _ in range(3):
            if isinstance(vnc_res, dict) and "status" not in vnc_res and "payload" in vnc_res:
                vnc_res = vnc_res.get("payload", {}).get("data", vnc_res)
            else:
                break
        ticket = ""
        if isinstance(vnc_res, dict):
            if vnc_res.get("status") not in ("SUCCESS", "OK"):
                hub.unregister_vnc_session(session_id)
                if vnc_res.get("status") == "ACCEPTED":
                    detail = ("agent returned ACCEPTED (no ticket) — the pxmx agent "
                              "on the Proxmox host is still on the old VNC code; "
                              "wait for its self-update or restart lm-pxmx-agent")
                else:
                    detail = vnc_res.get("message") or vnc_res.get("error") or "agent refused VNC_START"
                raise HTTPException(status_code=502, detail=f"failed to start console: {detail}")
            ticket = str(vnc_res.get("ticket") or "")
        return {"session_id": session_id, "ws_token": ws_token,
                "ticket": ticket, "expires_in": 60}

    @app.post("/sim/api/{tenant}/fleet-reclone")
    async def cs_fleet_reclone(request: Request, tenant: str,
                               tenant_id: str = Depends(get_tenant_id)):
        """Queue a `proxmox_reclone_all` command on the tenant's cs spoke
        (relayed to the pxmx agent by the CSBridgePoller). Body may carry
        `concurrency` (int) to cap parallel reclones; 0/omit = spoke default."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        concurrency = int((body or {}).get("concurrency", 0) or 0)
        payload = {"target": "proxmox", "action": "proxmox_reclone_all",
                    "type": "proxmox_reclone_all", "args": {"concurrency": concurrency}}
        # Fan out to EVERY server concurrently (was _cs_forward → only the first
        # bound spoke, so a 3-server tenant reclonled one host at a time). Each
        # agent then runs `concurrency` reclones in parallel internally, so the
        # fleet does concurrency×servers at once.
        results = await _cs_forward_all(tenant_id, "CS_QUEUE_COMMAND", payload, timeout=15.0)
        return {"queued": True, "servers": len(results),
                "dispatched": sum(1 for _s, d in results if d is not None)}

    @app.post("/sim/api/{tenant}/fleet-reclone-stop")
    async def cs_fleet_reclone_stop(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Stop the running fleet reclone on every server. `proxmox_reclone_stop`
        is a FAST op on the agent (it only sets a flag), so it isn't blocked
        behind the batch that holds the agent's long-op semaphore; in-flight
        reclones finish, the rest are skipped."""
        payload = {"target": "proxmox", "action": "proxmox_reclone_stop",
                   "type": "proxmox_reclone_stop", "args": {}}
        results = await _cs_forward_all(tenant_id, "CS_QUEUE_COMMAND", payload, timeout=10.0)
        return {"stopped": sum(1 for _s, d in results
                               if isinstance(d, dict) and d.get("stopped")),
                "servers": len(results)}

    @app.post("/sim/api/{tenant}/update-all")
    async def cs_update_all(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        payload = {"target": "proxmox", "action": "proxmox_agent_update",
                   "type": "proxmox_agent_update", "args": {}}
        return await _cs_forward(tenant_id, "CS_QUEUE_COMMAND", payload, timeout=10.0)

    @app.get("/sim/api/{tenant}/fleet-reclone-status")
    async def cs_fleet_reclone_status(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        spokes = []
        for sid, data in _tenant_cache(tenant_id).items():
            rs = data.get("reclone_state") or {}
            spokes.append({"spoke_id": sid, "spoke_name": data.get("spoke_name") or sid,
                            "reclone_state": rs})
        return {"spokes": spokes}

    @app.post("/sim/api/{tenant}/toggle-auto-provision")
    async def cs_toggle_auto_provision(request: Request, tenant: str,
                                        tenant_id: str = Depends(get_tenant_id)):
        """Toggle the tenant's `usb_auto_provision` hub-config flag (on/off),
        persist it, and push it to ALL bound cs spokes via `_push_config`
        (fans out to every approved connected Client-Sim spoke for the tenant,
        not just one). Also enables `hub_config_enabled` when turned on."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        enabled = bool(body.get("enabled")) if isinstance(body, dict) else False
        hc = await store.get_hub_config(tenant_id)
        cfg = dict(hc.get("hub_config") or {})
        cfg["usb_auto_provision"] = "on" if enabled else "off"
        await store.set_hub_config(tenant_id, bool(hc.get("hub_config_enabled", False)) or enabled, cfg)
        pushed = await _push_config(tenant_id, {"usb_auto_provision": cfg["usb_auto_provision"]})
        return {"saved": True, "usb_auto_provision": cfg["usb_auto_provision"], "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.get("/sim/api/{tenant}/usb-provisioning-status")
    async def cs_usb_provisioning_status(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        hc = await store.get_hub_config(tenant_id)
        return _usb_provisioning_status_payload(
            hc.get("hub_config") or {}, _tenant_cache(tenant_id),
            hub.state.system_state.get("agent_config", {}) or {}, tenant_id)

    @app.delete("/sim/api/{tenant}/proxmx/commands")
    async def cs_clear_commands(tenant: str, target: str = "",
                                tenant_id: str = Depends(get_tenant_id)):
        return await _cs_forward(tenant_id, "CS_CLEAR_COMMANDS", {"target": target or ""})

    @app.delete("/sim/api/{tenant}/proxmx/commands/pending")
    async def cs_expire_pending(tenant: str, target: str,
                                tenant_id: str = Depends(get_tenant_id)):
        """Expire in-flight commands for one target before VM destroy so they
        don't fire against a gone VM. Registered BEFORE the ``{cmd_id}`` route so
        the literal ``pending`` segment isn't captured as a command id."""
        if not target:
            raise HTTPException(status_code=400, detail="missing 'target'")
        return await _cs_forward(tenant_id, "CS_CLEAR_COMMANDS", {"target": target})

    @app.delete("/sim/api/{tenant}/proxmx/commands/{cmd_id}")
    async def cs_delete_command(tenant: str, cmd_id: str,
                                tenant_id: str = Depends(get_tenant_id)):
        """Remove a single queued command (per-row delete)."""
        return await _cs_forward(tenant_id, "CS_DELETE_COMMAND", {"id": cmd_id})

    @app.post("/sim/api/{tenant}/usb-vidpids")
    async def cs_usb_vidpids(request: Request, tenant: str,
                            tenant_id: str = Depends(get_tenant_id)):
        """Certify / ignore a USB vid:pid. Body: {vid, pid, action, type?} where
        action is ``certify`` (→ usb_vidpids) or ``ignore`` (→ usb_ignored_vidpids),
        or ``remove`` (removes from both). ``type`` (optional, certify only) is the
        dongle class — one of {_USB_TYPES}; it defaults to "wireless" and, on
        re-certify of an already-certified vid:pid, updates the stored class.
        Persists in the hub_config bucket and pushes the updated list to the spoke.

        Format matches the cs speak's re-filter (server.py _apply_proxmox_
        telemetry_state): ``usb_vidpids`` is a JSON array of
        ``{vidpid, type, label}`` dicts and ``usb_ignored_vidpids`` is a JSON
        array of bare lowercased vidpid strings. The speak stores them verbatim
        under hub_managed and parses with _parse_json_list, so the hub MUST
        send these exact shapes (a bare comma string would parse to an empty
        certified set and silently break certify/ignore)."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        vid = str(body.get("vid") or "").strip()
        pid = str(body.get("pid") or "").strip()
        action = str(body.get("action") or "").strip().lower()
        if not vid or not pid or action not in ("certify", "ignore", "remove"):
            raise HTTPException(status_code=400, detail="required: {vid, pid, action: certify|ignore|remove}")
        token = f"{vid.lower()}:{pid.lower()}"
        hc = await store.get_hub_config(tenant_id)
        cfg = dict(hc.get("hub_config") or {})
        # Normalize existing stored values: accept the current JSON-array shape
        # OR a legacy comma-joined bare-vidpid string (so already-stored comma
        # values migrate cleanly on the first action).
        cert_list = _normalize_usb_vidpids(cfg.get("usb_vidpids"))
        ign_set = set(_normalize_usb_ignored(cfg.get("usb_ignored_vidpids")))
        cert_by_vid = {e["vidpid"]: e for e in cert_list}
        if action == "certify":
            dtype = str(body.get("type") or "").strip().lower()
            if dtype not in _USB_TYPES:
                dtype = "wireless"
            existing = cert_by_vid.get(token)
            if existing:
                # Re-certify: update the type so a tenant can reclassify a
                # dongle (e.g. wired ↔ wireless) without removing/re-adding.
                existing["type"] = dtype
            else:
                cert_by_vid[token] = {"vidpid": token, "type": dtype, "label": token}
            ign_set.discard(token)
        elif action == "ignore":
            ign_set.add(token)
            cert_by_vid.pop(token, None)
        else:  # remove
            cert_by_vid.pop(token, None)
            ign_set.discard(token)
        cert_list = sorted(cert_by_vid.values(), key=lambda e: e["vidpid"])
        ign_list = sorted(ign_set)
        cfg["usb_vidpids"] = json.dumps(cert_list)
        cfg["usb_ignored_vidpids"] = json.dumps(ign_list)
        await store.set_hub_config(tenant_id, bool(hc.get("hub_config_enabled", False)) or True, cfg)
        # Push the EFFECTIVE list (global + tenant) so a per-tenant certify/ignore
        # still respects superadmin-global approvals, and vice versa.
        pushed = await _push_usb_to_tenant(tenant_id)
        return {"saved": True, "usb_vidpids": cfg["usb_vidpids"],
                "usb_ignored_vidpids": cfg["usb_ignored_vidpids"], "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    # ── Setup subtabs (Wave 2) ────────────────────────────────────────────────
    @app.get("/sim/api/{tenant}/settings/github")
    async def get_github(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        cfg = await store.get_github_config(tenant_id)
        # Never echo the token back to the UI — return only whether one is set.
        safe = dict(cfg or {})
        safe["has_token"] = bool(safe.get("github_token"))
        safe.pop("github_token", None)
        return safe

    @app.post("/sim/api/{tenant}/settings/github")
    async def set_github(request: Request, tenant: str,
                         tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        existing = await store.get_github_config(tenant_id)
        cfg = dict(existing) if isinstance(existing, dict) else {}
        for k in ("repo_url", "repo_branch"):
            if k in body:
                cfg[k] = str(body.get(k) or "").strip()
        # Token: only overwrite when a non-empty value is posted (UI sends blank
        # to keep the existing secret). The spoke's GitHub PAT is persisted
        # hub-side and pushed to the spoke via CS_CONFIG_UPDATE — intended flow.
        if body.get("github_token"):
            cfg["github_token"] = str(body.get("github_token"))
        await store.set_github_config(tenant_id, cfg)
        pushed = await _push_config(tenant_id, {"github_config": cfg})
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.delete("/sim/api/{tenant}/settings/github")
    async def clear_github(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        await store.set_github_config(tenant_id, {})
        pushed = await _push_config(tenant_id, {"github_config": None})
        return {"cleared": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    # ── Config Source of Truth (Config screen: Hub vs GitHub) ────────────────
    async def _config_gate(tenant_id: str):
        """(source, has_token) for the tenant's config ownership. Writes are only
        allowed when source='hub' OR source='github' with a token configured."""
        source = await store.get_source_of_truth(tenant_id)
        gh = await store.get_github_config(tenant_id) or {}
        return source, bool(gh.get("github_token"))

    async def _require_config_writable(tenant_id: str) -> str:
        source, has_token = await _config_gate(tenant_id)
        if source == "github" and not has_token:
            raise HTTPException(
                status_code=403,
                detail=("GitHub is the source of truth but no API key is configured — "
                        "the config is read-only. Add a GitHub API key, or switch "
                        "Source of Truth to Hub."))
        return source

    # ── Hub-as-sole-GitHub-client helpers ────────────────────────────────────
    async def _spoke_config_source(tenant_id: str) -> str:
        """The config mode to advertise to an ATTACHED spoke (``config_source``).

        The hub is the config authority whenever it can serve the config, so the
        spoke runs as a follower (``'hub'``): repo_sync no-ops and the spoke
        serves the hub-delivered files as its whole config. Returns ``'github'``
        ONLY during the brief bootstrap window for a github-managed tenant before
        the hub's first pull has populated the store — so the spoke isn't handed
        an empty whole-config (it keeps self-pulling until the hub takes over).
        Hub-owned tenants are always ``'hub'``."""
        try:
            sot = await store.get_source_of_truth(tenant_id)
        except Exception:  # noqa: BLE001
            sot = "github"
        if sot == "hub":
            return "hub"
        try:
            has_cfg = bool((await store.get_sim_conf_content(tenant_id) or "").strip())
        except Exception:  # noqa: BLE001
            has_cfg = False
        return "hub" if has_cfg else "github"

    async def _pull_github_into_store(tenant_id: str) -> bool:
        """Pull the tenant's simulation.conf / user-overrides.conf from GitHub
        (the hub is the sole GitHub client) into the hub store. Returns True when
        the stored content CHANGED (caller then re-distributes to spokes). No-op
        (False) for a tenant not github-managed or without creds, and on any
        network/auth error (logged, retried next cycle)."""
        try:
            if await store.get_source_of_truth(tenant_id) != "github":
                return False
            gh = await store.get_github_config(tenant_id) or {}
            if not github_config_client.is_configured(gh):
                return False
            pulled = await github_config_client.pull(gh)
        except Exception as exc:  # noqa: BLE001 — network/auth → skip this cycle
            logger.info("github pull for %s failed: %s", tenant_id, exc)
            return False
        if not pulled:
            return False
        changed = False
        sim_txt = pulled.get("sim_conf")
        if sim_txt is not None and sim_txt != (await store.get_sim_conf_content(tenant_id) or ""):
            await store.set_sim_conf_content(tenant_id, sim_txt)
            changed = True
        user_txt = pulled.get("user_overrides")
        if user_txt is not None and user_txt != (await store.get_user_overrides_content(tenant_id) or ""):
            await store.set_user_overrides_content(tenant_id, user_txt)
            changed = True
        return changed

    async def _commit_config_to_github(tenant_id: str, path: str, content: str,
                                       message: str) -> None:
        """Commit a config edit to the tenant's GitHub repo (the hub is the sole
        GitHub client). Best-effort: a GitHub failure is logged, not raised — the
        edit is already saved hub-side and fanned out to spokes, so the repo just
        lags until the next successful commit / poll."""
        try:
            gh = await store.get_github_config(tenant_id) or {}
            if not github_config_client.is_configured(gh):
                return
            await github_config_client.push(gh, path, content, message)
            logger.info("committed %s to GitHub for tenant %s", path, tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("github commit of %s for %s failed: %s", path, tenant_id, exc)

    async def _github_config_sync_once() -> None:
        for tid in list(store.tenant_ids()):
            try:
                if await _pull_github_into_store(tid):
                    logger.info("github config for tenant %s changed on repo — redistributing", tid)
                    await _push_config(tid, {
                        "sim_conf_override": await store.get_sim_conf_content(tid),
                        "user_conf_override": await store.get_user_overrides_content(tid),
                    })
                    try:
                        await _push_sim_quotas(tid)
                    except Exception:  # noqa: BLE001 — best-effort quota refresh
                        pass
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.debug("github sync for %s: %s", tid, exc)

    async def _github_config_sync_loop() -> None:
        """Hub is the single GitHub client: periodically pull each github-managed
        tenant's config from its repo and, when it changed on GitHub (an external
        commit, or catch-up after a hub restart), re-distribute to that tenant's
        spokes. ONE central puller for the whole fleet — replaces the per-spoke
        repo_sync. Interval via ``LM_HUB_GITHUB_SYNC_INTERVAL`` (default 3600s /
        hourly — external repo edits are rare; human edits push immediately via
        the save routes, so the poll only catches out-of-band commits; floor
        30s). Started from main.py."""
        import os
        try:
            interval = int(os.environ.get("LM_HUB_GITHUB_SYNC_INTERVAL", "3600"))
        except ValueError:
            interval = 3600
        interval = max(30, interval)
        # Initial pull shortly after startup so a github-managed tenant's config
        # is populated hub-side (and pushed to spokes as they connect) without
        # waiting a full interval — closes the cold-start blank-config window.
        await asyncio.sleep(5)
        while True:
            try:
                await _github_config_sync_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — a sweep must not kill the loop
                logger.warning("github config sync loop: %s", exc)
            await asyncio.sleep(interval)

    try:
        hub._github_config_sync_loop = _github_config_sync_loop
    except Exception:  # noqa: BLE001
        pass

    @app.get("/sim/api/{tenant}/config/source")
    async def get_config_source(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        source, has_token = await _config_gate(tenant_id)
        gh = await store.get_github_config(tenant_id) or {}
        return {"source": source, "has_token": has_token,
                "writable": (source == "hub") or has_token,
                "repo_url": gh.get("repo_url", ""), "repo_branch": gh.get("repo_branch", "")}

    @app.post("/sim/api/{tenant}/config/source")
    async def set_config_source(request: Request, tenant: str,
                                tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        source = "hub" if str((body or {}).get("source")) == "hub" else "github"
        # Seed the hub-owned config on the FIRST switch to Hub mode. In hub mode
        # the hub-owned override files ARE the whole config (repo base ignored);
        # until they exist the spoke's load_configs falls back to the repo copy —
        # a window where "Hub" silently serves the GitHub version. Close it: if a
        # hub-owned bucket is still empty, seed it from the current EFFECTIVE
        # config (repo base + any existing override, read live from the spoke) and
        # bundle it into the SAME push as the config_source flag so the spoke
        # writes the hub-owned files and flips mode atomically (no empty-override
        # gap). Only EMPTY buckets are seeded, so hub→github→hub never clobbers a
        # prior edit; an offline spoke skips seeding gracefully (the first save
        # still seeds later).
        seeded = {}
        if source == "hub":
            need_sim = not (await store.get_sim_conf_content(tenant_id) or "").strip()
            need_user = not (await store.get_user_overrides_content(tenant_id) or "").strip()
            if need_sim or need_user:
                eff = None
                try:
                    eff = await _cs_forward(tenant_id, "CS_GET_CONFIG", {}, timeout=6.0)
                except HTTPException as exc:
                    logger.info("config/source→hub: skipping seed, spoke round-trip "
                                "failed (%s); first save will seed instead", exc.detail)
                if isinstance(eff, dict):
                    if need_sim:
                        sim_txt = (eff.get("simulation_conf", "") or "")
                        if sim_txt.strip():
                            await store.set_sim_conf_content(tenant_id, sim_txt)
                            seeded["sim_conf_override"] = sim_txt
                    if need_user:
                        user_txt = (eff.get("user_overrides", "") or "")
                        if user_txt.strip():
                            await store.set_user_overrides_content(tenant_id, user_txt)
                            seeded["user_conf_override"] = user_txt
        await store.set_source_of_truth(tenant_id, source)
        # Tell the spoke which mode so load_configs resolves the effective conf
        # accordingly (hub = hub-owned full file, never git-reverted; github =
        # repo file is the base). Bundle any freshly-seeded hub-owned override
        # text in the same message so mode + files land together.
        pushed = await _push_config(tenant_id, {"config_source": source, **seeded})
        return {"saved": True, "source": source, "pushed_to_spokes": pushed,
                "seeded": sorted(seeded.keys())}

    @app.get("/sim/api/{tenant}/settings/security")
    async def get_security(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        return await store.get_security_config(tenant_id)

    @app.post("/sim/api/{tenant}/settings/security")
    async def set_security(request: Request, tenant: str,
                           tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        cfg = {k: str(body.get(k) or "").strip() for k in ("session_timeout_minutes", "auth_provider") if k in body}
        await store.set_security_config(tenant_id, cfg)
        pushed = await _push_config(tenant_id, {"security_config": cfg})
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

    @app.get("/sim/api/{tenant}/central-sites-config")
    async def get_central_sites(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        return await store.get_central_sites_config(tenant_id)

    @app.post("/sim/api/{tenant}/central-sites-config")
    async def set_central_sites(request: Request, tenant: str,
                                tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        # MERGE the incoming body into the existing config so a PARTIAL save (just
        # quotas, just the Pool & SSID card, just Site Links, just the sharing
        # toggle) updates only the keys it sends and never wipes the other
        # sections. Each editor fetches + resends the sections it owns; anything
        # it omits is preserved here. (Previously this replaced the whole config,
        # so saving quotas dropped the pool config, saving pool dropped the links,
        # etc.) Validate the sim_quotas field the same way.
        try:
            existing = await store.get_central_sites_config(tenant_id) or {}
        except Exception:  # noqa: BLE001
            existing = {}
        cfg = {**existing, **body}
        # Sanitize the per-site minimum client floor: coerce to a {site: int>0}
        # dict, dropping anything malformed. Sent whole by the WebUI toggle
        # (shallow top-level merge), like site_mappings.
        _smc = cfg.get("site_min_clients") or {}
        if isinstance(_smc, dict):
            clean_smc: dict = {}
            for k, v in _smc.items():
                try:
                    n = int(v)
                except (TypeError, ValueError):
                    continue
                if n > 0:
                    clean_smc[str(k)] = n
            cfg["site_min_clients"] = clean_smc
        else:
            cfg.pop("site_min_clients", None)
        sim_quota_errors: list[str] = []
        clean: list = list(cfg.get("sim_quotas") or [])
        try:
            sim_txt = await store.get_sim_conf_content(tenant_id) or ""
            sim_ids = [s["sim_id"] for s in available_sims_from_ini(sim_txt)] if sim_txt.strip() else None
            clean, sim_quota_errors = validate_sim_quotas(cfg.get("sim_quotas"), sim_ids)
            if sim_quota_errors:
                logger.warning("set_central_sites(%s): sim_quotas errors: %s", tenant_id, sim_quota_errors)
            cfg = {**cfg, "sim_quotas": clean}
        except Exception as exc:  # noqa: BLE001 — never block the save
            logger.warning("set_central_sites(%s): sim_quotas validate failed: %s", tenant_id, exc)
        await store.set_central_sites_config(tenant_id, cfg)
        _invalidate_sim_quota_catalog(tenant_id)  # site_mappings feed the catalog
        pushed = await _push_config(tenant_id, {
            "central_sites_config": cfg,
            "effective_sim_quotas": await _effective_sim_quotas(tenant_id),
            "sim_shareable": await _sim_shareable(tenant_id),
            **await _pool_config(tenant_id),
        })
        return {"saved": True, "pushed_to_spokes": pushed,
                "queued": bool(getattr(pushed, "queued", False)),
                "sim_quotas": clean,
                "sim_quota_errors": sim_quota_errors}

    @app.get("/sim/api/{tenant}/sim-quota-catalog")
    async def get_sim_quota_catalog(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Catalog the Sim-Quota UI (Config → Sim Quotas) renders against: the
        sims + sites derived from the tenant's ``simulation.conf`` + the global
        suggested alert→sim linkage + per-sim metadata. Forwards to the cs
        spoke (which reads ``simulation.conf`` directly — the source of truth);
        falls back to parsing the hub's cached ``sim_conf_content`` when no
        spoke is connected so the editor still works offline.

        Cached per tenant for ``_SIM_QUOTA_CATALOG_TTL_S`` (60s) — see the cache
        note above. A live spoke result is cached; the offline fallback (with a
        ``warning``) is NOT, so a reconnecting spoke refreshes immediately."""
        import time as _t
        now = _t.monotonic()
        hit = _sim_quota_catalog_cache.get(tenant_id)
        if hit and hit[0] > now:
            return hit[1]
        cached_ok = True
        try:
            cat = await _cs_forward(tenant_id, "CS_GET_SIM_QUOTA_CATALOG", {}, timeout=15.0)
        except HTTPException:
            sim_txt = await store.get_sim_conf_content(tenant_id) or ""
            csc0 = await store.get_central_sites_config(tenant_id) or {}
            cat = sim_quota_catalog_from_ini(sim_txt, csc0.get("site_mappings"))
            cat["warning"] = "Client-Sim spoke not connected — catalog from cached config."
            cached_ok = False  # don't cache a degraded/offline result
        # Attach the tenant's saved per-sim shareable overrides so the Sim Sharing
        # tile renders current state (authoritative; empty = use the SIM_META default).
        if isinstance(cat, dict):
            cat["sim_shareable"] = await _sim_shareable(tenant_id)
            cat["sim_na"] = await _sim_na(tenant_id)
            cat["alerts"], cat["insights"] = await _alert_insight_catalog()
        if cached_ok and isinstance(cat, dict) and not cat.get("warning"):
            _sim_quota_catalog_cache[tenant_id] = (now + _SIM_QUOTA_CATALOG_TTL_S, cat)
        return cat

    # ── PXMX server → site assignments (Config → PXMX Sites) ──────────────────
    # An operator assigns each connected pxmx server (agent host = short
    # hostname) to a site; the spoke's SimQuotaEngine resolves a client's site
    # via its hosting server's entry. Forwarded to the cs spoke (which owns the
    # agents + the map); 503 when no spoke is connected so the UI can say so.
    @app.get("/sim/api/{tenant}/pxmx-site-map")
    async def get_pxmx_site_map(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        # Cached per tenant for _PXMX_SITE_MAP_TTL_S (60s), invalidated on save.
        # Only a real (spoke-connected) merge is cached; the "not connected"
        # fallback is not, so a reconnecting spoke refreshes immediately.
        import time as _t
        now = _t.monotonic()
        hit = _pxmx_site_map_cache.get(tenant_id)
        if hit and hit[0] > now:
            return hit[1]
        # Tenant-wide: merge the pxmx agents + site maps from ALL of the tenant's
        # Client-Sim spokes (cs-svr-02/03/04) so every pxmx server shows and can
        # be assigned, not just bound[0]'s.
        results = await _cs_forward_all(tenant_id, "CS_GET_PXMX_SITE_MAP", {}, timeout=15.0)
        merged_map: dict = {}
        agents: list = []
        seen_agents: set = set()
        for _sid, data in results:
            if not isinstance(data, dict):
                continue
            for h, s in (data.get("pxmx_site_map") or {}).items():
                merged_map[str(h)] = s
            for a in (data.get("agents") or []):
                key = a.get("agent_id") or a.get("hostname")
                if key and key not in seen_agents:
                    seen_agents.add(key)
                    agents.append(a)
        if not results:
            return {"status": "SUCCESS", "pxmx_site_map": {}, "agents": [],
                    "warning": "Client-Sim spoke not connected."}
        out = {"status": "SUCCESS", "pxmx_site_map": merged_map, "agents": agents}
        _pxmx_site_map_cache[tenant_id] = (now + _PXMX_SITE_MAP_TTL_S, out)
        return out

    @app.post("/sim/api/{tenant}/pxmx-site-map")
    async def set_pxmx_site_map(tenant: str, request: Request,
                                tenant_id: str = Depends(get_tenant_id)):
        try:
            body = await request.json()
        except Exception:
            body = {}
        payload = body if isinstance(body, dict) else {}
        if "pxmx_site_map" not in payload and isinstance(body, dict):
            payload = {"pxmx_site_map": body}
        # Fan the FULL map out to every cs spoke — each keeps only its own agents'
        # entries but a shared map is harmless (a spoke ignores hosts it doesn't
        # host). Returns the merged saved map.
        results = await _cs_forward_all(tenant_id, "CS_SET_PXMX_SITE_MAP", payload, timeout=20.0)
        merged: dict = {}
        errors: list = []
        saved_any = False
        for _sid, data in results:
            if isinstance(data, dict) and data.get("status") == "SUCCESS":
                saved_any = True
                merged.update(data.get("pxmx_site_map") or {})
                errors.extend(data.get("errors") or [])
        _invalidate_pxmx_site_map(tenant_id)  # next GET re-fans-out the fresh map
        return {"saved": saved_any, "pxmx_site_map": merged, "errors": errors}

    @app.get("/sim/api/{tenant}/cs-agents")
    async def get_cs_agents(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Connected pxmx agents for the tenant's cs spoke (PXMX Sites dropdown)."""
        try:
            return await _cs_forward(tenant_id, "GET_AGENTS", {}, timeout=15.0)
        except HTTPException as he:
            if he.status_code == 503:
                return {"status": "SUCCESS", "agents": [], "pending_agents": [],
                        "warning": "Client-Sim spoke not connected."}
            raise

    @app.get("/sim/api/{tenant}/sim-quota-state")
    async def get_sim_quota_state(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Live SimQuotaEngine ledger for Config → Quota State: effective quotas +
        which clients are currently assigned to each. Forwards to the cs spoke;
        empty ledger when the spoke is down."""
        # Tenant-wide: merge the ledgers from ALL of the tenant's Client-Sim
        # spokes so the counts are tenant totals (cs-svr-02/03/04 together), not
        # bound[0]'s slice. The effective target comes from the hub (the tenant
        # config); each spoke fills its split share and we sum the assignments.
        results = await _cs_forward_all(tenant_id, "CS_GET_SIM_QUOTA_STATE", {}, timeout=15.0)
        merged_ledger: dict = {}
        monitored: list = []
        # Live per-check firing status merged across the tenant's cs spokes —
        # {site: {check_id: {status, message}}}. Each spoke polls its own site
        # slice, so a per-site union is correct (a site's status comes from the
        # spoke that owns it). Forwarded to the Engine State view so it can show
        # whether each alert/insight is firing using the SAME indicator the
        # dashboard Checks table uses (csStatusBadge), with no extra API query.
        check_status: dict = {}
        pool = {"online": 0, "by_site": {}, "tenant_pool": 0}   # cheap tenant-wide sum
        # The spoke's ACTUAL effective_sim_quotas (what its engine is running
        # against) — the hub pushes count to the spoke, but until it lands the
        # spoke runs a stale count. Capture per-quota count so the UI can show
        # the engine's real target vs. the controller's and flag a stale push
        # (the root cause of "4/15" that looks like an eligibility problem).
        spoke_counts: dict = {}
        # Per-quota "why (under)filled" diagnostics, summed across the tenant's cs
        # spokes (each fills its split share) — the same shape the spoke's
        # quota_diagnostics() returns. WITHOUT this the hub WebUI's Engine
        # Diagnostic is always empty (the spoke records it; the hub UI reads the
        # hub), so an underfilled quota gave no reason. blocked-reason counts sum;
        # target/assigned/eligible_free/not_harvestable sum; labels take first.
        merged_diag: dict = {}
        for _sid, data in results:
            if not isinstance(data, dict):
                continue
            for k, e in (data.get("ledger") or {}).items():
                m = merged_ledger.setdefault(
                    k, {"sim_id": e.get("sim_id"), "site": e.get("site"), "clients": []})
                m["clients"].extend(e.get("clients") or [])
            for d in (data.get("diagnostics") or []):
                if not isinstance(d, dict) or not d.get("key"):
                    continue
                md = merged_diag.get(d["key"])
                if md is None:
                    md = {"key": d["key"], "sim_id": d.get("sim_id"), "site": d.get("site"),
                          "claim": d.get("claim"), "multi": d.get("multi"),
                          "target": 0, "producing": 0, "assigned": 0,
                          "eligible_free": 0, "not_harvestable": 0, "blocked": {}}
                    merged_diag[d["key"]] = md
                for f in ("target", "producing", "assigned", "eligible_free", "not_harvestable"):
                    md[f] += int(d.get(f) or 0)
                for r, n in (d.get("blocked") or {}).items():
                    md["blocked"][r] = md["blocked"].get(r, 0) + int(n or 0)
            for q in (data.get("effective") or []):
                if isinstance(q, dict):
                    spoke_counts.setdefault(sim_quota.quota_dedup_key(q), int(q.get("count") or 0))
            p = data.get("pool") or {}
            pool["online"] += int(p.get("online") or 0)
            pool["tenant_pool"] += int(p.get("tenant_pool") or 0)
            for _s, _n in (p.get("by_site") or {}).items():
                pool["by_site"][_s] = pool["by_site"].get(_s, 0) + int(_n or 0)
            if not monitored:
                monitored = data.get("monitored_checks") or []
            for wsite, cmap in (data.get("check_status") or {}).items():
                if not isinstance(cmap, dict):
                    continue
                check_status.setdefault(wsite, {}).update(cmap)
        for m in merged_ledger.values():  # dedupe (a hostname is unique per tenant)
            m["clients"] = list(dict.fromkeys(m["clients"]))
        if not results:
            return {"status": "SUCCESS", "effective": [], "ledger": {},
                    "monitored_checks": [], "check_status": {},
                    "warning": "Client-Sim spoke not connected."}
        # Tenant-wide placement warnings: compare the merged fill to the tenant's
        # configured hold-N per cell (not each spoke's split share).
        placement_warnings: list = []
        try:
            csc = await store.get_central_sites_config(tenant_id) or {}
            for site, pcfg in (csc.get("ssid_placement") or {}).items():
                for cell, want in ((pcfg or {}).get("targets") or {}).items():
                    have = len((merged_ledger.get(f"placement:{site}:{cell}") or {}).get("clients") or [])
                    if have < int(want or 0):
                        placement_warnings.append(
                            {"site": site, "cell": cell, "have": have, "want": int(want or 0)})
        except Exception:  # noqa: BLE001
            pass
        eff_quotas = await _effective_sim_quotas(tenant_id)
        # Flag adaptive quotas whose spoke count (engine's real target) lags the
        # hub count (controller's applied target) — a push that hasn't landed yet,
        # which presents as "underfilled" but is really a stale count on the spoke.
        stale_push = _compute_stale_push(eff_quotas, spoke_counts)
        result = {"status": "SUCCESS",
                  "effective": eff_quotas,
                  "spoke_counts": spoke_counts,
                  "stale_push": stale_push,
                  "ledger": merged_ledger, "monitored_checks": monitored,
                  "placement_warnings": placement_warnings, "pool": pool,
                  "diagnostics": list(merged_diag.values()),
                  "check_status": check_status}
        try:
            result["adaptive_state"] = await store.get_adaptive_state(tenant_id)
        except Exception:  # noqa: BLE001
            pass
        return result

    @app.post("/sim/api/{tenant}/sim-quota-reset")
    async def reset_sim_quota_state(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Clear the engine ledger + engine-set overrides on EVERY bound spoke and
        reconcile fresh — a clean re-shuffle. Use to flush stale assignments (a
        client stuck in two quotas, or an ignored host lingering) after config or
        engine-model changes."""
        results = await _cs_forward_all(tenant_id, "CS_RESET_SIM_QUOTA", {}, timeout=30.0)
        return {"reset_spokes": sum(1 for _s, d in results
                                    if isinstance(d, dict) and d.get("status") != "ERROR"),
                "spokes": len(results)}

    # ── Sim-Quota global defaults (Setup → Simulations, superadmin) ──────────
    # Platform-wide default templates a tenant inherits unless it overrides per
    # alert_type:alert_id:site in Config → Sim Quotas. Validates against the full
    # SIM_META primitive set (global defaults aren't tied to one tenant's
    # simulation.conf). The catalog for this editor is the static SIM_META list
    # + the suggested linkage — no per-tenant site list (site is free-text /
    # "all sites" at the global level).
    @app.get("/sim/api/superadmin/sim-quota-defaults")
    async def get_sim_quota_defaults(request: Request):
        _require_admin(request)
        from .sim_quota import sim_quota_catalog_from_ini
        catalog = sim_quota_catalog_from_ini("")
        # Platform-wide Site list for the Defaults editor dropdown: the union of
        # sites every tenant's simulation.conf offers (relayed sim_conf_content in
        # the simulations_cache OR the stored override) plus each tenant's Central
        # site_mappings. Sims stay the full primitive catalog (a tenant's
        # simulation.conf may offer a subset); sites are pulled from the confs so
        # the editor offers a dropdown instead of free-text.
        catalog["sites"] = await _platform_wide_sim_quota_sites()
        # Shared alert/insight history (all tenants) so the Defaults editor's
        # Alert / Insight ID can be a dropdown of every alert ever seen — same
        # source the per-tenant Config → Sim Quotas picker uses.
        catalog["alerts"], catalog["insights"] = await _alert_insight_catalog()
        # Global Simulation Sharing (stacking) + N/A hide maps live here now.
        catalog["sim_shareable"] = await _sim_shareable()
        catalog["sim_na"] = await _sim_na()
        # Dongle-quarantine: the platform-wide exclusion-sim set (sims whose
        # no-IP/no-SSID outcome is the point — don't QT a client running only
        # these). A tenant csc ``qt_exclude_sims`` overrides per-tenant; this
        # is the global default the Sim-Quota Defaults editor curates.
        catalog["qt_exclude_sims"] = await store.get_qt_exclude_sims()
        return {"defaults": await store.get_sim_quota_defaults(),
                "catalog": catalog}

    # ── Observed Catalog (Setup → Simulations, superadmin) ───────────────────
    # A read-only view of the hub-wide catalog of every Central alert/insight
    # ever observed (all tenants), with occurrence counts — the same
    # __alert_insight_history__ that feeds every Sim-Quota picker, exposed whole
    # so an admin can browse/search what the poller and browse paths have seen.
    @app.get("/sim/api/superadmin/observed-catalog")
    async def get_observed_catalog(request: Request):
        """Admin-only: the full hub-wide alert/insight catalog, most-recent first."""
        _require_admin(request)
        try:
            catalog = await store.get_alert_insight_history()
        except Exception:  # noqa: BLE001
            catalog = []
        catalog = sorted(catalog, key=lambda e: float(e.get("last_seen") or 0), reverse=True)
        return {"catalog": catalog, "count": len(catalog)}

    async def _platform_wide_sim_quota_sites() -> list:
        """Union of sites known across all tenants — from each tenant's
        simulation.conf (cached relayed ``sim_conf_content`` or the stored
        override) and ``central_sites_config.site_mappings`` — so the
        platform-wide Sim Quota Defaults editor can offer a Site dropdown
        sourced from the actual simulation.conf content."""
        from .sim_quota import available_sites_from_ini
        sites: set = set()
        for data in (getattr(hub, "simulations_cache", {}) or {}).values():
            txt = (data or {}).get("sim_conf_content") or ""
            if txt:
                try:
                    sites.update(available_sites_from_ini(txt))
                except Exception:  # noqa: BLE001
                    pass
        for tid in _all_tenant_ids():
            try:
                txt = await store.get_sim_conf_content(tid) or ""
                if txt:
                    sites.update(available_sites_from_ini(txt))
            except Exception:  # noqa: BLE001
                pass
            try:
                csc = await store.get_central_sites_config(tid) or {}
                for k, v in (csc.get("site_mappings") or {}).items():
                    if k:
                        sites.add(str(k))
                    if v:
                        sites.add(str(v))
            except Exception:  # noqa: BLE001
                pass
        return sorted(s for s in sites if s)

    @app.put("/sim/api/superadmin/sim-quota-defaults")
    async def put_sim_quota_defaults(request: Request):
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        from .sim_quota import SIM_META, validate_sim_quotas
        clean, errs = validate_sim_quotas(
            (body or {}).get("defaults"), list(SIM_META.keys()))
        if errs:
            logger.warning("set_sim_quota_defaults: errors: %s", errs)
        await store.set_sim_quota_defaults(clean)
        # GLOBAL Simulation Sharing (stacking) + N/A hide maps, if present.
        if isinstance((body or {}).get("sim_shareable"), dict):
            await store.set_sim_shareable_global(
                {str(k): bool(v) for k, v in body["sim_shareable"].items()})
        if isinstance((body or {}).get("sim_na"), dict):
            await store.set_sim_na_global(
                {str(k): bool(v) for k, v in body["sim_na"].items()})
        # Dongle-quarantine exclusion sims (global default). Coerce to a list of
        # known sim ids; unknown ids are dropped (an admin typo shouldn't widen
        # the exclusion set silently). Empty list = exclude nothing (every sim
        # that never connects is shed); omitted = leave the stored set as-is.
        if isinstance((body or {}).get("qt_exclude_sims"), list):
            known = set(SIM_META.keys())
            cleaned_qt = [s for s in (body["qt_exclude_sims"] or [])
                          if str(s).strip() in known]
            await store.set_qt_exclude_sims(cleaned_qt)
        # Global sharing/N-A feed every tenant's catalog — clear the whole cache.
        _sim_quota_catalog_cache.clear()
        # A global-defaults / sharing change can shift every tenant's effective
        # quotas — re-push so each cs spoke's SimQuotaEngine reconciles (the push
        # carries the new global sim_shareable too).
        pushed = await _push_sim_quotas_all_tenants()
        return {"status": "saved", "defaults": clean, "errors": errs,
                "pushed_to_spokes": pushed}

    # ── Global Learned Values (Setup → Global Learned Values, superadmin) ──────
    # A Global Admin curates the platform-wide published learned operating points
    # (per alert). A learning tenant's lab rows produce stable learned_op values;
    # the Admin selects one and Publishes it here so every other tenant's
    # learning-OFF consumer rows seed/lift from it (applied_op = max(own, global)).
    @app.get("/sim/api/superadmin/learned-values/candidates")
    async def get_learned_value_candidates(request: Request):
        """Roll up every tenant's stable learning-ON ``learned_op`` per alert, so
        the Global Admin can pick one to Publish. Returns one row per
        (tenant, alert, site) that has reached ``stable`` with a recorded op."""
        _require_admin(request)
        from .sim_quota import _alert_key
        out = []
        for tid in _all_tenant_ids():
            try:
                state = await store.get_adaptive_state(tid)
            except Exception:  # noqa: BLE001
                continue
            for key, st in (state or {}).items():
                if not isinstance(st, dict) or st.get("phase") != "stable":
                    continue
                op = st.get("learned_op")
                if op is None:
                    continue
                # key = "{alert_type}:{alert_id}:{site}" (adaptive_key)
                head, _, site = key.rpartition(":")
                atype, _, aid = head.partition(":")
                out.append({"alert_key": _alert_key({"alert_type": atype, "alert_id": aid}),
                            "alert_type": atype or "alert", "alert_id": aid,
                            "site": site, "op": int(op),
                            "floor": st.get("floor"),
                            "source_tenant": tid})
        # Highest op per (tenant, alert_key) first for easy picking.
        out.sort(key=lambda r: (r["alert_key"], r["source_tenant"], -r["op"]))
        return {"candidates": out}

    @app.get("/sim/api/superadmin/global-learned-values")
    async def get_global_learned_values(request: Request):
        _require_admin(request)
        return {"published": await store.get_global_learned_values()}

    @app.put("/sim/api/superadmin/global-learned-values")
    async def put_global_learned_values(request: Request):
        """Publish the global learned-values registry. Body: ``{values: {
        alert_key: {op, floor, source_tenant, published_at?}}}``. Replaces the
        registry wholesale (the Admin curates the whole set in the UI). Each
        entry's ``published_at`` is stamped server-side when omitted. Force-pushes
        every tenant so consumers lift to the new op without waiting for a
        controller tick."""
        import time as _t
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        raw = (body or {}).get("values") or {}
        clean: dict = {}
        if isinstance(raw, dict):
            now = _t.time()
            for ak, v in raw.items():
                if not isinstance(v, dict) or v.get("op") is None:
                    continue
                try:
                    op = int(v.get("op"))
                except (TypeError, ValueError):
                    continue
                if op < 1:
                    continue
                clean[str(ak)] = {
                    "op": op,
                    "floor": int(v["floor"]) if v.get("floor") is not None else None,
                    "source_tenant": str(v.get("source_tenant") or ""),
                    "published_at": float(v.get("published_at") or now),
                }
        await store.set_global_learned_values(clean)
        pushed = await _push_sim_quotas_all_tenants()
        return {"status": "published", "values": clean, "pushed_to_spokes": pushed}

    # ── Known-good operating points (per tenant): view + reset-to-known-good ───
    @app.get("/sim/api/{tenant}/sim-quota/known-good")
    async def get_known_good_ops(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """The recorded known-good operating point per alert for this tenant —
        what the learner settled on ("exactly what it took"): count + the
        simulation.conf knobs + time-to-stable + when. Read-only; drives the UI."""
        return {"known_good": await store.get_known_good(tenant_id)}

    @app.post("/sim/api/{tenant}/sim-quota/reset-to-known-good")
    async def reset_to_known_good(tenant: str, request: Request,
                                  tenant_id: str = Depends(get_tenant_id)):
        """Restore this tenant's adaptive controllers to their recorded
        known-good (count + learned knobs), then reshuffle. A learning-ON alert
        HOLDS at the known-good count for 1h (all clients spin up + every sim
        fires) then resumes learning from there; a learning-OFF alert jumps +
        holds. Body: optional ``{alert_key}`` to scope to one alert, else all."""
        _require_admin(request)
        import time as _t
        from .sim_quota import normalize_quota, _alert_key as _ak, seed_state_to_known_good
        try:
            body = await request.json()
        except Exception:
            body = {}
        only_ak = (body or {}).get("alert_key")
        now = _t.time()
        kg_map = await store.get_known_good(tenant_id)
        if not kg_map:
            return {"status": "no_known_good",
                    "message": "No known-good recorded yet — let an alert reach 'stable' first."}
        csc = await store.get_central_sites_config(tenant_id) or {}
        quotas = [normalize_quota(r) for r in (csc.get("sim_quotas") or [])]
        state = await store.get_adaptive_state(tenant_id)
        knob_state = await store.get_knob_learn_state(tenant_id)
        restored = 0
        for q in quotas:
            if not (q.get("enabled") and _adaptive_is_on(q)):
                continue
            ak = _ak(q)
            if only_ak and ak != only_ak:
                continue
            kg = kg_map.get(ak)
            if not kg:
                continue
            # Restore the COUNT controller to the known-good (held if learning).
            state[_adaptive_key(q)] = seed_state_to_known_good(kg, bool(q.get("learning")), now)
            # Restore the learned simulation.conf KNOBS to what the snapshot took.
            if kg.get("knobs"):
                ent = dict(knob_state.get(_adaptive_key(q)) or {})
                ent["values"] = dict(kg["knobs"])
                knob_state[_adaptive_key(q)] = ent
            restored += 1
        if not restored:
            return {"status": "no_match",
                    "message": "No adaptive alert matched a recorded known-good."}
        await store.set_adaptive_state(tenant_id, state)
        await store.set_knob_learn_state(tenant_id, knob_state)
        # Reshuffle the placement ledger so clients redistribute to the restored
        # count, and push the restored quotas/knobs down to the spokes.
        await _cs_forward_all(tenant_id, "CS_RESET_SIM_QUOTA", {}, timeout=30.0)
        pushed = await _push_sim_quotas(tenant_id)
        return {"status": "ok", "restored_alerts": restored,
                "hold_seconds": 3600, "pushed_to_spokes": pushed}

    # ── Global learned-value APPROVAL QUEUE (superadmin) ──────────────────────
    @app.get("/sim/api/superadmin/global-learned-pending")
    async def get_global_learned_pending(request: Request):
        """Known-good operating points proposed by learning tenants, awaiting
        admin approval before they seed every tenant. Each: ``{count, floor,
        knobs, time_to_stable_s, source_tenant, proposed_at}`` keyed per alert."""
        _require_admin(request)
        return {"pending": await store.get_global_learned_pending(),
                "published": await store.get_global_learned_values()}

    @app.post("/sim/api/superadmin/global-learned-pending/approve")
    async def approve_global_learned_pending(request: Request):
        """Approve a proposed known-good → publish into global_learned_values
        (seeds every tenant). Body: ``{alert_key}`` or ``{alert_keys:[...]}``."""
        import time as _t
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        keys = list(body.get("alert_keys") or [])
        if body.get("alert_key"):
            keys.append(body["alert_key"])
        keys = [str(k) for k in keys if k]
        if not keys:
            raise HTTPException(status_code=400, detail="alert_key(s) required")
        pending = await store.get_global_learned_pending()
        published = await store.get_global_learned_values()
        now = _t.time()
        approved = []
        for ak in keys:
            p = pending.get(ak)
            if not isinstance(p, dict) or p.get("count") is None:
                continue
            published[ak] = {
                "op": int(p["count"]),
                "floor": int(p["floor"]) if p.get("floor") is not None else None,
                "knobs": dict(p.get("knobs") or {}),
                "time_to_stable_s": p.get("time_to_stable_s"),
                "source_tenant": str(p.get("source_tenant") or ""),
                "published_at": now,
            }
            pending.pop(ak, None)
            approved.append(ak)
        if not approved:
            raise HTTPException(status_code=404, detail="no matching pending entries")
        await store.set_global_learned_values(published)
        await store.set_global_learned_pending(pending)
        pushed = await _push_sim_quotas_all_tenants()
        return {"status": "approved", "approved": approved, "pushed_to_spokes": pushed}

    @app.post("/sim/api/superadmin/global-learned-pending/reject")
    async def reject_global_learned_pending(request: Request):
        """Discard a proposed known-good without publishing. Body: ``{alert_key}``."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        ak = str((body or {}).get("alert_key") or "")
        if not ak:
            raise HTTPException(status_code=400, detail="alert_key required")
        pending = await store.get_global_learned_pending()
        existed = pending.pop(ak, None) is not None
        if existed:
            await store.set_global_learned_pending(pending)
        return {"status": "rejected" if existed else "not_found", "alert_key": ak}

    @app.get("/sim/api/{tenant}/central/available")
    async def get_central_available(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Available-checks catalog (alerts/insights/hardware) for the Central API
        editor's monitored-check picker. Behavior depends on the tenant's
        ``processing_modes.central_api``:

        - **centralized** — the HUB fetches the catalog itself via
          ``aruba.get_central_available_from_config`` (new_central returns a
          static default catalog with no API call; classic live-fetches alert/
          insight types from the cluster gateway with a known-types fallback).
          The cs spoke is not contacted.
        - **distributed** (or unset) — forwards to the tenant's spoke via
          CS_GET_CENTRAL_AVAILABLE; degrades to an empty catalog when no spoke is
          connected (the editor still works with manual checks)."""
        modes = await store.get_processing_modes(tenant_id)
        if store.central_api_is_centralized(modes):  # unset defaults to centralized
            cc = await store.get_central_config(tenant_id)
            return await get_central_available_from_config(cc or {})
        try:
            return await _cs_forward(tenant_id, "CS_GET_CENTRAL_AVAILABLE", {}, timeout=15.0)
        except HTTPException:
            return {"alerts": [], "insights": [], "warning": "Client-Sim spoke not connected."}

    @app.post("/sim/api/{tenant}/test-central")
    async def test_central(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Live central connectivity check. Behavior depends on the tenant's
        ``processing_modes.central_api``:

        - **centralized** — the HUB holds the Aruba Central creds (Setup →
          Central API → ``central_config``) and runs a real token exchange
          itself via ``aruba.test_central_from_config`` (the hub's own minimal
          ArubaClient). Returns a single ``Hub (centralized)`` row.
        - **distributed** (or unset) — fans ``CS_TEST_CENTRAL`` out to each of
          the tenant's cs spokes; the spoke's ``central_poller.test_connection``
          runs the token exchange and logs the outcome to the spoke log. Falls
          back to the spoke's last relayed ``central`` telemetry when it is
          unreachable (stalled/disconnected) so the UI renders a row, not a 502.

        Previously this route only read cached relayed telemetry, so the button
        showed all-— on a hub-connected deployment (it never ran a live probe).
        A distributed-mode row that still shows all-— after this change means
        the spoke didn't respond within the fan-out timeout — check the hub log
        for the warning below and the spoke log for the CentralPoller entry."""
        out = []
        cache = _tenant_cache(tenant_id)
        # Centralized processing mode → the HUB holds the Aruba Central creds
        # (Setup → Central API → central_config) and makes the call itself; the
        # cs spoke is just a telemetry relay. Run a real token exchange on the
        # hub directly (the hub historically had no Aruba client, so this button
        # could never validate the creds the operator typed into the hub form).
        # Distributed mode → fan CS_TEST_CENTRAL out to the tenant's cs spokes.
        modes = await store.get_processing_modes(tenant_id)
        if store.central_api_is_centralized(modes):  # unset defaults to centralized
            cc = await store.get_central_config(tenant_id)
            return {"spokes": [await test_central_from_config(cc or {}, spoke_id="hub")]}
        # Registered Client-Sim spokes for this tenant (approved + bound, or
        # unassigned → claimable), looked up from module_metadata INDEPENDENT of
        # the CS_TELEMETRY cache. A stalled/flapping spoke that stopped relaying
        # telemetry drops out of `cache` but stays registered — without this
        # union the route returns an empty spokes list and the UI shows "No
        # spokes reporting central state" instead of a per-spoke "Spoke
        # unreachable" row that actually names the culprit spoke.
        md = hub.state.system_state.get("module_metadata", {}) or {}
        cs_types = {"Client-Sim", "simulation"}
        reg_sids = []
        for sid, meta in md.items():
            if not isinstance(meta, dict) or meta.get("module_type") not in cs_types:
                continue
            if not getattr(hub, "approved_modules", {}).get(hub._primary_key(sid), False):
                continue
            tid = meta.get("tenant_id")
            if tid == tenant_id or not tid:
                reg_sids.append(sid)
        all_sids = list(dict.fromkeys(list(cache.keys()) + reg_sids))
        for sid in all_sids:
            data = cache.get(sid, {})
            cached_central = data.get("central") or {}
            live_entry: Optional[dict] = None
            try:
                result = await hub.request_response(sid, "CS_TEST_CENTRAL", {}, timeout=8.0)
                payload = (result.get("payload", {}) or {}).get("data", result) if isinstance(result, dict) else result
                spokes = (payload or {}).get("spokes") if isinstance(payload, dict) else None
                if spokes:
                    live_entry = spokes[0]
            except Exception as exc:
                logger.warning("test_central: CS_TEST_CENTRAL fan-out to %s failed: %s",
                               sid, exc)
            if live_entry:
                out.append({"spoke_id": sid,
                            "spoke_name": live_entry.get("spoke_name") or data.get("spoke_name") or sid,
                            "token_state": live_entry.get("token_state"),
                            "token_valid": live_entry.get("token_valid"),
                            "status": live_entry.get("status")})
            else:
                # Spoke unreachable (stalled/disconnected) — surface cached
                # relayed state so the UI renders a row, not a 502. A registered
                # spoke with no cached telemetry (never relayed / evicted) shows
                # "Spoke unreachable — see hub log." so the operator knows WHICH
                # spoke is the culprit instead of a generic "No spokes reporting".
                out.append({"spoke_id": sid, "spoke_name": data.get("spoke_name") or sid,
                            "token_state": cached_central.get("token_state"),
                            "token_valid": cached_central.get("token_valid"),
                            "status": cached_central.get("status") or "Spoke unreachable — see hub log."})
        return {"spokes": out}

    @app.get("/sim/api/{tenant}/troubleshooting")
    async def get_troubleshooting(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        spokes = []
        for sid, data in _tenant_cache(tenant_id).items():
            api = data.get("api_server") or {}
            health = api.get("health") or {} if isinstance(api, dict) else {}
            spokes.append({"spoke_id": sid, "spoke_name": data.get("spoke_name") or sid,
                           "api_health": health,
                           "reclone_state": data.get("reclone_state") or {}})
        return {"spokes": spokes}

    # --- WebSocket Route ---

    @app.websocket("/sim/ws")
    async def simulation_websocket(websocket: WebSocket):
        # The http access_control_middleware does not cover WebSocket handshakes,
        # so enforce the Simulations module right here: admin OR the explicit
        # ``cs`` right. Reject before subscribing so a non-authorized user gets
        # no Simulations telemetry stream. The session is read from the
        # handshake cookie — Starlette WebSocket exposes ``.cookies`` like
        # Request (it has no ``.request`` attribute, so the old lookup always
        # yielded None and rejected even admins with a 1008 close).
        sess = session_user_fn(websocket)
        cs_ok = bool(is_admin_fn(sess)) or bool(has_cs_access_fn and has_cs_access_fn(sess))
        if not cs_ok:
            await websocket.accept()
            await websocket.close(code=1008, reason="Simulations module access required")
            return
        tenant_id = resolve_tenant_fn(websocket)
        is_admin = bool(is_admin_fn(sess))
        await websocket.accept()
        hub.simulations_broadcaster.subscribe(websocket, tenant_id, is_admin)
        try:
            while True:
                await websocket.receive_text() # Keep connection alive
        except Exception:
            hub.simulations_broadcaster.unsubscribe(websocket, tenant_id, is_admin)
