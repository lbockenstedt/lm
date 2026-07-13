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
from typing import Any, Dict
import asyncio
import configparser
from datetime import datetime, timezone
import hmac
import inspect
import json
import logging
import re
from .service import SimulationsService
from .aruba import test_central_from_config, get_central_available_from_config, browse_all_from_config
from .sim_quota import validate_sim_quotas, sim_quota_catalog_from_ini, available_sims_from_ini
from access import safe_external_url, host_resolves_external
from urllib.parse import urlsplit

logger = logging.getLogger("SimRoutes")


def _parse_ini_sections(text: str) -> Dict[str, Dict[str, str]]:
    """Parse raw INI ``text`` into ``{section: {key: value}}`` (case-preserving).

    Used by the Sim Config editor's structured view (``GET .../simulation-conf-parsed``).
    A malformed file degrades to an empty dict (never raises) so a bad override
    doesn't 500 the editor — the UI shows the raw text fallback instead.
    """
    p = configparser.ConfigParser()
    p.optionxform = str  # preserve key case (matches sim_config._new_parser)
    try:
        p.read_string(text or "")
    except configparser.Error:
        return {}
    return {section: dict(p.items(section)) for section in p.sections()}


def _now_iso() -> str:
    """UTC now as an ISO-8601 string (for ``fetched_at`` stamps in config reads)."""
    return datetime.now(timezone.utc).isoformat()

_USB_VIDPID_RE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{4}$")
# Allowed dongle classes. The Global USB Approvals UI offers these; the
# tenant approval surfaces (Per-Tenant USB + per-host Certify) send one of
# them so a tenant can classify a VID:PID as wired vs wireless etc. Anything
# outside the set falls back to "wireless" (the historic default). pxmx's
# _sim_phy_accepts matches dongle type against sim_phy {wireless, ethernet,
# any}; "wireless" binds to wireless/any sims, the others bind only to
# sim_phy=any until the pxmx enforcement domain is widened (separate change).
_USB_TYPES = ("wireless", "wired", "storage", "other")


def _normalize_usb_vidpids(raw: Any) -> list:
    """Normalize a stored ``usb_vidpids`` value into a list of
    ``{vidpid, type, label}`` dicts (the cs-spoke re-filter shape). Accepts:
    a JSON string of such a list, a JSON string of bare vidpid strings, an
    already-parsed list, or a legacy comma-joined bare-vidpid string. Invalid
    vidpids are dropped."""
    items = _coerce_vidpid_items(raw)
    out: list = []
    seen: set = set()
    for it in items:
        if isinstance(it, dict):
            vp = str(it.get("vidpid", "")).strip().lower()
            if not _USB_VIDPID_RE.match(vp) or vp in seen:
                continue
            seen.add(vp)
            out.append({"vidpid": vp,
                        "type": str(it.get("type") or "wireless"),
                        "label": str(it.get("label") or vp)})
        else:
            vp = str(it).strip().lower()
            if not _USB_VIDPID_RE.match(vp) or vp in seen:
                continue
            seen.add(vp)
            out.append({"vidpid": vp, "type": "wireless", "label": vp})
    return out


def _normalize_usb_ignored(raw: Any) -> list:
    """Normalize a stored ``usb_ignored_vidpids`` value into a sorted list of
    bare lowercased vidpid strings (the cs-spoke re-filter shape). Accepts the
    same shapes as ``_normalize_usb_vidpids`` (dicts → their ``vidpid``)."""
    items = _coerce_vidpid_items(raw)
    out: set = set()
    for it in items:
        vp = (it.get("vidpid") if isinstance(it, dict) else it)
        vp = str(vp or "").strip().lower()
        if _USB_VIDPID_RE.match(vp):
            out.add(vp)
    return sorted(out)


def _coerce_vidpid_items(raw: Any) -> list:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    s = str(raw).strip()
    if not s:
        return []
    # JSON array?
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, ValueError):
            return []
    # Legacy comma-joined bare vidpids.
    return [p.strip() for p in s.split(",") if p.strip()]


# ── Setup/Proxmox hub-config list fields ─────────────────────────────────────
# The WebUI collects these as comma/space-delimited text (no more raw JSON),
# but downstream — cs spoke _parse_json_list → pxmx agent — expects a list. The
# hub is source of truth for hub_config, so a delimited string is normalized into
# a list once, here, before store.set_hub_config + _push_config. Already-list or
# already-JSON values pass through (backward compat with older clients and
# pre-existing stored snapshots). usb_vidpids is a list of {vidpid,type,label};
# type/label are preserved from the currently-stored entry when the same vidpid
# already exists, so editing the field as a plain vidpid list does NOT discard
# metadata a user set via another UI.
_HUB_CONFIG_LIST_KEYS = (
    "usb_ignored_vidpids",   # list of "vid:pid"
    "t1_pci_vidpids",        # list of "vid:pid"
    "t3_pci_vidpids",        # list of "vid:pid"
    "ignored_hostnames",     # list of str
)
_HUB_CONFIG_VIDPID_OBJ_KEY = "usb_vidpids"  # list of {vidpid,type,label}


def _split_delim(s: str) -> list:
    """Split a comma/space/newline-delimited string into trimmed tokens."""
    return [p.strip() for p in re.split(r"[,\s]+", s) if p.strip()]


def _coerce_to_list(raw: Any) -> list:
    """Best-effort raw → list. Accepts an already-parsed list, a JSON array
    string, or a delimited string. Returns [] for empty/None."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    s = str(raw).strip()
    if not s:
        return []
    if s.startswith("["):
        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, ValueError):
            pass
    return _split_delim(s)


def _hub_config_list_value(key: str, raw: Any, stored_raw: Any = None) -> list:
    """Normalize one Setup/Proxmox list field for storage/push.

    vidpid string-list keys → deduped list of lowercased ``vid:pid`` (non-vidpid
    tokens dropped). ``ignored_hostnames`` → deduped list of non-empty strings
    (order preserved, case kept). ``usb_vidpids`` → deduped list of
    ``{vidpid,type,label}`` dicts, reusing the stored entry's type/label when the
    same vidpid already exists (else type ``"wireless"``, label = vidpid).
    """
    if key == _HUB_CONFIG_VIDPID_OBJ_KEY:
        items = _coerce_to_list(raw)
        prev: Dict[str, Dict[str, str]] = {}
        for it in _coerce_to_list(stored_raw):
            if isinstance(it, dict) and it.get("vidpid"):
                vp = str(it["vidpid"]).strip().lower()
                if _USB_VIDPID_RE.match(vp):
                    prev[vp] = {"type": str(it.get("type") or "wireless"),
                                "label": str(it.get("label") or vp)}
        out, seen = [], set()
        for it in items:
            vp = str(it.get("vidpid", "") if isinstance(it, dict) else it).strip().lower()
            if not _USB_VIDPID_RE.match(vp) or vp in seen:
                continue
            seen.add(vp)
            if isinstance(it, dict):
                # Already an object — keep its own type/label (defaults if missing).
                out.append({"vidpid": vp,
                            "type": str(it.get("type") or "wireless"),
                            "label": str(it.get("label") or vp)})
            else:
                # Bare vidpid from a delimited string — reuse stored type/label
                # when this vidpid already existed, else default.
                p = prev.get(vp)
                out.append({"vidpid": vp,
                            "type": p["type"] if p else "wireless",
                            "label": p["label"] if p else vp})
        return out
    items = _coerce_to_list(raw)
    if key == "ignored_hostnames":
        out, seen = [], set()
        for it in items:
            s = str(it).strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out
    out, seen = [], set()
    for it in items:
        vp = str(it.get("vidpid", "") if isinstance(it, dict) else it).strip().lower()
        if _USB_VIDPID_RE.match(vp) and vp not in seen:
            seen.add(vp)
            out.append(vp)
    return out


def normalize_hub_config_lists(hc: Any, stored_hc: Any = None) -> dict:
    """Return a copy of ``hc`` with the Setup/Proxmox list fields normalized to
    lists. The PUT /hub-config route calls this before persisting+pushing so the
    WebUI may send comma/space-delimited strings instead of raw JSON. Fields not
    present in ``hc`` are left untouched (the UI omits empty fields)."""
    if not isinstance(hc, dict):
        return hc
    out = dict(hc)
    stored_hc = stored_hc or {}
    for k in _HUB_CONFIG_LIST_KEYS:
        if k in out:
            out[k] = _hub_config_list_value(k, out[k], stored_hc.get(k))
    if _HUB_CONFIG_VIDPID_OBJ_KEY in out:
        out[_HUB_CONFIG_VIDPID_OBJ_KEY] = _hub_config_list_value(
            _HUB_CONFIG_VIDPID_OBJ_KEY, out[_HUB_CONFIG_VIDPID_OBJ_KEY],
            stored_hc.get(_HUB_CONFIG_VIDPID_OBJ_KEY))
    return out


def _usb_dev_vidpid(dev: Any) -> str:
    """Lowercased ``vid:pid`` for a USB device/state entry. Entries carry either
    explicit ``vid``+``pid`` fields or a single ``vidpid`` string."""
    if not isinstance(dev, dict):
        return ""
    vid, pid = dev.get("vid"), dev.get("pid")
    if vid is not None and pid is not None and str(vid).strip() and str(pid).strip():
        return f"{vid}:{pid}".strip().lower()
    return str(dev.get("vidpid") or "").strip().lower()


def _reclassify_host_usb(host: dict, ign: set, g_cert: dict, t_cert: dict) -> dict:
    """Apply the hub's effective USB certified/ignored sets to a proxmox host
    payload so the tenant UI reflects admin/tenant decisions even before the
    spoke re-filters its telemetry. Works on copies so the cached telemetry is
    never mutated.

    ``g_cert`` / ``t_cert`` are ``{vidpid: type}`` maps (global / tenant-local
    certified dongle class); tenant-local wins on overlap.
      * ignored vid:pids are dropped from present_usb / unknown_usb /
        usb_state / usb_devices and usb_count is recomputed to match;
      * any certified vid:pid (global or local) is removed from unknown_usb so
        a dongle already approved never still shows as "to be certified", and is
        added to present_usb if not already there;
      * each certified device is tagged with approval_scope (global / local /
        global+local) so the UI can show how it was approved, and its saved
        ``type`` (wired/wireless/...) is written onto the device dict so the
        UI's Wired/Wireless dropdown reflects the operator's choice immediately
        instead of reverting to stale spoke telemetry on the post-save
        re-render."""
    cert = {**g_cert, **t_cert}  # tenant-local type wins on overlap
    if not ign and not cert:
        return host
    px = host.get("proxmox")
    if isinstance(px, dict):
        px = dict(px)  # shallow copy — don't mutate the cached proxmox dict
        for key in ("present_usb", "unknown_usb", "usb_state"):
            v = px.get(key)
            if isinstance(v, list):
                px[key] = [d for d in v if _usb_dev_vidpid(d) not in ign]
        if cert:
            present = list(px.get("present_usb")) if isinstance(px.get("present_usb"), list) else []
            # present_usb / unknown_usb are PER PHYSICAL DONGLE (keyed by
            # bus_path), so multiple instances of the same vid:pid are legitimate
            # — 10 dongles of one type must count as 10, not collapse to 1.
            # Dedup only by bus_path (a true duplicate: the same physical device
            # already represented in present).
            present_paths = {(d.get("bus_path") if isinstance(d, dict) else None)
                             for d in present}
            unknown = px.get("unknown_usb")
            if isinstance(unknown, list):
                leftover = []
                for d in unknown:
                    vp = _usb_dev_vidpid(d)
                    if vp in cert:
                        # Certified (global or local) → move EVERY physical
                        # instance to present_usb. The old vidpid-dedup dropped
                        # all but the first, undercounting duplicate dongles (the
                        # "10 of one type → counted as 1" bug).
                        bp = d.get("bus_path") if isinstance(d, dict) else None
                        if bp and bp in present_paths:
                            continue  # same physical device already in present
                        present.append(d)
                        if bp:
                            present_paths.add(bp)
                    else:
                        leftover.append(d)
                px["unknown_usb"] = leftover
            # Tag each certified device with its approval scope (copy each dict so
            # cached device dicts aren't mutated).
            tagged = []
            for d in present:
                if isinstance(d, dict):
                    d = dict(d)
                    vp = _usb_dev_vidpid(d)
                    in_g, in_t = vp in g_cert, vp in t_cert
                    d["approval_scope"] = ("global+local" if (in_g and in_t)
                                            else "global" if in_g
                                            else "local" if in_t else "")
                    # Stamp the hub's saved dongle class onto the device so the
                    # UI's Wired/Wireless dropdown reflects the operator's
                    # choice immediately. Without this the post-save re-render
                    # rebuilds the dropdown from stale spoke telemetry
                    # (present_usb[].type) and the selection appears to revert.
                    saved_type = cert.get(vp)
                    if saved_type:
                        d["type"] = saved_type
                tagged.append(d)
            px["present_usb"] = tagged
        host["proxmox"] = px
    devs = host.get("usb_devices")
    if isinstance(devs, list):
        host["usb_devices"] = [d for d in devs if _usb_dev_vidpid(d) not in ign]
    host["usb_count"] = len(host.get("usb_devices") or [])
    return host


def _usb_keys_summary(node) -> dict:
    """Report which USB-related keys exist on a dict and, for list/dict ones,
    their length — enough to see the cs spoke's payload SHAPE without exposing
    any values (a CS payload may carry Proxmox tokens in other frames)."""
    if not isinstance(node, dict):
        return {}
    out = {}
    for k in ("present_usb", "unknown_usb", "usb_state",
              "usb_devices", "usb_count", "vm_count", "proxmox_vms"):
        if k in node:
            v = node[k]
            if isinstance(v, list):
                out[k] = f"list[{len(v)}]"
            elif isinstance(v, dict):
                out[k] = f"dict[{len(v)}]"
            else:
                out[k] = repr(v)
    return out


def _usb_structure_dump(data: dict) -> dict:
    """Summarize where USB data lives in one cached CS_TELEMETRY payload:
    top-level keys, payload shape (multi-host vs legacy), and which USB keys
    exist on ``proxmox`` vs the host top-level. Values are never returned."""
    data = data or {}
    entry = {"top_level_keys": sorted(data.keys() if isinstance(data, dict) else [])}
    ph = data.get("proxmox_hosts")
    if isinstance(ph, list) and ph:
        entry["shape"] = "multi-host"
        entry["proxmox_hosts"] = [
            {
                "host_keys": sorted((hh.keys() if isinstance(hh, dict) else [])),
                "proxmox.usb": _usb_keys_summary((hh or {}).get("proxmox")),
                "top.usb": _usb_keys_summary(hh),
            }
            for hh in ph
        ]
    else:
        entry["shape"] = "legacy"
        entry["proxmox.usb"] = _usb_keys_summary(data.get("proxmox"))
        entry["top.usb"] = _usb_keys_summary(data)
    return entry


def _usb_provisioning_status_payload(cfg: Dict[str, Any],
                                     tenant_cache: Dict[str, Any],
                                     agent_config: Dict[str, Any],
                                     tenant_id: Any) -> Dict[str, Any]:
    """Build the ``/usb-provisioning-status`` response (pure — no hub/store
    access — so it is unit-testable; the route gathers the inputs and calls
    this).

    Returns the tenant ``usb_auto_provision`` toggle, per-spoke USB counts plus
    the ``provision`` diagnostic (primary host + per-host ``hosts``), and the
    count of hypervisor agents with ``client_simulation.enabled`` for this
    tenant. ``provision`` carries WHY the last pass provisioned nothing (reason
    / ``loop_running`` heartbeat / config snapshot) so the WebUI Auto-Provisioning
    card can surface the silent gates (no dongle_vidpids / no template ids) and
    the "Auto-Provisioning on but no host has CS enabled" mismatch instead of
    grepping the pxmx agent log.
    """
    spokes: List[Dict[str, Any]] = []
    for sid, data in (tenant_cache or {}).items():
        if not isinstance(data, dict):
            continue
        px = data.get("proxmox") or {}
        px_prov = px.get("provision") if isinstance(px, dict) else None
        hosts: List[Dict[str, Any]] = []
        for h in (data.get("proxmox_hosts") or []):
            if not isinstance(h, dict):
                continue
            hp = h.get("proxmox") or {}
            hosts.append({
                "hostname": h.get("hostname") or h.get("spoke_name") or sid,
                "provision": hp.get("provision") or {} if isinstance(hp, dict) else {},
            })
        # present_usb / unknown_usb are PER PHYSICAL DONGLE and, in the
        # multi-host shape the cs spoke emits, live on each Proxmox host's OWN
        # proxmox block (data.proxmox_hosts[].proxmox) — the spoke-level
        # data.proxmox is empty there. Sum across hosts (mirroring
        # service.get_proxmox_data, which expands proxmox_hosts into the VM
        # Server rows) so the Setup "Present USB" count matches the USB view
        # instead of reading 0; fall back to the spoke-level block for the
        # legacy single-host shape.
        host_list = data.get("proxmox_hosts") or []
        if isinstance(host_list, list) and host_list:
            present = sum(len((h.get("proxmox") or {}).get("present_usb") or [])
                          for h in host_list if isinstance(h, dict))
            unknown = sum(len((h.get("proxmox") or {}).get("unknown_usb") or [])
                         for h in host_list if isinstance(h, dict))
        else:
            present = len(px.get("present_usb") or []) if isinstance(px, dict) else 0
            unknown = len(px.get("unknown_usb") or []) if isinstance(px, dict) else 0
        spokes.append({
            "spoke_id": sid, "spoke_name": data.get("spoke_name") or sid,
            "usb_auto_provision": px.get("usb_auto_provision") if isinstance(px, dict) else None,
            "present_usb": present,
            "unknown_usb": unknown,
            "provision": px_prov or {},
            "hosts": hosts,
        })
    # Per-agent ``client_simulation.enabled`` is what actually spawns the provision
    # loop; the tenant toggle alone provisions nothing without it. Counting it
    # (tenant-scoped) lets the UI warn about the most common "I enabled it but
    # nothing happens" cause. ``str()``-coerced so int/str tenant ids both match.
    tid = str(tenant_id or "")
    cs_enabled_agent_count = 0
    for ac in (agent_config or {}).values():
        if not isinstance(ac, dict):
            continue
        cs = ac.get("client_simulation") or {}
        if isinstance(cs, dict) and cs.get("enabled") \
                and str(cs.get("tenant_id") or "") == tid:
            cs_enabled_agent_count += 1
    return {"usb_auto_provision": (cfg or {}).get("usb_auto_provision", "off"),
            "spokes": spokes,
            "cs_enabled_agent_count": cs_enabled_agent_count}


def _cached_command_queue(hub_obj, sid):
    """The cs spoke's command queue from its cached CS_TELEMETRY payload, or
    None if not cached (cold start / spoke reconnecting). The cs spoke includes
    ``command_queue`` in every ~10s telemetry frame, so this lets the VM Server
    → Command Queue view load instantly instead of a live 15s
    ``request_response`` that stalls when the spoke is busy. Returns None for a
    non-list so the caller falls back to the live fetch rather than rendering a
    malformed queue."""
    cached = (getattr(hub_obj, "simulations_cache", {}) or {}).get(sid) or {}
    cq = cached.get("command_queue")
    return cq if isinstance(cq, list) else None


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

        async def _one(sid: str):
            """Push to one spoke. Returns (1, queued, msg) on delivery (live OR
            queued — a queued push still counts, it WILL apply on reconnect),
            (0, False, '') on transport failure."""
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
        global certified/ignored change so all tenants pick up the new devices."""
        pushed = 0
        for tid in _all_tenant_ids():
            pushed += await _push_usb_to_tenant(tid)
        return pushed

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
            return resolve_effective_quotas(t_csc.get("sim_quotas"), list(SIM_META.keys()))
        try:
            g_defaults = await store.get_sim_quota_defaults()
        except Exception:  # noqa: BLE001
            g_defaults = []
        merged = merge_effective_quotas(g_defaults, t_csc.get("sim_quotas"))
        return await _apply_adaptive_targets(tenant_id, merged)

    def _adaptive_is_on(q: dict) -> bool:
        """A quota is adaptive when it declares a max above its min (design §9).
        Fixed-count quotas (no min/max, or min==max) are left untouched."""
        try:
            return int(q.get("max")) > int(q.get("min") or 1)
        except (TypeError, ValueError):
            return False

    def _adaptive_key(q: dict) -> str:
        return f"{q.get('alert_type', 'alert')}:{q.get('alert_id', '')}:{q.get('site', '')}"

    async def _apply_adaptive_targets(tenant_id: str, quotas: list) -> list:
        """Replace an adaptive quota's ``count`` with the controller's current
        target (stored state; the controller loop advances it). A quota with no
        controller state yet starts at its ``min``."""
        adaptive = [q for q in quotas if _adaptive_is_on(q)]
        if not adaptive:
            return quotas
        try:
            state = await store.get_adaptive_state(tenant_id)
        except Exception:  # noqa: BLE001
            state = {}
        for q in adaptive:
            st = state.get(_adaptive_key(q)) or {}
            tgt = st.get("target")
            q["count"] = int(tgt) if tgt is not None else int(q.get("min") or 1)
        return quotas

    def _ceil(x: float) -> int:
        xi = int(x)
        return xi + 1 if x > xi else xi

    def _adaptive_step(st: dict, q: dict, firing, now: float) -> dict:
        """Advance one controller tick (design §9). ``firing`` is True/False/None
        (None = unknown → hold). Ramp up fast when not firing; when firing, learn
        the floor (min sufficient) and hold at floor×(1+buffer), decaying slowly
        toward it. Respects a settle window between changes."""
        mn = int(q.get("min") or 1)
        mx = max(mn, int(q.get("max") or mn))
        step = max(1, int(q.get("step") or 1))
        settle = float(q.get("settle") or 120)
        buffer = float(q.get("buffer") if q.get("buffer") is not None else 0.20)
        target = st.get("target")
        floor = st.get("floor")
        last = float(st.get("last_change") or 0)
        mode = st.get("mode") or "learning"
        if target is None:  # cold start (or warm-start from a persisted floor)
            if floor is not None:
                target = min(mx, max(mn, _ceil(float(floor) * (1 + buffer))))
                mode = "stable"
            else:
                target, mode = mn, "learning"
        target = max(mn, min(mx, int(target)))
        if (now - last) >= settle:
            if firing is False:
                if target >= mx:
                    mode = "at_max"
                else:
                    target = min(mx, target + step); mode = "learning"; last = now
            elif firing is True:
                floor = target if floor is None else min(int(floor), target)
                op = max(mn, _ceil(float(floor) * (1 + buffer)))
                if target > op:  # decay toward the operating point to probe lower
                    target = max(op, target - step); last = now
                mode = "stable"
            # firing None → hold
        return {"target": max(mn, min(mx, int(target))), "floor": floor,
                "mode": mode, "last_change": last}

    _adaptive_firing_cache: dict = {}

    async def _alert_firing(tenant_id: str, q: dict):
        """Best-effort: is this quota's alert currently firing at its site?
        Reads active Central alerts (mode-aware, cached ~30s). Returns None when
        the signal is unavailable, so the controller safely holds."""
        import time as _t
        now = _t.time()
        cached = _adaptive_firing_cache.get(tenant_id)
        if cached and now - cached[0] < 30:
            fmap = cached[1]
        else:
            fmap = {}
            try:
                modes = await store.get_processing_modes(tenant_id)
                if modes.get("central_api") == "centralized":
                    browse = await browse_all_from_config(await store.get_central_config(tenant_id) or {})
                else:
                    browse = await _cs_forward(tenant_id, "CS_CENTRAL_BROWSE", {}, timeout=20.0)
                for a in (browse or {}).get("alerts", []) or []:
                    if str(a.get("status") or "active").lower() == "cleared":
                        continue
                    nm = str(a.get("name") or a.get("category") or "").strip().lower()
                    if nm:
                        fmap.setdefault(nm, set()).add(str(a.get("site") or "").strip())
            except Exception:  # noqa: BLE001
                fmap = {}
            _adaptive_firing_cache[tenant_id] = (now, fmap)
        if not fmap:
            return None
        sites = fmap.get(str(q.get("alert_id") or "").strip().lower())
        if sites is None:
            return False
        site = str(q.get("site") or "").strip()
        return True if not site else (site in sites or "" in sites or "—" in sites)

    async def _run_adaptive_controller() -> None:
        """One controller pass over every tenant's adaptive quotas — advance the
        target and re-push when it moves. Small (per-quota state)."""
        import time as _t
        from .sim_quota import normalize_quota
        now = _t.time()
        for tid in _all_tenant_ids():
            try:
                csc = await store.get_central_sites_config(tid) or {}
                adaptive = [q for q in (normalize_quota(r) for r in (csc.get("sim_quotas") or []))
                            if q.get("enabled") and _adaptive_is_on(q)]
                if not adaptive:
                    continue
                state = await store.get_adaptive_state(tid)
                changed = False
                live = set()
                for q in adaptive:
                    k = _adaptive_key(q); live.add(k)
                    firing = await _alert_firing(tid, q)
                    before = dict(state.get(k) or {})
                    after = _adaptive_step(before, q, firing, now)
                    if after != before:
                        state[k] = after; changed = True
                for k in list(state.keys()):
                    if k not in live:
                        state.pop(k, None); changed = True
                if changed:
                    await store.set_adaptive_state(tid, state)
                    await _push_sim_quotas(tid)
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
                                  "site": a.get("site") or ""})
            for i in (browse.get("insights") or []):
                ident = str((i.get("name") or i.get("category") or "")).strip()
                if ident:
                    items.append({"type": "insight", "id": ident, "name": i.get("name") or ident,
                                  "site": i.get("site") or ""})
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
        return out

    async def _push_sim_quotas(tenant_id: str) -> int:
        """Push the tenant's effective sim quotas + per-sim shareable overrides +
        pool/SSID config to its cs spoke(s) as a CS_CONFIG_UPDATE the
        SimQuotaEngine reconciles against."""
        return await _push_config(tenant_id, {
            "effective_sim_quotas": await _effective_sim_quotas(tenant_id),
            "sim_shareable": await _sim_shareable(tenant_id),
            **await _pool_config(tenant_id),
        })

    async def _push_sim_quotas_all_tenants() -> int:
        """Re-push effective sim quotas to every tenant after a global-defaults
        change (Setup → Simulations → Sim Quotas)."""
        pushed = 0
        for tid in _all_tenant_ids():
            pushed += await _push_sim_quotas(tid)
        return pushed

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
                    {"spoke_id": sid, "online": sid in getattr(hub, "active_connections", {}),
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
                 "online": sid in getattr(hub, "active_connections", {}),
                 **_usb_structure_dump(raw)}
                for sid, raw in service._spokes_for_tenant(tenant_id)
            ],
        }

    @app.get("/sim/api/aggregate/central")
    async def get_central(tenant_id: str = Depends(get_tenant_id)):
        return await service.get_central_data(tenant_id)

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
        if modes.get("central_api") == "centralized":
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
                "online": sid in getattr(hub, "active_connections", {}),
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
                if t_id not in user_tenants or not approved.get(sid, False):
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
                "connected": sid in conns,
                "approved": bool(approved.get(sid, False)),
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
        hub.state.save_state()
        return {"saved": True, "spoke_id": spoke_id, "label": str(label).strip()}

    @app.patch("/sim/api/{tenant}/spokes/{spoke_id}/assigned-site")
    async def cs_spoke_set_assigned_site(request: Request, tenant: str, spoke_id: str,
                                          tenant_id: str = Depends(get_tenant_id)):
        _require_admin(request)
        body = await request.json()
        site = (body or {}).get("site", "")
        hub.state.update_module_metadata(spoke_id, {"assigned_site": site or ""})
        hub.state.save_state()
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
        hub.approved_modules[spoke_id] = approved
        if (body or {}).get("tenant_id"):
            hub.state.set_spoke_tenant(spoke_id, body["tenant_id"])
        hub.state.save_state()
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
        ws = hub.active_connections.get(spoke_id)
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
            hub.key_manager.delete_spoke_key(spoke_id)
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
        pushed = await _push_config(tenant_id, {"sim_conf_override": content,
                                                "config_source": source})
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

        Does a spoke round-trip ``CS_GET_CONFIG`` to read the MERGED effective
        config (base repo file + hub-managed override). Falls back to the stored
        ``sim_conf_content`` override when the spoke is offline so the editor
        still renders. ``source`` says which: ``spoke`` | ``stored-override``.
        """
        raw = ""
        source = "stored-override"
        mode = "local"
        try:
            data = await _cs_forward(tenant_id, "CS_GET_CONFIG", {}, timeout=6.0)
            raw = (data or {}).get("simulation_conf", "") if isinstance(data, dict) else ""
            mode = (data or {}).get("mode", "local") if isinstance(data, dict) else "local"
            source = "spoke"
        except HTTPException as exc:
            # Round-trip failed — fall back to the stored override text so the
            # editor still loads (read-only feel; save will re-push).
            logger.info("sim-conf-parsed: CS_GET_CONFIG fell back to stored override (%s)", exc.detail)
            raw = await store.get_sim_conf_content(tenant_id)
        # Distinguish a truly-offline spoke from one that IS connected but whose
        # live CS_GET_CONFIG round-trip failed/timed out (e.g. its event loop was
        # momentarily busy) — the editor mislabeled the latter as "spoke offline".
        spoke_connected = False
        try:
            _sid = hub.get_client_sim_spoke(tenant_id) if hasattr(hub, "get_client_sim_spoke") else None
            spoke_connected = bool(_sid and _sid in getattr(hub, "active_connections", {}))
        except Exception:
            spoke_connected = False
        return {"sections": _parse_ini_sections(raw), "raw": raw,
                "mode": mode, "source": source,
                "spoke_connected": spoke_connected,
                "fetched_at": _now_iso()}

    @app.get("/sim/api/{tenant}/config/user-overrides-conf")
    async def get_user_overrides_conf(tenant: str, tenant_id: str = Depends(get_tenant_id)):
        """Raw user-overrides.conf (merged effective) for the per-user editor.

        Spoke round-trip ``CS_GET_CONFIG`` → ``user_overrides`` text (base repo
        file + hub-user-override merged). Falls back to the stored
        ``user_overrides_content`` override when the spoke is offline.
        """
        content = ""
        source = "stored-override"
        mode = "local"
        try:
            data = await _cs_forward(tenant_id, "CS_GET_CONFIG", {}, timeout=6.0)
            content = (data or {}).get("user_overrides", "") if isinstance(data, dict) else ""
            mode = (data or {}).get("mode", "local") if isinstance(data, dict) else "local"
            source = "spoke"
        except HTTPException as exc:
            logger.info("user-overrides-conf: CS_GET_CONFIG fell back to stored override (%s)", exc.detail)
            content = await store.get_user_overrides_content(tenant_id)
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
        pushed = await _push_config(tenant_id, {"user_conf_override": content,
                                                "config_source": source})
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
        return await store.get_settings(tenant_id)

    @app.post("/sim/api/{tenant}/settings/notifications")
    async def set_notifications(request: Request, tenant: str, tenant_id: str = Depends(get_tenant_id)):
        body = await request.json()
        cfg = body if isinstance(body, dict) else {}
        await store.set_notifications(tenant_id, cfg)
        # Map sim-views field names onto the spoke's notifications settings.
        notif = {k: v for k, v in cfg.items() if k != "to_emails"}
        if cfg.get("to_emails"):
            notif["smtp_to"] = cfg["to_emails"] if isinstance(cfg["to_emails"], str) else ",".join(cfg["to_emails"])
        if cfg.get("smtp_pass"):
            notif["smtp_password"] = cfg["smtp_pass"]
        if cfg.get("teams_webhook_url"):
            notif["teams_webhook_url"] = cfg["teams_webhook_url"]
        pushed = await _push_config(tenant_id, {"notifications": notif})
        return {"saved": True, "pushed_to_spokes": pushed, "queued": bool(getattr(pushed, "queued", False))}

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
        action = str(body.get("action") or "").strip()
        if not action:
            raise HTTPException(status_code=400, detail="missing 'action'")
        args = body.get("args") if isinstance(body.get("args"), dict) else \
            {k: v for k, v in body.items() if k not in ("action", "target", "type")}
        target = body.get("target")
        if not target:
            cache = _tenant_cache(tenant_id).get(spoke_id, {})
            px = cache.get("proxmox") or {}
            node = (px.get("node") or {}) if isinstance(px, dict) else {}
            target = (node.get("hostname") or "proxmox") if isinstance(node, dict) else "proxmox"
        payload = {"target": target, "action": action, "args": args, "type": body.get("type")}
        return await _cs_forward(tenant_id, "CS_QUEUE_COMMAND", payload)

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
        return await _cs_forward(tenant_id, "CS_QUEUE_COMMAND", payload, timeout=10.0)

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
        cfg = body if isinstance(body, dict) else {}
        # Validate the additive sim_quotas field against the sims the tenant's
        # simulation.conf offers. Unknown/invalid quotas are dropped + reported;
        # the rest of central_sites_config passes through unchanged. The spoke
        # re-validates on CS_SET_CENTRAL_SITES_CONFIG apply (defense in depth).
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
        spoke is connected so the editor still works offline."""
        try:
            cat = await _cs_forward(tenant_id, "CS_GET_SIM_QUOTA_CATALOG", {}, timeout=15.0)
        except HTTPException:
            sim_txt = await store.get_sim_conf_content(tenant_id) or ""
            csc0 = await store.get_central_sites_config(tenant_id) or {}
            cat = sim_quota_catalog_from_ini(sim_txt, csc0.get("site_mappings"))
            cat["warning"] = "Client-Sim spoke not connected — catalog from cached config."
        # Attach the tenant's saved per-sim shareable overrides so the Sim Sharing
        # tile renders current state (authoritative; empty = use the SIM_META default).
        if isinstance(cat, dict):
            cat["sim_shareable"] = await _sim_shareable(tenant_id)
            cat["sim_na"] = await _sim_na(tenant_id)
            cat["alerts"], cat["insights"] = await _alert_insight_catalog()
        return cat

    # ── PXMX server → site assignments (Config → PXMX Sites) ──────────────────
    # An operator assigns each connected pxmx server (agent host = short
    # hostname) to a site; the spoke's SimQuotaEngine resolves a client's site
    # via its hosting server's entry. Forwarded to the cs spoke (which owns the
    # agents + the map); 503 when no spoke is connected so the UI can say so.
    @app.get("/sim/api/{tenant}/pxmx-site-map")
    async def get_pxmx_site_map(tenant: str, tenant_id: str = Depends(get_tenant_id)):
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
        return {"status": "SUCCESS", "pxmx_site_map": merged_map, "agents": agents}

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
        for _sid, data in results:
            if not isinstance(data, dict):
                continue
            for k, e in (data.get("ledger") or {}).items():
                m = merged_ledger.setdefault(
                    k, {"sim_id": e.get("sim_id"), "site": e.get("site"), "clients": []})
                m["clients"].extend(e.get("clients") or [])
            if not monitored:
                monitored = data.get("monitored_checks") or []
        for m in merged_ledger.values():  # dedupe (a hostname is unique per tenant)
            m["clients"] = list(dict.fromkeys(m["clients"]))
        if not results:
            return {"status": "SUCCESS", "effective": [], "ledger": {},
                    "monitored_checks": [], "warning": "Client-Sim spoke not connected."}
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
        result = {"status": "SUCCESS",
                  "effective": await _effective_sim_quotas(tenant_id),
                  "ledger": merged_ledger, "monitored_checks": monitored,
                  "placement_warnings": placement_warnings}
        try:
            result["adaptive_state"] = await store.get_adaptive_state(tenant_id)
        except Exception:  # noqa: BLE001
            pass
        return result

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
        return {"defaults": await store.get_sim_quota_defaults(),
                "catalog": catalog}

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
        # A global-defaults / sharing change can shift every tenant's effective
        # quotas — re-push so each cs spoke's SimQuotaEngine reconciles (the push
        # carries the new global sim_shareable too).
        pushed = await _push_sim_quotas_all_tenants()
        return {"status": "saved", "defaults": clean, "errors": errs,
                "pushed_to_spokes": pushed}

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
        if modes.get("central_api") == "centralized":
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
        if modes.get("central_api") == "centralized":
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
            if not getattr(hub, "approved_modules", {}).get(sid, False):
                continue
            tid = meta.get("tenant_id")
            if tid == tenant_id or not tid:
                reg_sids.append(sid)
        all_sids = list(dict.fromkeys(list(cache.keys()) + reg_sids))
        for sid in all_sids:
            data = cache.get(sid, {})
            cached_central = data.get("central") or {}
            live_entry: dict | None = None
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
