"""Pure, framework-free helpers for the Simulations (cs) routes.

Extracted verbatim from ``routes.py`` — no FastAPI/request objects, no ``self``.
Covers: the Sim-Quota-catalog / PXMX-site-map short-TTL caches and their
invalidators, INI parsing, USB VID:PID normalization / classification
(``_normalize_usb_*``, ``_reclassify_host_usb``, ``_usb_*``), the Setup/Proxmox
hub-config list normalizers, and the ``_usb_provisioning_status_payload`` /
``_cached_command_queue`` builders. Imported back into ``routes.py`` so behavior
is unchanged. The cache dicts are mutated in place by the route handlers via the
imported reference (same object); nothing here rebinds them.
"""

from typing import Any, Dict, List
import configparser
from datetime import datetime, timezone
import json
import re

# Sim-Quota catalog cache. The catalog (Config → Sim Quotas) is derived from the
# tenant's simulation.conf via a LIVE round-trip to the cs spoke (15s timeout) —
# the dominant, variable latency on that page. It changes only when the sim
# config / sharing / site mappings change, so cache the assembled response per
# tenant for a short TTL and invalidate on those saves. Repeat opens then serve
# from memory; only the first open (or one right after an edit) pays the spoke.
_SIM_QUOTA_CATALOG_TTL_S = 60.0
_sim_quota_catalog_cache: Dict[str, tuple] = {}  # tenant_id -> (monotonic_deadline, catalog)


def _invalidate_sim_quota_catalog(tenant_id: str) -> None:
    """Drop the cached Sim-Quota catalog for a tenant after a config change."""
    _sim_quota_catalog_cache.pop(tenant_id, None)


# PXMX site-map cache (Config → Sites). GET fans out to ALL of the tenant's cs
# spokes (CS_GET_PXMX_SITE_MAP, 15s each) to merge agents + assignments — the
# dominant latency on that page. The map changes only when an operator saves it,
# so cache the merged response per tenant for a short TTL and invalidate on save.
_PXMX_SITE_MAP_TTL_S = 60.0
_pxmx_site_map_cache: Dict[str, tuple] = {}  # tenant_id -> (monotonic_deadline, result)


def _invalidate_pxmx_site_map(tenant_id: str) -> None:
    """Drop the cached PXMX site-map for a tenant after a save."""
    _pxmx_site_map_cache.pop(tenant_id, None)


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
