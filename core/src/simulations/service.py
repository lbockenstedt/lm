"""Read shapers that project ``hub.simulations_cache[spoke_id]`` (the
``CS_TELEMETRY`` payload from the combined Client-Sim spoke) into the shapes
the native Simulations views in ``WebUI/sim-views.js`` consume.

Every view degrades to an empty list when the tenant has no cached spokes, so
the UI never white-screens. ``spoke_online`` is the live websocket connection
state from ``hub.active_connections``.
"""
import time
from typing import Any, Dict, List, Tuple

# Check statuses that count as pass / fail / warning for summaries.
_PASS = {"pass", "ok", "functional", "up", "healthy"}
_FAIL = {"fail", "failed", "down", "error", "critical"}
_WARN = {"warning", "warn", "degraded", "unknown", "no_data", "pending"}

# Warm-start freshness window: a cached telemetry frame younger than this is
# served as CURRENT (no live query, no "cached" notice) after a restart; older
# than this the UI shows a "cached data — check Spoke and Agent" notice. See
# _cache_fields + WebUI csVmServer render.
_CACHE_FRESH_S = 300
# A pxmx host whose last telemetry frame is older than this is treated as stale
# / offline on its VM Server row — matches the cs spoke's relay STALE_SECS so a
# shut-down agent stops showing "online" (recomputed per REQUEST, not baked into
# the memoized build, so a host with no new frame still ages out).
_HOST_STALE_S = 180


def _agent_cs_enabled(hub, hostname: str) -> bool:
    """True if the pxmx agent backing this host has ``client_simulation.enabled``.

    Used to hide a CS-disabled agent's host + VMs from the cs app everywhere
    (the bridge SKIPs it, so the user can't act on its VMs — showing them is a
    dead end). The host row carries the pxmx hostname, not an agent_id, so look
    up the agent_config entry by hostname (entries are keyed by agent_id OR
    hostname — tolerant, mirroring ``gateway/cs_bridge._agent_config_entry``).
    Unknown hosts default to True so a freshly-connected agent still shows
    while its config row is created (don't black-hole a brand-new agent)."""
    if not hostname:
        return True
    try:
        store = hub.state.system_state.get("agent_config", {}) or {}
    except Exception:
        return True
    entry = store.get(hostname)
    if not isinstance(entry, dict):
        hn = str(hostname).strip().lower()
        for v in store.values():
            if not isinstance(v, dict):
                continue
            alt = str(v.get("hostname") or v.get("display_name") or "").strip().lower()
            if alt and alt == hn:
                entry = v
                break
    if not isinstance(entry, dict):
        return True  # unknown → show
    cs = entry.get("client_simulation") or {}
    # enabled absent → treat as off ONLY when the entry exists with an explicit
    # client_simulation block; an entry with no client_simulation at all is an
    # unconfigured agent → show (matches the bridge's "skip only when an entry
    # exists and enabled is false" intent). The bridge reads bool(enabled) which
    # is False when absent, but hiding here is stricter — only hide when the
    # operator explicitly disabled CS on this agent.
    if not cs:
        return True
    return bool(cs.get("enabled", True))


class SimulationsService:
    """Read-only shaper projecting cached cs telemetry into WebUI view shapes.

    Each ``get_*`` method returns a tenant-scoped dict that degrades to empty
    when no cached spokes exist. See the module docstring for the degrade-to-
    empty contract.
    """

    def __init__(self, hub):
        self.hub = hub

    # ── cache access helpers ───────────────────────────────────────────────
    def _cache(self) -> Dict[str, dict]:
        return getattr(self.hub, "simulations_cache", {}) or {}

    def _is_online(self, spoke_id: str) -> bool:
        return self.hub._primary_key(spoke_id) in getattr(self.hub, "active_connections", {})

    def _spokes_for_tenant(self, tenant_id: str) -> List[Tuple[str, dict]]:
        """Cached Client-Sim spokes bound to this tenant (by module_metadata
        tenant_id). Admins viewing a specific tenant get that tenant's spokes."""
        out: List[Tuple[str, dict]] = []
        get_tenant = getattr(self.hub.state, "get_spoke_tenant", None)
        for sid, data in self._cache().items():
            try:
                if get_tenant is None or get_tenant(sid) == tenant_id:
                    out.append((sid, data or {}))
            except Exception:
                continue
        return out

    @staticmethod
    def _cache_fields(data: dict) -> Dict[str, Any]:
        """Warm-start freshness of this spoke's cached telemetry frame.
        ``fetched_at`` is stamped at ingest (main._handle_cs_telemetry) and
        survives the encrypted warm-load, so after a restart we can tell a fresh
        cache (< _CACHE_FRESH_S — serve as current, no notice) from a stale one
        (show the 'cached — check Spoke and Agent' notice). Missing timestamp
        (older frame) => treated as stale."""
        ts = float((data or {}).get("fetched_at") or 0)
        if not ts:
            return {"cache_age_s": None, "cache_fresh": False, "cache_stale": False}
        age = time.time() - ts
        return {"cache_age_s": int(age), "cache_fresh": age < _CACHE_FRESH_S,
                "cache_stale": age >= _CACHE_FRESH_S}

    def _meta(self, sid: str, data: dict) -> Dict[str, Any]:
        return {
            "spoke_id": sid,
            "spoke_name": data.get("spoke_name") or sid,
            "spoke_hostname": data.get("hostname") or "",
            "spoke_online": self._is_online(sid),
            **self._cache_fields(data),
        }

    @staticmethod
    def _check_status(info: Any) -> str:
        s = (info.get("status") if isinstance(info, dict) else info) or ""
        return str(s).lower()

    # ── centralized-mode hub Central status (no spoke holds creds) ──────────
    def _hub_central(self, tenant_id: str) -> Any:
        """Hub-side ``central_status`` for a centralized-mode tenant, or None
        when the tenant isn't centralized / hasn't been polled yet. Produced by
        CentralHubPoller (see simulations/central_hub_poller.py); presence
        implies centralized central_api mode."""
        return (getattr(self.hub, "central_hub_status", {}) or {}).get(tenant_id)

    @staticmethod
    def _hub_meta() -> Dict[str, Any]:
        """Synthetic spoke meta for the hub's own Central status so the per-spoke
        views render a 'Hub (centralized)' row identical to a real spoke."""
        return {"spoke_id": "hub", "spoke_name": "Hub (centralized)",
                "spoke_hostname": "", "spoke_online": True}

    def _central_site_rows(self, central: dict) -> List[dict]:
        """Per-wsite ok/fail/unknown check tally + wireless client count from a
        ``central_status`` block. Shared by the real-spoke and hub-centralized
        paths in get_central_status_data."""
        status_map = central.get("status") or {}
        clients_by_site = central.get("central_clients_by_site") or {}
        site_mappings = central.get("site_mappings") or {}
        sites: List[dict] = []
        for wsite, checks_map in status_map.items():
            ok = fail = unk = 0
            for _chk, info in (checks_map or {}).items():
                s = self._check_status(info)
                if s in _PASS:
                    ok += 1
                elif s in _FAIL:
                    fail += 1
                else:
                    unk += 1
            sites.append({"wsite": wsite,
                          "central_site": site_mappings.get(wsite) or wsite,
                          "check_ok": ok, "check_fail": fail, "check_unknown": unk,
                          "wireless_clients": clients_by_site.get(wsite) or 0})
        return sites

    # ── aggregate reads ────────────────────────────────────────────────────
    async def get_dashboard_data(self, tenant_id: str) -> Dict[str, Any]:
        """Roll up client count, hardware breakdown, and central-check summary for the tenant's cached spokes."""
        spokes = self._spokes_for_tenant(tenant_id)
        client_count = 0
        hw: Dict[str, int] = {}
        checks = {"pass": 0, "fail": 0, "warning": 0}
        for sid, data in spokes:
            for c in (data.get("clients") or []):
                client_count += 1
                k = (c or {}).get("hw_type") or (c or {}).get("platform") or "Unknown"
                hw[k] = hw.get(k, 0) + 1
            for _site, checks_map in ((data.get("central") or {}).get("status") or {}).items():
                for _chk, info in (checks_map or {}).items():
                    s = self._check_status(info)
                    if s in _PASS:
                        checks["pass"] += 1
                    elif s in _FAIL:
                        checks["fail"] += 1
                    elif s in _WARN:
                        checks["warning"] += 1
        # Centralized-mode Central checks come from the hub poller, not a spoke.
        hub_central = self._hub_central(tenant_id)
        if hub_central is not None:
            for _site, checks_map in (hub_central.get("status") or {}).items():
                for _chk, info in (checks_map or {}).items():
                    s = self._check_status(info)
                    if s in _PASS:
                        checks["pass"] += 1
                    elif s in _FAIL:
                        checks["fail"] += 1
                    elif s in _WARN:
                        checks["warning"] += 1
        online = sum(1 for sid, _ in spokes if self._is_online(sid))
        return {"tenant_id": tenant_id, "client_count": client_count,
                "hardware_breakdown": hw, "checks_summary": checks,
                "spokes_online": online, "spokes_total": len(spokes)}

    # ── shaped reads (built fresh per request) ───────────────────────────────
    # get_clients_data / get_proxmox_data rebuild + dedup a per-client / per-host
    # result on every read straight from the tenant's cached telemetry. There is
    # deliberately NO memo: the previous (gen, online) memoization served a stale
    # build between telemetry frames, so a VM delete/add wouldn't show until the
    # cache-gen bumped — the "clear the cache to make it refresh" bug. Building
    # per request is cheap at this fleet size; correctness beats the saved CPU.
    async def get_clients_data(self, tenant_id: str) -> Dict[str, Any]:
        """One row per cached client across the tenant's spokes (the Clients view
        shape). Built FRESH on every read from the current telemetry cache — NO
        memo, so an add/remove/state change can never be masked by a stale build
        (the 'clear the cache to make it refresh' bug). Cheap at this fleet size."""
        return self._build_clients_data(tenant_id)

    def _build_clients_data(self, tenant_id: str) -> Dict[str, Any]:
        rows: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            meta = self._meta(sid, data)
            for c in (data.get("clients") or []):
                c = c or {}
                rows.append({
                    **meta,
                    "hostname": c.get("hostname") or c.get("id") or "",
                    "id": c.get("id") or c.get("hostname") or "",
                    # IP / MAC surfaced for the Clients search (name / IP / MAC).
                    # Passthrough from the telemetry client (empty when the sim
                    # client doesn't report them).
                    "ip": c.get("ip") or c.get("ip_address") or (c.get("config") or {}).get("address") or "",
                    "mac": c.get("mac") or c.get("mac_address") or "",
                    "platform": c.get("platform") or c.get("hw_type") or "—",
                    "hw_type": c.get("hw_type") or c.get("platform") or "",
                    "online": bool(c.get("online", meta["spoke_online"])),
                    "connected_ssid": c.get("connected_ssid") or "—",
                    # Sim-network connectivity (relayed by the spoke) — surfaces
                    # "never got an IP" / "gateway unreachable" for the dongle-
                    # quarantine trigger (heartbeat rides a separate backend
                    # network, so online≠has-sim-IP).
                    "gateway_reachable": c.get("gateway_reachable"),
                    "simulation_id": c.get("simulation_id") or "",
                    "active_simulations": c.get("active_simulations") or [],
                    "last_seen": c.get("last_seen") or "—",
                    "error_count": c.get("error_count") or 0,
                    "recent_errors": c.get("recent_errors") or [],
                    # Tier signals — csClassifyClient reads these to render T1/T2/T3.
                    # The spoke's relay carries them (control_plane tier join); this
                    # row rebuild MUST pass them through or every client falls to the
                    # 't1' default (has_usb/vmid/tier dropped → Clients tab all T1).
                    "has_usb": c.get("has_usb"),
                    "vmid": c.get("vmid"),
                    "tier": c.get("tier"),
                    # Per-client sim overrides + config so the Clients tab's per-sim
                    # override buttons reflect what's SET and stay across refreshes.
                    "config": c.get("config") or {},
                    "overrides": c.get("overrides") or {},
                })
        # Dedup by hostname across spokes: the same client can be cached by
        # more than one cs spoke. The common cause is a per-client override
        # being set on the tenant's PRIMARY cs spoke (CS_SET_CLIENT_OVERRIDES
        # is forwarded via hub.get_client_sim_spoke(), which may NOT be the
        # spoke the client is actually connected to); registry.set_overrides
        # then creates a phantom registry entry on that primary spoke, so BOTH
        # spokes report the hostname — the real connection on one + an
        # override-only stub on the other. Without dedup the Clients view
        # showed two rows for one user. Collapse to one row per hostname,
        # MERGING so the single row carries BOTH the authoritative bucket sim
        # (from the online connection) AND the per-client override (from
        # whichever spoke holds it). Mirrors the get_proxmox_data cross-spoke
        # dedup; rows with no hostname are kept as-is (unique).
        def _ckey(c: dict) -> str:
            return str(c.get("hostname") or c.get("id") or "").strip().lower()

        def _ls(c: dict) -> float:
            ls = c.get("last_seen")
            try:
                return float(ls)
            except (TypeError, ValueError):
                return 0.0

        def _crank(c: dict):
            # online first, then most active sims, then most recent last_seen.
            return (1 if c.get("online") else 0,
                    len(c.get("active_simulations") or []), _ls(c))

        best: Dict[str, dict] = {}
        order: List[str] = []
        extras: List[dict] = []
        for c in rows:
            k = _ckey(c)
            if not k:
                extras.append(c)
                continue
            if k not in best:
                best[k] = c
                order.append(k)
                continue
            # Keep the richer row as the base (online real connection wins over
            # an override-only phantom) so its bucket sim / tier / config /
            # simulation_id survive; fold the other row's overrides +
            # active_simulations + last_seen in.
            a, b = best[k], c
            if _crank(b) > _crank(a):
                a, b = b, a
                best[k] = a
            # Union active simulations (preserve order, dedup case-insensitively).
            acts = list(a.get("active_simulations") or [])
            seen = {str(s).lower() for s in acts}
            for s in (b.get("active_simulations") or []):
                if str(s).lower() not in seen:
                    acts.append(s)
                    seen.add(str(s).lower())
            a["active_simulations"] = acts
            # Merge overrides: the base's authoritative value wins for a key it
            # already has set; the folded row fills any key the base lacks (this
            # is how the phantom's freshly-set override lands on the real
            # client's row).
            ov = dict(a.get("overrides") or {})
            for ok, ov_b in (b.get("overrides") or {}).items():
                if ov.get(ok) in (None, "", [], {}):
                    ov[ok] = ov_b
            a["overrides"] = ov
            # online is OR; last_seen is the most recent; error_count the max so
            # a real error isn't masked by the phantom's 0.
            if b.get("online"):
                a["online"] = True
            if _ls(b) > _ls(a):
                a["last_seen"] = b.get("last_seen")
            try:
                a["error_count"] = max(int(a.get("error_count") or 0),
                                        int(b.get("error_count") or 0))
            except (TypeError, ValueError):
                pass
        rows = [best[k] for k in order] + extras
        return {"tenant_id": tenant_id, "clients": rows}

    async def get_simulations_data(self, tenant_id: str) -> Dict[str, Any]:
        """One row per active simulation across the tenant's cached clients (the Simulations view shape)."""
        rows: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            meta = self._meta(sid, data)
            spoke_rows: List[dict] = []
            for c in (data.get("clients") or []):
                c = c or {}
                sims = c.get("active_simulations") or (
                    [c.get("simulation_id")] if c.get("simulation_id") else [])
                for sn in sims:
                    spoke_rows.append({"tenant_id": tenant_id, "spoke_id": sid,
                                       "spoke_name": meta["spoke_name"],
                                       "hostname": c.get("hostname") or "",
                                       "simulation_name": sn})
            if not spoke_rows:
                spoke_rows.append({"tenant_id": tenant_id, "spoke_id": sid,
                                   "spoke_name": meta["spoke_name"],
                                   "simulation_name": "—"})
            rows.extend(spoke_rows)
        return {"tenant_id": tenant_id, "simulations": rows}

    async def get_proxmox_data(self, tenant_id: str) -> Dict[str, Any]:
        """One VM Server row per known Proxmox host aggregated by the tenant's cs
        spoke(s). Built FRESH on every read from the current telemetry cache — NO
        memo, so a VM delete/add/state change can never be masked by a stale build
        (the 'clear the cache to make it refresh' bug that cost us a whole day).
        Cheap at this fleet size. The route caller mutates the result, so the
        per-request build + shallow host-dict copies below are what it gets."""
        result = self._build_proxmox_data(tenant_id)
        # Recompute per-hop AGES + online/stale HERE, per request — NOT in the
        # memoized build. The memo only rebuilds when a new telemetry frame bumps
        # the cache-gen, so a shut-down host (no new frame) would otherwise keep a
        # frozen "just now" age and show ONLINE forever. Computing ages from the
        # memoized raw timestamps on every request is what lets a dead host age
        # out and a genuinely-stale cache read "cached". Also powers the detail
        # page's telemetry-freshness panel (agent → spoke → hub → now chain).
        now = time.time()
        out_hosts = []
        for h in (result.get("hosts") or []):
            h = dict(h)
            hls = h.get("host_last_seen")
            if isinstance(hls, (int, float)) and hls:
                h["host_age_s"] = max(0, int(now - hls))
                h["host_stale"] = h["host_age_s"] > _HOST_STALE_S
                # ONLINE iff this host's own agent frame is fresh. A recent frame
                # can ONLY exist if the whole chain (agent → spoke → hub) is live,
                # so this is more reliable than spoke_online — which mis-keys after
                # a spoke rename (showed live hosts as "cached") and ignores a
                # shut-down agent under a still-live spoke (showed dead hosts as
                # "online"). Both reported symptoms.
                h["host_online"] = not h["host_stale"]
            else:
                # No per-host timestamp (old warm-loaded frame) → fall back to the
                # spoke-connection signal so nothing regresses during a cache roll.
                h["host_age_s"] = None
                h["host_stale"] = None
                h["host_online"] = bool(h.get("spoke_online"))
            # Recompute the cache freshness label from the hub receipt time each
            # request (was frozen at build time → misleading "cached"/"fresh").
            hf = h.get("hub_fetched_at")
            if isinstance(hf, (int, float)) and hf:
                cage = max(0, int(now - hf))
                h["cache_age_s"] = cage
                h["cache_fresh"] = cage < _CACHE_FRESH_S
                h["cache_stale"] = cage >= _CACHE_FRESH_S
            # Per-hop lag chain for the detail page (seconds, one-decimal).
            at = h.get("agent_telemetry") or {}
            gen = at.get("gen_ts")
            h["freshness"] = {
                "agent_gen_age_s":  round(now - gen, 1) if isinstance(gen, (int, float)) else None,
                "agent_to_spoke_s": at.get("agent_to_spoke_lag_s"),
                "spoke_ingest_age_s": round(now - hls, 1) if isinstance(hls, (int, float)) and hls else None,
                "hub_cache_age_s":  h.get("cache_age_s"),
                "relay_age_s":      h.get("relay_age_s"),
                "interval_s":       at.get("interval_s"),
                "phase_ms":         at.get("phase_ms") or {},
                "iter":             at.get("iter"),
                "vm_count":         at.get("vm_count"),
                "node_count":       at.get("node_count"),
                "agent_version":    at.get("agent_version"),
                # Reconnect context (#3) — how flappy the agent's link is.
                "reconnect_count":        at.get("reconnect_count"),
                "last_disconnect_reason": at.get("last_disconnect_reason"),
                "last_disconnect_age_s":  at.get("last_disconnect_age_s"),
            }
            out_hosts.append(h)
        return {"tenant_id": result.get("tenant_id", tenant_id), "hosts": out_hosts}

    def _build_proxmox_data(self, tenant_id: str) -> Dict[str, Any]:
        hosts: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            # New multi-host shape (cs spoke aggregating several pxmx agents):
            # ``proxmox_hosts`` is one entry per known Proxmox host. Expand it
            # into one VM Server row per host so each pxmx host is visible.
            host_list = data.get("proxmox_hosts")
            if isinstance(host_list, list) and host_list:
                for h in host_list:
                    h = h or {}
                    hpx = h.get("proxmox") or {}
                    hosts.append({
                        "spoke_id": sid,
                        "spoke_name": h.get("hostname") or (data.get("spoke_name") or sid),
                        "spoke_hostname": h.get("hostname") or "",
                        "spoke_online": self._is_online(sid),
                        **self._cache_fields(data),
                        "hostname": h.get("hostname") or "",
                        "vm_count": hpx.get("vm_count") or len(h.get("proxmox_vms") or []),
                        "usb_count": hpx.get("usb_count") or len(h.get("usb_devices") or []),
                        "proxmox": hpx,
                        "proxmox_vms": h.get("proxmox_vms") or [],
                        "usb_devices": h.get("usb_devices") or [],
                        "reclone_state": h.get("reclone_state") or (data.get("reclone_state") or {}),
                        "api_server": h.get("api_server") or (data.get("api_server") or {}),
                        "hub_rtt_ms": data.get("hub_rtt_ms"),
                        "hub_processing_ms": data.get("hub_processing_ms"),
                        "hub_loop_lag_ms": data.get("hub_loop_lag_ms"),
                        "telemetry_build_ms": data.get("telemetry_build_ms"),
                        "ws_reconnect_count": data.get("ws_reconnect_count"),
                        "ws_last_error": data.get("ws_last_error"),
                        "sim_conf_read_error": data.get("sim_conf_read_error"),
                        # ── Telemetry-freshness RAW timestamps (per-hop age chain).
                        # Only RAW epochs are memoized here; the AGES + online/stale
                        # are recomputed per-request in get_proxmox_data so a
                        # shut-down host (no new frame → no memo rebuild) still ages
                        # out instead of being frozen "online". agent → spoke → hub:
                        "host_last_seen":  hpx.get("last_seen"),
                        "agent_telemetry": hpx.get("agent_telemetry") or {},
                        "ingested_at":     hpx.get("ingested_at"),
                        "relayed_at":      h.get("relayed_at"),
                        "relay_age_s":     h.get("relay_age_s"),
                        "hub_fetched_at":  data.get("fetched_at"),
                    })
                continue
            # Legacy single-host shape (one Proxmox host per cs spoke).
            px = data.get("proxmox") or {}
            # Skip a pure RELAY spoke: a cs spoke that only relays pxmx agents is
            # not itself a Proxmox host, so it has no proxmox block / VMs of its
            # own — its agents already surface as per-host rows via
            # proxmox_hosts above. Emitting a spoke-level row for it put empty
            # "<host>-spoke" rows (0 VMs, —, —, Auto-Prov defaulting to Active on
            # no data) in the VM Server table next to the real agent rows. Only
            # emit when the spoke actually carries hypervisor data (a genuine
            # legacy direct-host cs spoke). This is the "show the agents, not the
            # relay spokes" fix — a spoke can host many agents; the agents are
            # the rows.
            if not px and not data.get("proxmox_vms"):
                continue
            hosts.append({
                **self._meta(sid, data),
                "vm_count": px.get("vm_count") or len(data.get("proxmox_vms") or []),
                "usb_count": px.get("usb_count") or len(data.get("usb_devices") or []),
                "proxmox": px,
                "proxmox_vms": data.get("proxmox_vms") or [],
                "usb_devices": data.get("usb_devices") or [],
                "reclone_state": data.get("reclone_state") or {},
                "api_server": data.get("api_server") or {},
                "hub_rtt_ms": data.get("hub_rtt_ms"),
                "hub_processing_ms": data.get("hub_processing_ms"),
                "hub_loop_lag_ms": data.get("hub_loop_lag_ms"),
                "telemetry_build_ms": data.get("telemetry_build_ms"),
                "ws_reconnect_count": data.get("ws_reconnect_count"),
                "ws_last_error": data.get("ws_last_error"),
                "sim_conf_read_error": data.get("sim_conf_read_error"),
                # Freshness raw timestamps (see the multi-host branch above).
                "host_last_seen":  px.get("last_seen"),
                "agent_telemetry": px.get("agent_telemetry") or {},
                "ingested_at":     px.get("ingested_at"),
                "hub_fetched_at":  data.get("fetched_at"),
            })
        # Dedup by agent hostname: one physical pxmx host can be relayed/cached
        # by more than one cs spoke (redundant relay paths or overlapping
        # telemetry caches), which listed the same host twice — with slightly
        # different live stats since each spoke snapshotted it at a different
        # moment. Collapse to one row per host, keeping the richest ONLINE entry
        # (online first, then most VMs, then most USB) so the fleet count is
        # accurate. Rows with no resolvable hostname are kept as-is (unique).
        def _host_key(h: dict) -> str:
            return str(h.get("hostname") or h.get("spoke_hostname")
                       or h.get("spoke_name") or h.get("spoke_id") or "").strip().lower()

        def _host_rank(h: dict):
            return (1 if h.get("spoke_online") else 0,
                    int(h.get("vm_count") or 0), int(h.get("usb_count") or 0))

        best: Dict[str, dict] = {}
        order: List[str] = []
        extras: List[dict] = []
        for h in hosts:
            k = _host_key(h)
            if not k:
                extras.append(h)
                continue
            if k not in best:
                best[k] = h
                order.append(k)
            elif _host_rank(h) > _host_rank(best[k]):
                best[k] = h
        hosts = [best[k] for k in order] + extras
        # Hide hosts whose backing agent has client_simulation.enabled = false.
        # An agent attached to a cs spoke but with CS disabled must not show its
        # VMs anywhere in the cs app (the user can't act on them — the bridge
        # SKIPs them, so delete/start would never reach the agent). The host row
        # carries the pxmx hostname, not an agent_id, so join against agent_config
        # by hostname (entries are keyed by agent_id OR hostname — tolerant
        # lookup, mirroring gateway/cs_bridge._agent_config_entry). Unknown
        # hosts default to shown so a freshly-connected agent still appears
        # while its config row is created. Filtering after dedup keeps the
        # richest-entry pick.
        hosts = [h for h in hosts
                 if _agent_cs_enabled(self.hub, h.get("hostname") or h.get("spoke_hostname") or "")]
        # Event-driven live-state overlay (see hub._vm_live_set): stamp the
        # transient prov_status (deleting/recloning/provisioning) onto matching
        # VM rows and PRUNE vmids whose delete just completed, so the table
        # reflects a mutation the instant its message arrives instead of waiting
        # for the next ~10-30s telemetry frame. Best-effort — never break render.
        #
        # First reconcile REAPPEARANCES: a vmid that shows up again in a telemetry
        # frame captured AFTER its delete was stamped is a reused/re-cloned vmid,
        # so clear its stale "deleted" overlay — otherwise a legitimately
        # re-created vmid stays hidden for the rest of _VM_DELETED_TTL (180s).
        present_ts: Dict[str, float] = {}
        for h in hosts:
            fa = h.get("hub_fetched_at")
            if not fa:
                continue
            for vm in (h.get("proxmox_vms") or []):
                if not isinstance(vm, dict):
                    continue
                vid = str(vm.get("vmid"))
                try:
                    present_ts[vid] = max(present_ts.get(vid, 0.0), float(fa))
                except (TypeError, ValueError):
                    continue
        try:
            self.hub.vm_live_drop_reappeared(tenant_id, present_ts)
        except Exception:  # noqa: BLE001
            pass
        try:
            overlay = self.hub.vm_live_states(tenant_id)
        except Exception:  # noqa: BLE001
            overlay = {}
        if overlay:
            for h in hosts:
                vms = h.get("proxmox_vms") or []
                kept = []
                pruned = 0
                for vm in vms:
                    if not isinstance(vm, dict):
                        kept.append(vm)
                        continue
                    state = overlay.get(str(vm.get("vmid")))
                    if state == "deleted":
                        pruned += 1
                        continue
                    if state:
                        vm = {**vm, "prov_status": state}
                    kept.append(vm)
                h["proxmox_vms"] = kept
                if pruned:
                    try:
                        h["vm_count"] = max(0, int(h.get("vm_count") or len(vms)) - pruned)
                    except (TypeError, ValueError):
                        h["vm_count"] = len(kept)
        return {"tenant_id": tenant_id, "hosts": hosts}

    async def get_central_data(self, tenant_id: str) -> Dict[str, Any]:
        """Simulations tab: per-spoke central checks / hardware alerts / client counts."""
        spokes: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            central = data.get("central") or {}
            spokes.append({**self._meta(sid, data), "central_status": central})
        hub_central = self._hub_central(tenant_id)
        if hub_central is not None:
            spokes.append({**self._hub_meta(), "central_status": hub_central})
        return {"tenant_id": tenant_id, "mode": "—", "spokes": spokes}

    async def get_central_status_data(self, tenant_id: str) -> Dict[str, Any]:
        """Central tab: per-spoke site breakdown (ok/fail/unknown + wireless clients)."""
        spokes: List[dict] = []
        token_valid: Any = None
        for sid, data in self._spokes_for_tenant(tenant_id):
            central = data.get("central") or {}
            tv = central.get("token_valid")
            token_valid = tv if tv is not None else token_valid
            spokes.append({**self._meta(sid, data),
                           "sites": self._central_site_rows(central)})
        hub_central = self._hub_central(tenant_id)
        if hub_central is not None:
            tv = hub_central.get("token_valid")
            token_valid = tv if tv is not None else token_valid
            spokes.append({**self._hub_meta(),
                           "sites": self._central_site_rows(hub_central)})
        return {"tenant_id": tenant_id, "mode": "—", "token_valid": token_valid,
                "hub_central_config": {}, "spokes": spokes}

    # ── Mist — mirror of the Central reads (separate product, not shared) ─────
    def _hub_mist(self, tenant_id: str) -> Any:
        """Hub-side ``mist_status`` for a centralized-mode tenant, or None when
        the tenant isn't centralized / hasn't been polled yet. Produced by
        MistHubPoller (simulations/mist_hub_poller.py); presence implies
        centralized mist_api mode. Mirror of _hub_central."""
        return (getattr(self.hub, "mist_hub_status", {}) or {}).get(tenant_id)

    # ── Central On-Prem — a SECOND, independent Aruba Central instance (same
    # ArubaClient/API as cloud Central, separate config + status slot so the two
    # never step on each other). Mirror of _hub_central; produced by the
    # CentralHubPoller instance="central_on_prem" (Phase 2). The getattr default
    # keeps this safe before the hub's central_on_prem_hub_status dict is wired.
    def _hub_central_on_prem(self, tenant_id: str) -> Any:
        """Hub-side ``central_on_prem_status`` for a centralized-mode tenant, or
        None when not centralized / not yet polled. Mirror of _hub_central."""
        return (getattr(self.hub, "central_on_prem_hub_status", {}) or {}).get(tenant_id)

    def _hub_block_for_source(self, source: str, tenant_id: str) -> Any:
        """Dispatch a sim-quota source to its hub-side status block. Central →
        _hub_central, Mist → _hub_mist, Central On-Prem → _hub_central_on_prem.
        Unknown/legacy source defaults to cloud Central (bare ids are Central).
        Used by the SimQuotaEngine firing-eval so each source's quota reads ONLY
        its own source's telemetry — a Central On-Prem quota never fires on
        cloud Central's status (and vice versa)."""
        src = str(source or "central").strip().lower()
        if src == "mist":
            return self._hub_mist(tenant_id)
        if src == "central_on_prem":
            return self._hub_central_on_prem(tenant_id)
        return self._hub_central(tenant_id)

    def _mist_site_rows(self, mist: dict) -> List[dict]:
        """Per-wsite ok/fail/unknown check tally + wireless client count from a
        ``mist_status`` block. Mirror of _central_site_rows — Mist's status block
        is the same shape the spoke's mist_poller writes (status / hardware_alerts
        / client_count_status / health). ``mist_clients_by_site`` is populated by
        the centralized MistHubPoller; a distributed spoke's relayed status lacks
        it (wireless_clients=0), identical to Central's distributed path."""
        status_map = mist.get("status") or {}
        clients_by_site = mist.get("mist_clients_by_site") or {}
        site_mappings = mist.get("site_mappings") or {}
        sites: List[dict] = []
        for wsite, checks_map in status_map.items():
            ok = fail = unk = 0
            for _chk, info in (checks_map or {}).items():
                s = self._check_status(info)
                if s in _PASS:
                    ok += 1
                elif s in _FAIL:
                    fail += 1
                else:
                    unk += 1
            sites.append({"wsite": wsite,
                          "mist_site": site_mappings.get(wsite) or wsite,
                          "check_ok": ok, "check_fail": fail, "check_unknown": unk,
                          "wireless_clients": clients_by_site.get(wsite) or 0})
        return sites

    async def get_mist_data(self, tenant_id: str) -> Dict[str, Any]:
        """Simulations tab: per-spoke Mist checks / hardware alerts / client
        counts. Mirror of get_central_data (reads the relayed ``data["mist"]``
        block + the centralized hub poller's synthetic spoke)."""
        spokes: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            mist = data.get("mist") or {}
            spokes.append({**self._meta(sid, data), "mist_status": mist})
        hub_mist = self._hub_mist(tenant_id)
        if hub_mist is not None:
            spokes.append({**self._hub_meta(), "mist_status": hub_mist})
        return {"tenant_id": tenant_id, "mode": "—", "spokes": spokes}

    async def get_mist_status_data(self, tenant_id: str) -> Dict[str, Any]:
        """Mist tab: per-spoke site breakdown (ok/fail/unknown + wireless
        clients). Mirror of get_central_status_data."""
        spokes: List[dict] = []
        token_valid: Any = None
        for sid, data in self._spokes_for_tenant(tenant_id):
            mist = data.get("mist") or {}
            tv = mist.get("token_valid")
            token_valid = tv if tv is not None else token_valid
            spokes.append({**self._meta(sid, data),
                           "sites": self._mist_site_rows(mist)})
        hub_mist = self._hub_mist(tenant_id)
        if hub_mist is not None:
            tv = hub_mist.get("token_valid")
            token_valid = tv if tv is not None else token_valid
            spokes.append({**self._hub_meta(),
                           "sites": self._mist_site_rows(hub_mist)})
        return {"tenant_id": tenant_id, "mode": "—", "token_valid": token_valid,
                "hub_mist_config": {}, "spokes": spokes}

    async def get_api_server_data(self, tenant_id: str) -> Dict[str, Any]:
        """Per-spoke API-server status block (the API Server view shape)."""
        spokes: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            spokes.append({**self._meta(sid, data),
                           "api_server": data.get("api_server") or {}})
        return {"tenant_id": tenant_id, "spokes": spokes}

    async def get_spoke_config(self, tenant_id: str, spoke_id: str) -> Dict[str, Any]:
        """Return a single spoke's cached config + raw telemetry (for the spoke detail view)."""
        data = self._cache().get(spoke_id, {})
        return {"config": data.get("config") or {}, "telemetry": data}