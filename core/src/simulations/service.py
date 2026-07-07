"""Read shapers that project ``hub.simulations_cache[spoke_id]`` (the
``CS_TELEMETRY`` payload from the combined Client-Sim spoke) into the shapes
the native Simulations views in ``WebUI/sim-views.js`` consume.

Every view degrades to an empty list when the tenant has no cached spokes, so
the UI never white-screens. ``spoke_online`` is the live websocket connection
state from ``hub.active_connections``.
"""
from typing import Any, Dict, List, Tuple

# Check statuses that count as pass / fail / warning for summaries.
_PASS = {"pass", "ok", "functional", "up", "healthy"}
_FAIL = {"fail", "failed", "down", "error", "critical"}
_WARN = {"warning", "warn", "degraded", "unknown", "no_data", "pending"}


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
        return spoke_id in getattr(self.hub, "active_connections", {})

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

    def _meta(self, sid: str, data: dict) -> Dict[str, Any]:
        return {
            "spoke_id": sid,
            "spoke_name": data.get("spoke_name") or sid,
            "spoke_hostname": data.get("hostname") or "",
            "spoke_online": self._is_online(sid),
        }

    @staticmethod
    def _check_status(info: Any) -> str:
        s = (info.get("status") if isinstance(info, dict) else info) or ""
        return str(s).lower()

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
        online = sum(1 for sid, _ in spokes if self._is_online(sid))
        return {"tenant_id": tenant_id, "client_count": client_count,
                "hardware_breakdown": hw, "checks_summary": checks,
                "spokes_online": online, "spokes_total": len(spokes)}

    async def get_clients_data(self, tenant_id: str) -> Dict[str, Any]:
        """One row per cached client across the tenant's spokes (the Clients view shape)."""
        rows: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            meta = self._meta(sid, data)
            for c in (data.get("clients") or []):
                c = c or {}
                rows.append({
                    **meta,
                    "hostname": c.get("hostname") or c.get("id") or "",
                    "id": c.get("id") or c.get("hostname") or "",
                    "platform": c.get("platform") or c.get("hw_type") or "—",
                    "hw_type": c.get("hw_type") or c.get("platform") or "",
                    "online": bool(c.get("online", meta["spoke_online"])),
                    "connected_ssid": c.get("connected_ssid") or "—",
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
        """One VM Server row per known Proxmox host aggregated by the tenant's cs spoke(s)."""
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
                    })
                continue
            # Legacy single-host shape (one Proxmox host per cs spoke).
            px = data.get("proxmox") or {}
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
            })
        return {"tenant_id": tenant_id, "hosts": hosts}

    async def get_central_data(self, tenant_id: str) -> Dict[str, Any]:
        """Simulations tab: per-spoke central checks / hardware alerts / client counts."""
        spokes: List[dict] = []
        for sid, data in self._spokes_for_tenant(tenant_id):
            central = data.get("central") or {}
            spokes.append({**self._meta(sid, data), "central_status": central})
        return {"tenant_id": tenant_id, "mode": "—", "spokes": spokes}

    async def get_central_status_data(self, tenant_id: str) -> Dict[str, Any]:
        """Central tab: per-spoke site breakdown (ok/fail/unknown + wireless clients)."""
        spokes: List[dict] = []
        token_valid: Any = None
        for sid, data in self._spokes_for_tenant(tenant_id):
            central = data.get("central") or {}
            tv = central.get("token_valid")
            token_valid = tv if tv is not None else token_valid
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
            spokes.append({**self._meta(sid, data), "sites": sites})
        return {"tenant_id": tenant_id, "mode": "—", "token_valid": token_valid,
                "hub_central_config": {}, "spokes": spokes}

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