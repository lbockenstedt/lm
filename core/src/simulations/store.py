"""JSON-backed, per-tenant store for Client-Sim config the LM hub owns.

The spoke remains the runtime source of truth (it actually runs the sims,
talks to Proxmox/Central, etc.). This store is what the Simulations UI reads
back without a spoke round-trip, and what the hub pushes down to the spoke via
``CS_CONFIG_UPDATE`` on every write (see routes.py ``_push_config``).

Persisted to ``simulations_store.json`` in the hub data dir with atomic saves.
"""
import json
import logging
import os
import threading
from typing import Any, Dict, List

logger = logging.getLogger("SimulationsStore")


class SimulationsStore:
    """Per-tenant JSON store for hub-owned Client-Sim config (see module docstring).

    All access is async + lock-guarded; every setter writes through atomically.
    Getters return defensive copies so callers can't mutate the live store.
    """

    def __init__(self, data_dir: str):
        self._path = os.path.join(data_dir, "simulations_store.json")
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ── persistence ────────────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            with open(self._path, "r") as f:
                self._data = json.load(f) or {}
        except FileNotFoundError:
            self._data = {}
        except Exception as exc:  # corrupt JSON, etc. — start empty rather than crash
            logger.warning("SimulationsStore: load failed (%s): %s — starting empty",
                           self._path, exc)
            self._data = {}

    def _save(self) -> None:
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp, self._path)
        except Exception as exc:
            logger.warning("SimulationsStore: save failed (%s): %s", self._path, exc)

    def _tenant(self, tenant_id: str) -> Dict[str, Any]:
        t = self._data.get(tenant_id)
        if t is None:
            t = {}
            self._data[tenant_id] = t
        return t

    # ── simulation / user overrides (legacy buckets, kept for compat) ──────
    async def get_user_overrides(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's legacy user-override bucket (empty if unset)."""
        return self._data.get(tenant_id, {}).get("user_overrides", {})

    async def set_user_overrides(self, tenant_id: str, overrides: Dict[str, Any]) -> None:
        """Replace the tenant's user-override bucket and persist."""
        with self._lock:
            self._tenant(tenant_id)["user_overrides"] = overrides
            self._save()

    # ── simulation.conf override content (raw INI pushed as sim_conf_override) ──
    async def set_sim_conf_content(self, tenant_id: str, content: str) -> None:
        """Store the raw simulation.conf override INI for the tenant and persist."""
        with self._lock:
            self._tenant(tenant_id)["sim_conf_content"] = content
            self._save()

    # ── hub-config (usb provisioning / vm images / reclone knobs) ──────────
    async def get_hub_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return ``{hub_config_enabled, hub_config}`` for the tenant."""
        t = self._data.get(tenant_id, {})
        return {"hub_config_enabled": bool(t.get("hub_config_enabled", False)),
                "hub_config": t.get("hub_config", {})}

    async def set_hub_config(self, tenant_id: str, enabled: bool,
                             hub_config: Dict[str, Any]) -> None:
        """Set the hub-config enabled flag + knob dict for the tenant and persist."""
        with self._lock:
            t = self._tenant(tenant_id)
            t["hub_config_enabled"] = bool(enabled)
            t["hub_config"] = hub_config or {}
            self._save()

    # ── central API config (mode + cluster creds) ──────────────────────────
    async def get_central_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's Central API config (mode + cluster creds)."""
        return self._data.get(tenant_id, {}).get("central_config", {})

    async def set_central_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's Central API config and persist."""
        with self._lock:
            self._tenant(tenant_id)["central_config"] = cfg or {}
            self._save()

    # ── central sites config (Setup → Central API / Central) ────────────────
    async def get_central_sites_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's Central sites config."""
        return self._data.get(tenant_id, {}).get("central_sites_config", {})

    async def set_central_sites_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's Central sites config and persist."""
        with self._lock:
            self._tenant(tenant_id)["central_sites_config"] = cfg or {}
            self._save()

    # ── github config (Setup → GitHub: per-spoke repo + token) ───────────────
    async def get_github_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's GitHub config (per-spoke repo + token)."""
        return self._data.get(tenant_id, {}).get("github_config", {})

    async def set_github_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's GitHub config and persist."""
        with self._lock:
            self._tenant(tenant_id)["github_config"] = cfg or {}
            self._save()

    # ── security config (Setup → Security: spoke-local dashboard auth) ──────
    async def get_security_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's spoke-local dashboard security config."""
        return self._data.get(tenant_id, {}).get("security_config", {})

    async def set_security_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's security config and persist."""
        with self._lock:
            self._tenant(tenant_id)["security_config"] = cfg or {}
            self._save()

    # ── NetBox → CPPM endpoint-sync last-run status (Setup → Security/NAC) ──
    # Per-tenant result of the most recent endpoint sync cycle (background loop
    # or on-demand "Sync now"). Persisted so the UI still shows the last run
    # after a hub restart. Shape: {status, pushed, errors, message,
    # last_sync_ts, tenant_name, endpoints_total}.
    async def get_endpoint_sync_status(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's last endpoint-sync status (empty if never run)."""
        return dict(self._data.get(tenant_id, {}).get("endpoint_sync", {}))

    async def set_endpoint_sync_status(self, tenant_id: str,
                                       status: Dict[str, Any]) -> None:
        """Replace the tenant's endpoint-sync status and persist."""
        with self._lock:
            self._tenant(tenant_id)["endpoint_sync"] = status or {}
            self._save()

    def get_all_endpoint_sync_status(self) -> Dict[str, Dict[str, Any]]:
        """Return {tenant_id: status} for every tenant that has a recorded sync.

        Synchronous (no I/O beyond the in-memory dict) so the status route can
        call it directly without ``await``; persistence already happened on
        each ``set_endpoint_sync_status`` write.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for tid, t in self._data.items():
            if tid == self._GLOBAL_KEY:
                continue
            st = t.get("endpoint_sync")
            if st:
                out[tid] = dict(st)
        return out

    # ── Hypervisor → NetBox VM-sync last-run status (Setup → IPAM) ──────────
    # Per-tenant result of the most recent VM sync cycle (background loop or
    # on-demand "Sync now"). Persisted so the UI still shows the last run after
    # a hub restart. Shape: {status, pushed, errors, skipped, deleted, message,
    # last_sync_ts, tenant_name, vms_total}.
    async def get_vm_sync_status(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's last VM-sync status (empty if never run)."""
        return dict(self._data.get(tenant_id, {}).get("vm_sync", {}))

    async def set_vm_sync_status(self, tenant_id: str,
                                 status: Dict[str, Any]) -> None:
        """Replace the tenant's VM-sync status and persist."""
        with self._lock:
            self._tenant(tenant_id)["vm_sync"] = status or {}
            self._save()

    def get_all_vm_sync_status(self) -> Dict[str, Dict[str, Any]]:
        """Return {tenant_id: status} for every tenant with a recorded VM sync.

        Synchronous — persistence happened on each ``set_vm_sync_status`` write.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for tid, t in self._data.items():
            if tid == self._GLOBAL_KEY:
                continue
            st = t.get("vm_sync")
            if st:
                out[tid] = dict(st)
        return out

    # ── Firewall → NetBox device-discovery sync last-run status (Setup → Sync) ─
    # Per-tenant result of the most recent firewall-discovery sync cycle
    # (background loop or on-demand "Sync now"). Persisted so the UI still shows
    # the last run after a hub restart. Shape: {status, pushed, errors, skipped,
    # deleted, discovered_total, message, last_sync_ts, tenant_name}.
    async def get_fw_discovery_sync_status(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's last firewall-discovery-sync status (empty if never run)."""
        return dict(self._data.get(tenant_id, {}).get("fw_discovery_sync", {}))

    async def set_fw_discovery_sync_status(self, tenant_id: str,
                                            status: Dict[str, Any]) -> None:
        """Replace the tenant's firewall-discovery-sync status and persist."""
        with self._lock:
            self._tenant(tenant_id)["fw_discovery_sync"] = status or {}
            self._save()

    def get_all_fw_discovery_sync_status(self) -> Dict[str, Dict[str, Any]]:
        """Return {tenant_id: status} for every tenant with a recorded firewall-discovery sync.

        Synchronous — persistence happened on each ``set_fw_discovery_sync_status`` write.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for tid, t in self._data.items():
            if tid == self._GLOBAL_KEY:
                continue
            st = t.get("fw_discovery_sync")
            if st:
                out[tid] = dict(st)
        return out

    # ── Network Devices → NetBox device-discovery sync last-run status ────────
    # Per-tenant result of the most recent nw-discovery sync cycle (background
    # loop or on-demand "Sync now"). Persisted so the UI still shows the last
    # run after a hub restart. Shape: {status, pushed, errors, skipped, deleted,
    # discovered_total, message, last_sync_ts, tenant_name}.
    async def get_nw_discovery_sync_status(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's last nw-discovery-sync status (empty if never run)."""
        return dict(self._data.get(tenant_id, {}).get("nw_discovery_sync", {}))

    async def set_nw_discovery_sync_status(self, tenant_id: str,
                                           status: Dict[str, Any]) -> None:
        """Replace the tenant's nw-discovery-sync status and persist."""
        with self._lock:
            self._tenant(tenant_id)["nw_discovery_sync"] = status or {}
            self._save()

    def get_all_nw_discovery_sync_status(self) -> Dict[str, Dict[str, Any]]:
        """Return {tenant_id: status} for every tenant with a recorded nw-discovery sync."""
        out: Dict[str, Dict[str, Any]] = {}
        for tid, t in self._data.items():
            if tid == self._GLOBAL_KEY:
                continue
            st = t.get("nw_discovery_sync")
            if st:
                out[tid] = dict(st)
        return out

    # ── Realtime NAC → IPAM reverse sync last-run status (Setup → Sync) ───────
    # Per-tenant result of the most recent realtime ClearPass Access Tracker →
    # NetBox pull (background loop or on-demand "Sync now"). Persisted so the UI
    # still shows the last run after a hub restart. Shape: {status, pushed,
    # errors, skipped, deleted, sessions_total, message, last_sync_ts,
    # tenant_name}.
    async def get_realtime_nac_sync_status(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's last realtime-NAC-sync status (empty if never run)."""
        return dict(self._data.get(tenant_id, {}).get("realtime_nac_sync", {}))

    async def set_realtime_nac_sync_status(self, tenant_id: str,
                                           status: Dict[str, Any]) -> None:
        """Replace the tenant's realtime-NAC-sync status and persist."""
        with self._lock:
            self._tenant(tenant_id)["realtime_nac_sync"] = status or {}
            self._save()

    def get_all_realtime_nac_sync_status(self) -> Dict[str, Dict[str, Any]]:
        """Return {tenant_id: status} for every tenant with a recorded realtime-NAC sync.

        Synchronous — persistence happened on each ``set_realtime_nac_sync_status`` write.
        """
        out: Dict[str, Dict[str, Any]] = {}
        for tid, t in self._data.items():
            if tid == self._GLOBAL_KEY:
                continue
            st = t.get("realtime_nac_sync")
            if st:
                out[tid] = dict(st)
        return out

    # ── onboarding PSKs (hub mints; the active one is pushed to the spoke) ──
    async def get_psks(self, tenant_id: str) -> List[str]:
        """Return a copy of the tenant's onboarding PSK list."""
        return list(self._data.get(tenant_id, {}).get("onboarding_psks", []))

    async def add_psk(self, tenant_id: str, psk: str) -> None:
        """Add an onboarding PSK to the tenant (idempotent) and persist."""
        with self._lock:
            t = self._tenant(tenant_id)
            psks = list(t.get("onboarding_psks", []))
            if psk not in psks:
                psks.append(psk)
            t["onboarding_psks"] = psks
            self._save()

    async def remove_psk(self, tenant_id: str, psk: str) -> bool:
        """Remove an onboarding PSK from the tenant; return True if it was present."""
        with self._lock:
            t = self._tenant(tenant_id)
            psks = list(t.get("onboarding_psks", []))
            if psk in psks:
                psks.remove(psk)
                t["onboarding_psks"] = psks
                self._save()
                return True
            return False

    # ── processing modes (central_api / teams / email → centralized|distributed) ──
    async def get_processing_modes(self, tenant_id: str) -> Dict[str, str]:
        return dict(self._data.get(tenant_id, {}).get("processing_modes", {}))

    async def set_processing_mode(self, tenant_id: str, feature: str, value: str) -> None:
        with self._lock:
            t = self._tenant(tenant_id)
            modes = dict(t.get("processing_modes", {}))
            modes[feature] = value
            t["processing_modes"] = modes
            self._save()

    # ── notifications (smtp / teams / email) ───────────────────────────────
    async def get_notifications(self, tenant_id: str) -> Dict[str, Any]:
        return dict(self._data.get(tenant_id, {}).get("notifications", {}))

    async def set_notifications(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        with self._lock:
            self._tenant(tenant_id)["notifications"] = cfg or {}
            self._save()

    # ── /settings bundle (processing_modes + notifications) ────────────────
    async def get_settings(self, tenant_id: str) -> Dict[str, Any]:
        return {"processing_modes": await self.get_processing_modes(tenant_id),
                "notifications": await self.get_notifications(tenant_id)}

    # ── platform-wide (superadmin) global config ───────────────────────────
    # Stored under a reserved "__global__" key so it sits alongside (but never
    # collides with) the per-tenant dicts. Mirrors the cs source store.py
    # _load_global_config / get_global_usb_vidpids (superadmin.py:589-658).
    _GLOBAL_KEY = "__global__"

    def _global(self) -> Dict[str, Any]:
        g = self._data.get(self._GLOBAL_KEY)
        if g is None:
            g = {}
            self._data[self._GLOBAL_KEY] = g
        return g

    async def get_global_usb_vidpids(self) -> List[Dict[str, Any]]:
        """Platform-wide (superadmin-certified) USB device list —
        {vidpid, type, label} dicts (the cs-spoke re-filter shape)."""
        return [dict(d) for d in (self._global().get("usb_vidpids") or [])
                if isinstance(d, dict)]

    async def set_global_usb_vidpids(self, devices: List[Dict[str, Any]]) -> None:
        with self._lock:
            g = self._global()
            g["usb_vidpids"] = [dict(d) for d in (devices or []) if isinstance(d, dict)]
            self._save()

    async def get_global_usb_ignored_vidpids(self) -> List[str]:
        """Platform-wide ignored USB VID:PIDs — bare lowercased vidpid strings."""
        raw = self._global().get("usb_ignored_vidpids") or []
        out: List[str] = []
        for d in raw:
            vp = (d.get("vidpid") if isinstance(d, dict) else d)
            vp = str(vp or "").strip().lower()
            if vp and vp not in out:
                out.append(vp)
        return out

    async def set_global_usb_ignored_vidpids(self, vidpids: List[Any]) -> None:
        with self._lock:
            g = self._global()
            norm: List[str] = []
            for d in (vidpids or []):
                vp = (d.get("vidpid") if isinstance(d, dict) else d)
                vp = str(vp or "").strip().lower()
                if vp and vp not in norm:
                    norm.append(vp)
            g["usb_ignored_vidpids"] = norm
            self._save()

    # ── staleness sweep last-run status (Setup → Sync, cluster-wide) ──────────
    # Result of the most recent NetBox staleness sweep (background loop or
    # on-demand "Sweep now"). Cluster-wide (not per-tenant), so it lives under
    # the reserved __global__ key. Shape: {status, scanned, decommissioned,
    # deleted, ip_freed, errors, message, per_tenant, last_sync_ts}.
    async def get_staleness_sweep_status(self) -> Dict[str, Any]:
        """Return the last cluster-wide staleness-sweep status (empty if never run)."""
        return dict(self._global().get("staleness_sweep", {}))

    async def set_staleness_sweep_status(self, status: Dict[str, Any]) -> None:
        """Replace the cluster-wide staleness-sweep status and persist."""
        with self._lock:
            g = self._global()
            g["staleness_sweep"] = status or {}
            self._save()