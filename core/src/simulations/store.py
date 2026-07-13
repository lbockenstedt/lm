"""JSON-backed, per-tenant store for Client-Sim config the LM hub owns.

The spoke remains the runtime source of truth (it actually runs the sims,
talks to Proxmox/Central, etc.). This store is what the Simulations UI reads
back without a spoke round-trip, and what the hub pushes down to the spoke via
``CS_CONFIG_UPDATE`` on every write (see routes.py ``_push_config``).

Persisted to ``simulations_store.json`` in the hub data dir with atomic saves.
Encrypted at rest with ``hub_encryption`` (Fernet) — this file holds onboarding
PSKs, per-tenant GitHub tokens, and Central API cluster creds, so it must not
sit on disk in cleartext. A pre-encryption plaintext file is migrated on the
first load (accepted once, then re-encrypted on the next save).
"""
import asyncio
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List

from security.encryption import hub_encryption

logger = logging.getLogger("SimulationsStore")


# Default hub-config knobs seeded for a tenant that hasn't saved any yet, so a
# NEW tenant's Setup/Proxmox card shows the details instead of a blank grid.
# Values mirror the cs speak ``_DEFAULTS`` (command_queue.py) in the HUB/UI key
# form (vm_image_*; the cs speak remaps to image*_template_id). This is
# display-only: get_hub_config merges stored values over these defaults but
# does NOT persist them — the first save's GET-merge-PUT persists the full set.
# JSON-list fields (usb_vidpids/usb_ignored_vidpids/ignored_hostnames),
# repo_branch, reclone_schedule_cron, and protected_vmids are deliberately NOT
# seeded (the card placeholder displays those; protected_vmids always merges
# 1001 at the cs speak regardless).
_DEFAULT_HUB_CONFIG: Dict[str, Any] = {
    # Provisioning Behavior
    "usb_auto_provision": "off",
    "usb_missing_timeout": 60,            # minutes (cs speak ×60 → seconds)
    "usb_max_slots": 24,
    # Resource Thresholds (% — 1-hour average)
    "cpu_provision_threshold": 80,
    "cpu_delete_threshold": 90,
    "mem_provision_threshold": 80,
    "mem_delete_threshold": 90,
    # Tier classification by PCI passthrough (T1/T3 are PCI, T2 is USB). A VM
    # whose hostpciN device matches one of these VID:PIDs is that tier. Defaults
    # match the solutions-hpe originals; edited in the Hub Config card. NOT in
    # preserve-on-reset: reset restores these canonical tier IDs.
    "t1_pci_vidpids": ["1912:0015"],
    "t3_pci_vidpids": ["168c:0034"],
    # VM Templates (clone-source VMIDs + image1 mix)
    "vm_image_1_template_id": 100,
    "vm_image_2_template_id": 200,
    "vm_image_1_pct": 50,
    # Parallel Provisioning
    "reclone_concurrency": 1,
    # VMID allocation range for new sim VMs (templates excluded by the agent)
    "vmid_start": 90000,
    "vmid_end": 99999,
    # Remaining hub-owned knobs (the Hub Config card)
    "use_all_dongles": "off",
    "vm_silent_timeout": 24,
    "l1_vlan_start": 100,
    "l1_vlan_end": 199,
    "reclone_schedule_enabled": "off",
    # Guest-agent watchdog group
    "guest_agent_watchdog_enabled": "on",
    "guest_agent_grace_minutes": 20,
    "guest_agent_check_interval_minutes": 10,
    "guest_agent_reboot_after_minutes": 10,
    "guest_agent_reclone_after_minutes": 30,
    "watchdog_reboot_enabled": "on",
}


# Setup → Hypervisors tab config (VM actions: backup / snapshot / confirm /
# per-host overrides). Tenant-scoped, stored under the tenant's
# ``hypervisors_config`` key. Backup defaults to vzdump snapshot mode (no
# downtime). ``per_host`` maps a Proxmox hostname → a partial override of the
# same keys (your hosts aren't clustered, so backup storage differs per host).
_DEFAULT_HYPERVISORS_CONFIG: Dict[str, Any] = {
    "backup_storage": "",          # Proxmox storage id for vzdump (per-host overridable)
    "backup_mode": "snapshot",     # snapshot | suspend | stop
    "backup_keep": 3,              # keep-last=N pruning (0 = no prune)
    "snapshot_keep": 5,            # informational retention target for the UI
    "snapshot_prefix": "lm",       # auto-snapshot name prefix
    "confirm_destructive": True,   # confirm prompt before stop/restart/backup/snapshot-delete
    "per_host": {},                # {hostname: {backup_storage, backup_mode, backup_keep, ...}}
}


class SimulationsStore:
    """Per-tenant JSON store for hub-owned Client-Sim config (see module docstring).

    All access is async + lock-guarded; every setter writes through atomically.
    Getters return defensive copies so callers can't mutate the live store.
    """

    def __init__(self, data_dir: str):
        self._path = os.path.join(data_dir, "simulations_store.json")
        self._lock = threading.Lock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._needs_rekey = False  # set when loaded via a fallback (plaintext) path
        # Set when the on-disk file EXISTED but could not be decrypted/parsed (bad
        # key, corrupt bytes, unreadable). Distinct from a legitimately absent/empty
        # file. When True, _save() REFUSES to overwrite the file so a transient
        # decrypt failure (e.g. a botched LM_FERNET_KEY rotation on deploy) can't
        # silently re-encrypt an empty store over every tenant's PSKs + tokens —
        # the next save after a failed load used to permanently destroy them.
        self._load_failed = False
        self._load()

    # ── persistence ────────────────────────────────────────────────────────
    def _load(self) -> None:
        """Load + decrypt the store. A pre-encryption plaintext file is accepted
        once as a migration and flagged for re-encryption on the next save."""
        try:
            with open(self._path, "rb") as f:
                content = f.read()
            if not content:
                self._data = {}
                return
            try:
                decrypted, used_primary = hub_encryption.decrypt_with_meta(content)
                if not used_primary:
                    # Decrypted via a previous-rotation or legacy key — re-encrypt
                    # under the current primary on the next save so this file stops
                    # depending on a fallback key (same migration as state/manager).
                    self._needs_rekey = True
                    logger.warning("SimulationsStore: %s decrypted with a FALLBACK "
                                   "key; will re-encrypt under the current key on "
                                   "next save.", self._path)
                self._data = json.loads(decrypted) or {}
            except Exception:
                # One-time migration: a file written before at-rest encryption was
                # applied to this store is plaintext JSON. Accept it this once and
                # re-encrypt on the next save rather than crashing or losing the
                # tenant onboarding PSKs / tokens already persisted — UNLESS the
                # operator set LM_ALLOW_PLAINTEXT_FALLBACK=0, in which case fail
                # closed (start empty) so a botched rotation can't silently flip
                # the simulations store to a plaintext read. Same gate KeyManager
                # and StateManager apply to their stores.
                from security.encryption import plaintext_fallback_allowed
                if not plaintext_fallback_allowed():
                    logger.error(
                        "SimulationsStore: %s failed Fernet decrypt and "
                        "LM_ALLOW_PLAINTEXT_FALLBACK=0 — refusing plaintext "
                        "fallback; starting empty AND refusing to overwrite the "
                        "file (re-run rotate_fernet_key / restore LM_FERNET_KEY).",
                        self._path)
                    self._data = {}
                    self._load_failed = True
                    self._backup_undecryptable()
                    return
                try:
                    with open(self._path, "r") as pf:
                        self._data = json.load(pf) or {}
                    self._needs_rekey = True
                    logger.warning("SimulationsStore: %s was plaintext "
                                   "(pre-encryption); migrating to Fernet on next "
                                   "save.", self._path)
                except Exception as exc:
                    logger.error("SimulationsStore: load failed (%s): %s — starting "
                                 "empty AND refusing to overwrite the file",
                                 self._path, exc)
                    self._data = {}
                    self._load_failed = True
                    self._backup_undecryptable()
        except FileNotFoundError:
            self._data = {}  # fresh install — legitimately absent, safe to save
        except Exception as exc:  # unreadable file, etc. — do NOT clobber it
            logger.error("SimulationsStore: load failed (%s): %s — starting empty "
                         "AND refusing to overwrite the file", self._path, exc)
            self._data = {}
            self._load_failed = True
            self._backup_undecryptable()

    def _backup_undecryptable(self) -> None:
        """Best-effort: preserve the on-disk bytes that could not be decrypted/
        parsed, so an operator can recover after fixing the key. Writes a one-time
        ``.undecryptable`` sidecar (never overwritten on repeated failed loads, so
        the FIRST-captured copy is kept)."""
        bak = self._path + ".undecryptable"
        try:
            if os.path.exists(self._path) and not os.path.exists(bak):
                with open(self._path, "rb") as src, open(bak, "wb") as dst:
                    dst.write(src.read())
                try:
                    os.chmod(bak, 0o600)
                except OSError:
                    pass
                logger.error("SimulationsStore: preserved undecryptable store at "
                             "%s for recovery", bak)
        except Exception as exc:  # noqa: BLE001 — backup is best-effort
            logger.warning("SimulationsStore: could not back up undecryptable "
                           "store (%s): %s", self._path, exc)

    def _save(self) -> None:
        if self._load_failed:
            # The on-disk store existed but could not be decrypted/parsed at load.
            # Overwriting it now would re-encrypt the empty in-memory store on top
            # of the real (recoverable) data — the exact silent-wipe this guard
            # prevents. Drop the write; fix the key / restore the file and restart.
            logger.error("SimulationsStore: NOT saving — the store failed to load "
                         "and overwriting would destroy the existing on-disk data "
                         "(%s). Restore LM_FERNET_KEY / the file, then restart.",
                         self._path)
            return
        try:
            tmp = self._path + ".tmp"
            encrypted = hub_encryption.encrypt(
                json.dumps(self._data, indent=2, default=str))
            with open(tmp, "wb") as f:
                f.write(encrypted)
            try:
                os.chmod(tmp, 0o600)  # encrypted simulations store: not world-readable
            except OSError:
                pass
            os.replace(tmp, self._path)
            self._needs_rekey = False
        except Exception as exc:
            logger.warning("SimulationsStore: save failed (%s): %s", self._path, exc)

    async def _asave(self) -> None:
        """Async wrapper around the synchronous atomic JSON write.

        ``_save`` runs on every setter (hub-config, overrides, sync-status, psk,
        processing-mode, …) — the Simulations UI save paths. Doing the fsync'd
        atomic replace inline on the hub's asyncio loop is the same
        I/O-starvation pattern that stalled cs-svr-02's WS link (sync disk
        writes on the shared loop → 5s Request Timeout). The ``_lock`` is held
        across the await by the caller, which serializes setters (intent) and
        keeps ``_data`` stable for the worker thread; ``_save`` itself doesn't
        touch the lock."""
        await asyncio.to_thread(self._save)

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
            await self._asave()

    # ── simulation.conf override content (raw INI pushed as sim_conf_override) ──
    async def set_sim_conf_content(self, tenant_id: str, content: str) -> None:
        """Store the raw simulation.conf override INI for the tenant and persist."""
        with self._lock:
            self._tenant(tenant_id)["sim_conf_content"] = content
            await self._asave()

    async def get_sim_conf_content(self, tenant_id: str) -> str:
        """Return the stored raw simulation.conf override INI ('' if unset)."""
        return self._data.get(tenant_id, {}).get("sim_conf_content", "") or ""

    # ── user-overrides.conf override content (raw INI pushed as user_conf_override) ──
    # Parallel to sim_conf_content: the raw user-overrides.conf override INI the
    # Sim Config editor saves. Pushed to the spoke as ``user_conf_override``
    # (CS_CONFIG_UPDATE → configs/hub-user-overrides.conf, merged on top of the
    # repo's user-overrides.conf by sim_config.load_configs).
    async def set_user_overrides_content(self, tenant_id: str, content: str) -> None:
        """Store the raw user-overrides.conf override INI for the tenant and persist."""
        with self._lock:
            self._tenant(tenant_id)["user_overrides_content"] = content
            await self._asave()

    async def get_user_overrides_content(self, tenant_id: str) -> str:
        """Return the stored raw user-overrides.conf override INI ('' if unset)."""
        return self._data.get(tenant_id, {}).get("user_overrides_content", "") or ""

    # JSON-list fields that hold real certified/ignored data — PRESERVED across
    # a "reset to default" (resetting the knobs must NOT de-certify the tenant's
    # dongles or wipe the ignored-host list; those are managed on the USB page).
    _HUB_CONFIG_PRESERVE_ON_RESET = (
        "usb_vidpids", "usb_ignored_vidpids", "ignored_hostnames",
    )

    # ── hub-config (usb provisioning / vm images / reclone knobs) ──────────
    async def get_hub_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return ``{hub_config_enabled, hub_config}`` for the tenant.

        Seeds ``_DEFAULT_HUB_CONFIG`` for fields the tenant hasn't stored so a
        new tenant sees the details (stored values win). Display-only — not
        persisted here; the first save's GET-merge-PUT persists the full set.
        """
        t = self._data.get(tenant_id, {})
        stored = t.get("hub_config") or {}
        merged = dict(_DEFAULT_HUB_CONFIG)
        merged.update(stored)
        return {"hub_config_enabled": bool(t.get("hub_config_enabled", False)),
                "hub_config": merged}

    async def set_hub_config(self, tenant_id: str, enabled: bool,
                             hub_config: Dict[str, Any]) -> None:
        """Set the hub-config enabled flag + knob dict for the tenant and persist."""
        with self._lock:
            t = self._tenant(tenant_id)
            t["hub_config_enabled"] = bool(enabled)
            t["hub_config"] = hub_config or {}
            await self._asave()

    async def get_hypervisors_config(self, tenant_id: str) -> Dict[str, Any]:
        """Setup → Hypervisors config for the tenant (backup/snapshot/per-host/
        confirm). Seeds ``_DEFAULT_HYPERVISORS_CONFIG`` for unset fields (stored
        values win). ``effective_for(hostname)`` merge happens at command time."""
        t = self._data.get(tenant_id, {})
        stored = t.get("hypervisors_config") or {}
        merged = dict(_DEFAULT_HYPERVISORS_CONFIG)
        merged.update(stored)
        merged["per_host"] = dict(stored.get("per_host") or {})
        return merged

    async def set_hypervisors_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Persist the tenant's Hypervisors config (full GET-merge-PUT from the UI)."""
        with self._lock:
            t = self._tenant(tenant_id)
            t["hypervisors_config"] = cfg or {}
            await self._asave()

    async def reset_hub_config(self, tenant_id: str) -> Dict[str, Any]:
        """Reset the tenant's Setup/Proxmox knobs to ``_DEFAULT_HUB_CONFIG``,
        preserving the certified/ignored USB vidpid lists + ignored-hostname list
        (real data managed on the USB page, not factory knobs) and the current
        ``hub_config_enabled`` flag. The returned ``hub_config`` carries an
        explicit value for every visible knob (incl. empties for protected_vmids
        / repo_branch / reclone_schedule_cron) so a push clears the spoke's prior
        user values too — the spoke's _apply_hub_config only sets present keys,
        so absent keys would otherwise linger. Returns
        ``{hub_config_enabled, hub_config}`` for the caller to push."""
        with self._lock:
            t = self._tenant(tenant_id)
            stored = t.get("hub_config") or {}
            preserved = {k: stored.get(k, "[]") for k in self._HUB_CONFIG_PRESERVE_ON_RESET}
            new_cfg = dict(_DEFAULT_HUB_CONFIG)
            # Explicit empties for visible fields not in _DEFAULT_HUB_CONFIG so
            # the spoke clears any user-set value (placeholder display on reset).
            new_cfg.update({
                "protected_vmids": "",
                "repo_branch": "",
                "reclone_schedule_cron": "",
            })
            new_cfg.update(preserved)
            t["hub_config"] = new_cfg
            await self._asave()
            return {"hub_config_enabled": bool(t.get("hub_config_enabled", False)),
                    "hub_config": dict(new_cfg)}

    # ── central API config (mode + cluster creds) ──────────────────────────
    async def get_central_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's Central API config (mode + cluster creds)."""
        return self._data.get(tenant_id, {}).get("central_config", {})

    async def set_central_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's Central API config and persist."""
        with self._lock:
            self._tenant(tenant_id)["central_config"] = cfg or {}
            await self._asave()

    # ── central sites config (Setup → Central API / Central) ────────────────
    async def get_central_sites_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's Central sites config."""
        return self._data.get(tenant_id, {}).get("central_sites_config", {})

    async def set_central_sites_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's Central sites config and persist."""
        with self._lock:
            self._tenant(tenant_id)["central_sites_config"] = cfg or {}
            await self._asave()

    # ── adaptive harvest controller state (design doc §9) ────────────────────
    # Per-tenant {quota_key: {target, floor, mode, last_change}} — the running
    # state of the min/max ramp-decay-learn controller. Small (tens of quotas).
    async def get_adaptive_state(self, tenant_id: str) -> Dict[str, Any]:
        v = self._data.get(tenant_id, {}).get("adaptive_quota_state")
        return dict(v) if isinstance(v, dict) else {}

    async def set_adaptive_state(self, tenant_id: str, state: Dict[str, Any]) -> None:
        with self._lock:
            self._tenant(tenant_id)["adaptive_quota_state"] = dict(state) if isinstance(state, dict) else {}
            await self._asave()

    # ── shared alert/insight history (GLOBAL — all tenants + system defaults) ──
    # A single hub-wide catalog of every Central alert/insight NAME ever observed,
    # so the Sim-Quota "Alert / Insight ID" picker can offer them BEFORE they fire
    # again — a quota has to be set while the alert is quiet (chicken/egg). Stored
    # under a reserved top-level key (NOT tenant-scoped: tenant ids never take this
    # form), so it is shared by every tenant's Config → Sim Quotas AND the
    # superadmin Setup → Simulations defaults. Keyed "{type}:{id}".
    _AIH_KEY = "__alert_insight_history__"

    async def get_alert_insight_history(self) -> List[Dict[str, Any]]:
        """Return the shared alert/insight history as a list of
        {type, id, name, site, first_seen, last_seen}."""
        hist = self._data.get(self._AIH_KEY)
        if not isinstance(hist, dict):
            return []
        return [dict(v) for v in hist.values() if isinstance(v, dict)]

    async def record_alert_insight_seen(self, items: List[Dict[str, Any]]) -> int:
        """Upsert observed alerts/insights into the shared history. Each item:
        {type: 'alert'|'insight', id|name, site?}. Returns the count of NEW entries.
        Persists only when a new entry is added or a name changes (last_seen alone
        updates in memory), so routine browse polls don't rewrite the store."""
        if not items:
            return 0
        now = time.time()
        added = 0
        with self._lock:
            hist = self._data.get(self._AIH_KEY)
            if not isinstance(hist, dict):
                hist = {}
                self._data[self._AIH_KEY] = hist
            changed = False
            for it in items:
                try:
                    typ = str((it or {}).get("type") or "alert").strip().lower()
                    if typ not in ("alert", "insight"):
                        typ = "alert"
                    ident = str((it or {}).get("id") or (it or {}).get("name") or "").strip()
                    if not ident:
                        continue
                    name = str((it or {}).get("name") or ident).strip()
                    site = str((it or {}).get("site") or "").strip()
                    key = f"{typ}:{ident}"
                    entry = hist.get(key)
                    if entry is None:
                        hist[key] = {"type": typ, "id": ident, "name": name,
                                     "site": site, "first_seen": now, "last_seen": now}
                        added += 1
                        changed = True
                    else:
                        entry["last_seen"] = now  # in-memory; not worth a write alone
                        if name and entry.get("name") != name:
                            entry["name"] = name
                            changed = True
                except Exception:  # noqa: BLE001 — never let telemetry recording throw
                    continue
            if changed:
                await self._asave()
        return added

    # ── github config (Setup → GitHub: per-spoke repo + token) ───────────────
    async def get_github_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's GitHub config (per-spoke repo + token)."""
        return self._data.get(tenant_id, {}).get("github_config", {})

    async def set_github_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's GitHub config and persist."""
        with self._lock:
            self._tenant(tenant_id)["github_config"] = cfg or {}
            await self._asave()

    # ── config Source of Truth (Config screen: Hub vs GitHub) ────────────────
    async def get_source_of_truth(self, tenant_id: str) -> str:
        """Where the tenant's simulation.conf / user-overrides.conf are owned:
        'hub'  = the hub stores the full files; the GitHub repo copy is ignored
                 and can never revert them (fully hub-owned).
        'github' = the GitHub repo is authoritative; edits require an API key and
                 are committed+pushed back. Default 'github' (preserves the
                 pre-feature behavior where the repo file is the base)."""
        val = self._data.get(tenant_id, {}).get("source_of_truth")
        return "hub" if val == "hub" else "github"

    async def set_source_of_truth(self, tenant_id: str, source: str) -> None:
        """Persist the tenant's config source of truth ('hub' | 'github')."""
        with self._lock:
            self._tenant(tenant_id)["source_of_truth"] = "hub" if source == "hub" else "github"
            await self._asave()

    # ── security config (Setup → Security: spoke-local dashboard auth) ──────
    async def get_security_config(self, tenant_id: str) -> Dict[str, Any]:
        """Return the tenant's spoke-local dashboard security config."""
        return self._data.get(tenant_id, {}).get("security_config", {})

    async def set_security_config(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        """Replace the tenant's security config and persist."""
        with self._lock:
            self._tenant(tenant_id)["security_config"] = cfg or {}
            await self._asave()

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
            await self._asave()

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
            await self._asave()

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
            await self._asave()

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
            await self._asave()

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
            await self._asave()

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
            await self._asave()

    async def remove_psk(self, tenant_id: str, psk: str) -> bool:
        """Remove an onboarding PSK from the tenant; return True if it was present."""
        with self._lock:
            t = self._tenant(tenant_id)
            psks = list(t.get("onboarding_psks", []))
            if psk in psks:
                psks.remove(psk)
                t["onboarding_psks"] = psks
                await self._asave()
                return True
            return False

    def tenant_ids(self) -> list:
        """Every tenant id with a record in the store — used by the hub-side
        Central poller to find centralized-mode tenants to poll."""
        return list(self._data.keys())

    # ── processing modes (central_api / teams / email → centralized|distributed) ──
    async def get_processing_modes(self, tenant_id: str) -> Dict[str, str]:
        return dict(self._data.get(tenant_id, {}).get("processing_modes", {}))

    async def set_processing_mode(self, tenant_id: str, feature: str, value: str) -> None:
        with self._lock:
            t = self._tenant(tenant_id)
            modes = dict(t.get("processing_modes", {}))
            modes[feature] = value
            t["processing_modes"] = modes
            await self._asave()

    # ── notifications (smtp / teams / email) ───────────────────────────────
    async def get_notifications(self, tenant_id: str) -> Dict[str, Any]:
        return dict(self._data.get(tenant_id, {}).get("notifications", {}))

    async def set_notifications(self, tenant_id: str, cfg: Dict[str, Any]) -> None:
        with self._lock:
            self._tenant(tenant_id)["notifications"] = cfg or {}
            await self._asave()

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

    async def get_sim_quota_defaults(self) -> List[Dict[str, Any]]:
        """Platform-wide Sim-Quota default templates (Setup → Simulations).
        Same schema as a tenant's ``central_sites_config.sim_quotas`` rows but
        site is optional (blank = "all sites"). A tenant's enabled sim_quotas
        override these per ``alert_type:alert_id:site``; the engine (Chunk 2)
        merges global defaults + tenant overrides."""
        return [dict(d) for d in (self._global().get("sim_quota_defaults") or [])
                if isinstance(d, dict)]

    async def set_sim_quota_defaults(self, quotas: List[Dict[str, Any]]) -> None:
        with self._lock:
            self._global()["sim_quota_defaults"] = [
                dict(d) for d in (quotas or []) if isinstance(d, dict)]
            await self._asave()

    # ── GLOBAL simulation sharing (stacking) + N/A hide (Setup → Simulations) ──
    # Platform-wide (all tenants) authoritative per-sim shareable/stackable map
    # and the UI-only N/A hide map. A non-shareable sim can NEVER be stacked by
    # any tenant's SimQuotaEngine. Lives under ``__global__`` and is pushed to
    # every tenant's spoke as CS_CONFIG_UPDATE.sim_shareable.
    async def get_sim_shareable_global(self) -> Dict[str, Any]:
        v = self._global().get("sim_shareable")
        return dict(v) if isinstance(v, dict) else {}

    async def set_sim_shareable_global(self, mapping: Dict[str, Any]) -> None:
        with self._lock:
            self._global()["sim_shareable"] = dict(mapping) if isinstance(mapping, dict) else {}
            await self._asave()

    async def get_sim_na_global(self) -> Dict[str, Any]:
        v = self._global().get("sim_na")
        return dict(v) if isinstance(v, dict) else {}

    async def set_sim_na_global(self, mapping: Dict[str, Any]) -> None:
        with self._lock:
            self._global()["sim_na"] = dict(mapping) if isinstance(mapping, dict) else {}
            await self._asave()

    async def get_global_usb_vidpids(self) -> List[Dict[str, Any]]:
        """Platform-wide (superadmin-certified) USB device list —
        {vidpid, type, label} dicts (the cs-spoke re-filter shape)."""
        return [dict(d) for d in (self._global().get("usb_vidpids") or [])
                if isinstance(d, dict)]

    async def set_global_usb_vidpids(self, devices: List[Dict[str, Any]]) -> None:
        with self._lock:
            g = self._global()
            g["usb_vidpids"] = [dict(d) for d in (devices or []) if isinstance(d, dict)]
            await self._asave()

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
            g["usb_ignored_vidpids"] = self._bare_vidpid_list(vidpids)
            await self._asave()

    # ── Global PCI-passthrough tier VID:PIDs (superadmin, platform-wide) ──────
    # T1/T3 are PCI passthrough. These platform-wide lists are merged (union)
    # with each tenant's t1_pci_vidpids/t3_pci_vidpids and pushed to every
    # tenant's spoke → agent, exactly like the global USB certified/ignored
    # lists. Bare lowercased ``vid:pid`` strings.
    @staticmethod
    def _bare_vidpid_list(vidpids: List[Any]) -> List[str]:
        out: List[str] = []
        for d in (vidpids or []):
            vp = (d.get("vidpid") if isinstance(d, dict) else d)
            vp = str(vp or "").strip().lower()
            if vp and vp not in out:
                out.append(vp)
        return out

    async def get_global_t1_pci_vidpids(self) -> List[str]:
        return self._bare_vidpid_list(self._global().get("t1_pci_vidpids"))

    async def set_global_t1_pci_vidpids(self, vidpids: List[Any]) -> None:
        with self._lock:
            self._global()["t1_pci_vidpids"] = self._bare_vidpid_list(vidpids)
            await self._asave()

    async def get_global_t3_pci_vidpids(self) -> List[str]:
        return self._bare_vidpid_list(self._global().get("t3_pci_vidpids"))

    async def set_global_t3_pci_vidpids(self, vidpids: List[Any]) -> None:
        with self._lock:
            self._global()["t3_pci_vidpids"] = self._bare_vidpid_list(vidpids)
            await self._asave()

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
            await self._asave()

    # ── repo sync last-run status (Setup → Sync) ───────────────────────────
    # Result of the most recent GitHub repo sync (background loop or on-demand
    # "Sync now"). Pulls the hub tree + provisioning_repos/* locally and fans
    # SPOKE_UPDATE out to every approved spoke. Cluster-wide, so under __global__.
    # Shape: {last_sync_ts, hub: {status,message}, provisioning_repos: [...],
    # message}.
    async def get_repo_sync_status(self) -> Dict[str, Any]:
        """Return the last GitHub repo-sync status (empty if never run)."""
        return dict(self._global().get("repo_sync", {}))

    async def set_repo_sync_status(self, status: Dict[str, Any]) -> None:
        """Replace the GitHub repo-sync status and persist."""
        with self._lock:
            g = self._global()
            g["repo_sync"] = status or {}
            await self._asave()