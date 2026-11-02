"""Fleet OS-update module (hub side).

The hub is the module: it COLLECTS pending-update state from every spoke and
agent, decides what is eligible, and — on explicit operator approval — SENDS the
apply commands. Nodes only execute; they never decide to update themselves.

Operator-chosen behaviour (see the WebUI panel):
  * ``apt-get dist-upgrade`` — everything: security, regular, and dependency
    transitions. (A Debian MAJOR release jump is a different operation that
    rewrites sources.list and is deliberately NOT behind this button.)
  * A manual apply NEVER reboots. ``reboot_required`` is surfaced as a badge;
    rebooting is a separate explicit action (or Auto-reboot, below).
  * Approve once, then ROLLING apply — one node at a time, each finishing before
    the next starts, so a bad update cannot take the fleet down simultaneously.
  * The HUB APPLIES LAST. Updating the hub restarts the very process serving the
    approval UI and the control plane every other node is reporting through, so
    it goes after every spoke and agent has reported.
  * Ineligible nodes (TrueNAS, OPNsense, `nw` devices) are listed as UNMANAGED
    with a reason rather than hidden — a partial fleet view that looks complete
    is how "up to date" gets confused with "not covered".

Selective patching: an apply can target chosen nodes, chosen packages on a
node, or only the security updates. Package-level apply and reboot use their
own command types (``OS_UPDATE_APPLY_PACKAGES`` / ``OS_REBOOT``) and are only
offered for nodes whose check reported the matching ``features`` — an older
node never sees a request it would misread as "upgrade everything".

Auto-patch (PER NODE; new spokes/agents are enrolled with auto-reboot on
first sight, the hub never is) only runs inside the
maintenance window (``window``: start/end "HH:MM" in a timezone, default
01:00-05:00; start == end means any time). Once per window, as soon as it
opens, the fleet is re-checked and the nodes an operator approved for
auto-patching that have pending updates are deployed automatically through the
same rolling, hub-last apply, audit-logged as actor "auto-patch". The run
starts no new node after the window closes. Security-only by default. Packages
matching the operator's exclude list (names or globs, e.g. ``linux-image-*``)
are never auto-installed. The scheduled auto-check (every 6h by default) only
detects updates; manual checks never patch, and a node whose update keeps
failing is retried once per window, not in a loop.

Auto-reboot (per node, only with auto-patch): ticked by default when a node is
approved for auto-patch, and can be unticked per node. After an auto-patch run
finishes, every auto-reboot node that installed something is rebooted through
the same command as the Reboot button (``shutdown -r +1``), audit-logged as
actor "auto-reboot". Spokes and agents are rebooted once they have all been
patched and BEFORE the hub is patched (patching the hub can restart LM, which
would lose any reboot still queued); the hub reboots last.

A Proxmox host agent that reports cluster membership (``pve_cluster`` +
the ``maintenance`` feature) is different: right after it is patched, and
only if it needs a reboot, it is put into HA maintenance mode (its HA guests
migrate to the other nodes; non-HA guests stay and are not critical), rebooted,
and the run waits until it is back and no longer needs a reboot before
clearing maintenance mode and moving on — so only one cluster node is ever
down. If it doesn't come back in time it is left in maintenance mode and the
rest of the run is stopped. The same happens on a MANUAL deploy to a cluster
node (a manual deploy otherwise never reboots) and for its Reboot button.

Pre-patch VM snapshots: each node is linked to the Proxmox VM it runs in
(matched by hostname, IP only to break a tie — see ``vm_snapshots.find_vm``);
Proxmox hosts themselves are bare metal and never linked. With snapshots on
(the default), a linked node's VM is snapshotted as ``lm-prepatch-<UTC time>``
right before it is patched — manual deploy and auto-patch alike — and only the
last ``keep`` (default 2) pre-patch snapshots are kept. If the snapshot fails
the node is not patched. Settings: ``global_config["os_updates_snapshot"]``.

Fixing access: a non-root node without the lm-os-update helper is "blocked".
``osu_fix_access`` relays a root/sudo login typed once in the WebUI to that
node, which uses it to install the helper (``os_update.fix_access``). The
password lives only in that one request — never stored or logged.

The last check results and the current/last run are persisted to
``<cache_dir>/os_updates.json`` so a hub restart (including the one the hub's
own update causes) doesn't blank the panel. A run that was in flight when the
hub stopped is marked ``interrupted`` on load. A run can be cancelled: the node
currently applying finishes (apt can't be safely aborted), the rest are skipped.

This module is DISTINCT from ``update_pipeline.py``, which ships LM's own code.
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import socket
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from cache_core import JsonCacheFile  # sibling leaf
from os_cve import CVE_RE, FeedCache, match_node  # sibling leaf
from sync_loop import run_sync_loop  # sibling leaf
import vm_snapshots  # sibling leaf

logger = logging.getLogger("Hub")

# Module types that are not Debian hosts at all. `nw` nodes are switches/APs
# reached over SNMP/CLI/REST — there is no host and no agent, so they are never
# even probed; probing would just time out and look like a failure.
_NEVER_PROBE_TYPES = {"nw", "firewall", "storage"}
_NEVER_PROBE_REASON = {
    "nw": "network device (switch/AP) — no host OS we manage; firmware is out of scope",
    "firewall": "OPNsense is FreeBSD and appliance-managed — update from its own UI",
    "storage": "TrueNAS is appliance-managed — apt here corrupts its own updater",
}

_CHECK_TIMEOUT_S = 240.0
_APPLY_TIMEOUT_S = 3700.0
_REBOOT_TIMEOUT_S = 60.0
# Auto-reboot of a clustered Proxmox node (see _osu_cluster_reboot).
_MAINT_POLL_S = 15.0
_MAINT_MIGRATE_TIMEOUT_S = 15 * 60.0
_REBOOT_GRACE_S = 90.0          # shutdown -r +1, plus time to go down
_REBOOT_RETURN_TIMEOUT_S = 20 * 60.0
_FIX_ACCESS_TIMEOUT_S = 180.0
_STATE_FILE = "os_updates.json"

# Auto-check config lives in global_config["os_updates_check"]: {enabled,
# interval_hours}. Enabled by default (seeded once — see
# seed_os_updates_check_defaults) so the panel's status stays fresh without an
# operator remembering to click "Check for updates"; every 6h by default.
_OSU_AUTOCHECK_CFG_KEY = "os_updates_check"
_OSU_AUTOCHECK_DEFAULT_HOURS = 6.0

# Auto-patch config lives in global_config["os_updates_autopatch"]:
# {security_only, nodes: ["kind:id", ...], exclude: ["pkg-or-glob", ...],
#  reboot_nodes: ["kind:id", ...], window: {start, end, tz}}.
# Only listed nodes are auto-patched; excluded packages are never auto-installed.
# reboot_nodes (always a subset of nodes) are rebooted after an auto-patch run.
# known: every node key ever seen. A node not in it yet is new and is enrolled
# in auto-patch + auto-reboot on first sight (the hub never is); after that the
# operator's choice sticks.
_OSU_AUTOPATCH_CFG_KEY = "os_updates_autopatch"
_AUTOPATCH_ACTOR = "auto-patch"
_AUTOREBOOT_ACTOR = "auto-reboot"
_CVE_MAX_RESULTS = 200
_DEFAULT_WINDOW = {"start": "01:00", "end": "05:00", "tz": "UTC"}
_AUTOPATCH_TICK_S = 300.0

# Pre-patch VM snapshots: global_config["os_updates_snapshot"] = {enabled, keep}.
# On by default; keep the last 2 pre-patch snapshots per VM.
_OSU_SNAPSHOT_CFG_KEY = "os_updates_snapshot"
_PREPATCH_PREFIX = "lm-prepatch-"
# Spokes of these types run their agents on Proxmox hosts themselves.
_PVE_HOST_SPOKE_TYPES = {"hypervisor", "simulation"}


def _parse_window(window: Any) -> Dict[str, str]:
    """Validate ``{start, end, tz}`` ("HH:MM", "HH:MM", IANA zone name).
    Raises ValueError on a bad value."""
    w = {**_DEFAULT_WINDOW, **(window or {})}
    for k in ("start", "end"):
        datetime.strptime(str(w[k]), "%H:%M")
    try:
        ZoneInfo(str(w["tz"]))
    except Exception as exc:  # noqa: BLE001 — ZoneInfoNotFoundError, ValueError, ...
        raise ValueError(f"unknown timezone {w['tz']!r}") from exc
    return {"start": str(w["start"]), "end": str(w["end"]), "tz": str(w["tz"])}


def _read_window(window: Any) -> Dict[str, str]:
    """Stored window, or the default if it is missing or no longer valid."""
    try:
        return _parse_window(window)
    except ValueError:
        return dict(_DEFAULT_WINDOW)


def window_bounds(window: Dict[str, str], now: float) -> Optional[Tuple[float, float]]:
    """``(opened_at, closes_at)`` of the maintenance window ``now`` falls in,
    or None when outside it. Handles windows across midnight; start == end is
    a 24h window (any time)."""
    tz = ZoneInfo(window["tz"])
    local = datetime.fromtimestamp(now, tz)
    sh, sm = map(int, window["start"].split(":"))
    eh, em = map(int, window["end"].split(":"))
    length = timedelta(minutes=((eh * 60 + em) - (sh * 60 + sm)) % (24 * 60) or 24 * 60)
    opened = local.replace(hour=sh, minute=sm, second=0, microsecond=0)
    if opened > local:
        opened -= timedelta(days=1)
    closes = opened + length
    if local >= closes:
        return None
    return opened.timestamp(), closes.timestamp()


class HubOsUpdatesMixin:
    """Collect + orchestrate OS package updates across the fleet."""

    # ── state ────────────────────────────────────────────────────────────────
    def _osu_state(self) -> Dict[str, Any]:
        st = getattr(self, "_os_update_state", None)
        if st is None:
            st = {"nodes": {}, "checked_at": 0.0, "run": None}
            self._os_update_state = st
        return st

    def _osu_file(self) -> Optional[JsonCacheFile]:
        """Persistence for check results + runs; None on a hub without a cache dir."""
        if not getattr(self, "cache_dir", None):
            return None
        f = getattr(self, "_osu_cache_file", None)
        if f is None:
            f = JsonCacheFile("os-updates", lambda: os.path.join(self.cache_dir, _STATE_FILE),
                              self._osu_state, flush_delay_s=1.0)
            self._osu_cache_file = f
        return f

    def _osu_save(self) -> None:
        f = self._osu_file()
        if f is not None:
            f.schedule_save()

    def osu_load_state(self) -> None:
        """Restore the last check + run at startup. A run that was still
        "running" died with the previous process — most often the hub's own
        update restarting it — so it is marked interrupted, not resumed."""
        f = self._osu_file()
        data = f.load() if f is not None else None
        if not isinstance(data, dict):
            return
        st = self._osu_state()
        if isinstance(data.get("nodes"), dict):
            st["nodes"] = data["nodes"]
        if isinstance(data.get("inventory"), dict):
            st["inventory"] = data["inventory"]
        st["checked_at"] = float(data.get("checked_at") or 0.0)
        st["autopatch_at"] = float(data.get("autopatch_at") or 0.0)
        run = data.get("run")
        if isinstance(run, dict):
            if run.get("status") == "running":
                run["status"] = "interrupted"
                run["current"] = ""
                for item in run.get("items") or []:
                    if item.get("status") == "applying":
                        item["status"] = "interrupted"
                        item["message"] = ("hub restarted while this node was "
                                           "updating — check it, then re-check")
                    elif item.get("status") in ("queued", "snapshotting"):
                        item["status"] = "skipped"
            st["run"] = run
        logger.info("os-updates: restored %d node result(s) from %s",
                    len(st["nodes"]), _STATE_FILE)

    # ── inventory ────────────────────────────────────────────────────────────
    def _osu_targets(self) -> List[Dict[str, str]]:
        """Every node we could update: connected spokes, their agents, + the hub.

        Returns ``[{kind, id, spoke_id, label, module_type}]``. Ineligible-by-type
        nodes are included so the panel can show them as unmanaged.
        """
        out: List[Dict[str, str]] = []
        conns = getattr(self, "active_connections", {}) or {}
        meta = {}
        try:
            meta = (self.state.system_state.get("module_metadata", {}) or {})
        except Exception:  # noqa: BLE001
            meta = {}
        for sid in list(conns.keys()):
            md = meta.get(sid, {}) or {}
            mtype = str(md.get("module_type") or md.get("type") or "").strip()
            label = (md.get("display_name") or md.get("name")
                     or md.get("hostname") or sid)
            out.append({"kind": "spoke", "id": sid, "spoke_id": sid,
                        "label": str(label), "module_type": mtype})
        def _host(name):
            return str(name or "").split(".")[0].strip().lower()
        spoke_hosts = set()
        for sid in conns:
            md = meta.get(sid, {}) or {}
            spoke_hosts |= {_host(md.get(f)) for f in ("display_name", "name", "hostname")}
        spoke_hosts.discard("")
        # Agents, routed via their owning spoke. An agent on a machine that is
        # already listed as a spoke is the same OS — patching it twice would
        # just duplicate the row, so it is skipped.
        # agent_info is guid-keyed once an agent is migrated (B2); the owning
        # spoke only knows the agent by the raw ``agent_id`` it reported, so the
        # relay must address it by that name (same as Remote Console).
        for aid, info in (getattr(self, "agent_info", {}) or {}).items():
            sid = (info or {}).get("spoke_id") or ""
            if not sid or _host((info or {}).get("hostname")) in spoke_hosts:
                continue
            out.append({"kind": "agent", "id": aid, "spoke_id": sid,
                        "agent_id": str((info or {}).get("agent_id") or aid),
                        "label": str((info or {}).get("hostname") or aid),
                        "module_type": "agent"})
        out.append({"kind": "hub", "id": "hub", "spoke_id": "",
                    "label": "hub (this server)", "module_type": "hub"})
        return out

    def osu_tenant_node_keys(self, tenants: "set[str]") -> "set[str]":
        """Node keys a tenant admin of ``tenants`` may see and patch: spokes
        bound to one of those tenants, and the agents those spokes own. Never
        the hub."""
        keys = set()
        for t in self._osu_targets():
            if t["kind"] == "hub":
                continue
            if self.state.get_spoke_tenant(t["spoke_id"]) in tenants:
                keys.add(f"{t['kind']}:{t['id']}")
        return keys

    # ── check ────────────────────────────────────────────────────────────────
    async def _osu_check_one(self, t: Dict[str, str], refresh: bool) -> Dict[str, Any]:
        base = {"kind": t["kind"], "id": t["id"], "label": t["label"],
                "module_type": t["module_type"], "spoke_id": t.get("spoke_id", ""),
                "agent_id": t.get("agent_id", "")}
        mtype = (t.get("module_type") or "").lower()
        if mtype in _NEVER_PROBE_TYPES:
            return {**base, "eligible": False, "unmanaged": True,
                    "reason": _NEVER_PROBE_REASON[mtype], "count": 0}
        try:
            if t["kind"] == "hub":
                try:
                    from .os_update import check_updates
                except ImportError:
                    from os_update import check_updates  # type: ignore
                d = await asyncio.to_thread(check_updates, refresh)
            elif t["kind"] == "agent":
                resp = await self.request_response(
                    t["spoke_id"], "AGENT_OS_UPDATE_CHECK",
                    {"agent_id": t.get("agent_id") or t["id"], "refresh": refresh},
                    timeout=_CHECK_TIMEOUT_S)
                d = _unwrap(resp)
            else:
                resp = await self.request_response(
                    t["id"], "OS_UPDATE_CHECK", {"refresh": refresh},
                    timeout=_CHECK_TIMEOUT_S)
                d = _unwrap(resp)
        except Exception as exc:  # noqa: BLE001 — one unreachable node must not blank the fleet view
            return {**base, "eligible": None, "unreachable": True,
                    "reason": f"no answer: {exc}", "count": 0}
        if not isinstance(d, dict):
            return {**base, "eligible": None, "unreachable": True,
                    "reason": "malformed response", "count": 0}
        return {
            **base,
            "eligible": bool(d.get("eligible")),
            "unmanaged": not d.get("eligible", False),
            "reason": d.get("reason", "") or d.get("message", ""),
            "flavor": d.get("flavor", ""),
            "count": int(d.get("count") or 0),
            "security_count": int(d.get("security_count") or 0),
            "other_count": int(d.get("other_count") or 0),
            "reboot_required": bool(d.get("reboot_required")),
            "packages": d.get("packages") or [],
            "warnings": d.get("warnings") or [],
            "features": d.get("features") or [],
            "apply_blocker": d.get("apply_blocker") or "",
            "pve_cluster": d.get("pve_cluster") or {},
            "checked_at": time.time(),
            # Popped by osu_check_fleet into st["inventory"]; never in the snapshot.
            "_inventory": {"os": d.get("os") or {}, "installed": d.get("installed")},
        }

    async def osu_check_fleet(self, refresh: bool = True) -> Dict[str, Any]:
        """Probe every node concurrently. Read-only — installs nothing."""
        targets = self._osu_targets()
        results = await asyncio.gather(
            *[self._osu_check_one(t, refresh) for t in targets],
            return_exceptions=True)
        nodes = [r for r in results if isinstance(r, dict)]
        st = self._osu_state()
        inventory = st.setdefault("inventory", {})
        for n in nodes:
            key = f"{n['kind']}:{n['id']}"
            inv = n.pop("_inventory", None)
            if inv is None:
                continue  # unreachable/unmanaged: keep the last inventory we had
            if isinstance(inv.get("installed"), list):
                inventory[key] = {**inv, "at": time.time()}
            else:
                inventory.pop(key, None)  # node too old to report one
        st["nodes"] = {f"{n['kind']}:{n['id']}": n for n in nodes}
        st["checked_at"] = time.time()
        self._osu_enroll_new_nodes(list(st["nodes"]))
        self._osu_save()
        # Warm the CVE feeds now so a lookup doesn't wait on a download.
        await asyncio.to_thread(self._osu_feeds_for, inventory)
        return self.osu_snapshot()

    # ── auto-check schedule (WebUI-configurable) ────────────────────────────
    def _osu_autocheck_cfg(self) -> Dict[str, Any]:
        """Read the auto-check config fresh (enabled/interval_hours)."""
        try:
            return (self.state.system_state.get("global_config", {})
                    .get(_OSU_AUTOCHECK_CFG_KEY, {})) or {}
        except Exception:  # noqa: BLE001 — hub without state (tests)
            return {}

    def seed_os_updates_check_defaults(self) -> None:
        """Seed ``global_config["os_updates_check"]`` defaults ONCE at startup
        if the key is absent: ``enabled=True``, every 6 hours — so a
        never-configured hub keeps the fleet's update status fresh without an
        operator remembering to click "Check for updates". A hub that already
        has the key set — including an explicit ``enabled=False`` — is NEVER
        overwritten. Best-effort: a state/save failure is logged DEBUG and
        swallowed (this must never block startup)."""
        try:
            sys_state = self.state.system_state
            if sys_state is None:  # defensive — always a dict in practice
                sys_state = self.state.system_state = {}
            gc = sys_state.setdefault("global_config", {})
            if _OSU_AUTOCHECK_CFG_KEY not in gc:
                gc[_OSU_AUTOCHECK_CFG_KEY] = {"enabled": True,
                                              "interval_hours": _OSU_AUTOCHECK_DEFAULT_HOURS}
                self.state._mark_dirty()
                logger.info("os-updates: seeded auto-check defaults (enabled=True, "
                           "every %gh)", _OSU_AUTOCHECK_DEFAULT_HOURS)
        except Exception as e:
            logger.debug("os-updates: seed auto-check defaults skipped: %s", e)

    def osu_autocheck_config(self) -> Dict[str, Any]:
        """Current auto-check config for the WebUI: ``{enabled, interval_hours}``.
        ``interval_hours`` is clamped >= 1 so a bad/blank stored value can't
        hot-loop probing the whole fleet."""
        cfg = self._osu_autocheck_cfg()
        try:
            hours = float(cfg.get("interval_hours", _OSU_AUTOCHECK_DEFAULT_HOURS))
        except (TypeError, ValueError):
            hours = _OSU_AUTOCHECK_DEFAULT_HOURS
        return {"enabled": bool(cfg.get("enabled", True)), "interval_hours": max(1.0, hours)}

    def osu_set_autocheck_config(self, enabled: bool, interval_hours: Any) -> Dict[str, Any]:
        """Persist the auto-check config (``interval_hours`` clamped >= 1).
        Read fresh on the NEXT loop cycle — a WebUI change takes effect
        without a hub restart."""
        try:
            hours = float(interval_hours)
        except (TypeError, ValueError):
            hours = _OSU_AUTOCHECK_DEFAULT_HOURS
        hours = max(1.0, hours)
        gc = self.state.system_state.setdefault("global_config", {})
        gc[_OSU_AUTOCHECK_CFG_KEY] = {"enabled": bool(enabled), "interval_hours": hours}
        self.state._mark_dirty()
        return self.osu_autocheck_config()

    async def run_os_updates_check_loop(self):
        """Periodically re-probe the whole fleet (the scheduled twin of the
        "Check for updates" button), per the configured interval (default
        every 6h). Reads the config fresh each cycle so a WebUI change takes
        effect without a restart. Disabled -> short re-check sleep; enabled ->
        a full ``osu_check_fleet(refresh=True)`` each cycle, same as a manual
        click. Never raises — one bad cycle (a hung spoke, etc.) must not kill
        the loop; see ``run_sync_loop``."""
        def _guard() -> bool:
            return bool(self.osu_autocheck_config()["enabled"])

        def _delay() -> float:
            cfg = self.osu_autocheck_config()
            return (cfg["interval_hours"] * 3600.0) if cfg["enabled"] else 300.0

        async def _check():
            await self.osu_check_fleet(refresh=True)

        await run_sync_loop(stagger=45, guard=_guard, body=_check, delay=_delay,
                            error_label="os-updates auto-check loop cycle failed")

    async def run_os_updates_autopatch_loop(self):
        """Every few minutes: when the maintenance window has opened and
        auto-patch hasn't run in it yet, re-check the fleet (so it patches
        what is pending now, not hours ago) and auto-patch."""
        async def _tick():
            if not self._osu_autopatch_skip_reason(time.time()):
                await self.osu_check_fleet(refresh=True)
                await self.osu_autopatch()

        await run_sync_loop(stagger=90, body=_tick, delay=lambda: _AUTOPATCH_TICK_S,
                            error_label="os-updates auto-patch loop cycle failed")

    # ── auto-patch (WebUI-configurable, per node) ────────────────────────────
    def osu_autopatch_config(self) -> Dict[str, Any]:
        """``{security_only, nodes, exclude, reboot_nodes}`` — the node keys
        approved for auto-patch, the package names/globs it must never install,
        and the auto-patch nodes that are rebooted after a run."""
        try:
            cfg = (self.state.system_state.get("global_config", {})
                   .get(_OSU_AUTOPATCH_CFG_KEY, {})) or {}
        except Exception:  # noqa: BLE001 — hub without state (tests)
            cfg = {}
        nodes = sorted(str(k) for k in (cfg.get("nodes") or []))
        return {"security_only": bool(cfg.get("security_only", True)),
                "nodes": nodes,
                "exclude": sorted(str(p) for p in (cfg.get("exclude") or [])),
                "reboot_nodes": sorted(set(str(k) for k in (cfg.get("reboot_nodes") or []))
                                       & set(nodes)),
                "window": _read_window(cfg.get("window"))}

    def _osu_save_autopatch(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        gc = self.state.system_state.setdefault("global_config", {})
        old = gc.get(_OSU_AUTOPATCH_CFG_KEY) or {}
        nodes = set(cfg["nodes"])
        gc[_OSU_AUTOPATCH_CFG_KEY] = {"security_only": bool(cfg["security_only"]),
                                      "nodes": sorted(nodes),
                                      "exclude": sorted(set(cfg["exclude"])),
                                      "reboot_nodes": sorted(set(cfg["reboot_nodes"]) & nodes),
                                      "window": _parse_window(cfg["window"]),
                                      "known": sorted(set(cfg.get("known", old.get("known") or [])))}
        self.state._mark_dirty()
        return self.osu_autopatch_config()

    def _osu_enroll_new_nodes(self, keys: List[str]) -> None:
        """Turn auto-patch and auto-reboot on for nodes seen for the first
        time. The first run on a hub that predates this only records the
        current fleet, so nobody's existing choices change."""
        try:
            raw = self.state.system_state.get("global_config", {}).get(_OSU_AUTOPATCH_CFG_KEY) or {}
        except Exception:  # noqa: BLE001 — hub without state (tests)
            return
        cfg = self.osu_autopatch_config()
        known = set(raw.get("known") or [])
        new = [k for k in keys if k not in known and not k.startswith("hub:")]
        if "known" in raw and not new:
            return
        if "known" in raw:
            logger.info("[os-updates] auto-patch + auto-reboot enabled for new node(s): %s",
                     ", ".join(new))
            cfg["nodes"] = cfg["nodes"] + new
            cfg["reboot_nodes"] = cfg["reboot_nodes"] + new
        cfg["known"] = list(known | set(keys))
        self._osu_save_autopatch(cfg)

    def osu_set_autopatch_security_only(self, security_only: bool) -> Dict[str, Any]:
        return self._osu_save_autopatch({**self.osu_autopatch_config(),
                                         "security_only": security_only})

    def osu_set_autopatch_window(self, window: Dict[str, Any]) -> Dict[str, Any]:
        """Set the maintenance window (ValueError on a bad time or timezone)."""
        return self._osu_save_autopatch({**self.osu_autopatch_config(),
                                         "window": _parse_window(window)})

    def osu_set_autopatch_exclude(self, patterns: List[str]) -> Dict[str, Any]:
        """Replace the never-auto-install list (package names or globs)."""
        exclude = [p.strip() for p in patterns if p and p.strip()]
        return self._osu_save_autopatch({**self.osu_autopatch_config(), "exclude": exclude})

    def osu_set_autopatch_node(self, node_key: str, enabled: bool) -> Dict[str, Any]:
        """Approve (or withdraw) one node for auto-patching. Approving also
        turns auto-reboot on for it (the default); withdrawing clears both."""
        cfg = self.osu_autopatch_config()
        nodes, reboot = set(cfg["nodes"]), set(cfg["reboot_nodes"])
        if enabled:
            if node_key not in nodes:
                reboot.add(node_key)
            nodes.add(node_key)
        else:
            nodes.discard(node_key)
            reboot.discard(node_key)
        return self._osu_save_autopatch({**cfg, "nodes": list(nodes), "reboot_nodes": list(reboot)})

    def osu_set_autoreboot_node(self, node_key: str, enabled: bool) -> Dict[str, Any]:
        """Turn auto-reboot on or off for one auto-patch node. A node that is
        not approved for auto-patch can't auto-reboot (ValueError)."""
        cfg = self.osu_autopatch_config()
        if node_key not in cfg["nodes"]:
            raise ValueError(f"{node_key}: approve it for auto-patch first")
        reboot = set(cfg["reboot_nodes"])
        if enabled:
            reboot.add(node_key)
        else:
            reboot.discard(node_key)
        return self._osu_save_autopatch({**cfg, "reboot_nodes": list(reboot)})

    # ── pre-patch VM snapshots ───────────────────────────────────────────────
    def osu_snapshot_config(self) -> Dict[str, Any]:
        """``{enabled, keep}`` — snapshot each node's VM before patching it."""
        try:
            cfg = (self.state.system_state.get("global_config", {})
                   .get(_OSU_SNAPSHOT_CFG_KEY, {})) or {}
        except Exception:  # noqa: BLE001 — hub without state (tests)
            cfg = {}
        return {"enabled": bool(cfg.get("enabled", True)), "keep": int(cfg.get("keep", 2))}

    def osu_set_snapshot_config(self, enabled: bool, keep: Any) -> Dict[str, Any]:
        """ValueError unless 1 <= keep <= 20."""
        try:
            keep = int(keep)
        except (TypeError, ValueError):
            raise ValueError("keep must be a number") from None
        if not 1 <= keep <= 20:
            raise ValueError("keep must be between 1 and 20")
        gc = self.state.system_state.setdefault("global_config", {})
        gc[_OSU_SNAPSHOT_CFG_KEY] = {"enabled": bool(enabled), "keep": keep}
        self.state._mark_dirty()
        return self.osu_snapshot_config()

    def _osu_vm_links(self, nodes: Dict[str, Dict[str, Any]]) -> None:
        """Set ``vm`` (the Proxmox VM the node runs in) or ``vm_note`` (why
        there is none) on each node, matched by hostname via vm_snapshots."""
        vms = vm_snapshots.all_vms(self)
        meta = (getattr(self, "state", None) and
                self.state.system_state.get("module_metadata", {})) or {}
        tele = getattr(self, "spoke_telemetry", {}) or {}
        for n in nodes.values():
            n["vm"], n["vm_note"] = None, ""
            spoke_type = str((meta.get(n.get("spoke_id"), {}) or {}).get("module_type") or "")
            if n.get("pve_cluster") or (n["kind"] == "agent" and spoke_type in _PVE_HOST_SPOKE_TYPES):
                n["vm_note"] = "Proxmox host (bare metal)"
                continue
            if not vms:
                n["vm_note"] = "VM list not loaded"
                continue
            names, ips = [n.get("label")], []
            if n["kind"] == "spoke":
                md = meta.get(n["id"], {}) or {}
                names += [md.get("display_name"), md.get("name"), md.get("hostname")]
                ips.append((tele.get(n["id"]) or {}).get("remote_ip"))
            elif n["kind"] == "hub":
                names.append(socket.gethostname())
            vm, why = vm_snapshots.find_vm(self, names, ips, vms)
            n["vm"], n["vm_note"] = (vm_snapshots.vm_ref(vm) if vm else None), why

    async def _osu_prepatch_snapshot(self, n: Dict[str, Any], run: Dict[str, Any],
                                     item: Optional[Dict[str, Any]]) -> bool:
        """Snapshot the node's VM before it is patched (when enabled and the
        node is a known VM). False = the snapshot failed: don't patch it."""
        cfg = self.osu_snapshot_config()
        vm = n.get("vm")
        if not cfg["enabled"] or not vm:
            return True
        run["current"] = f"{n['label']} — snapshotting VM {vm.get('name')}"
        if item:
            item["status"] = "snapshotting"
        self._osu_save()
        res = await vm_snapshots.take_snapshot(self, vm, _PREPATCH_PREFIX, cfg["keep"],
                                               run.get("actor") or "os-updates")
        if res.get("status") != "SUCCESS":
            if item:
                item.update(status="failed", message="pre-patch snapshot failed — not patched: "
                                                     + res.get("message", ""))
            return False
        if item:
            item["snapshot"] = res["snapshot"]
        return True

    def _osu_autopatch_skip_reason(self, now: float) -> str:
        """Why auto-patch must not start now ("" = go)."""
        cfg = self.osu_autopatch_config()
        if not cfg["nodes"]:
            return "no nodes approved for auto-patch"
        bounds = window_bounds(cfg["window"], now)
        if bounds is None:
            w = cfg["window"]
            return f"outside the maintenance window ({w['start']}-{w['end']} {w['tz']})"
        st = self._osu_state()
        if float(st.get("autopatch_at") or 0.0) >= bounds[0]:
            return "already ran in this maintenance window"
        run = st.get("run")
        if run and run.get("status") == "running":
            return "an update run is already in progress"
        return ""

    async def osu_autopatch(self) -> Dict[str, Any]:
        """Deploy what the last check found on the nodes approved for it.

        Same rolling, hub-last apply an operator would approve, followed by a
        reboot of the auto-reboot nodes that installed something; only
        approved nodes that can actually be patched are picked, so one
        blocked node doesn't stop the rest. Only inside the maintenance
        window and at most once per window (persisted), so a hub restart —
        including one caused by patching the hub — doesn't start another run.
        """
        now = time.time()
        reason = self._osu_autopatch_skip_reason(now)
        if reason:
            return {"status": "SKIPPED", "message": reason}
        cfg = self.osu_autopatch_config()
        st = self._osu_state()
        st["autopatch_at"] = now
        self._osu_save()
        _opened, closes = window_bounds(cfg["window"], now)
        keys, packages = self._osu_autopatch_plan(cfg)
        if not keys:
            return {"status": "SKIPPED", "message": "nothing to patch"}
        exclude = cfg["exclude"]
        logger.warning("OS-UPDATE: auto-patch found updates on %d node(s) (%s%s)",
                       len(keys), "security only" if cfg["security_only"] else "all updates",
                       f", excluding {', '.join(exclude)}" if exclude else "")
        res = await self.osu_apply_fleet(node_keys=keys, actor=_AUTOPATCH_ACTOR,
                                         packages=packages or None,
                                         security_only=cfg["security_only"],
                                         reboot_after=[k for k in keys if k in cfg["reboot_nodes"]],
                                         until=closes)
        if res.get("status") == "ERROR":
            logger.warning("OS-UPDATE: auto-patch not started: %s", res.get("message"))
        return res

    def _osu_autopatch_plan(self, cfg: Dict[str, Any]) -> "tuple[List[str], Dict[str, List[str]]]":
        """``(node keys, {key: package list})`` auto-patch would deploy now,
        from the last check. Only approved nodes that can actually be patched
        are picked, so one blocked node doesn't stop the rest."""
        keys: List[str] = []
        packages: Dict[str, List[str]] = {}
        approved = set(cfg["nodes"])
        exclude = cfg["exclude"]
        for n in self.osu_snapshot()["nodes"]:
            key = f"{n['kind']}:{n['id']}"
            if key not in approved:
                continue
            if not n.get("eligible") or not n.get("count") or n.get("apply_blocker"):
                continue
            can_pick_packages = "packages" in (n.get("features") or [])
            if cfg["security_only"]:
                # Security-only applies a package list, which older nodes can't do.
                if not n.get("security_count") or not can_pick_packages:
                    continue
            if exclude:
                # Excluding packages means sending an explicit package list.
                if not can_pick_packages:
                    continue
                pkgs = [p["package"] for p in n.get("packages") or []
                        if p.get("package")
                        and (p.get("security") or not cfg["security_only"])
                        and not any(fnmatch.fnmatch(p["package"], pat) for pat in exclude)]
                if not pkgs:
                    continue
                packages[key] = pkgs
            keys.append(key)
        return keys, packages

    def osu_pending_reboots(self, only: "Optional[set[str]]" = None) -> Dict[str, Any]:
        """Nodes auto-reboot will restart in the current maintenance window —
        for the "Pending Reboot" alert in the WebUI footer.

        ``{in_window, window, nodes: [{key, label, note}]}``. While an
        auto-patch run is going: its auto-reboot nodes not rebooted yet. Before
        it starts: the auto-reboot nodes it would patch. A clustered Proxmox
        node only reboots if the update needs it, so it is listed as "may"."""
        cfg = self.osu_autopatch_config()
        now = time.time()
        bounds = window_bounds(cfg["window"], now)
        by_key = {f"{n['kind']}:{n['id']}": n for n in self.osu_snapshot()["nodes"]}
        st = self._osu_state()
        run = st.get("run") or {}
        if run.get("status") == "running":
            keys = [i["key"] for i in run.get("items") or []
                    if i["key"] in (run.get("reboot_after") or [])
                    and not i.get("auto_reboot") and i.get("status") in ("queued", "applying", "done")]
        elif bounds and float(st.get("autopatch_at") or 0.0) < bounds[0]:
            keys = [k for k in self._osu_autopatch_plan(cfg)[0] if k in cfg["reboot_nodes"]]
        else:
            keys = []
        if only is not None:
            keys = [k for k in keys if k in only]
        nodes = []
        for key in keys:
            n = by_key.get(key) or {}
            clustered = _is_cluster_node(n)
            nodes.append({"key": key, "label": n.get("label") or key,
                          "note": ("may reboot (Proxmox cluster, HA maintenance mode)" if clustered
                                   else "reboots after patching")})
        return {"in_window": bounds is not None or run.get("status") == "running",
                "window": cfg["window"], "nodes": nodes}

    # ── fix access on a blocked (non-root, no helper) node ──────────────────
    async def osu_fix_access(self, node_key: str, username: str, password: str,
                             actor: str = "") -> Dict[str, Any]:
        """Send a one-time root/sudo login to a blocked node so it can install
        its update helper. The password is passed through, never kept."""
        n = next((x for x in self.osu_snapshot()["nodes"]
                  if f"{x['kind']}:{x['id']}" == node_key), None)
        if n is None:
            return {"status": "ERROR", "message": f"{node_key}: not connected"}
        if not n.get("apply_blocker"):
            return {"status": "ERROR", "message": f"{n['label']}: not blocked — nothing to fix"}
        if "fix_access" not in (n.get("features") or []):
            return {"status": "ERROR", "message": f"{n['label']}: needs an LM update "
                                                  "before access can be fixed from here"}
        username = (username or "root").strip()
        logger.warning("OS-UPDATE: fix-access on %s as %s requested by %s",
                       n["label"], username, actor or "?")
        try:
            if n["kind"] == "hub":
                try:
                    from .os_update import fix_access
                except ImportError:
                    from os_update import fix_access  # type: ignore
                d = await asyncio.to_thread(fix_access, username, password)
            elif n["kind"] == "agent":
                d = _unwrap(await self.request_response(
                    n["spoke_id"], "AGENT_OS_FIX_ACCESS",
                    {"agent_id": n.get("agent_id") or n["id"],
                     "username": username, "password": password},
                    timeout=_FIX_ACCESS_TIMEOUT_S))
            else:
                d = _unwrap(await self.request_response(
                    n["id"], "OS_FIX_ACCESS",
                    {"username": username, "password": password},
                    timeout=_FIX_ACCESS_TIMEOUT_S))
        except Exception as exc:  # noqa: BLE001
            d = {"status": "ERROR", "message": str(exc)}
        ok = isinstance(d, dict) and d.get("status") == "SUCCESS"
        msg = (d or {}).get("message", "") if isinstance(d, dict) else ""
        logger.warning("OS-UPDATE: fix-access on %s → %s (%s)", n["label"],
                       "ok" if ok else "FAILED", msg)
        if ok:
            # Re-check just this node so the "blocked" badge clears right away.
            target = next((t for t in self._osu_targets()
                           if f"{t['kind']}:{t['id']}" == node_key), None)
            if target is not None:
                self._osu_state()["nodes"][node_key] = await self._osu_check_one(target, False)
                self._osu_save()
        return {"status": "SUCCESS" if ok else "ERROR",
                "message": msg or ("access fixed" if ok else "fix failed")}

    def osu_snapshot(self, only: "Optional[set[str]]" = None) -> Dict[str, Any]:
        """Panel state. ``only``: just these node keys (a tenant admin's view);
        the run then lists only their items."""
        st = self._osu_state()
        # Merge in the CURRENTLY connected targets so a spoke/agent that is
        # installed and reporting in over the control plane always appears in
        # the panel — even before it's ever been probed (fresh hub boot / a
        # newly-approved node / the hub just restarted, wiping this in-memory,
        # never-persisted cache). Without this, "checked_at == 0" or a node
        # that connected after the last Check silently vanishes from the list,
        # which reads as "there are no nodes" rather than "not checked yet".
        live = {f"{t['kind']}:{t['id']}": t for t in self._osu_targets()}
        merged: Dict[str, Any] = {}
        for key, t in live.items():
            cached = st["nodes"].get(key)
            if cached is not None:
                # Live routing wins over a persisted entry (an agent's raw name
                # or owning spoke can change across a hub restart).
                merged[key] = {"checked": True, **cached,
                               "spoke_id": t.get("spoke_id", ""),
                               "agent_id": t.get("agent_id", "")}
            else:
                merged[key] = {
                    "kind": t["kind"], "id": t["id"], "label": t["label"],
                    "module_type": t["module_type"], "spoke_id": t.get("spoke_id", ""),
                    "agent_id": t.get("agent_id", ""), "checked": False, "eligible": None, "unmanaged": False,
                    "unreachable": False, "reason": "not checked yet", "count": 0,
                }
        ap_cfg = self.osu_autopatch_config()
        approved, reboot = set(ap_cfg["nodes"]), set(ap_cfg["reboot_nodes"])
        for key, n in merged.items():
            n["auto_patch"] = key in approved
            n["auto_reboot"] = key in reboot
        self._osu_vm_links(merged)
        if only is not None:
            merged = {k: n for k, n in merged.items() if k in only}
        nodes = sorted(merged.values(), key=lambda n: (n["kind"] != "hub", n["label"]))
        run = st.get("run")
        if only is not None and run:
            run = {**run, "items": [i for i in run.get("items") or [] if i["key"] in only]}
        pending = [n for n in nodes if n.get("eligible") and n.get("count")
                   and not n.get("apply_blocker")]
        return {
            "checked_at": st["checked_at"],
            "nodes": nodes,
            "totals": {
                "nodes": len(nodes),
                "eligible": sum(1 for n in nodes if n.get("eligible")),
                "unmanaged": sum(1 for n in nodes if n.get("unmanaged") and not n.get("unreachable")),
                "unreachable": sum(1 for n in nodes if n.get("unreachable")),
                "with_updates": len(pending),
                "packages": sum(int(n.get("count") or 0) for n in nodes),
                "security": sum(int(n.get("security_count") or 0) for n in nodes),
                "reboot_required": sum(1 for n in nodes if n.get("reboot_required")),
                "blocked": sum(1 for n in nodes if n.get("apply_blocker")),
                "not_checked": sum(1 for n in nodes if not n.get("checked")),
            },
            "run": run,
        }

    # ── CVE lookup: "who is affected by CVE-XXXX-YYYY?" ─────────────────────
    def _osu_feed_cache(self) -> FeedCache:
        fc = getattr(self, "_osu_cve_feeds", None)
        if fc is None:
            fc = FeedCache(getattr(self, "cache_dir", None))
            self._osu_cve_feeds = fc
        return fc

    def _osu_feeds_for(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Debian feed per release in use. Blocking (may download)."""
        codenames = {(inv.get("os") or {}).get("codename", "")
                     for inv in inventory.values()
                     if (inv.get("os") or {}).get("id") == "debian"}
        fc = self._osu_feed_cache()
        return {c: f for c in sorted(codenames) if c and (f := fc.get(c)) is not None}

    def _osu_cve_search_sync(self, query: str,
                             only: "Optional[set[str]]" = None) -> Dict[str, Any]:
        st = self._osu_state()
        inventory = dict(st.get("inventory") or {})
        nodes = st.get("nodes") or {}
        if only is not None:
            inventory = {k: v for k, v in inventory.items() if k in only}
            nodes = {k: v for k, v in nodes.items() if k in only}
        feeds = self._osu_feeds_for(inventory)
        fc = self._osu_feed_cache()
        is_cve = bool(CVE_RE.match(query))
        q = query.upper() if is_cve else query.lower()

        results: Dict[str, Dict[str, Any]] = {}
        unknown: List[Dict[str, str]] = []
        labels = {k: n.get("label") or k for k, n in nodes.items()}
        for key, n in nodes.items():
            inv = inventory.get(key)
            if not n.get("eligible"):
                continue
            os_info = (inv or {}).get("os") or {}
            if inv is None:
                reason = "node has not reported its installed packages (needs a newer LM)"
            elif os_info.get("id") != "debian":
                reason = f"not Debian ({os_info.get('id') or 'unknown OS'}) — no feed"
            elif os_info.get("codename") not in feeds:
                reason = f"no security feed for Debian {os_info.get('codename') or '?'}"
            else:
                continue
            unknown.append({"node": key, "label": labels[key], "reason": reason})

        for key, inv in inventory.items():
            feed = feeds.get(((inv.get("os") or {}).get("codename")) or "")
            if feed is None or ((inv.get("os") or {}).get("id")) != "debian":
                continue
            if is_cve:
                lines = feed.by_cve.get(q, [])
            else:
                lines = [ln for pkg, pkg_lines in feed.by_package.items()
                         if q in pkg for ln in pkg_lines]
            entries = [feed.entry(ln) for ln in lines]
            pending = [p.get("package") for p in (nodes.get(key) or {}).get("packages") or []]
            found = match_node(feed, inv.get("installed") or [], entries, pending)
            for state in ("affected", "patched") if is_cve else ("affected",):
                for f in found[state]:
                    r = results.setdefault(f["cve"], {
                        "cve": f["cve"], "description": feed.descriptions.get(f["cve"], ""),
                        "urgency": f["urgency"], "remote": f["remote"],
                        "affected": [], "patched": []})
                    r[state].append({"node": key, "label": labels.get(key, key),
                                     "release": inv["os"]["codename"], **f})
            if is_cve and lines and q not in results:
                results[q] = {"cve": q, "description": feed.descriptions.get(q, ""),
                              "urgency": entries[0]["urgency"], "remote": entries[0]["remote"],
                              "affected": [], "patched": []}

        ordered = sorted(results.values(), key=lambda r: (-len(r["affected"]), r["cve"]))
        if not is_cve:
            ordered = [r for r in ordered if r["affected"]]
        truncated = len(ordered) > _CVE_MAX_RESULTS
        known = any(q in f.descriptions for f in feeds.values()) if is_cve else bool(ordered)
        return {
            "query": q, "kind": "cve" if is_cve else "package", "known": known,
            "results": ordered[:_CVE_MAX_RESULTS], "truncated": truncated,
            "affected_nodes": len({a["node"] for r in ordered for a in r["affected"]}),
            "checked_nodes": sum(1 for inv in inventory.values()
                                 if (inv.get("os") or {}).get("codename") in feeds),
            "unknown": unknown,
            "feeds": {c: {"fetched_at": fc.fetched_at(c), "error": fc.errors.get(c, "")}
                      for c in feeds},
        }

    def _osu_fleet_cves_sync(self, only: "Optional[set[str]]" = None) -> List[Dict[str, Any]]:
        """Every CVE that affects at least one node right now, newest first:
        ``[{cve, description, urgency, nodes}]`` (``nodes`` is a count). Feeds
        the search box's suggestions. Matches each node's installed packages
        against the feed entries for just those packages, and is cached until
        the next check or feed refresh. ``only``: count just these nodes."""
        st = self._osu_state()
        inventory = dict(st.get("inventory") or {})
        feeds = self._osu_feeds_for(inventory)
        fc = self._osu_feed_cache()
        stamp = (st.get("checked_at"), tuple((c, fc.fetched_at(c)) for c in feeds))
        cached = getattr(self, "_osu_fleet_cves", None)
        if not (cached and cached[0] == stamp):
            cached = (stamp, self._osu_fleet_cve_nodes(inventory, feeds))
            self._osu_fleet_cves = cached
        out = []
        for r in cached[1]:
            n = len(r["nodes"] if only is None else r["nodes"] & only)
            if n:
                out.append({**r, "nodes": n})
        return out

    def _osu_fleet_cve_nodes(self, inventory: Dict[str, Any],
                             feeds: Dict[str, Any]) -> List[Dict[str, Any]]:
        """``[{cve, description, urgency, nodes: {node keys}}]``, newest first."""
        found: Dict[str, Dict[str, Any]] = {}
        for key, inv in inventory.items():
            os_info = inv.get("os") or {}
            feed = feeds.get(os_info.get("codename") or "")
            if feed is None or os_info.get("id") != "debian":
                continue
            installed = inv.get("installed") or []
            # Same lookup rule as match_node: source package if the feed knows it.
            keys = {row[2] if len(row) > 2 and row[2] in feed.by_package else row[0]
                    for row in installed if len(row) >= 2}
            entries = [feed.entry(ln) for k in keys for ln in feed.by_package.get(k, [])]
            for f in match_node(feed, installed, entries)["affected"]:
                r = found.setdefault(f["cve"], {"cve": f["cve"],
                                                "description": feed.descriptions.get(f["cve"], "")[:160],
                                                "urgency": f["urgency"], "nodes": set()})
                r["nodes"].add(key)
        out = list(found.values())
        out.sort(key=lambda r: [-int(p) for p in r["cve"].split("-")[1:]])
        return out

    async def osu_fleet_cves(self, only: "Optional[set[str]]" = None) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._osu_fleet_cves_sync, only)

    async def osu_cve_search(self, query: str,
                             only: "Optional[set[str]]" = None) -> Dict[str, Any]:
        """Which nodes run a package vulnerable to ``query`` — a CVE id, or a
        package-name fragment (e.g. ``php``) listing its open CVEs. Matches the
        inventory from the last check; never probes the nodes."""
        return await asyncio.to_thread(self._osu_cve_search_sync, query.strip(), only)

    # ── rolling apply ────────────────────────────────────────────────────────
    async def osu_apply_fleet(self, node_keys: Optional[List[str]] = None,
                              actor: str = "",
                              packages: Optional[Dict[str, List[str]]] = None,
                              security_only: bool = False,
                              reboot_after: Optional[List[str]] = None,
                              until: Optional[float] = None) -> Dict[str, Any]:
        """Approve-once, rolling apply. Returns immediately; progress via snapshot.

        Scope:
          * ``node_keys`` — only these ``kind:id`` nodes (default: every node
            with pending updates).
          * ``packages`` — ``{kind:id: [pkg, ...]}``: upgrade only those packages
            on that node (the node is included even if not in ``node_keys``).
          * ``security_only`` — for nodes without an explicit package list,
            upgrade only their pending security packages; nodes with none are
            left out.
          * ``reboot_after`` — ``kind:id`` nodes to reboot after they installed
            something (auto-reboot; see ``_osu_auto_reboot``). Omitted (a
            manual deploy): just the Proxmox cluster nodes, which are rebooted
            in maintenance mode only if the update needs it.
          * ``until`` — no node is started after this time (end of the
            maintenance window); the rest are skipped.
        Everything requested is validated BEFORE anything runs, so a bad
        selection is refused outright rather than half-applied.

        One node at a time so a bad update can't hit the fleet at once, and the
        HUB LAST because applying to it restarts the process running this loop.
        """
        st = self._osu_state()
        run = st.get("run")
        if run and run.get("status") == "running":
            return {"status": "ERROR", "message": "an update run is already in progress"}
        packages = {k: list(v or []) for k, v in (packages or {}).items()}
        snap = self.osu_snapshot()
        by_key = {f"{n['kind']}:{n['id']}": n for n in snap["nodes"]}
        wanted = list(dict.fromkeys(list(node_keys or []) + list(packages)))
        if not wanted:
            wanted = [k for k, n in by_key.items() if n.get("eligible") and n.get("count")
                      and not n.get("apply_blocker")]
        problems: List[str] = []
        plan: List[Dict[str, Any]] = []
        for key in wanted:
            n = by_key.get(key)
            if n is None:
                problems.append(f"{key}: not connected")
                continue
            if not n.get("eligible") or not n.get("count"):
                problems.append(f"{n['label']}: no pending updates")
                continue
            if n.get("apply_blocker"):
                problems.append(f"{n['label']}: {n['apply_blocker']}")
                continue
            pending = {p.get("package"): p for p in n.get("packages") or []}
            pkgs: Optional[List[str]] = None
            if key in packages:
                pkgs = list(dict.fromkeys(packages[key]))
                unknown = [p for p in pkgs if p not in pending]
                if not pkgs:
                    problems.append(f"{n['label']}: no packages selected")
                    continue
                if unknown:
                    problems.append(f"{n['label']}: not pending: {', '.join(unknown[:10])}")
                    continue
            elif security_only:
                pkgs = [name for name, p in pending.items() if p.get("security")]
                if not pkgs:
                    continue  # nothing security-related pending — leave it alone
            if pkgs is not None and "packages" not in (n.get("features") or []):
                problems.append(f"{n['label']}: needs an LM update before individual "
                                "packages can be applied")
                continue
            plan.append({**n, "key": key, "apply_packages": pkgs})
        if problems:
            return {"status": "ERROR", "message": "; ".join(problems)}
        if not plan:
            return {"status": "ERROR", "message": "no eligible nodes with pending updates"
                                                  + (" (security-only)" if security_only else "")}
        if reboot_after is None:
            reboot_after = [n["key"] for n in plan if _is_cluster_node(n)]
        # Hub last — see the module docstring.
        plan.sort(key=lambda n: n["kind"] == "hub")
        st["run"] = {
            "status": "running", "started_at": time.time(), "actor": actor,
            "total": len(plan), "done": 0, "current": "", "cancel_requested": False,
            "security_only": bool(security_only),
            "reboot_after": list(reboot_after or []),
            "until": until,
            "items": [{"key": n["key"], "label": n["label"], "status": "queued",
                       "mode": "all" if n["apply_packages"] is None else "packages",
                       "packages": n["apply_packages"] or []} for n in plan],
        }
        self._osu_save()
        logger.warning("OS-UPDATE: apply approved by %s — %s, hub last", actor or "?",
                       ", ".join(f"{n['label']}[{'all' if n['apply_packages'] is None else len(n['apply_packages'])}]"
                                 for n in plan))
        asyncio.create_task(self._osu_run(plan))
        return {"status": "SUCCESS", "queued": len(plan)}

    def osu_cancel_run(self, actor: str = "") -> Dict[str, Any]:
        """Stop the roll after the node currently applying (apt can't be safely
        interrupted mid-transaction); every queued node is skipped."""
        run = self._osu_state().get("run")
        if not run or run.get("status") != "running":
            return {"status": "ERROR", "message": "no update run in progress"}
        run["cancel_requested"] = True
        run["cancelled_by"] = actor
        self._osu_save()
        logger.warning("OS-UPDATE: run cancel requested by %s (current node finishes)",
                       actor or "?")
        return {"status": "SUCCESS", "message": "cancelling after the current node"}

    async def osu_reboot_node(self, node_key: str, actor: str = "") -> Dict[str, Any]:
        """Explicit, operator-approved reboot of ONE node (``shutdown -r +1``) —
        the Reboot button. Refused during a run and on nodes that haven't
        reported the ``reboot`` feature."""
        st = self._osu_state()
        run = st.get("run")
        if run and run.get("status") == "running":
            return {"status": "ERROR", "message": "an update run is in progress — "
                                                  "reboot after it finishes"}
        n = next((x for x in self.osu_snapshot()["nodes"]
                  if f"{x['kind']}:{x['id']}" == node_key), None)
        if n is None:
            return {"status": "ERROR", "message": f"{node_key}: not connected"}
        if not n.get("eligible"):
            return {"status": "ERROR", "message": f"{n['label']}: not a managed node"}
        if "reboot" not in (n.get("features") or []):
            return {"status": "ERROR", "message": f"{n['label']}: needs an LM update "
                                                  "before it can be rebooted from here"}
        if _is_cluster_node(n):
            return self._osu_start_cluster_reboot(n, actor)
        return await self._osu_reboot(n, actor)

    def _osu_start_cluster_reboot(self, n: Dict[str, Any], actor: str) -> Dict[str, Any]:
        """Reboot button on a Proxmox cluster node: a one-node run so the panel
        shows progress and nothing else starts until the node is back."""
        key = f"{n['kind']}:{n['id']}"
        item = {"key": key, "label": n["label"], "status": "rebooting", "mode": "reboot",
                "packages": []}
        run = {"status": "running", "started_at": time.time(), "actor": actor,
               "total": 1, "done": 0, "current": "", "cancel_requested": False,
               "security_only": False, "reboot_after": [], "until": None, "items": [item]}
        self._osu_state()["run"] = run
        self._osu_save()

        async def _go():
            item["auto_reboot"], _ = await self._osu_cluster_reboot(n, run, actor)
            item["status"] = "failed" if item["auto_reboot"].startswith("failed") else "done"
            run.update(status="finished", current="", done=1, finished_at=time.time())
            self._osu_save()
        asyncio.create_task(_go())
        return {"status": "SUCCESS",
                "message": "entering maintenance mode — HA guests move off, then it reboots"}

    async def _osu_reboot(self, n: Dict[str, Any], actor: str) -> Dict[str, Any]:
        """Send the reboot command to one node (no checks — see callers)."""
        node_key = f"{n['kind']}:{n['id']}"
        logger.warning("OS-UPDATE: REBOOT of %s approved by %s", n["label"], actor or "?")
        try:
            if n["kind"] == "hub":
                try:
                    from .os_update import reboot_node
                except ImportError:
                    from os_update import reboot_node  # type: ignore
                d = await asyncio.to_thread(reboot_node)
            elif n["kind"] == "agent":
                d = _unwrap(await self.request_response(
                    n["spoke_id"], "AGENT_OS_REBOOT",
                    {"agent_id": n.get("agent_id") or n["id"]}, timeout=_REBOOT_TIMEOUT_S))
            else:
                d = _unwrap(await self.request_response(
                    n["id"], "OS_REBOOT", {}, timeout=_REBOOT_TIMEOUT_S))
        except Exception as exc:  # noqa: BLE001
            d = {"status": "ERROR", "message": str(exc)}
        ok = isinstance(d, dict) and d.get("status") == "SUCCESS"
        msg = (d or {}).get("message", "") if isinstance(d, dict) else ""
        logger.warning("OS-UPDATE: reboot %s → %s (%s)", n["label"],
                       "scheduled" if ok else "FAILED", msg)
        if ok:
            cached = self._osu_state()["nodes"].get(node_key)
            if cached is not None:
                cached["reboot_scheduled_at"] = time.time()
                self._osu_save()
        return {"status": "SUCCESS" if ok else "ERROR",
                "message": msg or ("reboot scheduled" if ok else "reboot failed")}

    async def _osu_apply_one(self, n: Dict[str, Any]) -> Dict[str, Any]:
        pkgs = n.get("apply_packages")
        if n["kind"] == "hub":
            try:
                from .os_update import apply_updates
            except ImportError:
                from os_update import apply_updates  # type: ignore
            return await asyncio.to_thread(apply_updates, pkgs)
        if n["kind"] == "agent":
            cmd = "AGENT_OS_UPDATE_APPLY" if pkgs is None else "AGENT_OS_UPDATE_APPLY_PACKAGES"
            data: Dict[str, Any] = {"agent_id": n.get("agent_id") or n["id"]}
            if pkgs is not None:
                data["packages"] = pkgs
            return _unwrap(await self.request_response(
                n["spoke_id"], cmd, data, timeout=_APPLY_TIMEOUT_S))
        cmd = "OS_UPDATE_APPLY" if pkgs is None else "OS_UPDATE_APPLY_PACKAGES"
        return _unwrap(await self.request_response(
            n["id"], cmd, {} if pkgs is None else {"packages": pkgs},
            timeout=_APPLY_TIMEOUT_S))

    async def _osu_run(self, targets: List[Dict[str, Any]]) -> None:
        st = self._osu_state()
        run = st["run"]
        for n in targets:
            key = f"{n['kind']}:{n['id']}"
            item = next((i for i in run["items"] if i["key"] == key), None)
            if run.get("cancel_requested"):
                if item:
                    item["status"] = "skipped"
                continue
            if run.get("until") and time.time() > run["until"]:
                if item:
                    item.update(status="skipped", message="maintenance window ended")
                continue
            if n["kind"] == "hub":
                await self._osu_auto_reboot(run)
            if not await self._osu_prepatch_snapshot(n, run, item):
                run["done"] += 1
                self._osu_save()
                logger.warning("OS-UPDATE: %s → not patched (pre-patch snapshot failed)",
                               n["label"])
                continue
            run["current"] = n["label"]
            if item:
                item["status"] = "applying"
            self._osu_save()
            try:
                d = await self._osu_apply_one(n)
            except Exception as exc:  # noqa: BLE001 — one failure must not abort the roll
                d = {"status": "ERROR", "message": str(exc)}
            ok = isinstance(d, dict) and d.get("status") == "SUCCESS"
            if item:
                item.update({
                    "status": "done" if ok else "failed",
                    "applied": (d or {}).get("applied"),
                    "remaining": (d or {}).get("remaining"),
                    "skipped_packages": (d or {}).get("skipped") or [],
                    "reboot_required": bool((d or {}).get("reboot_required")),
                    "message": (d or {}).get("message", ""),
                })
            run["done"] += 1
            self._osu_save()
            logger.warning("OS-UPDATE: %s → %s (%s)", n["label"],
                           "ok" if ok else "FAILED", (d or {}).get("message", "") or "")
            if ok and item and key in (run.get("reboot_after") or []) and _is_cluster_node(n):
                if not item["reboot_required"]:
                    item["auto_reboot"] = "not needed"
                else:
                    actor = (_AUTOREBOOT_ACTOR if run.get("actor") == _AUTOPATCH_ACTOR
                             else run.get("actor") or _AUTOREBOOT_ACTOR)
                    item["auto_reboot"], stop = await self._osu_cluster_reboot(n, run, actor)
                    if stop:
                        run["cancel_requested"] = True
                self._osu_save()
        run["status"] = "cancelled" if run.get("cancel_requested") else "finished"
        run["current"] = ""
        run["finished_at"] = time.time()
        self._osu_save()
        await self._osu_auto_reboot(run)
        # Refresh so the panel reflects reality (and any new reboot_required)
        # without the operator having to hit Check again.
        try:
            await self.osu_check_fleet(refresh=False)
        except Exception:  # noqa: BLE001
            pass


    async def _osu_maintenance(self, n: Dict[str, Any], action: str) -> Dict[str, Any]:
        """HA maintenance mode on a Proxmox host agent: enable/disable/status."""
        try:
            return _unwrap(await self.request_response(
                n["spoke_id"], "AGENT_OS_MAINTENANCE",
                {"agent_id": n.get("agent_id") or n["id"], "action": action},
                timeout=_REBOOT_TIMEOUT_S))
        except Exception as exc:  # noqa: BLE001
            return {"status": "ERROR", "message": str(exc)}

    async def _osu_cluster_reboot(self, n: Dict[str, Any], run: Dict[str, Any],
                                  actor: str = _AUTOREBOOT_ACTOR) -> "tuple[str, bool]":
        """Maintenance mode -> wait for HA guests to leave -> reboot -> wait
        until the node is back without a pending reboot -> maintenance off.
        Returns ``(result text for the run item, stop the rest of the run)``."""
        key, label = f"{n['kind']}:{n['id']}", n["label"]
        run["current"] = f"{label} — entering maintenance mode"
        self._osu_save()
        logger.warning("OS-UPDATE: %s (Proxmox cluster %s) → maintenance mode before reboot by %s",
                       label, (n.get("pve_cluster") or {}).get("name", "?"), actor)
        r = await self._osu_maintenance(n, "enable")
        if r.get("status") != "SUCCESS":
            return f"failed: maintenance mode: {r.get('message', '')}", False
        deadline = time.time() + _MAINT_MIGRATE_TIMEOUT_S
        guests = r.get("ha_guests") or []
        while guests:
            if time.time() > deadline:
                await self._osu_maintenance(n, "disable")
                return (f"failed: HA guests did not move off in time ({', '.join(guests)}) — "
                        "not rebooted, maintenance mode cleared"), False
            run["current"] = f"{label} — waiting for {len(guests)} HA guest(s) to migrate"
            await asyncio.sleep(_MAINT_POLL_S)
            r = await self._osu_maintenance(n, "status")
            if r.get("status") == "SUCCESS":
                guests = r.get("ha_guests") or []
        res = await self._osu_reboot(n, actor)
        if res.get("status") != "SUCCESS":
            await self._osu_maintenance(n, "disable")
            return f"failed: {res.get('message', '')} — maintenance mode cleared", False
        run["current"] = f"{label} — rebooting"
        self._osu_save()
        await asyncio.sleep(_REBOOT_GRACE_S)
        deadline = time.time() + _REBOOT_RETURN_TIMEOUT_S
        while True:
            target = next((t for t in self._osu_targets()
                           if f"{t['kind']}:{t['id']}" == key), None)
            if target is not None:
                chk = await self._osu_check_one(target, False)
                if chk.get("eligible") and not chk.get("reboot_required"):
                    self._osu_state()["nodes"][key] = chk
                    break
            if time.time() > deadline:
                logger.warning("OS-UPDATE: %s did not come back from its auto-reboot — "
                               "left in maintenance mode, stopping the run", label)
                return ("failed: did not come back within "
                        f"{int(_REBOOT_RETURN_TIMEOUT_S // 60)} min — left in maintenance mode, "
                        "rest of the run stopped"), True
            await asyncio.sleep(_MAINT_POLL_S)
        r = await self._osu_maintenance(n, "disable")
        logger.warning("OS-UPDATE: %s back from its reboot; maintenance mode %s",
                       label, "cleared" if r.get("status") == "SUCCESS" else "NOT cleared")
        if r.get("status") != "SUCCESS":
            return f"rebooted, but maintenance mode NOT cleared: {r.get('message', '')}", False
        return "rebooted (cluster maintenance mode)", False

    async def _osu_auto_reboot(self, run: Dict[str, Any]) -> None:
        """Reboot the run's ``reboot_after`` nodes that are done and installed
        something, each at most once. Called before the hub is patched and
        again when the run ends, so the hub is always rebooted last. Skipped
        if the run was cancelled. The result is kept on the run item as
        ``auto_reboot`` so the panel can show it."""
        if run.get("cancel_requested"):
            return
        wanted = set(run.get("reboot_after") or [])
        nodes = {f"{n['kind']}:{n['id']}": n for n in self.osu_snapshot()["nodes"]}
        for item in run["items"]:
            if item["key"] not in wanted or item["status"] != "done" or item.get("auto_reboot"):
                continue
            if not (item.get("applied") or item.get("reboot_required")):
                continue  # nothing was installed — no reason to reboot
            n = nodes.get(item["key"])
            if n is None or "reboot" not in (n.get("features") or []):
                item["auto_reboot"] = "failed: node can't be rebooted from LM (needs an LM update)"
            else:
                res = await self._osu_reboot(n, _AUTOREBOOT_ACTOR)
                item["auto_reboot"] = ("scheduled" if res.get("status") == "SUCCESS"
                                       else f"failed: {res.get('message', '')}")
            self._osu_save()


def _is_cluster_node(n: Dict[str, Any]) -> bool:
    """A Proxmox host in a cluster whose agent can do HA maintenance mode."""
    return bool(n.get("pve_cluster")) and "maintenance" in (n.get("features") or [])


def _unwrap(resp: Any) -> Dict[str, Any]:
    """Pull the payload out of a request_response envelope."""
    if isinstance(resp, dict):
        inner = resp.get("payload", {})
        if isinstance(inner, dict) and "data" in inner:
            return inner["data"] or {}
        return resp
    return {}
