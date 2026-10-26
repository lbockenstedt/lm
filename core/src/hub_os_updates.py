"""Fleet OS-update module (hub side).

The hub is the module: it COLLECTS pending-update state from every spoke and
agent, decides what is eligible, and — on explicit operator approval — SENDS the
apply commands. Nodes only execute; they never decide to update themselves.

Operator-chosen behaviour (see the WebUI panel):
  * ``apt-get dist-upgrade`` — everything: security, regular, and dependency
    transitions. (A Debian MAJOR release jump is a different operation that
    rewrites sources.list and is deliberately NOT behind this button.)
  * NEVER auto-reboot. ``reboot_required`` is surfaced as a badge; rebooting is
    a separate explicit action.
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

Auto-patch (opt-in, off by default): after each SCHEDULED check, nodes with
pending updates are deployed automatically through the same rolling,
hub-last apply, audit-logged as actor "auto-patch". Security-only by default;
the hub itself is left out unless the operator includes it. Still NEVER
reboots. Manual checks and a run's own follow-up re-check never trigger it, so
a node whose update keeps failing is retried once per schedule, not in a loop.

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
import logging
import os
import time
from typing import Any, Dict, List, Optional

from cache_core import JsonCacheFile  # sibling leaf
from sync_loop import run_sync_loop  # sibling leaf

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
_FIX_ACCESS_TIMEOUT_S = 180.0
_STATE_FILE = "os_updates.json"

# Auto-check config lives in global_config["os_updates_check"]: {enabled,
# interval_hours}. Enabled by default (seeded once — see
# seed_os_updates_check_defaults) so the panel's status stays fresh without an
# operator remembering to click "Check for updates"; every 6h by default.
_OSU_AUTOCHECK_CFG_KEY = "os_updates_check"
_OSU_AUTOCHECK_DEFAULT_HOURS = 6.0

# Auto-patch config lives in global_config["os_updates_autopatch"]:
# {enabled, security_only, include_hub}. Off unless an operator turns it on.
_OSU_AUTOPATCH_CFG_KEY = "os_updates_autopatch"
_AUTOPATCH_ACTOR = "auto-patch"


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
                    elif item.get("status") == "queued":
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
        # Agents, routed via their owning spoke.
        # agent_info is guid-keyed once an agent is migrated (B2); the owning
        # spoke only knows the agent by the raw ``agent_id`` it reported, so the
        # relay must address it by that name (same as Remote Console).
        for aid, info in (getattr(self, "agent_info", {}) or {}).items():
            sid = (info or {}).get("spoke_id") or ""
            if not sid:
                continue
            out.append({"kind": "agent", "id": aid, "spoke_id": sid,
                        "agent_id": str((info or {}).get("agent_id") or aid),
                        "label": str((info or {}).get("hostname") or aid),
                        "module_type": "agent"})
        out.append({"kind": "hub", "id": "hub", "spoke_id": "",
                    "label": "hub (this server)", "module_type": "hub"})
        return out

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
            "checked_at": time.time(),
        }

    async def osu_check_fleet(self, refresh: bool = True) -> Dict[str, Any]:
        """Probe every node concurrently. Read-only — installs nothing."""
        targets = self._osu_targets()
        results = await asyncio.gather(
            *[self._osu_check_one(t, refresh) for t in targets],
            return_exceptions=True)
        nodes = [r for r in results if isinstance(r, dict)]
        st = self._osu_state()
        st["nodes"] = {f"{n['kind']}:{n['id']}": n for n in nodes}
        st["checked_at"] = time.time()
        self._osu_save()
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

        async def _check_then_autopatch():
            await self.osu_check_fleet(refresh=True)
            await self.osu_autopatch()

        await run_sync_loop(stagger=45, guard=_guard,
                            body=_check_then_autopatch,
                            delay=_delay,
                            error_label="os-updates auto-check loop cycle failed")

    # ── auto-patch (WebUI-configurable, off by default) ─────────────────────
    def osu_autopatch_config(self) -> Dict[str, Any]:
        """``{enabled, security_only, include_hub}`` — off / security-only /
        hub excluded unless set otherwise."""
        try:
            cfg = (self.state.system_state.get("global_config", {})
                   .get(_OSU_AUTOPATCH_CFG_KEY, {})) or {}
        except Exception:  # noqa: BLE001 — hub without state (tests)
            cfg = {}
        return {"enabled": bool(cfg.get("enabled", False)),
                "security_only": bool(cfg.get("security_only", True)),
                "include_hub": bool(cfg.get("include_hub", False))}

    def osu_set_autopatch_config(self, enabled: bool, security_only: bool,
                                 include_hub: bool) -> Dict[str, Any]:
        gc = self.state.system_state.setdefault("global_config", {})
        gc[_OSU_AUTOPATCH_CFG_KEY] = {"enabled": bool(enabled),
                                      "security_only": bool(security_only),
                                      "include_hub": bool(include_hub)}
        self.state._mark_dirty()
        return self.osu_autopatch_config()

    async def osu_autopatch(self) -> Dict[str, Any]:
        """Deploy what the last check found, if auto-patch is on.

        Same rolling, hub-last, never-reboot apply an operator would approve;
        only nodes that can actually be patched are picked, so one blocked
        node doesn't stop the rest. At most once per auto-check interval
        (persisted), so a hub restart — including one caused by patching the
        hub — doesn't start another run right away.
        """
        cfg = self.osu_autopatch_config()
        if not cfg["enabled"]:
            return {"status": "SKIPPED", "message": "auto-patch is off"}
        st = self._osu_state()
        run = st.get("run")
        if run and run.get("status") == "running":
            return {"status": "SKIPPED", "message": "an update run is already in progress"}
        interval_s = self.osu_autocheck_config()["interval_hours"] * 3600.0
        # 0.9: the check loop's own timing jitter must not skip a whole cycle.
        if time.time() - float(st.get("autopatch_at") or 0.0) < interval_s * 0.9:
            return {"status": "SKIPPED", "message": "already ran this interval"}
        keys = []
        for n in self.osu_snapshot()["nodes"]:
            if not n.get("eligible") or not n.get("count") or n.get("apply_blocker"):
                continue
            if n["kind"] == "hub" and not cfg["include_hub"]:
                continue
            if cfg["security_only"]:
                # Security-only applies a package list, which older nodes can't do.
                if not n.get("security_count") or "packages" not in (n.get("features") or []):
                    continue
            keys.append(f"{n['kind']}:{n['id']}")
        if not keys:
            return {"status": "SKIPPED", "message": "nothing to patch"}
        st["autopatch_at"] = time.time()
        self._osu_save()
        logger.warning("OS-UPDATE: auto-patch found updates on %d node(s) (%s)",
                       len(keys), "security only" if cfg["security_only"] else "all updates")
        res = await self.osu_apply_fleet(node_keys=keys, actor=_AUTOPATCH_ACTOR,
                                         security_only=cfg["security_only"])
        if res.get("status") == "ERROR":
            logger.warning("OS-UPDATE: auto-patch not started: %s", res.get("message"))
        return res

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

    def osu_snapshot(self) -> Dict[str, Any]:
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
        nodes = sorted(merged.values(), key=lambda n: (n["kind"] != "hub", n["label"]))
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
            "run": st.get("run"),
        }

    # ── rolling apply ────────────────────────────────────────────────────────
    async def osu_apply_fleet(self, node_keys: Optional[List[str]] = None,
                              actor: str = "",
                              packages: Optional[Dict[str, List[str]]] = None,
                              security_only: bool = False) -> Dict[str, Any]:
        """Approve-once, rolling apply. Returns immediately; progress via snapshot.

        Scope:
          * ``node_keys`` — only these ``kind:id`` nodes (default: every node
            with pending updates).
          * ``packages`` — ``{kind:id: [pkg, ...]}``: upgrade only those packages
            on that node (the node is included even if not in ``node_keys``).
          * ``security_only`` — for nodes without an explicit package list,
            upgrade only their pending security packages; nodes with none are
            left out.
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
        # Hub last — see the module docstring.
        plan.sort(key=lambda n: n["kind"] == "hub")
        st["run"] = {
            "status": "running", "started_at": time.time(), "actor": actor,
            "total": len(plan), "done": 0, "current": "", "cancel_requested": False,
            "security_only": bool(security_only),
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
        """Explicit, operator-approved reboot of ONE node (``shutdown -r +1``).
        Never part of an apply. Refused during a run and on nodes that haven't
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
            cached = st["nodes"].get(node_key)
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
        run["status"] = "cancelled" if run.get("cancel_requested") else "finished"
        run["current"] = ""
        run["finished_at"] = time.time()
        self._osu_save()
        # Refresh so the panel reflects reality (and any new reboot_required)
        # without the operator having to hit Check again.
        try:
            await self.osu_check_fleet(refresh=False)
        except Exception:  # noqa: BLE001
            pass


def _unwrap(resp: Any) -> Dict[str, Any]:
    """Pull the payload out of a request_response envelope."""
    if isinstance(resp, dict):
        inner = resp.get("payload", {})
        if isinstance(inner, dict) and "data" in inner:
            return inner["data"] or {}
        return resp
    return {}
