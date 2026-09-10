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

This module is DISTINCT from ``update_pipeline.py``, which ships LM's own code.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

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

# Auto-check config lives in global_config["os_updates_check"]: {enabled,
# interval_hours}. Enabled by default (seeded once — see
# seed_os_updates_check_defaults) so the panel's status stays fresh without an
# operator remembering to click "Check for updates"; every 6h by default.
_OSU_AUTOCHECK_CFG_KEY = "os_updates_check"
_OSU_AUTOCHECK_DEFAULT_HOURS = 6.0


class HubOsUpdatesMixin:
    """Collect + orchestrate OS package updates across the fleet."""

    # ── state ────────────────────────────────────────────────────────────────
    def _osu_state(self) -> Dict[str, Any]:
        st = getattr(self, "_os_update_state", None)
        if st is None:
            st = {"nodes": {}, "checked_at": 0.0, "run": None}
            self._os_update_state = st
        return st

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
        for aid, info in (getattr(self, "agent_info", {}) or {}).items():
            sid = (info or {}).get("spoke_id") or ""
            if not sid:
                continue
            out.append({"kind": "agent", "id": aid, "spoke_id": sid,
                        "label": str((info or {}).get("hostname") or aid),
                        "module_type": "agent"})
        out.append({"kind": "hub", "id": "hub", "spoke_id": "",
                    "label": "hub (this server)", "module_type": "hub"})
        return out

    # ── check ────────────────────────────────────────────────────────────────
    async def _osu_check_one(self, t: Dict[str, str], refresh: bool) -> Dict[str, Any]:
        base = {"kind": t["kind"], "id": t["id"], "label": t["label"],
                "module_type": t["module_type"], "spoke_id": t.get("spoke_id", "")}
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
                    {"agent_id": t["id"], "refresh": refresh},
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

        await run_sync_loop(stagger=45, guard=_guard,
                            body=lambda: self.osu_check_fleet(refresh=True),
                            delay=_delay,
                            error_label="os-updates auto-check loop cycle failed")

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
                merged[key] = {"checked": True, **cached}
            else:
                merged[key] = {
                    "kind": t["kind"], "id": t["id"], "label": t["label"],
                    "module_type": t["module_type"], "spoke_id": t.get("spoke_id", ""),
                    "checked": False, "eligible": None, "unmanaged": False,
                    "unreachable": False, "reason": "not checked yet", "count": 0,
                }
        nodes = sorted(merged.values(), key=lambda n: (n["kind"] != "hub", n["label"]))
        pending = [n for n in nodes if n.get("eligible") and n.get("count")]
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
                "not_checked": sum(1 for n in nodes if not n.get("checked")),
            },
            "run": st.get("run"),
        }

    # ── rolling apply ────────────────────────────────────────────────────────
    async def osu_apply_fleet(self, node_keys: Optional[List[str]] = None,
                              actor: str = "") -> Dict[str, Any]:
        """Approve-once, rolling apply. Returns immediately; progress via snapshot.

        One node at a time so a bad update can't hit the fleet at once, and the
        HUB LAST because applying to it restarts the process running this loop.
        """
        st = self._osu_state()
        run = st.get("run")
        if run and run.get("status") == "running":
            return {"status": "ERROR", "message": "an update run is already in progress"}
        snap = self.osu_snapshot()
        targets = [n for n in snap["nodes"] if n.get("eligible") and n.get("count")]
        if node_keys:
            want = set(node_keys)
            targets = [n for n in targets if f"{n['kind']}:{n['id']}" in want]
        if not targets:
            return {"status": "ERROR", "message": "no eligible nodes with pending updates"}
        # Hub last — see the module docstring.
        targets.sort(key=lambda n: n["kind"] == "hub")
        st["run"] = {
            "status": "running", "started_at": time.time(), "actor": actor,
            "total": len(targets), "done": 0, "current": "",
            "items": [{"key": f"{n['kind']}:{n['id']}", "label": n["label"],
                       "status": "queued"} for n in targets],
        }
        logger.warning("OS-UPDATE: fleet apply approved by %s — %d node(s), hub last",
                       actor or "?", len(targets))
        asyncio.create_task(self._osu_run(targets))
        return {"status": "SUCCESS", "queued": len(targets)}

    async def _osu_run(self, targets: List[Dict[str, Any]]) -> None:
        st = self._osu_state()
        run = st["run"]
        for n in targets:
            key = f"{n['kind']}:{n['id']}"
            run["current"] = n["label"]
            item = next((i for i in run["items"] if i["key"] == key), None)
            if item:
                item["status"] = "applying"
            try:
                if n["kind"] == "hub":
                    try:
                        from .os_update import apply_updates
                    except ImportError:
                        from os_update import apply_updates  # type: ignore
                    d = await asyncio.to_thread(apply_updates)
                elif n["kind"] == "agent":
                    d = _unwrap(await self.request_response(
                        n["spoke_id"], "AGENT_OS_UPDATE_APPLY",
                        {"agent_id": n["id"]}, timeout=_APPLY_TIMEOUT_S))
                else:
                    d = _unwrap(await self.request_response(
                        n["id"], "OS_UPDATE_APPLY", {}, timeout=_APPLY_TIMEOUT_S))
            except Exception as exc:  # noqa: BLE001 — one failure must not abort the roll
                d = {"status": "ERROR", "message": str(exc)}
            ok = isinstance(d, dict) and d.get("status") == "SUCCESS"
            if item:
                item.update({
                    "status": "done" if ok else "failed",
                    "applied": (d or {}).get("applied"),
                    "remaining": (d or {}).get("remaining"),
                    "reboot_required": bool((d or {}).get("reboot_required")),
                    "message": (d or {}).get("message", ""),
                })
            run["done"] += 1
            logger.warning("OS-UPDATE: %s → %s (%s)", n["label"],
                           "ok" if ok else "FAILED", (d or {}).get("message", "") or "")
        run["status"] = "finished"
        run["current"] = ""
        run["finished_at"] = time.time()
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
