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

    def osu_snapshot(self) -> Dict[str, Any]:
        st = self._osu_state()
        nodes = sorted(st["nodes"].values(), key=lambda n: (n["kind"] != "hub", n["label"]))
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
