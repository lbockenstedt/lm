"""Shared VM snapshot service (hub side).

One place that knows how to snapshot a Proxmox VM and prune its old snapshots,
used by every module that needs it:

  * ``take_snapshot(hub, vm, prefix, keep)`` — snapshot one VM through the pxmx
    spoke (``PXMX_VM_ACTION snapshot``), then delete the oldest snapshots whose
    name starts with ``prefix`` so at most ``keep`` remain. Snapshots made by
    hand or by another prefix are never touched.
  * ``find_vm(hub, names, ips)`` — the VM a host runs in, matched by hostname
    and (optionally) IP against the hub's VM list.
  * Snapshot schedules — snapshot chosen VMs, or groups of VMs (Proxmox tag or
    pool), every N hours, keeping the last K. Stored in
    ``global_config["vm_snapshot_schedules"]`` and run by ``run_loop``.

OS Updates uses ``find_vm`` + ``take_snapshot`` for its pre-patch snapshots.
The VM list comes from the hub's warm cache (``pxmx_vms``, all-tenants scope),
which the pxmx cache feed keeps fresh.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("Hub")

SCHEDULES_KEY = "vm_snapshot_schedules"
_TICK_S = 300.0
_ACTION_TIMEOUT_S = 60.0
_DELETE_TIMEOUT_S = 130.0
# Proxmox snapshot names: a letter, then letters/digits/_/-, at most 40 chars.
# The timestamp suffix is 14 chars, so a prefix may be up to 26.
_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,25}$")
_running: set = set()


# ── VM lookup ─────────────────────────────────────────────────────────────────
def all_vms(hub) -> List[Dict[str, Any]]:
    """Every VM/container the hub knows (all tenants), templates excluded."""
    data = hub.warm_get("pxmx_vms", "_all_|agent=") if hasattr(hub, "warm_get") else None
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    vms = data.get("vms") if isinstance(data, dict) else data
    return [vm for vm in (vms or []) if isinstance(vm, dict) and vm.get("vmid") is not None
            and not vm.get("template")]


def _short(name: Any) -> str:
    return str(name or "").split(".")[0].strip().lower()


def find_vm(hub, names: Iterable[str], ips: Iterable[str] = (),
            vms: Optional[List[Dict[str, Any]]] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    """``(vm, "")`` for the one VM a host runs in, else ``(None, reason)``.
    A VM matches when its name equals one of the host's short names; when
    several do, the one that also has one of ``ips`` wins. An IP alone is never
    enough (a NATed spoke reports its gateway's address), and two equally good
    candidates are never guessed between."""
    names = {_short(n) for n in names} - {""}
    ips = {str(i) for i in ips if i}
    vms = all_vms(hub) if vms is None else vms
    by_name = [vm for vm in vms if _short(vm.get("name")) in names]
    if len(by_name) > 1 and ips:
        by_ip = [vm for vm in by_name if ips & set(vm.get("ips") or [])]
        by_name = by_ip or by_name
    if len(by_name) == 1:
        return by_name[0], ""
    if by_name:
        return None, "several VMs match: " + ", ".join(
            f"{vm.get('name')} ({vm.get('vmid')}@{vm.get('node')})" for vm in by_name[:4])
    return None, "no VM with this hostname"


def vm_ref(vm: Dict[str, Any]) -> Dict[str, Any]:
    """The fields needed to act on a VM later (stored on nodes/schedules)."""
    return {k: vm.get(k) for k in ("unique_id", "name", "vmid", "node", "type", "cluster")}


# ── snapshot + prune ──────────────────────────────────────────────────────────
def snapshot_name(prefix: str, now: Optional[float] = None) -> str:
    return prefix + time.strftime("%Y%m%d%H%M%S", time.gmtime(now or time.time()))


def _route(hub, vm: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """``(spoke_id, agent_id)`` for the agent on the VM's own node, so ``qm``
    runs where the VM lives. Falls back to the hypervisor spoke (it then picks
    an agent in the VM's cluster)."""
    node = _short(vm.get("node"))
    for info in (getattr(hub, "agent_info", None) or {}).values():
        if isinstance(info, dict) and info.get("spoke_id") and node and node in (
                _short(info.get("hostname")), _short(info.get("agent_id"))):
            return info["spoke_id"], str(info.get("agent_id") or "")
    return hub.get_hypervisor_spoke(), ""


def _unwrap(resp: Any) -> Dict[str, Any]:
    if isinstance(resp, dict):
        inner = resp.get("payload")
        if isinstance(inner, dict) and "data" in inner:
            return inner["data"] or {}
        if isinstance(resp.get("data"), dict):
            return resp["data"]
        return resp
    return {}


async def _vm_action(hub, vm: Dict[str, Any], action: str, name: str = "",
                     timeout: float = _ACTION_TIMEOUT_S) -> Dict[str, Any]:
    spoke, agent = _route(hub, vm)
    if not spoke:
        return {"status": "ERROR", "message": "no Proxmox spoke connected"}
    payload = {"unique_id": vm.get("unique_id", ""), "vmid": vm.get("vmid"),
               "node": vm.get("node", ""), "type": vm.get("type") or "qemu",
               "action": action, "snapshot_name": name or None}
    if agent:
        payload["agent_id"] = agent
    try:
        d = _unwrap(await hub.request_response(spoke, "PXMX_VM_ACTION", payload, timeout=timeout))
    except Exception as exc:  # noqa: BLE001 — reported to the caller
        return {"status": "ERROR", "message": str(exc)}
    return d if isinstance(d, dict) else {"status": "ERROR", "message": "malformed response"}


async def take_snapshot(hub, vm: Dict[str, Any], prefix: str, keep: int = 0,
                        actor: str = "") -> Dict[str, Any]:
    """Snapshot ``vm`` as ``<prefix><UTC timestamp>``, then prune the oldest
    ``<prefix>*`` snapshots beyond ``keep`` (0 = keep all). Returns
    ``{status, snapshot, pruned, message}``; a failed prune is reported in
    ``message`` but does not fail the snapshot."""
    if not _PREFIX_RE.match(prefix):
        return {"status": "ERROR", "message": f"bad snapshot prefix {prefix!r}"}
    label = f"{vm.get('name')} ({vm.get('vmid')}@{vm.get('node')})"
    name = snapshot_name(prefix)
    d = await _vm_action(hub, vm, "snapshot", name)
    if d.get("status") != "SUCCESS":
        logger.warning("[vm-snapshot] %s: snapshot FAILED (%s) by %s", label,
                       d.get("message", ""), actor or "?")
        return {"status": "ERROR", "message": d.get("message") or "snapshot failed"}
    logger.info("[vm-snapshot] %s: took %s by %s", label, name, actor or "?")
    res = {"status": "SUCCESS", "snapshot": name, "pruned": [], "message": ""}
    if keep <= 0:
        return res
    listing = await _vm_action(hub, vm, "list_snapshots")
    if listing.get("status") != "SUCCESS":
        res["message"] = f"old snapshots not pruned: {listing.get('message', '')}"
        return res
    ours = [s["name"] for s in listing.get("snapshots") or []
            if str(s.get("name", "")).startswith(prefix)]
    for old in ours[:max(0, len(ours) - keep)]:
        r = await _vm_action(hub, vm, "delete_snapshot", old, timeout=_DELETE_TIMEOUT_S)
        if r.get("status") == "SUCCESS":
            res["pruned"].append(old)
        else:
            res["message"] = f"could not delete {old}: {r.get('message', '')}"
    if res["pruned"]:
        logger.info("[vm-snapshot] %s: pruned %s", label, ", ".join(res["pruned"]))
    return res


# ── schedules ─────────────────────────────────────────────────────────────────
def _store(hub) -> Dict[str, Dict[str, Any]]:
    gc = hub.state.system_state.setdefault("global_config", {})
    return gc.setdefault(SCHEDULES_KEY, {})


def list_schedules(hub) -> List[Dict[str, Any]]:
    try:
        store = hub.state.system_state.get("global_config", {}).get(SCHEDULES_KEY) or {}
    except Exception:  # noqa: BLE001 — hub without state (tests)
        store = {}
    return sorted(store.values(), key=lambda s: s.get("name", "").lower())


def _clean_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise ValueError("vms, tags and pools must be lists")
    return sorted({str(v).strip() for v in value if str(v).strip()})


def save_schedule(hub, body: Dict[str, Any], sid: str = "") -> Dict[str, Any]:
    """Create (no ``sid``) or replace a schedule. ValueError on bad input.

    ``{name, enabled, vms: [unique_id], tags: [...], pools: [...],
    every_hours, keep}`` — a VM is included if it is listed, or carries one of
    the tags, or is in one of the pools."""
    store = _store(hub)
    if sid and sid not in store:
        raise KeyError(sid)
    name = str(body.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    try:
        every = float(body.get("every_hours"))
        keep = int(body.get("keep"))
    except (TypeError, ValueError):
        raise ValueError("every_hours and keep must be numbers") from None
    if not 1 <= every <= 8760:
        raise ValueError("every_hours must be between 1 and 8760")
    if not 1 <= keep <= 100:
        raise ValueError("keep must be between 1 and 100")
    targets = {k: _clean_list(body.get(k) or []) for k in ("vms", "tags", "pools")}
    if not any(targets.values()):
        raise ValueError("pick at least one VM, tag or pool")
    old = store.get(sid, {})
    sid = sid or uuid.uuid4().hex[:6]
    store[sid] = {"id": sid, "name": name, "enabled": bool(body.get("enabled", True)),
                  **targets, "every_hours": every, "keep": keep,
                  "prefix": old.get("prefix") or f"lms-{sid}-",
                  "last_run": old.get("last_run", 0.0), "last_result": old.get("last_result")}
    hub.state._mark_dirty()
    return store[sid]


def delete_schedule(hub, sid: str) -> None:
    if _store(hub).pop(sid, None) is None:
        raise KeyError(sid)
    hub.state._mark_dirty()


def schedule_vms(sched: Dict[str, Any], vms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    want_vms, tags, pools = set(sched.get("vms") or []), set(sched.get("tags") or []), \
        set(sched.get("pools") or [])
    return [vm for vm in vms if vm.get("unique_id") in want_vms
            or tags & set(vm.get("tags") or []) or (vm.get("pool") and vm.get("pool") in pools)]


async def run_schedule(hub, sid: str, actor: str = "schedule") -> Dict[str, Any]:
    """Snapshot every VM of one schedule now (one at a time)."""
    sched = _store(hub).get(sid)
    if sched is None:
        raise KeyError(sid)
    if sid in _running:
        return {"status": "ERROR", "message": "this schedule is already running"}
    known = all_vms(hub)
    if not known:
        return {"status": "ERROR", "message": "the VM list hasn't loaded yet"}
    vms = schedule_vms(sched, known)
    _running.add(sid)
    try:
        results = []
        for vm in vms:
            r = await take_snapshot(hub, vm, sched["prefix"], sched["keep"], actor)
            results.append({"vm": vm.get("name"), "vmid": vm.get("vmid"), **r})
    finally:
        _running.discard(sid)
    failed = [r for r in results if r["status"] != "SUCCESS"]
    errors = [f"{r['vm']}: {r['message']}" for r in failed][:10]
    if not vms:
        errors = ["no VMs match this schedule"]
    summary = {"at": time.time(), "ok": len(results) - len(failed), "failed": len(failed),
               "errors": errors}
    sched.update(last_run=summary["at"], last_result=summary)
    hub.state._mark_dirty()
    return {"status": "SUCCESS" if not errors else "ERROR", **summary, "results": results}


def due_schedules(hub, now: float) -> List[str]:
    return [s["id"] for s in list_schedules(hub)
            if s.get("enabled") and s["id"] not in _running
            and now - float(s.get("last_run") or 0) >= s["every_hours"] * 3600]


def is_running(sid: str) -> bool:
    return sid in _running


async def run_loop(hub) -> None:
    """Every few minutes, run the schedules that are due. Never raises."""
    from sync_loop import run_sync_loop  # sibling leaf

    async def _tick():
        for sid in due_schedules(hub, time.time()):
            res = await run_schedule(hub, sid)
            if res.get("status") != "SUCCESS":
                logger.warning("[vm-snapshot] schedule %s: %s", sid,
                               res.get("message") or "; ".join(res.get("errors") or []))

    await run_sync_loop(stagger=120, body=_tick, delay=lambda: _TICK_S,
                        error_label="vm snapshot schedule loop failed")
