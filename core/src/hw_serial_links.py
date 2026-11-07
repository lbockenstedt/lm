"""Hardware-serial stitching: link a server's management controller (iLO/iDRAC,
nw object_type ``ipmi``) to the host-OS record of the SAME physical machine.

The controller and the host OS report the same chassis serial from two
different places (SNMP poll of the BMC; TrueNAS ``system.info`` or an agent's
DMI read). Matching on that serial links the two records without any manual
config. Nothing is merged and nothing is forced: a serial is linked only when
exactly one controller and one host carry it, otherwise it is reported as
ambiguous.

``match_links`` is pure. ``refresh_hw_serial_links`` gathers the inputs from the
hub, persists the result on the records and is cheap enough to call from the
existing periodic paths (nw poll, truenas poll, agent heartbeat).
"""
import logging
import re
import time
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("Hub")

# Placeholder values firmware ships when the serial was never programmed.
_JUNK = {
    "NOTSPECIFIED", "TOBEFILLEDBYOEM", "TOBEFILLEDBYO.E.M.", "NONE", "DEFAULTSTRING",
    "UNKNOWN", "NA", "N/A", "NOTAPPLICABLE", "NULL", "EMPTY", "SYSTEMSERIALNUMBER",
    "SERIALNUMBER", "CHASSISSERIALNUMBER", "FILLEDBYOEM", "OEM", "SERIAL",
    "1234567890", "0123456789", "123456789", "1234567",
}
# Virtual-machine firmware serials: not a physical box, never link.
_VM_PREFIXES = ("VMWARE", "VIRTUALBOX", "QEMU", "KVM", "XEN", "PARALLELS", "AMAZONEC2", "EC2")
_MIN_LEN = 5
# Controllers carry a short DNS label identity that never matches a host name,
# so a host seen from two sources (TrueNAS + agent) is collapsed by short name.
_KIND_PREF = {"truenas": 0, "agent": 1}


def normalize_serial(value: Any) -> str:
    """Canonical (upper-case, trimmed) hardware serial, or "" for empty,
    placeholder, too-short, repeated-character or virtual-machine values."""
    s = str(value or "").strip().strip("\x00").strip()
    if not s:
        return ""
    up = s.upper()
    squashed = re.sub(r"[\s_\-]+", "", up)
    if squashed in _JUNK or up in _JUNK:
        return ""
    if len(squashed) < _MIN_LEN or len(set(squashed)) == 1:
        return ""
    if up.startswith(_VM_PREFIXES):
        return ""
    return up


def _short(name: Any) -> str:
    """First DNS label, lower-cased."""
    return str(name or "").strip().split(".", 1)[0].lower()


def _brief(rec: Dict[str, Any], keys: Iterable[str]) -> Dict[str, Any]:
    """Copy only the identifying keys of a record."""
    return {k: rec.get(k) for k in keys if rec.get(k) not in (None, "")}


def match_links(controllers: List[Dict[str, Any]],
                hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Match controllers to hosts by normalized serial.

    ``controllers``: ``{id, name, address, serial}``; ``hosts``:
    ``{kind, id, name, serial}``. Returns ``{"links": [...], "ambiguous": [...],
    "unmatched_controllers": [...]}`` where each link is
    ``{serial, controller, host}``. A serial links only when it has exactly one
    controller and one host (hosts that are the same machine seen through two
    sources, i.e. the same short name, count once)."""
    by_ctl: Dict[str, List[Dict[str, Any]]] = {}
    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for c in controllers or []:
        s = normalize_serial((c or {}).get("serial"))
        if s:
            by_ctl.setdefault(s, []).append(c)
    for h in hosts or []:
        s = normalize_serial((h or {}).get("serial"))
        if s:
            by_host.setdefault(s, []).append(h)

    links: List[Dict[str, Any]] = []
    ambiguous: List[Dict[str, Any]] = []
    for serial, ctls in by_ctl.items():
        hs = by_host.get(serial) or []
        # One machine reported by two sources collapses to its preferred record.
        uniq: Dict[str, Dict[str, Any]] = {}
        for h in sorted(hs, key=lambda x: _KIND_PREF.get(str(x.get("kind")), 9)):
            uniq.setdefault(_short(h.get("name")) or f"{h.get('kind')}:{h.get('id')}", h)
        hosts_u = list(uniq.values())
        if len(ctls) == 1 and len(hosts_u) == 1:
            links.append({
                "serial": serial,
                "controller": _brief(ctls[0], ("id", "name", "address")),
                "host": _brief(hosts_u[0], ("kind", "id", "name")),
            })
        elif hosts_u and len(ctls) + len(hosts_u) > 2:
            ambiguous.append({
                "serial": serial,
                "controllers": [_brief(c, ("id", "name")) for c in ctls],
                "hosts": [_brief(h, ("kind", "id", "name")) for h in hosts_u],
            })
    linked = {l["controller"].get("id") for l in links}
    unmatched = [_brief(c, ("id", "name", "address")) for cs in by_ctl.values() for c in cs
                 if c.get("id") not in linked
                 and not any(a["serial"] == normalize_serial(c.get("serial")) for a in ambiguous)]
    return {"links": links, "ambiguous": ambiguous, "unmatched_controllers": unmatched}


def _dig_serial(info: Any) -> str:
    """system_serial from a cached TrueNAS info envelope (tolerates one extra
    ``data`` nesting, which the probe and poll caches differ on)."""
    for _ in range(3):
        if not isinstance(info, dict):
            return ""
        for k in ("system_serial", "serial", "system_serial_number"):
            if info.get(k):
                return str(info[k])
        info = info.get("data")
    return ""


def gather_inputs(hub: Any, serial_override: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Collect controllers and hosts from the hub's live state."""
    override = serial_override or {}
    gc = hub.state.system_state.get("global_config", {}) or {}
    identity: Dict[str, Dict[str, Any]] = {}
    getter = getattr(hub, "_nw_identity_cache", None)
    if callable(getter):
        try:
            identity = getter() or {}
        except Exception:  # noqa: BLE001
            identity = {}
    controllers = []
    for d in gc.get("nw_devices", []) or []:
        if not isinstance(d, dict) or str(d.get("object_type") or "").lower() != "ipmi":
            continue
        did = str(d.get("id") or "")
        serial = override.get(did) or (identity.get(did) or {}).get("serial") or d.get("serial") or ""
        controllers.append({"id": did, "name": d.get("name"),
                            "address": d.get("address"), "serial": serial})
    hosts = []
    cache = getattr(hub, "truenas_appliance_cache", {}) or {}
    # The fleet listing also carries each appliance's probed system info.
    fleet = (getattr(hub, "truenas_fleet_cache", {}) or {}).get("appliances")
    if isinstance(fleet, dict):
        fleet = fleet.get("data")
    fleet_info = {str(r.get("id")): r.get("info") for r in (fleet or []) if isinstance(r, dict)}
    for a in gc.get("truenas_appliances", []) or []:
        if not isinstance(a, dict) or not a.get("id"):
            continue
        entry = cache.get(str(a["id"])) or {}
        serial = (_dig_serial(entry.get("info")) or _dig_serial(fleet_info.get(str(a["id"])))
                  or a.get("hw_serial") or "")
        hosts.append({"kind": "truenas", "id": str(a["id"]),
                      "name": a.get("name") or a["id"], "serial": serial})
    for pk, info in (getattr(hub, "agent_info", {}) or {}).items():
        if isinstance(info, dict) and info.get("hw_serial"):
            hosts.append({"kind": "agent", "id": str(pk),
                          "name": info.get("hostname") or info.get("agent_id") or pk,
                          "serial": info["hw_serial"]})
    return {"controllers": controllers, "hosts": hosts}


def refresh_hw_serial_links(hub: Any, serial_override: Optional[Dict[str, str]] = None,
                            min_interval_s: float = 0.0) -> Dict[str, Any]:
    """Recompute links and persist them on the records. Sets and updates only:
    a host that is temporarily unreported never drops an existing link, but a
    controller whose serial changed (box swap) loses its stale one. Never
    raises. Returns the match report plus ``changed``."""
    try:
        now = time.monotonic()
        last = getattr(hub, "_hw_links_last", 0.0)
        if min_interval_s and now - last < min_interval_s and not serial_override:
            return {"skipped": True}
        hub._hw_links_last = now
        inp = gather_inputs(hub, serial_override)
        rep = match_links(inp["controllers"], inp["hosts"])
        gc = hub.state.system_state.get("global_config", {}) or {}
        devs = {str(d.get("id")): d for d in gc.get("nw_devices", []) or [] if isinstance(d, dict)}
        appliances = {str(a.get("id")): a for a in gc.get("truenas_appliances", []) or []
                      if isinstance(a, dict)}
        changed = False
        # Persist the polled serial on every controller record.
        for c in inp["controllers"]:
            d = devs.get(c["id"])
            s = normalize_serial(c["serial"])
            if d is not None and s and d.get("serial") != s:
                d["serial"] = s
                changed = True
            # A swapped box keeps no link to the old host.
            if d is not None and s and (d.get("host_link") or {}).get("serial") not in (None, s):
                d.pop("host_link", None)
                changed = True
        for ln in rep["links"]:
            ctl, host = ln["controller"], ln["host"]
            d = devs.get(str(ctl.get("id")))
            if d is None:
                continue
            new = {**host, "serial": ln["serial"]}
            old = d.get("host_link") or {}
            if {k: old.get(k) for k in new} != new:
                d["host_link"] = {**new, "linked_at": time.time()}
                changed = True
                logger.info("hw-serial link: %s <-> %s %s (serial %s)", ctl.get("name"),
                            host.get("kind"), host.get("name"), ln["serial"])
            if host.get("kind") == "truenas":
                a = appliances.get(str(host.get("id")))
                back = {"id": ctl.get("id"), "name": ctl.get("name"), "address": ctl.get("address")}
                if a is not None and a.get("linked_controller") != back:
                    a["linked_controller"] = back
                    changed = True
            elif host.get("kind") == "agent":
                ai = (getattr(hub, "agent_info", {}) or {}).get(str(host.get("id")))
                if isinstance(ai, dict):
                    ai["linked_controller"] = {"id": ctl.get("id"), "name": ctl.get("name")}
        for amb in rep["ambiguous"]:
            logger.warning("hw-serial link ambiguous for %s: %s controller(s), %s host(s) — not linked",
                           amb["serial"], len(amb["controllers"]), len(amb["hosts"]))
        if changed:
            hub.state.system_state["global_config"] = gc
            try:
                hub.state._mark_dirty()
            except Exception:  # noqa: BLE001
                pass
        rep["changed"] = changed
        return rep
    except Exception as e:  # noqa: BLE001
        logger.warning("hw-serial link refresh failed: %s", e)
        return {"error": str(e)}


def controller_link_for(device_cfg: Dict[str, Any], serial: str = "") -> Dict[str, Any]:
    """The host identity to push to NetBox for a controller record: the
    persisted link, only while it still matches the controller's serial."""
    link = (device_cfg or {}).get("host_link") or {}
    if not link.get("name"):
        return {}
    ser = normalize_serial(serial) or normalize_serial(device_cfg.get("serial"))
    if ser and link.get("serial") and link["serial"] != ser:
        return {}
    return {"kind": link.get("kind", ""), "name": link["name"], "serial": link.get("serial", "")}
