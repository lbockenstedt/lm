"""Device model specs (manufacturer, model, role, size, ports) for NetBox.

A spec is learned once per vendor+model: on a miss the hub asks the LLM (the
AppBuilder agent's HELP_ASK relay, same path as console identify) and records
the answer in ``<data_dir>/device_specs.json``. Every later device of that
model uses the recorded spec, so the LLM is asked only once per model.

Only the model string, a vendor hint and the device's own interface NAMES go
to the LLM (scrubbed by ``_ask_llm``) — never addresses, hostnames or serials.

The spec uses the NetBox seed-catalog shape so the netbox spoke builds the
device type and its port templates with its existing catalog seeder.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger("DeviceSpecs")

_FILE_NAME = "device_specs.json"
_UNKNOWN_RETRY_S = 24 * 3600     # re-ask about a model the LLM couldn't identify
_MAX_INTERFACE_NAMES = 120

_CACHE: Dict[str, Dict[str, Any]] = {}
_ASK_LOCK: Optional[asyncio.Lock] = None   # created on first use, in the hub's loop

_SYS_SPEC = (
    "You are a network hardware catalog assistant. Given a device's reported "
    "model string, a vendor hint and the device's own interface names, identify "
    "the exact hardware model and describe it for a NetBox device type.\n"
    "Respond with ONLY a single JSON object and no other text:\n"
    "{\"identified\": bool, \"manufacturer\": \"...\", \"model\": \"<marketing model, "
    "e.g. 8325-48Y8C>\", \"part_number\": \"<SKU or null>\", \"role\": \"<one of: "
    "switch, router, firewall, gateway, access-point, server, storage, "
    "load-balancer, other>\", \"u_height\": int, \"is_full_depth\": bool, "
    "\"ports\": [{\"prefix\": \"...\", \"start\": int, \"count\": int, \"type\": "
    "\"<NetBox interface type slug, e.g. 1000base-t, 10gbase-x-sfpp, "
    "25gbase-x-sfp28, 100gbase-x-qsfp28>\"}], \"console\": {\"name\": \"...\", "
    "\"type\": \"rj-45|usb-c|usb-mini-b|...\"} or null, \"power\": [{\"name\": "
    "\"PSU1\", \"type\": \"<NetBox power port type, e.g. iec-60320-c14>\"}], "
    "\"comments\": \"<one line>\", \"confidence\": 0.0-1.0}\n"
    "\"ports\" lists ONLY the fixed front-panel data ports. Port names are "
    "prefix + number and MUST follow the naming in the given interface names "
    "(e.g. prefix \"1/1/\" for AOS-CX, \"ge-0/0/\" for Junos, \"\" for AOS-S). "
    "If you cannot tell what the device is, respond {\"identified\": false}."
)

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,40}$")


def _file(hub) -> Optional[str]:
    data_dir = getattr(getattr(hub, "state", None), "data_dir", None)
    return os.path.join(data_dir, _FILE_NAME) if isinstance(data_dir, str) and data_dir else None


def _db(hub) -> Dict[str, Any]:
    path = _file(hub)
    key = path or "__ephemeral__"
    db = _CACHE.get(key)
    if db is None:
        db = {"models": {}}
        try:
            if path and os.path.exists(path):
                with open(path) as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict) and isinstance(loaded.get("models"), dict):
                    db = loaded
        except Exception as e:  # noqa: BLE001
            logger.warning("device spec DB load failed (%s): %s", path, e)
        _CACHE[key] = db
    return db


def _save(hub) -> None:
    path = _file(hub)
    if not path:
        return
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_db(hub), f, indent=1, sort_keys=True)
        os.replace(tmp, path)
    except Exception as e:  # noqa: BLE001
        logger.warning("device spec DB save failed: %s", e)


def model_key(vendor: str, model: str) -> str:
    return re.sub(r"\s+", " ", f"{vendor or ''}|{model or ''}".strip().lower())


def _int(v, lo, hi) -> Optional[int]:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None


def _slug(v) -> str:
    s = str(v or "").strip().lower()
    return s if _SLUG_RE.match(s) else ""


def clean_spec(js: Any) -> Optional[Dict[str, Any]]:
    """Validate an LLM answer into a seed-catalog style spec, or None."""
    if not isinstance(js, dict) or js.get("identified") is False:
        return None
    mfr = str(js.get("manufacturer") or "").strip()[:60]
    model = str(js.get("model") or "").strip()[:80]
    if not mfr or not model:
        return None
    ports = []
    for p in js.get("ports") or []:
        if not isinstance(p, dict):
            continue
        count, start, ptype = _int(p.get("count"), 1, 512), _int(p.get("start"), 0, 512), _slug(p.get("type"))
        if count and start is not None and ptype:
            ports.append({"prefix": str(p.get("prefix") or "")[:20], "start": start,
                          "count": count, "type": ptype})
    power = [{"name": str(p.get("name") or "")[:30], "type": _slug(p.get("type"))}
             for p in (js.get("power") or []) if isinstance(p, dict)]
    power = [p for p in power if p["name"] and p["type"]]
    con = js.get("console") if isinstance(js.get("console"), dict) else None
    console = ({"name": str(con.get("name") or "Console")[:30], "type": _slug(con.get("type"))}
               if con and _slug(con.get("type")) else None)
    return {
        "manufacturer": mfr,
        "model": model,
        "part_number": str(js.get("part_number") or "").strip()[:40],
        "role": _slug(js.get("role")) or "other",
        "u_height": _int(js.get("u_height"), 0, 60) or 1,
        "is_full_depth": bool(js.get("is_full_depth", True)),
        "comments": str(js.get("comments") or "").strip()[:200],
        "ports": ports,
        "console": console,
        "power": power,
    }


def _question(model: str, vendor: str, interface_names: Iterable[str]) -> str:
    names = sorted({str(n) for n in interface_names or [] if n})[:_MAX_INTERFACE_NAMES]
    return (f"Reported model: {model}\nVendor hint: {vendor or 'unknown'}\n"
            f"Interface names: {', '.join(names) or '(none)'}")


async def get_spec(hub, model: str, vendor: str = "",
                   interface_names: Iterable[str] = ()) -> Optional[Dict[str, Any]]:
    """The recorded spec for this vendor+model; on a miss ask the LLM once and
    record the answer. Best-effort: None when unknown or the LLM is unreachable."""
    model = str(model or "").strip()
    if not model:
        return None
    key = model_key(vendor, model)
    models = _db(hub)["models"]

    def _known():
        rec = models.get(key) or {}
        if rec.get("spec"):
            return rec["spec"], True
        if not rec.get("unidentified"):
            return None, False
        return None, time.time() - float(rec.get("asked") or 0) < _UNKNOWN_RETRY_S

    spec, done = _known()
    if done:
        return spec
    global _ASK_LOCK
    if _ASK_LOCK is None:
        _ASK_LOCK = asyncio.Lock()
    async with _ASK_LOCK:
        spec, done = _known()          # another poll may have just asked
        if done:
            return spec
        from routes.console_llm_identify import _ask_llm, _extract_json, find_ab
        agent = find_ab(hub)
        if not agent:
            return None
        try:
            # A catalog answer is recorded for good, so use the most capable model.
            reply = await _ask_llm(hub, agent, _SYS_SPEC,
                                   _question(model, vendor, interface_names),
                                   timeout=120.0, role="final")
        except Exception as e:  # noqa: BLE001
            logger.warning("device spec: LLM ask for %r failed: %s", model, e)
            return None
        answer = _extract_json(reply)
        spec = clean_spec(answer)
        if not spec and not (isinstance(answer, dict) and answer.get("identified") is False):
            # Not an explicit "don't know": a bad reply, so don't hold off for a day.
            logger.warning("device spec: unusable LLM reply for %r: %.300s", model, reply)
            return None
        models[key] = {"spec": spec, "unidentified": not spec, "asked": time.time(),
                       "reported_model": model}
        _save(hub)
        logger.info("device spec: %r -> %s", model,
                    f"{spec['manufacturer']} {spec['model']} ({len(spec['ports'])} port groups)"
                    if spec else "unidentified")
        return spec
