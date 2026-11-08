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
# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio.Lock ensures only one LLM question is in flight at a time.
import asyncio
# json reads/writes the spec database file and nothing else.
import json
# Standard-library logging for load/save/LLM messages.
import logging
# os builds file paths and does atomic file replacement.
import os
# re normalises keys and validates slugs.
import re
# time.time() timestamps when a model was last asked about.
import time
# Type hints only.
from typing import Any, Dict, Iterable, Optional

# One named logger so device-spec messages can be filtered together.
logger = logging.getLogger("DeviceSpecs")

# File name of the spec database inside the hub's data directory.
_FILE_NAME = "device_specs.json"
_UNKNOWN_RETRY_S = 24 * 3600     # re-ask about a model the LLM couldn't identify
# Cap on interface names sent to the LLM, to keep the prompt small.
_MAX_INTERFACE_NAMES = 120

# In-memory copy of each spec database, keyed by file path.
_CACHE: Dict[str, Dict[str, Any]] = {}
_ASK_LOCK: Optional[asyncio.Lock] = None   # created on first use, in the hub's loop

# System prompt telling the LLM exactly what JSON shape to return.
_SYS_SPEC = (
    "You are a network hardware catalog assistant. Given a device's reported "
    "model string, a vendor hint and the device's own interface names, identify "
    "the exact hardware model and describe it for a NetBox device type.\n"
    "Respond with ONLY a single JSON object and no other text:\n"
    "{\"identified\": bool, \"manufacturer\": \"...\", \"model\": \"<marketing model, "
    "e.g. 8325-48Y8C>\", \"part_number\": \"<SKU or null>\", \"role\": \"<one of: "
    "switch, router, firewall, gateway, access-point, server, storage, "
    "load-balancer, other>\", \"u_height\": int, \"is_full_depth\": bool, "
    "\"is_half_width\": bool, "
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

# A NetBox-style slug: lower-case letters, digits and dashes, 2-41 characters.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,40}$")


def _file(hub) -> Optional[str]:
    """Return the path of the spec database file, or None if the hub has no data dir."""
    # Safely dig out hub.state.data_dir (any piece may be missing in tests).
    data_dir = getattr(getattr(hub, "state", None), "data_dir", None)
    # Only build a path when the data dir is a non-empty string.
    return os.path.join(data_dir, _FILE_NAME) if isinstance(data_dir, str) and data_dir else None


def _db(hub) -> Dict[str, Any]:
    """Return the (cached) spec database, loading it from disk on first use."""
    # Cache key is the file path; a hub without a data dir gets an in-memory-only DB.
    path = _file(hub)
    key = path or "__ephemeral__"
    # Already loaded? Then reuse it.
    db = _CACHE.get(key)
    # First use: start empty, then try to load the file.
    if db is None:
        db = {"models": {}}
        # A missing or corrupt file just means starting empty.
        try:
            # Load the file if it exists.
            if path and os.path.exists(path):
                with open(path) as f:
                    loaded = json.load(f)
                # Accept it only if it has the expected {"models": {...}} shape.
                if isinstance(loaded, dict) and isinstance(loaded.get("models"), dict):
                    db = loaded
        # Unreadable file: warn and carry on with an empty DB.
        except Exception as e:  # noqa: BLE001
            logger.warning("device spec DB load failed (%s): %s", path, e)
        # Remember the DB for next time.
        _CACHE[key] = db
    return db


def _save(hub) -> None:
    """Write the spec database to disk atomically (best-effort)."""
    # No data dir means nothing to persist.
    path = _file(hub)
    if not path:
        return
    # Disk errors are logged, never raised.
    try:
        # Write to a temp file, then atomically replace the real file.
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_db(hub), f, indent=1, sort_keys=True)
        os.replace(tmp, path)
    # Save failed: warn; the in-memory DB still works.
    except Exception as e:  # noqa: BLE001
        logger.warning("device spec DB save failed: %s", e)


def model_key(vendor: str, model: str) -> str:
    """Return the normalised "vendor|model" lookup key (lower-case, single spaces)."""
    # Join vendor and model, lower-case it, and collapse runs of whitespace.
    return re.sub(r"\s+", " ", f"{vendor or ''}|{model or ''}".strip().lower())


def _int(v, lo, hi) -> Optional[int]:
    """Return ``v`` as an int if it is within [lo, hi], else None."""
    # Non-numeric values are rejected rather than raising.
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    # Out-of-range values are rejected.
    return n if lo <= n <= hi else None


def _slug(v) -> str:
    """Return ``v`` as a lower-case slug if valid, else ""."""
    # Normalise to a trimmed lower-case string.
    s = str(v or "").strip().lower()
    # Reject anything that is not a valid slug.
    return s if _SLUG_RE.match(s) else ""


def clean_spec(js: Any) -> Optional[Dict[str, Any]]:
    """Validate an LLM answer into a seed-catalog style spec, or None."""
    # Not a dict, or the LLM explicitly said it does not know: no spec.
    if not isinstance(js, dict) or js.get("identified") is False:
        return None
    # Manufacturer and model are required; trim and cap their length.
    mfr = str(js.get("manufacturer") or "").strip()[:60]
    model = str(js.get("model") or "").strip()[:80]
    if not mfr or not model:
        return None
    # Validated front-panel port groups.
    ports = []
    # Check each port group the LLM proposed.
    for p in js.get("ports") or []:
        # Skip malformed entries.
        if not isinstance(p, dict):
            continue
        # Port count, starting number and NetBox interface type must all be sane.
        count, start, ptype = _int(p.get("count"), 1, 512), _int(p.get("start"), 0, 512), _slug(p.get("type"))
        # Keep only complete, valid port groups.
        if count and start is not None and ptype:
            ports.append({"prefix": str(p.get("prefix") or "")[:20], "start": start,
                          "count": count, "type": ptype})
    # Power supplies: keep a capped name and validated type...
    power = [{"name": str(p.get("name") or "")[:30], "type": _slug(p.get("type"))}
             for p in (js.get("power") or []) if isinstance(p, dict)]
    # ...and drop any with a missing name or invalid type.
    power = [p for p in power if p["name"] and p["type"]]
    # Console port, if the LLM gave one as a dict.
    con = js.get("console") if isinstance(js.get("console"), dict) else None
    # Keep the console only if its type is a valid slug (default name "Console").
    console = ({"name": str(con.get("name") or "Console")[:30], "type": _slug(con.get("type"))}
               if con and _slug(con.get("type")) else None)
    # Half-width chassis (two side by side in one U, e.g. Aruba CX 9004) are
    # never full depth, and carry a marker the NetBox sync/auto-rack reads.
    half = bool(js.get("is_half_width", False))
    comments = str(js.get("comments") or "").strip()[:200]
    if half and "half-width" not in comments.lower():
        comments = (comments[:180] + " [half-width]").strip()
    # Assemble the clean spec, filling safe defaults (role "other", 1U, full depth).
    return {
        "manufacturer": mfr,
        "model": model,
        "part_number": str(js.get("part_number") or "").strip()[:40],
        "role": _slug(js.get("role")) or "other",
        "u_height": _int(js.get("u_height"), 0, 60) or 1,
        "is_full_depth": False if half else bool(js.get("is_full_depth", True)),
        "comments": comments,
        "ports": ports,
        "console": console,
        "power": power,
    }


def _question(model: str, vendor: str, interface_names: Iterable[str]) -> str:
    """Build the user prompt describing the device for the LLM."""
    # De-duplicate, sort and cap interface names (names only, never addresses).
    names = sorted({str(n) for n in interface_names or [] if n})[:_MAX_INTERFACE_NAMES]
    # Three lines: model, vendor hint, interface names.
    return (f"Reported model: {model}\nVendor hint: {vendor or 'unknown'}\n"
            f"Interface names: {', '.join(names) or '(none)'}\n"
            "Answer with the JSON object only: no prose, no markdown.")


async def get_spec(hub, model: str, vendor: str = "",
                   interface_names: Iterable[str] = ()) -> Optional[Dict[str, Any]]:
    """The recorded spec for this vendor+model; on a miss ask the LLM once and
    record the answer. Best-effort: None when unknown or the LLM is unreachable."""
    # Normalise the model string; without one there is nothing to look up.
    model = str(model or "").strip()
    if not model:
        return None
    # Lookup key and the per-model records.
    key = model_key(vendor, model)
    models = _db(hub)["models"]

    def _known():
        """Return (spec, done): done is True when no LLM question is needed right now."""
        # Existing record for this model (empty if never seen).
        rec = models.get(key) or {}
        # A recorded spec: use it.
        if rec.get("spec"):
            return rec["spec"], True
        # Never asked: we need to ask.
        if not rec.get("unidentified"):
            return None, False
        # Previously unidentified: only re-ask once the retry interval has passed.
        return None, time.time() - float(rec.get("asked") or 0) < _UNKNOWN_RETRY_S

    # Fast path: answer from the database without locking.
    spec, done = _known()
    if done:
        return spec
    # Create the lock lazily so it binds to the running event loop.
    global _ASK_LOCK
    if _ASK_LOCK is None:
        _ASK_LOCK = asyncio.Lock()
    # Only one LLM question at a time.
    async with _ASK_LOCK:
        spec, done = _known()          # another poll may have just asked
        if done:
            return spec
        # Imported lazily to avoid a circular import with the routes package.
        from routes.console_llm_identify import _ask_llm, _extract_json, find_ab
        # Find the AppBuilder agent that relays LLM questions; none means we cannot ask.
        agent = find_ab(hub)
        if not agent:
            return None
        # Ask the LLM (a second time if it answered in prose instead of JSON); any
        # failure is logged and treated as "unknown for now".
        try:
            for _ in range(2):
                # A catalog answer is recorded for good, so use the most capable model.
                reply = await _ask_llm(hub, agent, _SYS_SPEC,
                                       _question(model, vendor, interface_names),
                                       timeout=120.0, role="final")
                answer = _extract_json(reply)
                if answer is not None:
                    break
        except Exception as e:  # noqa: BLE001
            logger.warning("device spec: LLM ask for %r failed: %s", model, e)
            return None
        # Validate the reply.
        spec = clean_spec(answer)
        # The reply was neither a usable spec nor an explicit "unknown".
        if not spec and not (isinstance(answer, dict) and answer.get("identified") is False):
            # Not an explicit "don't know": a bad reply, so don't hold off for a day.
            logger.warning("device spec: unusable LLM reply for %r: %.300s", model, reply)
            return None
        # Record the result (spec, or unidentified with a timestamp) and persist it.
        models[key] = {"spec": spec, "unidentified": not spec, "asked": time.time(),
                       "reported_model": model}
        _save(hub)
        # Log what was learned.
        logger.info("device spec: %r -> %s", model,
                    f"{spec['manufacturer']} {spec['model']} ({len(spec['ports'])} port groups)"
                    if spec else "unidentified")
        # Return the spec (None if unidentified).
        return spec
