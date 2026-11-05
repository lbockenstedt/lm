"""Local, self-building console-fingerprint database.

Every time the LLM-guided identify pipeline works out what read-only commands
coax an identity out of a device — or nails the vendor/model/OS from a given
prompt — we write that knowledge to a JSON file on the hub
(``<data_dir>/console_fingerprints.json``). It is keyed by a *prompt signature*:
a scrubbed, generalized fingerprint of the console tail (hostnames/IPs/serials
stripped, digits collapsed) so the same class of device produces the same key
across ports and sites.

The next time a device presents a matching signature, the orchestrator reuses
the learned commands (and vendor, if known) and skips the LLM round entirely —
the system genuinely learns from what it sees and gets faster/cheaper over time.

The file holds only scrubbed, non-sensitive cues (the signature already passes
through :func:`console_llm_identify.scrub_for_llm`), never addressing,
credentials, or hostnames.
"""
# JSON load/save of the fingerprint file.
import json
# Logging under the "Console" logger.
import logging
# File paths and the atomic file swap.
import os
# Regexes that generalise the signature text.
import re
# Timestamps for first/last seen.
import time
# Type hints.
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Console")

# File name (in the hub data dir) and the format version.
_FILE_NAME = "console_fingerprints.json"
_VERSION = 1
_MAX_ENTRIES = 2000          # cap the file; evict least-recently-seen beyond this
_MAX_SIG = 240               # signature length cap
_MAX_SAMPLE = 400            # stored scrubbed sample length cap

# In-memory cache keyed by absolute file path so multiple hubs/tests stay isolated.
_CACHE: Dict[str, Dict[str, Any]] = {}


def _file(hub) -> Optional[str]:
    """Return the fingerprint file path for this hub, or None if it has no data dir."""
    data_dir = getattr(getattr(hub, "state", None), "data_dir", None)
    if not data_dir:
        return None
    return os.path.join(data_dir, _FILE_NAME)


def _db(hub) -> Dict[str, Any]:
    """Return the (lazily loaded) in-memory DB for this hub's data dir. When the
    hub exposes no data dir (e.g. tests), an ephemeral, non-persisted DB is used."""
    path = _file(hub)
    # Load once per path and cache it; a missing, empty or bad file starts an empty DB.
    key = path or "__ephemeral__"
    db = _CACHE.get(key)
    if db is None:
        db = {"version": _VERSION, "entries": {}}
        try:
            if path and os.path.exists(path) and os.path.getsize(path) > 0:
                with open(path) as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict) and isinstance(loaded.get("entries"), dict):
                    db = loaded
        except Exception as exc:  # noqa: BLE001
            logger.warning("console fingerprint DB load failed (%s): %s", path, exc)
        _CACHE[key] = db
    return db


def signature(text: Optional[str]) -> str:
    """Build a stable, generalized key from a console tail: scrub site-specific
    data, take the last few non-empty lines, lowercase, collapse digits so serial
    numbers / version numbers / hostnames don't fragment the key."""
    from .console_llm_identify import scrub_for_llm  # lazy: avoid import cycle
    # Scrub, then keep the last 3 non-empty lines, lower-cased.
    s = scrub_for_llm(text or "")
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    key = " | ".join(lines[-3:]).lower()
    key = re.sub(r"\d+", "#", key)              # generalize version/serial digits
    key = re.sub(r"[ \t]+", " ", key).strip()
    return key[:_MAX_SIG]


def lookup(hub, sig: str) -> Optional[Dict[str, Any]]:
    """Return the learned record for a signature (or None)."""
    # No signature -> no match; return a copy so callers can't change the cache.
    if not sig:
        return None
    rec = _db(hub)["entries"].get(sig)
    return dict(rec) if isinstance(rec, dict) else None


def _save(hub) -> None:
    """Atomically persist the DB (best-effort; never raises)."""
    # Too many entries: keep only the most recently seen.
    db = _db(hub)
    entries = db.get("entries") or {}
    if len(entries) > _MAX_ENTRIES:            # evict least-recently-seen
        keep = sorted(entries.items(), key=lambda kv: kv[1].get("last", 0),
                      reverse=True)[:_MAX_ENTRIES]
        db["entries"] = dict(keep)
    # Write to a temp file and swap it in (skip when there's no data dir).
    try:
        path = _file(hub)
        if not path:
            return                              # ephemeral (no data dir) — skip disk
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(db, f)
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("console fingerprint DB persist failed: %s", exc)


def _touch(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Bump the entry's seen count and last-seen time (setting first-seen once)."""
    now = time.time()
    entry["seen"] = int(entry.get("seen", 0)) + 1
    entry["last"] = now
    entry.setdefault("first", now)
    return entry


def learn_commands(hub, sig: str, commands: List[str], sample: str = "") -> None:
    """Record that ``commands`` are the read-only steps that draw an identity out
    of a device with this signature."""
    # Keep only non-empty string commands; nothing to record without them.
    cmds = [c for c in (commands or []) if isinstance(c, str) and c.strip()]
    if not sig or not cmds:
        return
    # Store the commands (and a first sample), update seen times and save.
    entries = _db(hub)["entries"]
    entry = entries.get(sig) or {}
    entry["commands"] = cmds
    if sample and not entry.get("sample"):
        entry["sample"] = (sample or "")[-_MAX_SAMPLE:]
    entries[sig] = _touch(entry)
    _save(hub)


def learn_identity(hub, sig: str, vendor: Optional[str],
                   identity: Optional[Dict[str, Any]] = None) -> None:
    """Record the resolved vendor/model/OS for this signature so a repeat sighting
    can short-circuit to a known device."""
    # Nothing to record without a signature and some identity.
    if not sig or not (vendor or identity):
        return
    # Store the vendor and merge in the non-empty identity fields, then save.
    entries = _db(hub)["entries"]
    entry = entries.get(sig) or {}
    if vendor:
        entry["vendor"] = vendor
    ident = {k: v for k, v in (identity or {}).items() if v not in (None, "")}
    if ident:
        entry["identity"] = {**(entry.get("identity") or {}), **ident}
    entries[sig] = _touch(entry)
    _save(hub)

