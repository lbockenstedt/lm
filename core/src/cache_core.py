"""The ONE shared cache implementation: atomic JSON persistence + staleness timers.

``nw_cache``, ``truenas_cache``, ``le_cache`` and ``warm_cache`` each grew their
own copy of the same "keep the last spoke answer, serve it when the spoke is
down, persist it so a hub restart isn't a cold start" logic. Four copies drifted:
two debounce their writes and two re-serialize the whole file on every single
set; only the console page ever aged its entries out. This module is the single
implementation they delegate to, so "this needs to be cached" means one
behaviour everywhere instead of whichever copy was pasted.

THE THREE THRESHOLDS ARE SEPARATE ON PURPOSE. One timer cannot express the rule
we actually want, which is "a brief outage must not become a user-visible
error":

  * ``refresh_after_s`` (30s)  — old enough to revalidate in the BACKGROUND. The
    reader still gets the cached value immediately; nothing is blocked.
  * ``stale_after_s`` (300s)   — old enough to admit it (data under 5 minutes
    old is shown as if live, with no badge). Still served, now with
    the "cached data" badge. This is the window that covers a spoke restarting
    during a hub/agent update: it is offline for less than this, so the
    Hypervisor/Diagnostics pages keep rendering last-known data instead of
    replacing the page with "Timed out waiting for spoke response".
  * ``expire_after_s`` (24h)   — old enough that serving it would be a lie. This
    is the ONLY state permitted to surface an error, because only now is the
    error the honest answer rather than an artifact of a 20-second restart.

CACHE THE RAW ENVELOPE, NEVER THE FILTERED VIEW. Every value stored here must be
the raw pre-tenant-filter spoke envelope, so each reader's tenant/subnet filter
is re-applied from that raw on every read. Caching a filtered result would let
whoever warmed the entry decide what the NEXT reader sees — i.e. hand one
tenant another tenant's rows.

A leaf: stdlib only. MUST NOT import ``main`` or ``api`` (dependency direction is
``main → cache_core`` only). Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional, Set

logger = logging.getLogger("Hub")

DEFAULT_FLUSH_DELAY_S = 5.0
DEFAULT_REFRESH_AFTER_S = 30.0
DEFAULT_STALE_AFTER_S = 300.0
DEFAULT_EXPIRE_AFTER_S = 86400.0


FRESH = "fresh"
REFRESH = "refresh"
STALE = "stale"
EXPIRED = "expired"
MISSING = "missing"


class JsonCacheFile:
    """
    Manages atomic JSON persistence of cache data.

    Owns NO cache data; it only persists whatever the owner hands it.
    """

    def __init__(
        self,
        label: str,
        path_fn: Callable[[], str],
        snapshot_fn: Callable[[], Dict[str, Any]],
        *,
        flush_delay_s: float = DEFAULT_FLUSH_DELAY_S
    ) -> None:
        """
        Initialize a JsonCacheFile.

        :param label: Used in log messages (e.g. "nw cache")
        :param path_fn: Callable returning the absolute file path (deferred)
        :param snapshot_fn: Callable returning dict to serialize at write time
        :param flush_delay_s: Debounce delay for writes
        """
        self._label = label
        self._path_fn = path_fn
        self._snapshot_fn = snapshot_fn
        self._flush_delay_s = flush_delay_s

        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Any = None
        self._tasks: Set[asyncio.Task] = set()
        self._dirty = False

    def _get_lock(self) -> asyncio.Lock:
        """A lock bound to the RUNNING loop, created on first use.

        These cache objects are constructed in a synchronous ``__init__`` during
        hub startup — before any event loop exists. On Python < 3.10
        ``asyncio.Lock()`` captures a loop at construction time, and a lock
        captured from the wrong loop raises "got Future attached to a different
        loop" the first time two writers genuinely contend. That is exactly the
        poll-burst case this class exists to serialize, so it would fail only
        under load. Binding lazily keeps the behaviour identical across
        interpreter versions.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def load(self) -> Optional[Dict[str, Any]]:
        """
        Load cache from disk.

        Returns parsed dict or None if file is missing/empty/not a dict.
        Catches all expected exceptions and logs at WARNING.
        Never raises.
        """
        path = ""
        try:
            path = self._path_fn()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return None
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("%s load failed (%s): %s — starting empty", self._label, path, exc)
            return None

    def schedule_save(self) -> None:
        """
        Schedule a save with debounce.

        Ensures exactly one flusher is pending. If one already exists,
        it will pick up the change.
        """
        self._dirty = True
        if any(not t.done() for t in self._tasks):
            return  # a flusher is already pending — it will pick this up

        coro = self._flush_after_delay()
        try:
            task = asyncio.create_task(coro)
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (startup path)
            # Close the coroutine we just built, or Python warns "coroutine was
            # never awaited" on every startup-path set.
            coro.close()
            logger.debug("%s: skipping async persist (no running loop)", self._label)

    async def flush_now(self) -> None:
        """
        Immediately persist, skipping debounce.

        Used during shutdown or forced sync.
        """
        self._dirty = False
        await self._persist()

    async def _flush_after_delay(self) -> None:
        while self._dirty:
            self._dirty = False
            await asyncio.sleep(self._flush_delay_s)
            await self._persist()

    async def _persist(self) -> None:
        """
        Persist the current snapshot to disk.

        Locks, calls snapshot_fn(), writes via asyncio.to_thread.
        Logs WARNING on failure (best-effort).
        """
        async with self._get_lock():
            try:
                snapshot = self._snapshot_fn()
                await asyncio.to_thread(self._write, snapshot)
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("%s persist failed: %s", self._label, exc)

    def _write(self, snapshot: Dict[str, Any]) -> None:
        """
        Write snapshot atomically to disk.

        Creates parent dir, writes to tmp file with json.dump(..., default=str),
        chmod 0o600, then os.replace(tmp, path).
        """
        path = self._path_fn()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


class StalenessPolicy:
    """
    Pure staleness classifier for cached data.

    Fully synchronous and testable. No I/O.
    """

    def __init__(
        self,
        *,
        refresh_after_s: float = DEFAULT_REFRESH_AFTER_S,
        stale_after_s: float = DEFAULT_STALE_AFTER_S,
        expire_after_s: float = DEFAULT_EXPIRE_AFTER_S
    ) -> None:
        """
        Initialize a staleness policy.

        :param refresh_after_s: Age after which data should be refreshed in background
        :param stale_after_s: Age after which data is "cached" but still usable
        :param expire_after_s: Age after which data is no longer trustworthy
        """
        self.refresh_after_s = refresh_after_s
        self.stale_after_s = stale_after_s
        self.expire_after_s = expire_after_s

    def age(self, fetched_at: Optional[float], now: Optional[float] = None) -> Optional[float]:
        """
        Compute the age of data in seconds.

        Returns None if fetched_at is invalid.
        Clamps at 0.0 to prevent negative ages from clock skew.
        """
        if not fetched_at or not isinstance(fetched_at, (int, float)):
            return None
        if now is None:
            now = time.time()
        return max(0.0, now - fetched_at)

    def classify(self, fetched_at: Optional[float], now: Optional[float] = None) -> str:
        """
        Classify the staleness of data.

        Returns one of FRESH, REFRESH, STALE, EXPIRED, MISSING.
        Checked in order of severity.
        """
        a = self.age(fetched_at, now)
        if a is None:
            return MISSING
        if a > self.expire_after_s:
            return EXPIRED
        if a > self.stale_after_s:
            return STALE
        if a > self.refresh_after_s:
            return REFRESH
        return FRESH

    def should_refresh(self, fetched_at, now=None) -> bool:
        """
        Should data be refreshed in background?

        True for MISSING, REFRESH, STALE and EXPIRED.
        """
        return self.classify(fetched_at, now) != FRESH

    def is_stale(self, fetched_at, now=None) -> bool:
        """
        Is data stale (should be shown with badge)?

        True for STALE and EXPIRED.
        """
        c = self.classify(fetched_at, now)
        return c in (STALE, EXPIRED)

    def is_expired(self, fetched_at, now=None) -> bool:
        """
        Is data expired (should surface an error)?

        True only for EXPIRED.
        """
        return self.classify(fetched_at, now) == EXPIRED

    def is_usable(self, fetched_at, now=None) -> bool:
        """
        Is data still usable?

        True for anything except MISSING and EXPIRED.
        """
        c = self.classify(fetched_at, now)
        return c not in (MISSING, EXPIRED)


# ─────────────────────────────────────────────────────────────────────────────
# Per-namespace, compressed, encrypted cache files (the hub data cache)
# ─────────────────────────────────────────────────────────────────────────────
#
# WHY A DIFFERENT FILE FORMAT FROM ``JsonCacheFile``:
#   The hub data cache (``warm_cache``) now holds every page's data for every
#   tenant — NetBox devices/IPs, NAC endpoints, firewall rules, VMs. That is
#   (a) tenant data at rest, so it is ENCRYPTED with the hub's Fernet key, the
#   same key that protects system.json; and (b) large and repetitive JSON, so
#   it is zlib-COMPRESSED first (typically 5–10x smaller, and encrypting
#   compressed bytes is cheaper than encrypting raw JSON).
#
# WHY ONE FILE PER NAMESPACE (not one big file, not one per tenant):
#   One namespace = one kind of data (e.g. ``nb_netbox_devices``). A refresh
#   normally touches one namespace, so only that file is rewritten instead of
#   re-encrypting the whole cache. A corrupt/unreadable file loses one kind of
#   data, not everything. Shared device data (a firewall seen by several
#   tenants) is stored once, not copied per tenant.
#
# FILE LAYOUT  (``<dir>/<namespace>.bin``):
#     4 bytes   magic  b"LMC1"   — format + version. Anything else is ignored.
#     1 byte    mode   b"E"      — Fernet(zlib(json))   (production)
#                      b"Z"      — zlib(json), NOT encrypted (tests/dev only,
#                                  used only when no encrypt function is given)
#     rest      body
#   json = {"ns": <namespace>, "entries": {key: entry}}
#
# SAFETY RULES:
#   * A file that fails ANY check (magic, mode, decrypt, decompress, json) is
#     skipped with a warning — the cache starts that namespace empty and the
#     refresher refills it. It never crashes the hub.
#   * If encryption is configured but fails, the file is NOT written at all —
#     tenant data is never silently downgraded to plaintext.
#   * Writes are atomic (tmp file + rename) and owner-only (0600).
#   * A namespace whose compressed content is byte-identical to the last write
#     is skipped (no pointless re-encrypt + disk write every refresh).

CACHE_FILE_MAGIC = b"LMC1"
CACHE_MODE_ENCRYPTED = b"E"
CACHE_MODE_PLAIN = b"Z"
CACHE_FILE_SUFFIX = ".bin"


def _ns_filename(ns: str) -> str:
    """Filesystem-safe file name for a namespace. Normal names
    (letters/digits/``_.-``) map to themselves so the directory is readable by
    a human; anything else is hashed (the real name is stored inside)."""
    import hashlib
    import re
    if re.fullmatch(r"[A-Za-z0-9_.\-]{1,100}", ns or "") and not ns.startswith("."):
        return ns + CACHE_FILE_SUFFIX
    return "ns-" + hashlib.sha1((ns or "").encode()).hexdigest() + CACHE_FILE_SUFFIX


class ShardedCacheFile:
    """Debounced, per-namespace persistence for the hub data cache.

    Like ``JsonCacheFile`` it owns NO data: ``snapshot_fn(ns)`` returns the
    current ``{key: entry}`` dict for one namespace at write time.

    :param label:        log label (e.g. ``"hub cache"``)
    :param dir_fn:       returns the directory holding the ``.bin`` files
    :param snapshot_fn:  ``ns -> dict`` of entries (empty dict → delete file)
    :param encrypt:      ``bytes -> bytes`` (Fernet) or None for plaintext
    :param decrypt:      ``bytes -> bytes`` inverse of ``encrypt``
    """

    def __init__(self, label: str, dir_fn: Callable[[], str],
                 snapshot_fn: Callable[[str], Dict[str, Any]], *,
                 encrypt: Optional[Callable[[bytes], bytes]] = None,
                 decrypt: Optional[Callable[[bytes], bytes]] = None,
                 flush_delay_s: float = DEFAULT_FLUSH_DELAY_S) -> None:
        self._label = label
        self._dir_fn = dir_fn
        self._snapshot_fn = snapshot_fn
        self.encrypt = encrypt
        self.decrypt = decrypt
        self._flush_delay_s = flush_delay_s
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Any = None
        self._tasks: Set[asyncio.Task] = set()
        self._dirty = False            # any namespace pending (kept for tests/compat)
        self._dirty_ns: Set[str] = set()
        self._last_digest: Dict[str, str] = {}   # ns → sha256 of last written zlib bytes
        self.last_write_at: Dict[str, float] = {}
        self.last_size: Dict[str, int] = {}

    _get_lock = JsonCacheFile._get_lock

    # ── encode / decode (pure, synchronous, unit-testable) ────────────────────

    def encode(self, ns: str, entries: Dict[str, Any]) -> tuple:
        """``(file_bytes, digest)`` for one namespace. Raises if encryption is
        configured and fails (caller must then NOT write)."""
        import hashlib
        import zlib
        raw = json.dumps({"ns": ns, "entries": entries}, default=str,
                         separators=(",", ":")).encode()
        packed = zlib.compress(raw, 6)
        digest = hashlib.sha256(packed).hexdigest()
        if self.encrypt is not None:
            return CACHE_FILE_MAGIC + CACHE_MODE_ENCRYPTED + self.encrypt(packed), digest
        return CACHE_FILE_MAGIC + CACHE_MODE_PLAIN + packed, digest

    def decode(self, blob: bytes) -> tuple:
        """``(ns, entries)`` from file bytes. Raises ``ValueError`` on any
        format problem (wrong magic/mode, missing key, bad payload)."""
        import zlib
        if not blob.startswith(CACHE_FILE_MAGIC) or len(blob) < 5:
            raise ValueError("not a hub cache file (bad magic/version)")
        mode, body = blob[4:5], blob[5:]
        if mode == CACHE_MODE_ENCRYPTED:
            if self.decrypt is None:
                raise ValueError("file is encrypted but no decrypt key is configured")
            body = self.decrypt(body)
        elif mode != CACHE_MODE_PLAIN:
            raise ValueError("unknown cache file mode %r" % mode)
        doc = json.loads(zlib.decompress(body).decode())
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), dict):
            raise ValueError("cache file payload is not {ns, entries}")
        return str(doc.get("ns") or ""), doc["entries"]

    # ── load ──────────────────────────────────────────────────────────────────

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        """Read every ``*.bin`` in the directory → ``{ns: entries}``.
        Unreadable files are skipped (logged), never fatal."""
        out: Dict[str, Dict[str, Any]] = {}
        d = ""
        try:
            d = self._dir_fn()
            names = sorted(os.listdir(d)) if os.path.isdir(d) else []
        except OSError as exc:
            logger.warning("%s: cannot list %s: %s — starting empty", self._label, d, exc)
            return out
        for name in names:
            if not name.endswith(CACHE_FILE_SUFFIX):
                continue
            path = os.path.join(d, name)
            try:
                with open(path, "rb") as f:
                    ns, entries = self.decode(f.read())
                if not ns:
                    raise ValueError("missing namespace name")
                out[ns] = entries
                self.last_size[ns] = os.path.getsize(path)
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the rest
                logger.warning("%s: ignoring unreadable %s: %s", self._label, path, exc)
        return out

    # ── save ──────────────────────────────────────────────────────────────────

    def schedule_save(self, ns: Optional[str] = None) -> None:
        """Mark ``ns`` (or, if None, nothing new) dirty and ensure exactly one
        delayed flusher is pending — a refresh burst becomes one write per
        namespace, not one per set."""
        if ns is not None:
            self._dirty_ns.add(ns)
        self._dirty = bool(self._dirty_ns)
        if any(not t.done() for t in self._tasks):
            return
        coro = self._flush_after_delay()
        try:
            task = asyncio.create_task(coro)
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (startup path)
            coro.close()

    async def _flush_after_delay(self) -> None:
        while self._dirty_ns:
            await asyncio.sleep(self._flush_delay_s)
            await self._persist()

    async def flush_now(self) -> None:
        """Write every dirty namespace immediately (shutdown path)."""
        await self._persist()

    async def _persist(self) -> None:
        async with self._get_lock():
            pending, self._dirty_ns = self._dirty_ns, set()
            self._dirty = False
            for ns in sorted(pending):
                try:
                    snap = self._snapshot_fn(ns)
                    await asyncio.to_thread(self._write_ns, ns, snap)
                except RuntimeError as exc:
                    # "dict changed size during iteration": a refresh mutated
                    # the namespace mid-serialize. Retry on the next flush.
                    self._dirty_ns.add(ns)
                    self._dirty = True
                    logger.debug("%s: %s busy (%s) — will retry", self._label, ns, exc)
                except Exception as exc:  # noqa: BLE001 - best-effort persist
                    logger.warning("%s: persist %s failed: %s", self._label, ns, exc)

    def write_all_sync(self, namespaces) -> None:
        """Synchronous write of the given namespaces (startup migration only,
        before an event loop exists)."""
        for ns in namespaces:
            try:
                self._write_ns(ns, self._snapshot_fn(ns))
            except Exception as exc:  # noqa: BLE001
                logger.warning("%s: persist %s failed: %s", self._label, ns, exc)

    def _write_ns(self, ns: str, entries: Dict[str, Any]) -> None:
        d = self._dir_fn()
        path = os.path.join(d, _ns_filename(ns))
        if not entries:
            # Namespace emptied (purge/drop) → remove its file so a restart
            # doesn't resurrect purged data.
            if os.path.exists(path):
                os.remove(path)
            self._last_digest.pop(ns, None)
            self.last_size.pop(ns, None)
            return
        blob, digest = self.encode(ns, entries)
        if self._last_digest.get(ns) == digest and os.path.exists(path):
            return  # identical content already on disk
        os.makedirs(d, mode=0o700, exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        self._last_digest[ns] = digest
        self.last_write_at[ns] = time.time()
        self.last_size[ns] = len(blob)
