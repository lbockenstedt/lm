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

# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio provides the write lock, debounced flush tasks and off-thread file writes.
import asyncio
# json serialises cache contents.
import hashlib
import json
# Standard-library logging for load/persist warnings.
import logging
# os handles paths, directory creation, permissions and atomic rename.
import os
# time.time() timestamps entries and measures their age.
import time
# Type hints only.
from typing import Any, Callable, Dict, Optional, Set

# Use the hub's main logger so cache warnings appear alongside other hub output.
logger = logging.getLogger("Hub")

# Default timings (seconds): write debounce, then the three staleness thresholds
# (refresh in background, show "cached" badge, treat as expired) described above.
# THE one write-frequency setting for every persisted cache (nw, truenas, certs,
# storage perf, os updates, warm cache): the data lives in memory and a poll
# refills anything a crash loses, so disk is only a warm-start seed.
DEFAULT_FLUSH_DELAY_S = 300.0
DEFAULT_REFRESH_AFTER_S = 30.0
DEFAULT_STALE_AFTER_S = 300.0
DEFAULT_EXPIRE_AFTER_S = 86400.0


# Staleness classes returned by StalenessPolicy.classify(), mildest first.
FRESH = "fresh"
REFRESH = "refresh"
STALE = "stale"
EXPIRED = "expired"
MISSING = "missing"


class _DebouncedFlusher:
    """Shared plumbing of every persisted cache: a loop-aware lazy lock and ONE
    delayed flusher task. Subclasses decide what "dirty" means and what a flush
    writes (``_flush_after_delay``/``_persist``)."""

    _lock: Optional[asyncio.Lock] = None
    _lock_loop: Any = None
    _label = "cache"

    def _get_lock(self) -> asyncio.Lock:
        """A lock bound to the RUNNING loop, created on first use.

        These objects are built in a synchronous ``__init__`` during hub startup,
        before any event loop exists; on Python < 3.10 a lock captured from the
        wrong loop raises "got Future attached to a different loop" the first
        time two writers contend. Binding lazily avoids that."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def _ensure_flusher(self) -> None:
        """Start the delayed flusher unless one is already pending (it will pick the change up)."""
        if any(not t.done() for t in self._tasks):  # type: ignore[attr-defined]
            return
        coro = self._flush_after_delay()  # type: ignore[attr-defined]
        try:
            task = asyncio.create_task(coro)
            self._tasks.add(task)  # type: ignore[attr-defined]
            task.add_done_callback(self._tasks.discard)  # type: ignore[attr-defined]
        except RuntimeError:  # pragma: no cover - no running loop (startup path)
            # Close the coroutine, or Python warns "never awaited" on every startup-path set.
            coro.close()
            logger.debug("%s: skipping async persist (no running loop)", self._label)


class JsonCacheFile(_DebouncedFlusher):
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
        # Remember the configuration.
        self._label = label
        self._path_fn = path_fn
        self._snapshot_fn = snapshot_fn
        self._flush_delay_s = flush_delay_s

        # Lock is created lazily (see _get_lock); _tasks holds the pending flusher.
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Any = None
        self._tasks: Set[asyncio.Task] = set()
        # True when there are changes not yet written.
        self._dirty = False

    def load(self) -> Optional[Dict[str, Any]]:
        """
        Load cache from disk.

        Returns parsed dict or None if file is missing/empty/not a dict.
        Catches all expected exceptions and logs at WARNING.
        Never raises.
        """
        # Kept for the log message if anything fails.
        path = ""
        # Resolve the path; a missing or empty file means "no cache yet".
        try:
            path = self._path_fn()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return None
            # Parse the file; only a dict is a valid cache.
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
        # Unreadable/corrupt file: warn and start empty.
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("%s load failed (%s): %s — starting empty", self._label, path, exc)
            return None

    def schedule_save(self) -> None:
        """
        Schedule a save with debounce.

        Ensures exactly one flusher is pending. If one already exists,
        it will pick up the change.
        """
        # Remember there is something to write.
        self._dirty = True
        self._ensure_flusher()

    async def flush_now(self) -> None:
        """
        Immediately persist, skipping debounce.

        Used during shutdown or forced sync.
        """
        # Clear the dirty flag, then write immediately.
        self._dirty = False
        await self._persist()

    async def _flush_after_delay(self) -> None:
        """Wait the debounce delay, then persist; repeat while new changes arrived meanwhile."""
        # Clear the flag before sleeping so changes made during the wait trigger another round.
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
        # One writer at a time; take the snapshot and write it in a worker thread.
        async with self._get_lock():
            try:
                snapshot = self._snapshot_fn()
                await asyncio.to_thread(self._write, snapshot)
            # Persistence is best-effort: log and carry on.
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("%s persist failed: %s", self._label, exc)

    def _write(self, snapshot: Dict[str, Any]) -> None:
        """
        Write snapshot atomically to disk.

        Creates parent dir, writes to tmp file with json.dump(..., default=str),
        chmod 0o600, then os.replace(tmp, path).
        """
        # Make sure the target directory exists.
        path = self._path_fn()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        # Write to a temp file, lock down permissions, then atomically replace the real file.
        tmp = path + ".tmp"
        # json.dumps uses the C encoder (json.dump streams through the far slower
        # pure-Python one, which held the GIL for seconds on a large cache).
        with open(tmp, "w") as f:
            f.write(json.dumps(snapshot, default=str, separators=(",", ":")))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


class TenantShardCache(_DebouncedFlusher):
    """Debounced persistence of a tenant-keyed cache, one JSON file per tenant.

    Files live at ``<data_dir>/tenants/<tenant>/<module>/<name>`` (the layout
    ``tenant_sharded`` already uses). Like ``JsonCacheFile`` it owns NO data:
    ``resident_fn()`` returns ``{"<tenant>\\x1f<key>": entry}`` at write time.

    A change marks only its tenant dirty, so a flush rewrites that tenant's
    file instead of every tenant's data, and a tenant whose content is
    byte-identical to the last write is skipped.
    """

    # Marker meaning "every tenant" in the dirty set.
    ALL = "\x00all"

    def __init__(self, label: str, data_dir_fn: Callable[[], str], module: str, name: str,
                 resident_fn: Callable[[], Dict[str, Any]], *,
                 flush_delay_s: float = DEFAULT_FLUSH_DELAY_S) -> None:
        """Store the configuration; nothing is read or written yet."""
        self._label = label
        self._data_dir_fn = data_dir_fn
        self._module = module
        self._name = name
        self._resident_fn = resident_fn
        self._flush_delay_s = flush_delay_s
        # Lock is created lazily (see _get_lock); _tasks holds the pending flusher.
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Any = None
        self._tasks: Set[asyncio.Task] = set()
        self._dirty = False
        self._dirty_tenants: Set[str] = set()
        # Tenants written so far (so an emptied tenant's file is removed) and the
        # digest of each tenant's last written content.
        self._written: Set[str] = set()
        self._digest: Dict[str, str] = {}

    def load(self) -> Dict[str, Any]:
        """Merge every tenant's file back into one resident dict (bad files skipped)."""
        import glob
        merged: Dict[str, Any] = {}
        pattern = os.path.join(self._data_dir_fn(), "tenants", "*", self._module, self._name)
        for p in glob.glob(pattern):
            try:
                with open(p, "rb") as f:
                    data = json.loads(f.read().decode() or "{}")
                if isinstance(data, dict):
                    merged.update(data)
                    # Remember tenants with files so an emptied slice removes them.
                    self._written.add(os.path.relpath(p, os.path.join(self._data_dir_fn(), "tenants")).split(os.sep)[0])
            except Exception as exc:  # noqa: BLE001 - a bad file loses one tenant only
                logger.warning("%s: skipped bad shard %s: %s", self._label, p, exc)
        return merged

    def schedule_save(self, tenant: Optional[str] = None) -> None:
        """Mark ``tenant`` (None = every tenant) dirty and ensure one delayed flusher is pending."""
        self._dirty_tenants.add(self.ALL if tenant is None else str(tenant))
        self._dirty = True
        self._ensure_flusher()

    async def _flush_after_delay(self) -> None:
        """Wait the debounce delay and persist; repeat while tenants are still dirty."""
        while self._dirty_tenants:
            await asyncio.sleep(self._flush_delay_s)
            await self._persist()

    async def flush_now(self) -> None:
        """Write every dirty tenant immediately (shutdown path)."""
        await self._persist()

    async def _persist(self) -> None:
        """Write the dirty tenants in a worker thread (best-effort)."""
        async with self._get_lock():
            dirty, self._dirty_tenants = self._dirty_tenants, set()
            self._dirty = False
            try:
                resident = self._resident_fn()
                await asyncio.to_thread(self._write, resident, dirty)
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                self._dirty_tenants |= dirty
                self._dirty = True
                logger.warning("%s persist failed: %s", self._label, exc)

    def _write(self, resident: Dict[str, Any], dirty: Set[str]) -> None:
        """Serialise and atomically replace each dirty tenant's file."""
        data_dir = self._data_dir_fn()
        grouped: Dict[str, Dict[str, Any]] = {}
        for k, v in resident.items():
            t = str(k).split("\x1f", 1)[0]
            if t:
                grouped.setdefault(t, {})[k] = v
        targets = set(grouped) | self._written if self.ALL in dirty else set(dirty)
        for t in sorted(targets):
            path = os.path.join(data_dir, "tenants", t, self._module, self._name)
            slice_ = grouped.get(t)
            if not slice_:
                # Tenant emptied: remove its file so a restart cannot resurrect it.
                if os.path.exists(path):
                    os.remove(path)
                self._written.discard(t)
                self._digest.pop(t, None)
                continue
            # The C encoder (json.dumps) is atomic with respect to other threads.
            blob = json.dumps(slice_, default=str, separators=(",", ":")).encode()
            digest = hashlib.sha1(blob).hexdigest()
            if self._digest.get(t) == digest and os.path.exists(path):
                continue  # identical content already on disk
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            os.replace(tmp, path)
            self._written.add(t)
            self._digest[t] = digest


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
        # Store the three thresholds.
        self.refresh_after_s = refresh_after_s
        self.stale_after_s = stale_after_s
        self.expire_after_s = expire_after_s

    def age(self, fetched_at: Optional[float], now: Optional[float] = None) -> Optional[float]:
        """
        Compute the age of data in seconds.

        Returns None if fetched_at is invalid.
        Clamps at 0.0 to prevent negative ages from clock skew.
        """
        # No (or a non-numeric) timestamp means we cannot tell the age.
        if not fetched_at or not isinstance(fetched_at, (int, float)):
            return None
        # Default to the current time.
        if now is None:
            now = time.time()
        # Clamp to zero in case of clock skew.
        return max(0.0, now - fetched_at)

    def classify(self, fetched_at: Optional[float], now: Optional[float] = None) -> str:
        """
        Classify the staleness of data.

        Returns one of FRESH, REFRESH, STALE, EXPIRED, MISSING.
        Checked in order of severity.
        """
        # Age of the data.
        a = self.age(fetched_at, now)
        # Check from most to least severe.
        if a is None:
            return MISSING
        if a > self.expire_after_s:
            return EXPIRED
        if a > self.stale_after_s:
            return STALE
        if a > self.refresh_after_s:
            return REFRESH
        return FRESH

    def is_stale(self, fetched_at, now=None) -> bool:
        """
        Is data stale (should be shown with badge)?

        True for STALE and EXPIRED.
        """
        # STALE and EXPIRED both show the "cached data" badge.
        c = self.classify(fetched_at, now)
        return c in (STALE, EXPIRED)


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

# File format markers (see the layout above) and the file extension.
CACHE_FILE_MAGIC = b"LMC1"
CACHE_MODE_ENCRYPTED = b"E"
CACHE_MODE_PLAIN = b"Z"
CACHE_FILE_SUFFIX = ".bin"


def _ns_filename(ns: str) -> str:
    """Filesystem-safe file name for a namespace. Normal names
    (letters/digits/``_.-``) map to themselves so the directory is readable by
    a human; anything else is hashed (the real name is stored inside)."""
    # Imported lazily; only needed when naming files.
    import hashlib
    import re
    # Safe, non-hidden names are used as-is so the directory stays human-readable.
    if re.fullmatch(r"[A-Za-z0-9_.\-]{1,100}", ns or "") and not ns.startswith("."):
        return ns + CACHE_FILE_SUFFIX
    # Anything else is hashed into a safe name.
    return "ns-" + hashlib.sha1((ns or "").encode()).hexdigest() + CACHE_FILE_SUFFIX


class ShardedCacheFile(_DebouncedFlusher):
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
        """Store the configuration; see the class docstring for the parameters."""
        # Remember the configuration and encryption hooks.
        self._label = label
        self._dir_fn = dir_fn
        self._snapshot_fn = snapshot_fn
        self.encrypt = encrypt
        self.decrypt = decrypt
        self._flush_delay_s = flush_delay_s
        # Lock is created lazily (see _get_lock); _tasks holds the pending flusher.
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Any = None
        self._tasks: Set[asyncio.Task] = set()
        self._dirty = False            # any namespace pending (kept for tests/compat)
        # Namespaces with changes not yet written.
        self._dirty_ns: Set[str] = set()
        self._last_digest: Dict[str, str] = {}   # ns → sha256 of last written zlib bytes
        # Per-namespace write time and file size, for status display.
        self.last_write_at: Dict[str, float] = {}
        self.last_size: Dict[str, int] = {}

    # ── encode / decode (pure, synchronous, unit-testable) ────────────────────

    def encode(self, ns: str, entries: Dict[str, Any]) -> tuple:
        """``(file_bytes, digest)`` for one namespace. Raises if encryption is
        configured and fails (caller must then NOT write)."""
        # Imported lazily: hashing and compression.
        import hashlib
        import zlib
        # Serialise compactly with the namespace name inside the payload.
        raw = json.dumps({"ns": ns, "entries": entries}, default=str,
                         separators=(",", ":")).encode()
        # Compress, and fingerprint the compressed bytes to detect unchanged content.
        packed = zlib.compress(raw, 6)
        digest = hashlib.sha256(packed).hexdigest()
        # Encrypted mode when an encrypt function is configured (it raises on failure).
        if self.encrypt is not None:
            return CACHE_FILE_MAGIC + CACHE_MODE_ENCRYPTED + self.encrypt(packed), digest
        # Otherwise plain (compressed, unencrypted) mode, for tests/dev.
        return CACHE_FILE_MAGIC + CACHE_MODE_PLAIN + packed, digest

    def decode(self, blob: bytes) -> tuple:
        """``(ns, entries)`` from file bytes. Raises ``ValueError`` on any
        format problem (wrong magic/mode, missing key, bad payload)."""
        # Imported lazily: decompression.
        import zlib
        # Check the magic header.
        if not blob.startswith(CACHE_FILE_MAGIC) or len(blob) < 5:
            raise ValueError("not a hub cache file (bad magic/version)")
        # Split the mode byte from the body.
        mode, body = blob[4:5], blob[5:]
        # Encrypted files need the decrypt function.
        if mode == CACHE_MODE_ENCRYPTED:
            if self.decrypt is None:
                raise ValueError("file is encrypted but no decrypt key is configured")
            body = self.decrypt(body)
        # Anything other than the two known modes is rejected.
        elif mode != CACHE_MODE_PLAIN:
            raise ValueError("unknown cache file mode %r" % mode)
        # Decompress and parse, then check the payload shape.
        doc = json.loads(zlib.decompress(body).decode())
        if not isinstance(doc, dict) or not isinstance(doc.get("entries"), dict):
            raise ValueError("cache file payload is not {ns, entries}")
        # Return the namespace name and its entries.
        return str(doc.get("ns") or ""), doc["entries"]

    # ── load ──────────────────────────────────────────────────────────────────

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        """Read every ``*.bin`` in the directory → ``{ns: entries}``.
        Unreadable files are skipped (logged), never fatal."""
        # Result and directory (kept for the log message).
        out: Dict[str, Dict[str, Any]] = {}
        d = ""
        # List the directory; a missing directory just means an empty cache.
        try:
            d = self._dir_fn()
            names = sorted(os.listdir(d)) if os.path.isdir(d) else []
        # Cannot read the directory: warn and start empty.
        except OSError as exc:
            logger.warning("%s: cannot list %s: %s — starting empty", self._label, d, exc)
            return out
        # Read each cache file.
        for name in names:
            # Ignore unrelated files.
            if not name.endswith(CACHE_FILE_SUFFIX):
                continue
            path = os.path.join(d, name)
            # Decode the file; it must name its namespace.
            try:
                with open(path, "rb") as f:
                    ns, entries = self.decode(f.read())
                if not ns:
                    raise ValueError("missing namespace name")
                # Keep its entries and remember its size.
                out[ns] = entries
                self.last_size[ns] = os.path.getsize(path)
            # A bad file is skipped so the others still load.
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the rest
                logger.warning("%s: ignoring unreadable %s: %s", self._label, path, exc)
        return out

    # ── save ──────────────────────────────────────────────────────────────────

    def schedule_save(self, ns: Optional[str] = None) -> None:
        """Mark ``ns`` (or, if None, nothing new) dirty and ensure exactly one
        delayed flusher is pending — a refresh burst becomes one write per
        namespace, not one per set."""
        # Mark this namespace dirty.
        if ns is not None:
            self._dirty_ns.add(ns)
        self._dirty = bool(self._dirty_ns)
        self._ensure_flusher()

    async def _flush_after_delay(self) -> None:
        """Wait the debounce delay and persist; repeat while namespaces are still dirty."""
        while self._dirty_ns:
            await asyncio.sleep(self._flush_delay_s)
            await self._persist()

    async def flush_now(self) -> None:
        """Write every dirty namespace immediately (shutdown path)."""
        # Write all dirty namespaces without waiting.
        await self._persist()

    async def _persist(self) -> None:
        """Write every dirty namespace; ones changed mid-write are re-queued for the next flush."""
        # One writer at a time; take ownership of the dirty set.
        async with self._get_lock():
            pending, self._dirty_ns = self._dirty_ns, set()
            self._dirty = False
            # Write each namespace's snapshot in a worker thread.
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
                # Any other failure is logged; persistence is best-effort.
                except Exception as exc:  # noqa: BLE001 - best-effort persist
                    logger.warning("%s: persist %s failed: %s", self._label, ns, exc)

    def write_all_sync(self, namespaces) -> None:
        """Synchronous write of the given namespaces (startup migration only,
        before an event loop exists)."""
        # Write each namespace directly; failures are logged and skipped.
        for ns in namespaces:
            try:
                self._write_ns(ns, self._snapshot_fn(ns))
            except Exception as exc:  # noqa: BLE001
                logger.warning("%s: persist %s failed: %s", self._label, ns, exc)

    def _write_ns(self, ns: str, entries: Dict[str, Any]) -> None:
        """Write one namespace's file atomically (or delete it if the namespace is empty)."""
        # Target file path.
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
        # Encode (and encrypt) the entries.
        blob, digest = self.encode(ns, entries)
        if self._last_digest.get(ns) == digest and os.path.exists(path):
            return  # identical content already on disk
        # Make sure the owner-only directory exists.
        os.makedirs(d, mode=0o700, exist_ok=True)
        # Write to an owner-only temp file, then atomically replace the real file.
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        # Remember what was written, when, and how big.
        self._last_digest[ns] = digest
        self.last_write_at[ns] = time.time()
        self.last_size[ns] = len(blob)
