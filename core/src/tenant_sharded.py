"""Per-tenant / per-module JSON sharding helpers.

The hub keeps derived dashboard/telemetry state in module-global JSON files keyed
INTERNALLY by tenant (e.g. ``check_health_history.json`` = ``{tenant\\x1fsite\\x1fcheck:
…}``). That means every save rewrites ALL tenants' data every poll cycle, one
corrupt file loses every tenant, and a tenant delete is a dict-filter not a file
unlink. These helpers shard such a store into one file per ``(tenant, module,
store-name)`` under ``<data_dir>/tenants/<tenant>/<module>/<name>``:

  - writes touch only the tenants that changed (``dirty`` set),
  - a corrupt file loses one tenant, not the fleet,
  - ``forget(tenant)`` / corruption-recovery reset is an ``unlink`` / ``rmtree``.

The resident in-memory dict and the store's public API are UNCHANGED — only its
``_persist``/``_load``/``forget`` route through here. Stdlib-only + best-effort:
every function swallows its own I/O errors (never raise into a poll loop) and the
in-memory dict stays the source of truth. ``encrypt``/``decrypt`` hooks let the
Fernet-encrypted stores (simulations_cache, central_hub_status) reuse this.

See lm/docs (persistence) + the plan; INVARIANT: only DERIVED/cache data is
sharded here — config/identity (state.json, simulations_store.json, sessions)
stays at the data_dir root and is never touched by shard_* or the reset.
"""
from __future__ import annotations

# glob finds shards; json/os handle the files; logging; type hints.
import glob
import json
import logging
import os
from typing import Any, Callable, Dict, Iterable, Optional

# Module logger.
logger = logging.getLogger("TenantSharded")

# Separator used in composite store keys.
_KEYSEP = "\x1f"  # matches simulations/central_hub_poller._CC_KEYSEP


def _tenant_of_composite(key: str) -> str:
    """Tenant = the first ``\\x1f``-separated field of a composite store key."""
    # First field of the key.
    return str(key).split(_KEYSEP, 1)[0]


def tenants_root(data_dir: str) -> str:
    """Return the root directory that holds every tenant's shards."""
    # <data_dir>/tenants.
    return os.path.join(data_dir, "tenants")


def shard_dir(data_dir: str, tenant: str, module: str) -> str:
    """Return (creating if needed) the shard directory for tenant and module."""
    # <root>/<tenant>/<module>, created on demand.
    d = os.path.join(tenants_root(data_dir), str(tenant), module)
    os.makedirs(d, exist_ok=True)
    return d


def shard_path(data_dir: str, tenant: str, module: str, name: str) -> str:
    """Return the shard file path for tenant, module and store name."""
    # Join the directory and file name.
    return os.path.join(shard_dir(data_dir, tenant, module), name)


def group_by_tenant(resident: Dict[str, Any],
                    tenant_of: Optional[Callable[[str], str]] = None
                    ) -> Dict[str, Dict[str, Any]]:
    """Split a resident store dict into ``{tenant: {key: value}}``.

    Default grouper treats the first ``\\x1f`` field of the key as the tenant
    (composite-keyed stores). Pass ``tenant_of`` for stores keyed directly by
    tenant (identity) or by something else (e.g. spoke_id → tenant resolver)."""
    # Grouping function: the given one, or the composite-key default.
    tof = tenant_of or _tenant_of_composite
    out: Dict[str, Dict[str, Any]] = {}
    # Bucket each entry by tenant, skipping keys that fail or have no tenant.
    for k, v in resident.items():
        try:
            t = tof(k)
        except Exception:  # noqa: BLE001
            continue
        if not t:
            continue
        out.setdefault(str(t), {})[k] = v
    return out


def _atomic_write_bytes(path: str, blob: bytes) -> None:
    """Write blob to path atomically: temp file, fsync, then rename."""
    # Write and fsync a temp file.
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    # Rename over the target.
    os.replace(tmp, path)


def shard_save(data_dir: str, module: str, name: str, resident: Dict[str, Any],
               *, tenant_of: Optional[Callable[[str], str]] = None,
               dirty: Optional[Iterable[str]] = None,
               encrypt: Optional[Callable[[str], bytes]] = None) -> None:
    """Persist ``resident`` sharded per tenant. Only tenants in ``dirty`` are
    rewritten (pass ``None`` to write all). A tenant whose slice became empty has
    its file removed. ``encrypt(json_str)->bytes`` mirrors the store's at-rest
    encryption; without it a plain UTF-8 JSON file is written."""
    # Group by tenant; write only dirty tenants (all if dirty is None).
    grouped = group_by_tenant(resident, tenant_of)
    targets = set(str(t) for t in dirty) if dirty is not None else set(grouped.keys())
    # A dirty tenant that no longer has any keys → delete its shard file.
    for t in targets:
        # Shard path and this tenant's data.
        p = shard_path(data_dir, t, module, name)
        slice_ = grouped.get(t)
        # Write or delete the shard; failures are logged.
        try:
            # No data: remove the shard file.
            if not slice_:
                if os.path.exists(p):
                    os.remove(p)
                continue
            # Serialise, optionally encrypt, and write atomically.
            payload = json.dumps(slice_, default=str)
            blob = encrypt(payload) if encrypt else payload.encode("utf-8")
            _atomic_write_bytes(p, blob)
        except Exception as e:  # noqa: BLE001 — persistence is best-effort
            logger.warning("shard_save %s/%s/%s failed: %s", t, module, name, e)


def shard_load(data_dir: str, module: str, name: str,
               *, decrypt: Optional[Callable[[bytes], str]] = None
               ) -> Dict[str, Any]:
    """Merge every ``tenants/*/<module>/<name>`` shard back into one dict.
    A corrupt/undecryptable shard is skipped (that tenant starts empty), not
    fatal."""
    # Merged result and the glob for every tenant's shard.
    merged: Dict[str, Any] = {}
    pattern = os.path.join(tenants_root(data_dir), "*", module, name)
    # Read each shard; a bad one is logged and skipped.
    for p in glob.glob(pattern):
        try:
            with open(p, "rb") as f:
                blob = f.read()
            # Empty file: skip.
            if not blob:
                continue
            # Decode (decrypting if needed), parse, and merge dicts.
            text = decrypt(blob) if decrypt else blob.decode("utf-8")
            data = json.loads(text) or {}
            if isinstance(data, dict):
                merged.update(data)
        except Exception as e:  # noqa: BLE001 — one bad shard must not break load
            logger.warning("shard_load skipped bad shard %s: %s", p, e)
    return merged


def migrate_legacy(data_dir: str, module: str, name: str,
                   *, legacy_path: Optional[str] = None,
                   tenant_of: Optional[Callable[[str], str]] = None,
                   encrypt: Optional[Callable[[str], bytes]] = None,
                   decrypt: Optional[Callable[[bytes], str]] = None) -> bool:
    """One-time split of a legacy module-global file into per-tenant shards.

    Reads ``<data_dir>/<name>`` (or ``legacy_path``), groups by tenant, writes the
    shards, and renames the legacy file to ``<name>.migrated`` so a rollback still
    has the original. No-op (returns False) when the legacy file is absent or the
    shard tree already exists. Best-effort; never raises."""
    # Legacy file path; everything below is best-effort.
    legacy = legacy_path or os.path.join(data_dir, name)
    try:
        # No legacy file: nothing to migrate.
        if not os.path.exists(legacy):
            return False
        # If shards already exist, assume a prior migration ran — don't clobber.
        if glob.glob(os.path.join(tenants_root(data_dir), "*", module, name)):
            return False
        # Read the legacy file.
        with open(legacy, "rb") as f:
            blob = f.read()
        # Non-empty: decode, parse, and write the shards.
        if blob:
            text = decrypt(blob) if decrypt else blob.decode("utf-8")
            data = json.loads(text) or {}
            if isinstance(data, dict) and data:
                shard_save(data_dir, module, name, data,
                           tenant_of=tenant_of, dirty=None, encrypt=encrypt)
        # Keep the original as .migrated and report success.
        os.replace(legacy, legacy + ".migrated")
        logger.info("migrate_legacy: split %s into tenants/*/%s/%s", name, module, name)
        return True
    # Failure: log and leave the legacy file in place.
    except Exception as e:  # noqa: BLE001
        logger.warning("migrate_legacy %s failed (leaving legacy in place): %s", name, e)
        return False


# ── whole-file snapshot (non-sharded, module-global warm-start caches) ───────
def snapshot_save(path: str, obj: Any, *,
                  encrypt: Optional[Callable[[str], bytes]] = None) -> None:
    """Atomic whole-file JSON snapshot for a module-GLOBAL (not per-tenant) cache
    — the warm-start analog of shard_save for stores that aren't tenant-keyed
    (e.g. the aggregated agents list, cert device reports). Best-effort."""
    # Make the directory, serialise, optionally encrypt, and write atomically.
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = json.dumps(obj, default=str)
        blob = encrypt(payload) if encrypt else payload.encode("utf-8")
        _atomic_write_bytes(path, blob)
    # Failure: log only.
    except Exception as e:  # noqa: BLE001
        logger.warning("snapshot_save %s failed: %s", path, e)


def snapshot_load(path: str, *, decrypt: Optional[Callable[[bytes], str]] = None,
                  default: Any = None) -> Any:
    """Restore a whole-file snapshot written by snapshot_save. Returns ``default``
    on absent/empty/corrupt file (never raises)."""
    # Missing or empty file gives the default.
    try:
        if not os.path.exists(path):
            return default
        with open(path, "rb") as f:
            blob = f.read()
        if not blob:
            return default
        # Decode (decrypting if needed) and parse.
        text = decrypt(blob) if decrypt else blob.decode("utf-8")
        return json.loads(text)
    # Failure: log and return the default.
    except Exception as e:  # noqa: BLE001
        logger.warning("snapshot_load %s failed: %s", path, e)
        return default


# ── corruption-recovery reset (Part 2) ──────────────────────────────────────
def reset_tenant_files(data_dir: str, tenant: str) -> int:
    """Delete ALL sharded derived files for one tenant (every module). Returns the
    count removed. Only touches ``tenants/<tenant>/`` — never the data_dir-root
    config/identity files."""
    # Local shutil import; the tenant's directory.
    import shutil
    d = os.path.join(tenants_root(data_dir), str(tenant))
    # Nothing to delete.
    if not os.path.isdir(d):
        return 0
    # Count the files, then delete the tree.
    n = sum(len(files) for _, _, files in os.walk(d))
    shutil.rmtree(d, ignore_errors=True)
    return n


def reset_all_tenant_files(data_dir: str) -> int:
    """Delete the whole ``tenants/`` derived subtree (all tenants, all modules).
    Never touches data_dir-root config/identity files."""
    # Local shutil import; the tenants root.
    import shutil
    root = tenants_root(data_dir)
    # Nothing to delete.
    if not os.path.isdir(root):
        return 0
    # Count the files, then delete the tree.
    n = sum(len(files) for _, _, files in os.walk(root))
    shutil.rmtree(root, ignore_errors=True)
    return n
