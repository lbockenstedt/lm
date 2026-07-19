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

import glob
import json
import logging
import os
from typing import Any, Callable, Dict, Iterable, Optional

logger = logging.getLogger("TenantSharded")

_KEYSEP = "\x1f"  # matches simulations/central_hub_poller._CC_KEYSEP


def _tenant_of_composite(key: str) -> str:
    """Tenant = the first ``\\x1f``-separated field of a composite store key."""
    return str(key).split(_KEYSEP, 1)[0]


def tenants_root(data_dir: str) -> str:
    return os.path.join(data_dir, "tenants")


def shard_dir(data_dir: str, tenant: str, module: str) -> str:
    d = os.path.join(tenants_root(data_dir), str(tenant), module)
    os.makedirs(d, exist_ok=True)
    return d


def shard_path(data_dir: str, tenant: str, module: str, name: str) -> str:
    return os.path.join(shard_dir(data_dir, tenant, module), name)


def group_by_tenant(resident: Dict[str, Any],
                    tenant_of: Optional[Callable[[str], str]] = None
                    ) -> Dict[str, Dict[str, Any]]:
    """Split a resident store dict into ``{tenant: {key: value}}``.

    Default grouper treats the first ``\\x1f`` field of the key as the tenant
    (composite-keyed stores). Pass ``tenant_of`` for stores keyed directly by
    tenant (identity) or by something else (e.g. spoke_id → tenant resolver)."""
    tof = tenant_of or _tenant_of_composite
    out: Dict[str, Dict[str, Any]] = {}
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
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def shard_save(data_dir: str, module: str, name: str, resident: Dict[str, Any],
               *, tenant_of: Optional[Callable[[str], str]] = None,
               dirty: Optional[Iterable[str]] = None,
               encrypt: Optional[Callable[[str], bytes]] = None) -> None:
    """Persist ``resident`` sharded per tenant. Only tenants in ``dirty`` are
    rewritten (pass ``None`` to write all). A tenant whose slice became empty has
    its file removed. ``encrypt(json_str)->bytes`` mirrors the store's at-rest
    encryption; without it a plain UTF-8 JSON file is written."""
    grouped = group_by_tenant(resident, tenant_of)
    targets = set(str(t) for t in dirty) if dirty is not None else set(grouped.keys())
    # A dirty tenant that no longer has any keys → delete its shard file.
    for t in targets:
        p = shard_path(data_dir, t, module, name)
        slice_ = grouped.get(t)
        try:
            if not slice_:
                if os.path.exists(p):
                    os.remove(p)
                continue
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
    merged: Dict[str, Any] = {}
    pattern = os.path.join(tenants_root(data_dir), "*", module, name)
    for p in glob.glob(pattern):
        try:
            with open(p, "rb") as f:
                blob = f.read()
            if not blob:
                continue
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
    legacy = legacy_path or os.path.join(data_dir, name)
    try:
        if not os.path.exists(legacy):
            return False
        # If shards already exist, assume a prior migration ran — don't clobber.
        if glob.glob(os.path.join(tenants_root(data_dir), "*", module, name)):
            return False
        with open(legacy, "rb") as f:
            blob = f.read()
        if blob:
            text = decrypt(blob) if decrypt else blob.decode("utf-8")
            data = json.loads(text) or {}
            if isinstance(data, dict) and data:
                shard_save(data_dir, module, name, data,
                           tenant_of=tenant_of, dirty=None, encrypt=encrypt)
        os.replace(legacy, legacy + ".migrated")
        logger.info("migrate_legacy: split %s into tenants/*/%s/%s", name, module, name)
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("migrate_legacy %s failed (leaving legacy in place): %s", name, e)
        return False


# ── corruption-recovery reset (Part 2) ──────────────────────────────────────
def reset_tenant_files(data_dir: str, tenant: str) -> int:
    """Delete ALL sharded derived files for one tenant (every module). Returns the
    count removed. Only touches ``tenants/<tenant>/`` — never the data_dir-root
    config/identity files."""
    import shutil
    d = os.path.join(tenants_root(data_dir), str(tenant))
    if not os.path.isdir(d):
        return 0
    n = sum(len(files) for _, _, files in os.walk(d))
    shutil.rmtree(d, ignore_errors=True)
    return n


def reset_all_tenant_files(data_dir: str) -> int:
    """Delete the whole ``tenants/`` derived subtree (all tenants, all modules).
    Never touches data_dir-root config/identity files."""
    import shutil
    root = tenants_root(data_dir)
    if not os.path.isdir(root):
        return 0
    n = sum(len(files) for _, _, files in os.walk(root))
    shutil.rmtree(root, ignore_errors=True)
    return n
