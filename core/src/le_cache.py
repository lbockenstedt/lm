"""In-memory + JSON-persisted cache for the Certificates (le) module.

Mirrors ``nw_cache.NwCacheMixin`` exactly (cache the raw spoke envelope, serve
it — marked stale — when the le spoke is offline or a live fetch overruns,
refresh on every live fetch) so the Certificates page renders instantly from
last-known data instead of blocking on a live LE_LIST_CERTS round-trip or
503-ing until the le spoke reconnects.

Warm start: persisted to ``<cache_dir>/le_certs.json`` (atomic tmp +
``os.replace``, ``asyncio.Lock``-guarded, written off the event loop) and
reloaded on startup via ``le_cache_load``. The cert-distribution loop refreshes
it every cycle, so the on-disk snapshot is superseded by the next poll.

Persistence and the staleness timers come from ``cache_core`` rather than a
local copy, so this cache writes and ages out exactly like every other one.

A leaf: stdlib only. MUST NOT import ``main``/``api`` (direction is
``main → le_cache`` only). Audience: Hub developers.
"""

# Postpone evaluation of type hints so annotations stay cheap at import time.
from __future__ import annotations

# asyncio paces the wait for a spoke to become command-ready.
import asyncio
# logging reports cache restores and vault sync results.
import logging
# os builds the on-disk cache file path.
import os
# time stamps each cache entry with when it was fetched.
import time
# Type hints for cache dicts and optional lookups.
from typing import Any, Dict, Optional

# Shared cache helpers: atomic JSON persistence and fresh/stale/expired classification.
from cache_core import JsonCacheFile, StalenessPolicy

# Share the hub's logger so cache messages appear with other hub logs.
logger = logging.getLogger("Hub")


class LeCacheMixin:
    """Last-known Certificates data (cert list + status) for warm serve."""

    # File name of the persisted cache inside the hub's cache directory.
    LE_CACHE_FILE = "le_certs.json"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def le_cache_init(self) -> None:
        """Initialize the in-memory cache slots. Call once from ``__init__``."""
        # Empty in-memory cache, the shared staleness rules, and the JSON file that persists a
        # snapshot.
        self.le_cache: Dict[str, Any] = {}
        self.le_policy = StalenessPolicy()
        self._le_cache_file = JsonCacheFile(
            "le cache", self._le_cache_path, lambda: dict(self.le_cache))

    def _le_cache_path(self) -> str:
        """Return the full path of the persisted cache file."""
        return os.path.join(getattr(self, "cache_dir", "."), self.LE_CACHE_FILE)

    def le_cache_load(self) -> None:
        """Rehydrate the cache from disk on startup (best-effort). Missing/corrupt
        file → cache stays empty (the first live fetch repopulates)."""
        # Load the saved snapshot; anything that is not a dict is ignored.
        data = self._le_cache_file.load()
        if not isinstance(data, dict):
            return
        # Restore it with string keys.
        self.le_cache = {str(k): v for k, v in data.items()}
        logger.info("le cache: restored %d key(s) from %s",
                    len(self.le_cache), self._le_cache_path())

    # ── read/write ─────────────────────────────────────────────────────────────

    def le_cache_get(self, key: str) -> Optional[Any]:
        """Last-known raw envelope for ``key`` (e.g. 'certs'/'status'), or None."""
        # Return the stored envelope's data, or None if missing or malformed.
        v = self.le_cache.get(key)
        return v.get("data") if isinstance(v, dict) and "data" in v else None

    def le_cache_fetched_at(self, key: str) -> Optional[float]:
        """Epoch of the last write for ``key``, or None — feeds ``le_cache_state``
        and any background-refresh decision."""
        # Read the entry's fetch time, accepting only a numeric value.
        v = self.le_cache.get(key)
        ts = v.get("fetched_at") if isinstance(v, dict) else None
        return ts if isinstance(ts, (int, float)) else None

    def le_cache_state(self, key: str) -> str:
        """Shared staleness verdict for ``key`` (``cache_core`` vocabulary)."""
        return self.le_policy.classify(self.le_cache_fetched_at(key))

    async def le_cache_set(self, key: str, data: Any) -> None:
        """Store a fresh envelope for ``key`` + persist (best-effort)."""
        # Store the data with the current time, then schedule a coalesced save to disk.
        self.le_cache[key] = {"data": data, "fetched_at": time.time()}
        self._le_cache_file.schedule_save()

    async def le_cache_flush_now(self) -> None:
        """Immediate persist (shutdown path) — skips the coalescing delay."""
        await self._le_cache_file.flush_now()

    # ── vault DNS-01 credential durability ────────────────────────────────────
    # The DNS-01 secret (e.g. the Hurricane Electric account login) lives ONLY in
    # the Credential Vault. The hub stores a secret-free {bucket,name} reference
    # per cert domain in ``global_config['le_vault_dns_creds']`` at issue time,
    # then re-resolves it from the vault and pushes it to the le spoke on every
    # (re)connect — so certbot's DNS hook creds (``/etc/lm-le/he-login.ini``)
    # survive a spoke reinstall that wiped them. Reach=role, decrypt=hub key.

    async def _le_resolve_vault_map(self) -> Dict[str, Dict[str, str]]:
        """Resolve every stored LE vault DNS-01 reference to inline creds, keyed
        by cert domain. Best-effort — a reference that can't be resolved is
        skipped, never raised. Currently supports HE account-login (he-login)."""
        # Resolved creds keyed by cert domain.
        out: Dict[str, Dict[str, str]] = {}
        try:
            # Read the stored vault references; none means nothing to resolve.
            gc = self.state.system_state.get("global_config", {}) or {}
            refs = gc.get("le_vault_dns_creds") or {}
            if not isinstance(refs, dict) or not refs:
                return out
            # Imported lazily so this module stays a leaf.
            import cred_vault
            # Resolve each domain's reference.
            for domain, ref in list(refs.items()):
                # Skip malformed references.
                if not isinstance(ref, dict):
                    continue
                bucket = (ref.get("bucket") or "").strip()
                name = (ref.get("name") or "").strip()
                if not (bucket and name):
                    continue
                # Fetch the secret value from the vault; failures skip only this domain.
                try:
                    val = await cred_vault.automation_get(self, bucket, name)
                except Exception as e:  # noqa: BLE001 — vault/network, per-ref
                    logger.debug("le vault map: resolve %s failed: %s", domain, e)
                    continue
                # Only dict values carry credentials.
                if not isinstance(val, dict):
                    continue
                # Hurricane Electric account login: keep it when both username and password are
                # present.
                if (val.get("provider") == "he-login" or val.get("he_username")):
                    u = (val.get("he_username") or "").strip()
                    p = val.get("he_password") or ""
                    if u and p:
                        out[domain] = {"he_username": u, "he_password": p}
        except Exception as e:  # noqa: BLE001
            # Any unexpected failure just means no creds this time.
            logger.debug("le vault map resolve skipped: %s", e)
        return out

    async def _le_sync_vault_dns_creds(self, spoke_id: str) -> None:
        """Push freshly vault-resolved DNS-01 hook creds to the le spoke so its
        ``he-login.ini`` is (re)seeded — e.g. after a reconnect/reinstall. HE
        uses a single account-login file, so one push suffices. Best-effort;
        never raises (durability nicety, not a hard dependency of connect)."""
        # No spoke to push to.
        if not spoke_id:
            return
        try:
            # Resolve creds and pick the first complete HE login (one file serves every domain).
            vmap = await self._le_resolve_vault_map()
            he = next((v for v in vmap.values()
                       if v.get("he_username") and v.get("he_password")), None)
            # Nothing to push.
            if not he:
                return
            # Fired from the connect handler a beat before the spoke finishes
            # authenticating; wait (up to ~10s) until it can actually take a
            # command. Without this the request sits unanswered until the 60s
            # timeout ("Request Timeout: [LE_SYNC_VAULT_DNS] … after 60.1s").
            # Poll (20 x 0.5s) for the spoke to accept commands, if the hub exposes that check.
            can_check = getattr(self, "spoke_can_accept_commands", None)
            if callable(can_check):
                for _ in range(20):
                    ok, _reason = can_check(spoke_id)
                    if ok:
                        break
                    await asyncio.sleep(0.5)
                else:
                    logger.info("le vault sync: %s never became command-ready; "
                                "skipping this connect", spoke_id)
                    return
            # Push the creds to the le spoke.
            await self.request_response(spoke_id, "LE_SYNC_VAULT_DNS", he, timeout=60)
            logger.info("le vault sync: pushed HE DNS-01 creds to %s", spoke_id)
        except Exception as e:  # noqa: BLE001
            # Best-effort: a failure is logged and the next connect tries again.
            logger.debug("le vault sync to %s skipped: %s", spoke_id, e)

