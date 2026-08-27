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

A leaf: stdlib only. MUST NOT import ``main``/``api`` (direction is
``main → le_cache`` only). Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")


class LeCacheMixin:
    """Last-known Certificates data (cert list + status) for warm serve."""

    LE_CACHE_FILE = "le_certs.json"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def le_cache_init(self) -> None:
        """Initialize the in-memory cache slots. Call once from ``__init__``."""
        self.le_cache: Dict[str, Any] = {}
        self._le_cache_lock = asyncio.Lock()
        self._le_cache_save_tasks: set = set()

    def _le_cache_path(self) -> str:
        return os.path.join(getattr(self, "cache_dir", "."), self.LE_CACHE_FILE)

    def le_cache_load(self) -> None:
        """Rehydrate the cache from disk on startup (best-effort). Missing/corrupt
        file → cache stays empty (the first live fetch repopulates)."""
        try:
            path = self._le_cache_path()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.le_cache = {str(k): v for k, v in data.items()}
                logger.info("le cache: restored %d key(s) from %s",
                            len(self.le_cache), path)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("le cache load failed (%s): %s — starting empty",
                           self._le_cache_path(), exc)

    # ── read/write ─────────────────────────────────────────────────────────────

    def le_cache_get(self, key: str) -> Optional[Any]:
        """Last-known raw envelope for ``key`` (e.g. 'certs'/'status'), or None."""
        v = self.le_cache.get(key)
        return v.get("data") if isinstance(v, dict) and "data" in v else None

    async def le_cache_set(self, key: str, data: Any) -> None:
        """Store a fresh envelope for ``key`` + persist (best-effort)."""
        self.le_cache[key] = {"data": data, "fetched_at": time.time()}
        self._le_cache_schedule_save()

    # ── persist (mirrors nw_cache) ──────────────────────────────────────────────

    def _le_cache_schedule_save(self) -> None:
        try:
            task = asyncio.create_task(self._le_cache_persist())
            self._le_cache_save_tasks.add(task)
            task.add_done_callback(self._le_cache_save_tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (sync init)
            logger.debug("le cache: skipping async persist (no running loop)")

    async def _le_cache_persist(self) -> None:
        async with self._le_cache_lock:
            try:
                await asyncio.to_thread(self._le_cache_write, dict(self.le_cache))
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("le cache persist failed: %s", exc)

    def _le_cache_write(self, snapshot: Dict[str, Any]) -> None:
        path = self._le_cache_path()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f, default=str)
        os.chmod(tmp, 0o600)  # cert domains/targets — match the 0600 at-rest policy
        os.replace(tmp, path)

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
        out: Dict[str, Dict[str, str]] = {}
        try:
            gc = self.state.system_state.get("global_config", {}) or {}
            refs = gc.get("le_vault_dns_creds") or {}
            if not isinstance(refs, dict) or not refs:
                return out
            import cred_vault
            for domain, ref in list(refs.items()):
                if not isinstance(ref, dict):
                    continue
                bucket = (ref.get("bucket") or "").strip()
                name = (ref.get("name") or "").strip()
                if not (bucket and name):
                    continue
                try:
                    val = await cred_vault.automation_get(self, bucket, name)
                except Exception as e:  # noqa: BLE001 — vault/network, per-ref
                    logger.debug("le vault map: resolve %s failed: %s", domain, e)
                    continue
                if not isinstance(val, dict):
                    continue
                if (val.get("provider") == "he-login" or val.get("he_username")):
                    u = (val.get("he_username") or "").strip()
                    p = val.get("he_password") or ""
                    if u and p:
                        out[domain] = {"he_username": u, "he_password": p}
        except Exception as e:  # noqa: BLE001
            logger.debug("le vault map resolve skipped: %s", e)
        return out

    async def _le_sync_vault_dns_creds(self, spoke_id: str) -> None:
        """Push freshly vault-resolved DNS-01 hook creds to the le spoke so its
        ``he-login.ini`` is (re)seeded — e.g. after a reconnect/reinstall. HE
        uses a single account-login file, so one push suffices. Best-effort;
        never raises (durability nicety, not a hard dependency of connect)."""
        if not spoke_id:
            return
        try:
            vmap = await self._le_resolve_vault_map()
            he = next((v for v in vmap.values()
                       if v.get("he_username") and v.get("he_password")), None)
            if not he:
                return
            # Fired from the connect handler a beat before the spoke finishes
            # authenticating; wait (up to ~10s) until it can actually take a
            # command. Without this the request sits unanswered until the 60s
            # timeout ("Request Timeout: [LE_SYNC_VAULT_DNS] … after 60.1s").
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
            await self.request_response(spoke_id, "LE_SYNC_VAULT_DNS", he, timeout=60)
            logger.info("le vault sync: pushed HE DNS-01 creds to %s", spoke_id)
        except Exception as e:  # noqa: BLE001
            logger.debug("le vault sync to %s skipped: %s", spoke_id, e)

