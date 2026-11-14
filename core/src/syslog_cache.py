"""Hub cache for the Syslog overview (collectors + sources), per tenant.

``GET /api/syslog/overview`` renders from this cache; a background loop
refreshes every tenant that has connected collectors every 60 s by asking
each collector for ``SYSLOG_STATUS`` and ``SYSLOG_SOURCES``. Cache shape::

  {<tenant>: {"fetched_at": epoch,
              "collectors": [{"name", "spoke_id", "online", "error", **status}],
              "sources":    [{"collector", "host", "src_ip", "last_ts", ...}]}}

Persisted to ``<cache_dir>/syslog_data.json`` (``cache_core.JsonCacheFile``) so
a hub restart shows last-known collectors at once. No secrets are cached:
``SYSLOG_STATUS`` carries no passwords. Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional

from cache_core import JsonCacheFile, StalenessPolicy

logger = logging.getLogger("Hub")

# Refresh interval, per-command timeout and fan-out bound.
SYSLOG_REFRESH_S = 60.0
SYSLOG_STATUS_TIMEOUT_S = 20.0
SYSLOG_FANOUT = 8


class SyslogCacheMixin:
    """Per-tenant last-known syslog collector status, refreshed in the background."""

    SYSLOG_CACHE_FILE = "syslog_data.json"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def syslog_cache_init(self) -> None:
        """Initialize the in-memory cache. Call once from ``__init__``."""
        self.syslog_cache: Dict[str, Dict[str, Any]] = {}
        self.syslog_policy = StalenessPolicy()
        self._syslog_cache_file = JsonCacheFile(
            "syslog cache", self._syslog_cache_path, lambda: self.syslog_cache)

    def _syslog_cache_path(self) -> str:
        """Return the path of the syslog cache file under cache_dir."""
        return os.path.join(getattr(self, "cache_dir", "."), self.SYSLOG_CACHE_FILE)

    def syslog_cache_load(self) -> None:
        """Rehydrate the cache from disk on startup (best-effort)."""
        data = self._syslog_cache_file.load()
        if not isinstance(data, dict):
            return
        self.syslog_cache = {str(t): dict(v) for t, v in data.items() if isinstance(v, dict)}
        if self.syslog_cache:
            logger.info("syslog cache: restored %d tenant(s) from %s",
                        len(self.syslog_cache), self._syslog_cache_path())

    async def syslog_cache_flush_now(self) -> None:
        """Write any pending cache change now (graceful shutdown)."""
        await self._syslog_cache_file.flush_now()

    # ── read ─────────────────────────────────────────────────────────────────

    def syslog_cache_get(self, tenant) -> Optional[Dict[str, Any]]:
        """The tenant's cached overview entry, or None if never refreshed."""
        from syslog_archive import _tkey
        return self.syslog_cache.get(_tkey(tenant))

    # ── write ────────────────────────────────────────────────────────────────

    async def syslog_cache_set(self, tenant, entry: Dict[str, Any]) -> None:
        """Store a tenant's overview entry and schedule a save."""
        from syslog_archive import _tkey
        self.syslog_cache[_tkey(tenant)] = entry
        self._syslog_cache_file.schedule_save()

    # ── refresh ──────────────────────────────────────────────────────────────

    def syslog_tenants_with_collectors(self) -> List[str]:
        """Tenants that have at least one connected, approved logging spoke."""
        md = self.state.system_state.get("module_metadata", {}) or {}
        out = []
        for sid in self.get_all_spokes_by_type("logging") or []:
            tid = (md.get(sid) or {}).get("tenant_id")
            if tid and sid in self.active_connections and self.approved_modules.get(sid) \
                    and tid not in out:
                out.append(tid)
        return out

    async def _syslog_ask(self, sid: str, cmd: str, data: Dict[str, Any]):
        """One command to one collector: ``(reply, error)``; never raises."""
        import syslog_archive as sa
        try:
            res = sa.unwrap(await self.request_response(sid, cmd, data,
                                                        timeout=SYSLOG_STATUS_TIMEOUT_S))
            err = sa.reply_error(res)
            return (None, err) if err else (res, None)
        except Exception as e:  # noqa: BLE001 - "couldn't ask" is reported, not raised
            return None, str(e) or type(e).__name__

    async def refresh_syslog_tenant(self, tenant) -> Dict[str, Any]:
        """Ask each of the tenant's collectors for status + sources and cache it.

        A collector that does not answer keeps its row with ``online: False``
        and the error, so "couldn't ask" stays distinct from "no data"."""
        import syslog_archive as sa
        sids = sa.logging_spokes(self, tenant)
        sem = asyncio.Semaphore(SYSLOG_FANOUT)

        async def one(sid):
            """Status + sources for one collector."""
            name = sa.collector_name(self, sid)
            async with sem:
                status, s_err = await self._syslog_ask(sid, "SYSLOG_STATUS", {})
                src, src_err = await self._syslog_ask(sid, "SYSLOG_SOURCES", {"window_s": 3600})
            err = s_err or src_err
            if err:
                logger.warning("syslog: status refresh for tenant %s: collector %s: error %s",
                               tenant, name, err)
            row = {"name": name, "spoke_id": sid, "online": s_err is None, "error": err}
            if isinstance(status, dict):
                row.update({k: status.get(k) for k in ("collector", "archive", "forward")})
            sources = [{**s, "collector": name} for s in ((src or {}).get("sources") or [])
                       if isinstance(s, dict)]
            return row, sources

        # Fan out, then merge the per-collector sources newest-first.
        results = await asyncio.gather(*(one(s) for s in sids))
        sources = [s for _row, srcs in results for s in srcs]
        sources.sort(key=lambda s: float(s.get("last_ts") or 0), reverse=True)
        entry = {"fetched_at": time.time(), "collectors": [r for r, _s in results],
                 "sources": sources, "archive_host": await self._syslog_archive_host(tenant)}
        await self.syslog_cache_set(tenant, entry)
        return entry

    async def _syslog_archive_host(self, tenant) -> Optional[Dict[str, Any]]:
        """Deploy-role state of an LM-installed archive's agent (units enabled),
        from its GET_AVAILABLE_ROLES; None for no/external archive."""
        import syslog_archive as sa
        record = sa.get_archive(self, tenant) or {}
        role, sid = record.get("managed_by_role"), record.get("spoke_id")
        if not role or not sid:
            return None
        # The archive host has no spoke of its own: ask its agent.
        if sid not in self.active_connections:
            return {"online": False, "role": role, "error": "agent not connected"}
        reply, err = await self._syslog_ask(sid, "GET_AVAILABLE_ROLES", {})
        if err:
            logger.warning("syslog: archive host %s for tenant %s: error %s",
                           record.get("spoke_name") or sid, tenant, err)
            return {"online": True, "role": role, "error": err}
        deploys = [d for d in (reply.get("deploys") or [])
                   if isinstance(d, dict) and d.get("role") == role]
        return {"online": True, "role": role, "error": None,
                "installed": role in (reply.get("installed_deploy_roles") or []),
                "units_enabled": role in (reply.get("active_deploy_roles") or []),
                # Install state only; the installer output tail stays on the agent.
                "deploy": ({k: deploys[-1].get(k) for k in ("state", "returncode", "duration")}
                           if deploys else None)}

    async def _syslog_refresh_all(self) -> None:
        """One refresh cycle over every tenant with connected collectors."""
        for tenant in self.syslog_tenants_with_collectors():
            await self.refresh_syslog_tenant(tenant)

    async def run_syslog_cache_loop(self) -> None:
        """Refresh the syslog overview cache every 60 s, forever."""
        from sync_loop import run_sync_loop
        await run_sync_loop(stagger=45.0, body=self._syslog_refresh_all,
                            delay=lambda: SYSLOG_REFRESH_S,
                            error_label="syslog cache refresh failed")
