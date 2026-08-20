"""Scheduled HE.NET (External DNS) re-sync subsystem for the Hub.

The manual **Sync all** button re-applies every managed HE.NET record to the
dns.he.net web control panel (account-login web write). This mixin does the
same thing on a schedule, so records LM manages are periodically reconciled at
Hurricane Electric without an operator pressing the button — useful when a
record's target address drifts (the managed value in LM is authoritative and is
re-written to HE each cycle).

Design mirrors :class:`DnsDhcpSyncMixin` / the other discovery-sync mixins: a
self-contained mixin added to ``LabManagerHub`` bases, driven by
``global_config["henet_sync"]`` (``enabled`` default **False** — opt-in, like
self-backup), scheduled by :func:`sync_loop.next_schedule_delay` (interval or a
daily HH:MM). The web write is done **hub-side** (the hub has outbound access to
dns.he.net + the vault credential); the outcome is relayed to the henet spoke as
``HENET_WEB_RECORD`` to refresh local management state — exactly what the
on-demand ``POST /api/henet/sync`` route does, so the loop and the button can't
diverge.

Tenant-aware: managed records are grouped by ``tenant_id`` and each group is
written with THAT scope's account login (the tenant's own assigned credential,
falling back to the global slot) — mirroring
``net_services._henet_resolve_account_login``. A scope with no assignable
credential is skipped (not an error).

This module is a **leaf**: it imports only stdlib + sibling leaves and must NOT
import ``main`` or ``api`` (dependency direction is ``main → henet_sync`` only).

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from access import unwrap_spoke  # sibling leaf (no main/api back-import)
from sync_loop import next_schedule_delay, run_sync_loop  # sibling leaf

logger = logging.getLogger("Hub")

_CFG_KEY = "henet_sync"
_DEFAULT_INTERVAL = 3600  # seconds (1h)
_MIN_INTERVAL = 300       # never re-scrape HE more often than every 5 min


def _valid_ref(ref: Any) -> bool:
    return (isinstance(ref, dict)
            and bool((ref.get("bucket") or "").strip())
            and bool((ref.get("name") or "").strip()))


def cred_ref_for_scope(hub, tenant_id: str) -> Optional[Dict[str, str]]:
    """The assigned HE account-login credential {bucket,name} for ``tenant_id``
    (its own slot), falling back to the module-level global slot. ``None`` when
    neither is assigned. Mirrors ``net_services._henet_get_assigned_cred`` (with
    the global fallback ``_henet_resolve_account_login`` applies)."""
    gc = hub.state.system_state.get("global_config", {}) or {}
    hn = gc.get("henet") or {}
    tid = (tenant_id or "").strip()
    if tid:
        ref = (hn.get("tenant_credentials") or {}).get(tid)
        if _valid_ref(ref):
            return {"bucket": ref["bucket"].strip(), "name": ref["name"].strip()}
    ref = hn.get("vault_credential")
    if _valid_ref(ref):
        return {"bucket": ref["bucket"].strip(), "name": ref["name"].strip()}
    return None


def extract_account_login(val: Any) -> Tuple[str, str]:
    """Pull ``(username, password)`` out of a resolved vault secret, tolerating
    the several field shapes an HE account-login secret can take. Mirrors
    ``net_services._henet_resolve_account_login``. Returns ``("", "")`` when the
    secret carries no usable account login (e.g. a bare DDNS key)."""
    if not isinstance(val, dict):
        return "", ""
    username = (val.get("he_username") or val.get("username") or val.get("email") or "").strip()
    password = val.get("he_password") or val.get("password") or ""
    return username, (password or "")


class HenetSyncMixin:
    """Periodic HE.NET managed-record re-sync for ``LabManagerHub``.

    Exposes :meth:`sync_henet_scheduled` (one full reconcile across all scopes)
    and :meth:`run_henet_sync_loop` (started in ``LabManagerHub.start``). Per-run
    status is recorded in :attr:`henet_sync_status` for the WebUI status line.
    """

    def _henet_sync_cfg(self) -> Dict[str, Any]:
        """Read the schedule config fresh. ``enabled`` default False (opt-in);
        ``mode`` interval|daily; ``interval_seconds`` clamped to >= 300."""
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get(_CFG_KEY, {}) or {}
        try:
            interval = int(cfg.get("interval_seconds", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL)
        except (TypeError, ValueError):
            interval = _DEFAULT_INTERVAL
        return {
            "enabled":         bool(cfg.get("enabled", False)),
            "mode":            str(cfg.get("mode", "interval")).strip().lower() or "interval",
            "interval_seconds": max(_MIN_INTERVAL, interval),
            "daily_time":      str(cfg.get("daily_time", "02:00")).strip() or "02:00",
        }

    @property
    def henet_sync_status(self) -> Dict[str, Any]:
        """Last-run status; lazily initialized (mixin has no __init__)."""
        st = getattr(self, "_henet_sync_status", None)
        if st is None:
            st = {}
            self._henet_sync_status = st
        return st

    def _record_henet_status(self, **fields) -> Dict[str, Any]:
        entry = {"last_run": time.time(), **fields}
        self._henet_sync_status = entry
        return entry

    async def _henet_write_scope(self, spoke_id: str, tenant_id: str,
                                 records: List[Dict[str, Any]]) -> Dict[str, int]:
        """Write one tenant scope's managed records to HE via the account login,
        then relay the accepted ones to the spoke as ``HENET_WEB_RECORD``.

        Returns ``{applied, errors, skipped}`` (skipped=1 with no write when the
        scope has no assignable credential / account login)."""
        ref = cred_ref_for_scope(self, tenant_id)
        if not ref:
            logger.debug("henet scheduled sync: scope %r has no credential — skipped",
                         tenant_id or "global")
            return {"applied": 0, "errors": 0, "skipped": len(records)}
        import cred_vault as _cv
        try:
            val = await _cv.automation_get(self, ref["bucket"], ref["name"])
        except Exception as e:  # noqa: BLE001 — vault/network
            logger.warning("henet scheduled sync: scope %r credential resolve failed: %s",
                           tenant_id or "global", e)
            return {"applied": 0, "errors": len(records), "skipped": 0}
        username, password = extract_account_login(val)
        if not username or not password:
            logger.warning("henet scheduled sync: scope %r credential has no account login — skipped",
                           tenant_id or "global")
            return {"applied": 0, "errors": 0, "skipped": len(records)}

        import henet_scrape
        scraper = henet_scrape.HENetScraper()
        result = await asyncio.to_thread(scraper.set_records, username, password, records)
        by_key = {(str(r.get("name", "")).strip().rstrip("."),
                   str(r.get("type", "A")).upper()): r for r in records}
        local: List[Dict[str, Any]] = []
        for res in result.get("results", []):
            if not res.get("ok"):
                continue
            src = by_key.get((res["name"], res["type"]), {})
            local.append({"name": res["name"], "type": res["type"],
                          "value": src.get("value", ""), "ttl": src.get("ttl", 300),
                          "tenant_id": tenant_id, "ok": True,
                          "detail": res.get("detail", "")})
        if local:
            try:
                await self.request_response(spoke_id, "HENET_WEB_RECORD",
                                            {"records": local}, timeout=30.0)
            except Exception as e:  # noqa: BLE001 — spoke persist is best-effort
                logger.warning("henet scheduled sync: HENET_WEB_RECORD relay failed: %s", e)
        errors = sum(1 for r in result.get("results", []) if not r.get("ok"))
        return {"applied": len(local), "errors": errors, "skipped": 0}

    async def sync_henet_scheduled(self) -> Dict[str, Any]:
        """One scheduled reconcile: re-apply every managed A/AAAA HE.NET record
        to Hurricane Electric, grouped + written per tenant scope. Returns a
        status dict (``status`` ``ok`` / ``skipped`` when the spoke is offline /
        ``error``). Never raises — the loop depends on it."""
        spoke_id = self.get_spoke_by_type("henet")
        if not spoke_id:
            return self._record_henet_status(status="skipped",
                                              reason="HE.NET spoke not connected")
        try:
            listed = unwrap_spoke(await self.request_response(spoke_id, "HENET_LIST", {}, timeout=30.0))
        except Exception as e:  # noqa: BLE001
            logger.warning("henet scheduled sync: HENET_LIST failed: %s", e)
            return self._record_henet_status(status="error", error=str(e))

        records = (listed or {}).get("records") or []
        # Match the manual "Sync all" scope: A/AAAA managed records only.
        by_scope: Dict[str, List[Dict[str, Any]]] = {}
        for r in records:
            rtype = str(r.get("type") or "").upper()
            if rtype not in ("A", "AAAA"):
                continue
            name = str(r.get("name") or "").strip().rstrip(".")
            value = str(r.get("value") or "").strip()
            if not name or not value:
                continue
            scope = str(r.get("tenant_id") or "").strip()
            by_scope.setdefault(scope, []).append(
                {"name": name, "type": rtype, "value": value,
                 "ttl": r.get("ttl", 300), "tenant_id": scope})

        if not by_scope:
            return self._record_henet_status(status="ok", applied=0, errors=0,
                                             scopes=0, reason="no managed records")

        totals = {"applied": 0, "errors": 0, "skipped": 0}
        for scope, recs in by_scope.items():
            res = await self._henet_write_scope(spoke_id, scope, recs)
            for k in totals:
                totals[k] += res.get(k, 0)

        status = "error" if totals["errors"] else "ok"
        return self._record_henet_status(status=status, scopes=len(by_scope), **totals)

    async def run_henet_sync_loop(self):
        """Background loop: re-apply managed HE.NET records on the configured
        schedule. Disabled (skipped, not stopped) while
        ``global_config.henet_sync.enabled`` is False, so toggling it in the
        WebUI takes effect without a hub restart. Skips quietly whenever the
        henet spoke is offline."""
        logger.info("HE.NET scheduled sync loop started.")

        def _delay() -> float:
            cfg = self._henet_sync_cfg()
            d = next_schedule_delay(
                {"mode": cfg["mode"], "daily_time": cfg["daily_time"],
                 "interval_seconds": cfg["interval_seconds"]},
                default_interval=_DEFAULT_INTERVAL, log_name="henet-sync")
            # When disabled, re-check every 60s so a WebUI enable takes effect
            # promptly instead of after a full interval.
            return d if cfg["enabled"] else 60.0

        await run_sync_loop(
            stagger=90,  # let the fleet settle before the first HE scrape
            guard=lambda: bool(self._henet_sync_cfg()["enabled"]),
            body=self.sync_henet_scheduled,
            delay=_delay,
            on_error=lambda e: logger.error("Error in HE.NET scheduled sync loop: %s", e),
            error_delay=_delay)
