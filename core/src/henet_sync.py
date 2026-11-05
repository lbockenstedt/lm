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

# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio.to_thread runs the blocking web scraper without freezing the event loop.
import asyncio
# Standard-library logging for sync progress and failures.
import logging
# time.time() timestamps each run's status record.
import time
# Type hints only.
from typing import Any, Dict, List, Optional, Tuple

# Unwraps a spoke's reply envelope into its payload.
from access import unwrap_spoke  # sibling leaf (no main/api back-import)
# Shared scheduling helpers: compute the next delay and run the periodic loop.
from sync_loop import next_schedule_delay, run_sync_loop  # sibling leaf

# Use the hub's main logger so these messages appear with other hub output.
logger = logging.getLogger("Hub")

# global_config key holding this feature's schedule settings.
_CFG_KEY = "henet_sync"
_DEFAULT_INTERVAL = 3600  # seconds (1h)
_MIN_INTERVAL = 300       # never re-scrape HE more often than every 5 min


def _valid_ref(ref: Any) -> bool:
    """Return True if ``ref`` is a vault reference dict with non-blank bucket and name."""
    # Must be a dict whose bucket and name are both non-empty after trimming.
    return (isinstance(ref, dict)
            and bool((ref.get("bucket") or "").strip())
            and bool((ref.get("name") or "").strip()))


def cred_ref_for_scope(hub, tenant_id: str) -> Optional[Dict[str, str]]:
    """The assigned HE account-login credential {bucket,name} for ``tenant_id``
    (its own slot), falling back to the module-level global slot. ``None`` when
    neither is assigned. Mirrors ``net_services._henet_get_assigned_cred`` (with
    the global fallback ``_henet_resolve_account_login`` applies)."""
    # Read the HE.NET section of the hub-wide settings.
    gc = hub.state.system_state.get("global_config", {}) or {}
    hn = gc.get("henet") or {}
    # Normalised tenant id ("" means the global scope).
    tid = (tenant_id or "").strip()
    # A tenant scope first tries its own assigned credential.
    if tid:
        ref = (hn.get("tenant_credentials") or {}).get(tid)
        if _valid_ref(ref):
            return {"bucket": ref["bucket"].strip(), "name": ref["name"].strip()}
    # Fall back to the module-wide (global) credential.
    ref = hn.get("vault_credential")
    if _valid_ref(ref):
        return {"bucket": ref["bucket"].strip(), "name": ref["name"].strip()}
    # No credential assigned anywhere.
    return None


def extract_account_login(val: Any) -> Tuple[str, str]:
    """Pull ``(username, password)`` out of a resolved vault secret, tolerating
    the several field shapes an HE account-login secret can take. Mirrors
    ``net_services._henet_resolve_account_login``. Returns ``("", "")`` when the
    secret carries no usable account login (e.g. a bare DDNS key)."""
    # Secrets that are not dicts (e.g. a bare key string) carry no account login.
    if not isinstance(val, dict):
        return "", ""
    # Accept the username under any of its known field names.
    username = (val.get("he_username") or val.get("username") or val.get("email") or "").strip()
    # Accept the password under any of its known field names.
    password = val.get("he_password") or val.get("password") or ""
    # Return the pair (password normalised to "" if missing).
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
        # Read this feature's settings fresh each time so WebUI changes apply immediately.
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get(_CFG_KEY, {}) or {}
        # Interval in seconds; fall back to the default if the setting is not a number.
        try:
            interval = int(cfg.get("interval_seconds", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL)
        except (TypeError, ValueError):
            interval = _DEFAULT_INTERVAL
        # Normalised settings with defaults; interval is clamped to the 5-minute minimum.
        return {
            "enabled":         bool(cfg.get("enabled", False)),
            "mode":            str(cfg.get("mode", "interval")).strip().lower() or "interval",
            "interval_seconds": max(_MIN_INTERVAL, interval),
            "daily_time":      str(cfg.get("daily_time", "02:00")).strip() or "02:00",
        }

    @property
    def henet_sync_status(self) -> Dict[str, Any]:
        """Last-run status; lazily initialized (mixin has no __init__)."""
        # Create the status dict on first access, since the mixin has no __init__ to do it.
        st = getattr(self, "_henet_sync_status", None)
        if st is None:
            st = {}
            self._henet_sync_status = st
        # Return the (possibly new) status dict.
        return st

    def _record_henet_status(self, **fields) -> Dict[str, Any]:
        """Replace the last-run status with ``fields`` plus a timestamp and return it."""
        # Stamp the run time alongside the supplied fields.
        entry = {"last_run": time.time(), **fields}
        # Store and return it for the WebUI status line.
        self._henet_sync_status = entry
        return entry

    async def _henet_write_scope(self, spoke_id: str, tenant_id: str,
                                 records: List[Dict[str, Any]]) -> Dict[str, int]:
        """Write one tenant scope's managed records to HE via the account login,
        then relay the accepted ones to the spoke as ``HENET_WEB_RECORD``.

        Returns ``{applied, errors, skipped}`` (skipped=1 with no write when the
        scope has no assignable credential / account login)."""
        # Which vault credential applies to this scope?
        ref = cred_ref_for_scope(self, tenant_id)
        # No credential: skip this scope's records (not an error).
        if not ref:
            logger.debug("henet scheduled sync: scope %r has no credential — skipped",
                         tenant_id or "global")
            return {"applied": 0, "errors": 0, "skipped": len(records)}
        # Imported lazily to avoid a circular import at module load.
        import cred_vault as _cv
        # Fetch the secret; a vault/network failure counts every record as an error.
        try:
            val = await _cv.automation_get(self, ref["bucket"], ref["name"])
        except Exception as e:  # noqa: BLE001 — vault/network
            logger.warning("henet scheduled sync: scope %r credential resolve failed: %s",
                           tenant_id or "global", e)
            return {"applied": 0, "errors": len(records), "skipped": 0}
        # Extract username/password from the secret.
        username, password = extract_account_login(val)
        # Secret lacks an account login: skip this scope.
        if not username or not password:
            logger.warning("henet scheduled sync: scope %r credential has no account login — skipped",
                           tenant_id or "global")
            return {"applied": 0, "errors": 0, "skipped": len(records)}

        # Imported lazily; the scraper is only needed when actually writing.
        import henet_scrape
        # Log in to dns.he.net and write the records on a worker thread (blocking HTTP).
        scraper = henet_scrape.HENetScraper()
        result = await asyncio.to_thread(scraper.set_records, username, password, records)
        # Index the requested records by (name, type) to look up their values afterwards.
        by_key = {(str(r.get("name", "")).strip().rstrip("."),
                   str(r.get("type", "A")).upper()): r for r in records}
        # Records HE accepted, in the shape the henet spoke expects.
        local: List[Dict[str, Any]] = []
        # Walk HE's per-record results.
        for res in result.get("results", []):
            # Skip records HE rejected (counted as errors below).
            if not res.get("ok"):
                continue
            # Rebuild the full record (value, TTL, tenant) from the original request.
            src = by_key.get((res["name"], res["type"]), {})
            local.append({"name": res["name"], "type": res["type"],
                          "value": src.get("value", ""), "ttl": src.get("ttl", 300),
                          "tenant_id": tenant_id, "ok": True,
                          "detail": res.get("detail", "")})
        # Tell the henet spoke which records were written so its local state stays current.
        if local:
            try:
                await self.request_response(spoke_id, "HENET_WEB_RECORD",
                                            {"records": local}, timeout=60.0)
            # Relay failure is logged; the HE write itself already succeeded.
            except Exception as e:  # noqa: BLE001 — spoke persist is best-effort
                logger.warning("henet scheduled sync: HENET_WEB_RECORD relay failed: %s", e)
        # Count records HE rejected.
        errors = sum(1 for r in result.get("results", []) if not r.get("ok"))
        # Summary for this scope.
        return {"applied": len(local), "errors": errors, "skipped": 0}

    async def sync_henet_scheduled(self) -> Dict[str, Any]:
        """One scheduled reconcile: re-apply every managed A/AAAA HE.NET record
        to Hurricane Electric, grouped + written per tenant scope. Returns a
        status dict (``status`` ``ok`` / ``skipped`` when the spoke is offline /
        ``error``). Never raises — the loop depends on it."""
        # Find the connected henet spoke; without it there is no record list to sync.
        spoke_id = self.get_spoke_by_type("henet")
        if not spoke_id:
            return self._record_henet_status(status="skipped",
                                              reason="HE.NET spoke not connected")
        # Ask the spoke for every managed record.
        try:
            listed = unwrap_spoke(await self.request_response(spoke_id, "HENET_LIST", {}, timeout=30.0))
        # Spoke did not answer: record an error status.
        except Exception as e:  # noqa: BLE001
            logger.warning("henet scheduled sync: HENET_LIST failed: %s", e)
            return self._record_henet_status(status="error", error=str(e))

        # The managed records list (empty if missing).
        records = (listed or {}).get("records") or []
        # Match the manual "Sync all" scope: A/AAAA managed records only.
        by_scope: Dict[str, List[Dict[str, Any]]] = {}
        # Inspect each record.
        for r in records:
            # Keep only A/AAAA records.
            rtype = str(r.get("type") or "").upper()
            if rtype not in ("A", "AAAA"):
                continue
            # Normalise name (no trailing dot) and value; skip incomplete records.
            name = str(r.get("name") or "").strip().rstrip(".")
            value = str(r.get("value") or "").strip()
            if not name or not value:
                continue
            # Group by tenant scope ("" = global) so each scope uses its own credential.
            scope = str(r.get("tenant_id") or "").strip()
            by_scope.setdefault(scope, []).append(
                {"name": name, "type": rtype, "value": value,
                 "ttl": r.get("ttl", 300), "tenant_id": scope})

        # Nothing to sync.
        if not by_scope:
            return self._record_henet_status(status="ok", applied=0, errors=0,
                                             scopes=0, reason="no managed records")

        # Running totals across all scopes.
        totals = {"applied": 0, "errors": 0, "skipped": 0}
        # Write each scope and add up its results.
        for scope, recs in by_scope.items():
            res = await self._henet_write_scope(spoke_id, scope, recs)
            for k in totals:
                totals[k] += res.get(k, 0)

        # Any errors make the whole run "error"; otherwise "ok".
        status = "error" if totals["errors"] else "ok"
        return self._record_henet_status(status=status, scopes=len(by_scope), **totals)

    async def run_henet_sync_loop(self):
        """Background loop: re-apply managed HE.NET records on the configured
        schedule. Disabled (skipped, not stopped) while
        ``global_config.henet_sync.enabled`` is False, so toggling it in the
        WebUI takes effect without a hub restart. Skips quietly whenever the
        henet spoke is offline."""
        # Announce the loop at startup.
        logger.info("HE.NET scheduled sync loop started.")

        def _delay() -> float:
            """Return seconds until the next run (60 s while disabled so enabling takes effect
            quickly).
            """
            # Read the schedule fresh each cycle.
            cfg = self._henet_sync_cfg()
            # Compute the delay for interval or daily-at-HH:MM mode.
            d = next_schedule_delay(
                {"mode": cfg["mode"], "daily_time": cfg["daily_time"],
                 "interval_seconds": cfg["interval_seconds"]},
                default_interval=_DEFAULT_INTERVAL, log_name="henet-sync")
            # When disabled, re-check every 60s so a WebUI enable takes effect
            # promptly instead of after a full interval.
            return d if cfg["enabled"] else 60.0

        # Start the loop: wait 90 s after boot, run only while enabled, follow the schedule.
        await run_sync_loop(
            stagger=90,  # let the fleet settle before the first HE scrape
            guard=lambda: bool(self._henet_sync_cfg()["enabled"]),
            body=self.sync_henet_scheduled,
            delay=_delay,
            on_error=lambda e: logger.error("Error in HE.NET scheduled sync loop: %s", e),
            error_delay=_delay)
