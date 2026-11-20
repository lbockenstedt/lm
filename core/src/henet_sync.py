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
credential is skipped (not an error). A tenant that several credential slots
name (saved before slots were matched in any case) is an error, so the run
reports ``error`` rather than ``ok``, and none of its records are written.

The last-run status carries a short ``reason`` built only from counts and the
failure classes in ``_FAILURE_LABELS``: ``GET /api/henet/sync-config`` returns
it to every user with HE.NET or DNS access, tenant users included, so it never
names a tenant, record, HE username or vault path, nor quotes an HE.NET, vault
or spoke error. Those details go to the hub log only.

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
from access import raw_tenant_id, tenant_key_in, unwrap_spoke  # sibling leaf (no main/api back-import)
# Shared scheduling helpers: compute the next delay and run the periodic loop.
from sync_loop import next_schedule_delay, run_sync_loop  # sibling leaf

# Use the hub's main logger so these messages appear with other hub output.
logger = logging.getLogger("Hub")

# global_config key holding this feature's schedule settings.
_CFG_KEY = "henet_sync"
_DEFAULT_INTERVAL = 3600  # seconds (1h)
_MIN_INTERVAL = 300       # never re-scrape HE more often than every 5 min

# Why a scope wrote nothing, as the tenant-neutral run reason names it (see
# the module docstring). In this order in the reason.
_FAILURE_LABELS = {
    "he_write_failed": "HE.NET login or connection failure",
    "credential_conflict": "credential conflict",
    "vault_read_failed": "vault read failure",
}
# Reason for a run whose record list could not be read from the spoke.
_LIST_FAILED_REASON = "the HE.NET spoke did not return its record list"


def _plural(n: int, noun: str) -> str:
    """``n`` and ``noun``, with an ``s`` unless ``n`` is 1 ("2 records")."""
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _run_reason(scopes: int, failures: Dict[str, int], rejected: int) -> str:
    """The tenant-neutral reason for a run with errors, e.g. "2 of 5 scopes
    failed (1 HE.NET login or connection failure, 1 credential conflict);
    3 records rejected by HE.NET". ``failures`` counts the scopes that wrote
    nothing, by class; ``rejected`` counts records HE.NET refused in the scopes
    that did write."""
    parts = []
    # Scopes that wrote nothing, with how many failed each way.
    failed = sum(failures.values())
    if failed:
        kinds = ", ".join(_plural(failures[k], label)
                          for k, label in _FAILURE_LABELS.items() if failures.get(k))
        parts.append(f"{failed} of {_plural(scopes, 'scope')} failed ({kinds})")
    # Records HE.NET refused one by one.
    if rejected:
        parts.append(f"{_plural(rejected, 'record')} rejected by HE.NET")
    return "; ".join(parts)


def _valid_ref(ref: Any) -> bool:
    """Return True if ``ref`` is a vault reference dict with non-blank bucket and name."""
    # Must be a dict whose bucket and name are both non-empty after trimming.
    return (isinstance(ref, dict)
            and bool((ref.get("bucket") or "").strip())
            and bool((ref.get("name") or "").strip()))


def cred_ref_for_scope(hub, tenant_id: str) -> Optional[Dict[str, str]]:
    """The assigned HE account-login credential {bucket,name} for ``tenant_id``
    (its own slot), falling back to the module-level global slot. ``None`` when
    neither is assigned. Raises ``ValueError`` when several slots name the
    tenant (see below). Mirrors ``net_services._henet_get_assigned_cred`` (with
    the global fallback ``_henet_resolve_account_login`` applies)."""
    # Read the HE.NET section of the hub-wide settings.
    gc = hub.state.system_state.get("global_config", {}) or {}
    hn = gc.get("henet") or {}
    # A tenant scope first tries its own assigned credential: the one slot
    # same_tenant matches, in any case or spaces, never a legacy twin's (a
    # blank tenant id means the global scope). Several such slots (saved
    # before slots were matched in any case) raise, even when one is spelt
    # exactly like the scope, rather than one being picked, with no global
    # fallback: the tenant assigned its own HE account, so its records must
    # not be written with the global one.
    creds = hn.get("tenant_credentials") or {}
    key = tenant_key_in(creds, tenant_id)
    if key is not None:
        ref = creds.get(key)
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
                                 records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Write one tenant scope's managed records to HE via the account login,
        then relay the accepted ones to the spoke as ``HENET_WEB_RECORD``.

        Returns ``{applied, errors, skipped, failure}``: every record skipped,
        with no write, when the scope has no assignable credential or account
        login; every record an error, with ``failure`` naming the class in
        ``_FAILURE_LABELS``, when several credential slots name the tenant, the
        vault read fails, or HE.NET could not be logged in to or reached.
        Otherwise ``failure`` is None and ``errors`` counts the records HE.NET
        rejected."""
        # Which vault credential applies to this scope? Several slots for the
        # tenant are refused as errors, not skips, so the run reports "error"
        # rather than "ok" until the credential is assigned again.
        try:
            ref = cred_ref_for_scope(self, tenant_id)
        except ValueError as e:
            logger.warning("henet scheduled sync: scope %r not synced: %s; assign its "
                           "credential again to keep one", tenant_id or "global", e)
            return {"applied": 0, "errors": len(records), "skipped": 0,
                    "failure": "credential_conflict"}
        # No credential: skip this scope's records (not an error).
        if not ref:
            logger.debug("henet scheduled sync: scope %r has no credential — skipped",
                         tenant_id or "global")
            return {"applied": 0, "errors": 0, "skipped": len(records), "failure": None}
        # Imported lazily to avoid a circular import at module load.
        import cred_vault as _cv
        # Fetch the secret; a vault/network failure counts every record as an error.
        try:
            val = await _cv.automation_get(self, ref["bucket"], ref["name"])
        except Exception as e:  # noqa: BLE001 — vault/network
            logger.warning("henet scheduled sync: scope %r credential resolve failed: %s",
                           tenant_id or "global", e)
            return {"applied": 0, "errors": len(records), "skipped": 0,
                    "failure": "vault_read_failed"}
        # Extract username/password from the secret.
        username, password = extract_account_login(val)
        # Secret lacks an account login: skip this scope.
        if not username or not password:
            logger.warning("henet scheduled sync: scope %r credential has no account login — skipped",
                           tenant_id or "global")
            return {"applied": 0, "errors": 0, "skipped": len(records), "failure": None}

        # Imported lazily; the scraper is only needed when actually writing.
        import henet_scrape
        # Log in to dns.he.net and write the records on a worker thread (blocking HTTP).
        scraper = henet_scrape.HENetScraper()
        try:
            result = await asyncio.to_thread(scraper.set_records, username, password, records)
        except Exception as e:  # noqa: BLE001 — the loop must never raise
            result = {"status": "ERROR", "message": f"web write raised: {e}"}
        # ERROR with no per-record results: login failed, dns.he.net was not
        # reached, or the account has no zones, so no record was attempted.
        # Every record is an error (the manual Sync all answers 502 here).
        if result.get("status") == "ERROR" and not result.get("results"):
            logger.warning("henet scheduled sync: scope %r not written: %s",
                           tenant_id or "global", result.get("message") or "no reason given")
            return {"applied": 0, "errors": len(records), "skipped": 0,
                    "failure": "he_write_failed"}
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
        return {"applied": len(local), "errors": errors, "skipped": 0, "failure": None}

    async def sync_henet_scheduled(self) -> Dict[str, Any]:
        """One scheduled reconcile: re-apply every managed A/AAAA HE.NET record
        to Hurricane Electric, grouped + written per tenant scope. Returns a
        status dict (``status`` ``ok`` / ``skipped`` when the spoke is offline /
        ``error``, with a tenant-neutral ``reason`` when it is not ``ok``; see
        the module docstring). Never raises — the loop depends on it."""
        # Find the connected henet spoke; without it there is no record list to sync.
        spoke_id = self.get_spoke_by_type("henet")
        if not spoke_id:
            return self._record_henet_status(status="skipped",
                                              reason="HE.NET spoke not connected")
        # Ask the spoke for every managed record.
        try:
            listed = unwrap_spoke(await self.request_response(spoke_id, "HENET_LIST", {}, timeout=30.0))
        except Exception as e:  # noqa: BLE001
            listed = {"status": "ERROR", "message": str(e)}
        # A raise, or an ERROR reply (the hub answers a timeout with one), is
        # an error. Its details go to the log only.
        if not isinstance(listed, dict) or listed.get("status") == "ERROR":
            logger.warning("henet scheduled sync: HENET_LIST failed: %s", listed)
            return self._record_henet_status(status="error", reason=_LIST_FAILED_REASON)

        # The managed records list (empty if missing).
        records = listed.get("records") or []
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
            # Group by tenant scope ("" = global) so each scope uses its own
            # credential; one scope per tenant as same_tenant compares ids (a
            # legacy " ACME " twin keeps its own scope and credential). Built
            # this way, the keys are one per tenant, so tenant_key_in never
            # finds several here. The first record's spelling names the scope,
            # but it does not decide the credential: cred_ref_for_scope
            # matches slots in any case and refuses several.
            scope = raw_tenant_id(r.get("tenant_id"))
            scope = tenant_key_in(by_scope, scope) or scope
            by_scope.setdefault(scope, []).append(
                {"name": name, "type": rtype, "value": value,
                 "ttl": r.get("ttl", 300), "tenant_id": scope})

        # Nothing to sync.
        if not by_scope:
            return self._record_henet_status(status="ok", applied=0, errors=0,
                                             scopes=0, reason="no managed records")

        # Running totals across all scopes, the scopes that wrote nothing (by
        # class) and the records HE.NET rejected in the scopes that did write.
        totals = {"applied": 0, "errors": 0, "skipped": 0}
        failures: Dict[str, int] = {}
        rejected = 0
        # Write each scope and add up its results.
        for scope, recs in by_scope.items():
            res = await self._henet_write_scope(spoke_id, scope, recs)
            for k in totals:
                totals[k] += res.get(k, 0)
            # A scope that wrote nothing counts once, by class; otherwise its
            # errors are records HE.NET rejected.
            if res.get("failure"):
                failures[res["failure"]] = failures.get(res["failure"], 0) + 1
            else:
                rejected += res.get("errors", 0)

        # Any errors make the whole run "error", with a reason; otherwise "ok".
        if not totals["errors"]:
            return self._record_henet_status(status="ok", scopes=len(by_scope), **totals)
        return self._record_henet_status(status="error", scopes=len(by_scope), **totals,
                                         reason=_run_reason(len(by_scope), failures, rejected))

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
