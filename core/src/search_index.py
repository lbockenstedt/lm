"""In-memory global-search index — warm-cache-backed, live-fallback.

Global search (``/api/search`` → ``cross_system_search``) historically fanned
every query out to five live spokes (NetBox, hypervisor, NAC/CPPM, LDAP,
OPNsense/DHCP) and, for scoped callers, first did an *uncached* 30-second
NetBox prefix round-trip — so interactive typing paid full cross-system
latency on every keystroke-search even though the underlying inventory barely
changes.

This mixin keeps, per ``(leg, scope)``, the **full spoke-scoped result set**
(pulled in the background by re-issuing each leg's own search command with an
empty query, so the spoke applies its normal tenant scoping and returns the
exact result shape the UI expects). ``cross_system_search`` then serves matches
for a warmed scope straight from memory — no live fan-out, and the 30-second
prefix fetch drops off the request path entirely (prefixes are a deterministic
function of the tenant slug, so the background refresher owns that cost).

Safety contract (mirrors ``warm_cache`` / the console search leg):
  * The cache key includes the caller's **scope** (tenant slug + proxmox tag +
    admin flag). A caller only ever reads its own scope bucket, so a warmed
    index can never leak another tenant's rows — scoping stays spoke-side, the
    hub only substring-matches (exactly like ``console_port_matches``).
  * Every fast path degrades to the original live fan-out on a cache miss,
    a stale entry, an empty populate, or any error — so the worst case is
    today's behaviour, never a regression and never a fabricated result.
  * A populate that returns nothing (or a spoke that rejects an empty query)
    is simply not cached, leaving that leg on the live path.

A leaf: stdlib only. MUST NOT import ``main``/``api``. Audience: Hub developers.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("Hub")

# (leg key surfaced in ``spokes_queried``, spoke search command).
SEARCH_LEGS: List[Tuple[str, str]] = [
    ("ipam", "NETBOX_SEARCH"),
    ("hypervisor", "SEARCH_VMS"),
    ("nac", "SEARCH_SESSIONS"),
    ("directory", "SEARCH_USERS"),
    ("firewall", "SEARCH_DHCP"),
]
# Only this leg consumes the (expensive) tenant prefixes in its scoped payload;
# the others scope by tenant slug / proxmox tag alone.
PREFIX_SCOPED_CMD = "SEARCH_DHCP"

_MAX_BLOB_FIELD = 256  # ignore oversized/opaque values when building match blob


# ── pure helpers (unit-testable, no hub/network) ───────────────────────────────
def search_scope_key(nb_slug: str, proxmox_tag: str, is_admin: bool) -> str:
    """Stable key for a caller's *scope*.

    Prefixes are intentionally omitted: they are a deterministic function of the
    NetBox tenant slug (``NETBOX_GET_PREFIXES`` for that slug), so the slug fully
    identifies the DHCP scope — letting the request path compute this key WITHOUT
    the 30-second prefix fetch (which moves into the background populate)."""
    payload = {
        "slug": nb_slug or "",
        "ptag": proxmox_tag or "",
        "admin": bool(is_admin),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def search_result_blob(item: Dict[str, Any]) -> str:
    """Lower-cased, space-joined blob of an item's scalar fields — the haystack
    a query needle is tested against (mirrors ``console_port_search_blob``)."""
    if not isinstance(item, dict):
        return str(item).lower()
    parts: List[str] = []
    for v in item.values():
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, (str, int, float)):
            s = str(v)
            if s and len(s) <= _MAX_BLOB_FIELD:
                parts.append(s)
    return " ".join(parts).lower()


def search_result_matches(item: Dict[str, Any], needle: str) -> bool:
    """True when the (already lower-cased, non-empty) ``needle`` is a substring
    of the item's identifier blob."""
    return bool(needle) and needle in search_result_blob(item)


def _extract_results(unwrapped: Any) -> Optional[List[Dict[str, Any]]]:
    """Pull the ``results`` list out of an unwrapped spoke envelope, or None if
    the envelope is an error / not a usable result set. Error rows inside the
    list are dropped so a transient per-item error never poisons the cache."""
    if not isinstance(unwrapped, dict):
        return None
    if unwrapped.get("status") == "ERROR":
        return None
    results = unwrapped.get("results")
    if not isinstance(results, list):
        return None
    return [r for r in results if isinstance(r, dict) and r.get("type") != "error"]


class SearchIndexMixin:
    """Background-refreshed, warm-cache-backed global-search index."""

    # ── config (env-overridable) ─────────────────────────────────────────────
    @property
    def _search_index_enabled(self) -> bool:
        return os.environ.get("LM_SEARCH_INDEX", "1").strip().lower() not in (
            "0", "false", "off", "no", "")

    @property
    def _search_index_interval(self) -> float:
        try:
            return max(10.0, float(os.environ.get("LM_SEARCH_INDEX_INTERVAL", "60")))
        except (TypeError, ValueError):
            return 60.0

    @property
    def _search_index_ttl(self) -> float:
        """Max age a cached leg set may reach before the request path treats it
        as stale and falls back to a live call for that leg."""
        try:
            return max(30.0, float(os.environ.get("LM_SEARCH_INDEX_TTL", "180")))
        except (TypeError, ValueError):
            return 180.0

    @property
    def _search_index_max_items(self) -> int:
        try:
            return max(100, int(os.environ.get("LM_SEARCH_INDEX_MAX_ITEMS", "5000")))
        except (TypeError, ValueError):
            return 5000

    # ── lifecycle ────────────────────────────────────────────────────────────
    def search_index_init(self) -> None:
        """Initialise scope registry. Call once from ``__init__`` (after
        ``warm_cache_init``)."""
        # scope_key -> {"resolved": str, "is_admin": bool, "proxmox_tag": str,
        #               "nb_slug": str, "seen": epoch}
        self._search_scopes: Dict[str, Dict[str, Any]] = {}

    def search_index_enabled(self) -> bool:
        return self._search_index_enabled

    @staticmethod
    def _search_ns(cmd: str) -> str:
        return f"search_idx_{cmd}"

    # ── request-path reads ────────────────────────────────────────────────────
    def search_register_scope(self, scope_key: str, *, resolved: str,
                              is_admin: bool, nb_slug: str,
                              proxmox_tag: str) -> None:
        """Record a scope the request path has observed so the background loop
        keeps it warm. Cheap + idempotent (just refreshes ``seen``)."""
        try:
            self._search_scopes[scope_key] = {
                "resolved": resolved or "",
                "is_admin": bool(is_admin),
                "nb_slug": nb_slug or "",
                "proxmox_tag": proxmox_tag or "",
                "seen": time.time(),
            }
        except Exception:  # pragma: no cover - registry is best-effort
            pass

    def search_index_leg_items(self, cmd: str, scope_key: str
                               ) -> Optional[List[Dict[str, Any]]]:
        """Fresh cached full result set for ``(cmd, scope)``, or None when the
        entry is absent or older than the TTL (→ caller falls back to a live
        leg call)."""
        entry = self.warm_get(self._search_ns(cmd), scope_key)
        if not isinstance(entry, dict):
            return None
        at = entry.get("at", 0)
        if not at or at < time.time() - self._search_index_ttl:
            return None
        items = entry.get("items")
        return items if isinstance(items, list) else None

    def search_leg_is_warm(self, cmd: str, scope_key: str) -> bool:
        return self.search_index_leg_items(cmd, scope_key) is not None

    # ── background populate ───────────────────────────────────────────────────
    def _resolve_search_spokes(self, resolved: str, is_admin: bool
                               ) -> Dict[str, Optional[str]]:
        """Map each leg command to the spoke that serves it for this scope —
        the SAME resolution ``cross_system_search`` uses (tenant-bound
        hypervisor/directory so a scope never reaches another tenant's spoke)."""
        scoped = bool(resolved and resolved != "default")
        if scoped:
            hypervisor = self.get_hypervisor_spoke_for_tenant(resolved)
            directory = (self.get_directory_spoke_for_tenant(resolved)
                         or self.get_spoke_by_type("directory"))
        else:
            hypervisor = self.get_hypervisor_spoke()
            directory = self.get_spoke_by_type("directory")
        return {
            "NETBOX_SEARCH": self.get_spoke_by_type("ipam"),
            "SEARCH_VMS": hypervisor,
            "SEARCH_SESSIONS": self.get_spoke_by_type("nac"),
            "SEARCH_USERS": directory,
            "SEARCH_DHCP": self.get_spoke_by_type("firewall"),
        }

    async def _search_scope_payload(self, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Build the empty-query, fully-scoped populate payload for a scope,
        fetching tenant prefixes here (off the request path) for the DHCP leg."""
        nb_slug = scope.get("nb_slug") or ""
        prefixes: List[str] = []
        if nb_slug:
            try:
                import access
                prefixes = await access.resolve_prefixes_for_tenant(
                    self, scope.get("resolved")) or []
            except Exception as e:  # noqa: BLE001 - best-effort warm-up
                logger.debug("search-index: prefix fetch for '%s' failed: %s",
                             scope.get("resolved"), e)
        return {
            "q": "",
            "tenant": nb_slug,
            "proxmox_tag": scope.get("proxmox_tag") or "",
            "prefixes": prefixes,
            "is_admin": bool(scope.get("is_admin")),
        }

    async def _search_populate_leg(self, cmd: str, spoke: Optional[str],
                                   scope_key: str, payload: Dict[str, Any]
                                   ) -> None:
        """Refresh one ``(leg, scope)`` cache entry. Never raises; only stores a
        non-empty, well-formed result set (so a rejected empty-query or a down
        spoke leaves the leg on the live path)."""
        if not spoke:
            return
        try:
            r = await self.request_response(spoke, cmd, payload)
        except Exception as e:  # noqa: BLE001 - a leg failure must not break others
            logger.debug("search-index populate %s/%s failed: %s", cmd, scope_key, e)
            return
        try:
            import access  # leaf module (no api/main cycle)
            unwrapped = access.unwrap_spoke(r)
        except Exception:  # pragma: no cover - fall back to raw dict shape
            unwrapped = r
        results = _extract_results(unwrapped)
        if not results:
            return
        if len(results) > self._search_index_max_items:
            results = results[: self._search_index_max_items]
        await self.warm_set(self._search_ns(cmd), scope_key,
                            {"items": results, "at": time.time()})

    async def _search_refresh_once(self) -> None:
        scopes = list(self._search_scopes.items())
        for scope_key, scope in scopes:
            try:
                spokes = self._resolve_search_spokes(
                    scope.get("resolved") or "", bool(scope.get("is_admin")))
                payload = await self._search_scope_payload(scope)
                for _leg, cmd in SEARCH_LEGS:
                    await self._search_populate_leg(
                        cmd, spokes.get(cmd), scope_key, payload)
            except Exception as e:  # noqa: BLE001 - one bad scope must not stall the loop
                logger.debug("search-index refresh scope %s failed: %s", scope_key, e)

    async def run_search_index_refresh_loop(self) -> None:
        """Periodically re-populate every observed scope's leg caches."""
        while True:
            try:
                if self._search_index_enabled and self._search_scopes:
                    await self._search_refresh_once()
            except asyncio.CancelledError:  # pragma: no cover
                raise
            except Exception as e:  # noqa: BLE001 - loop must survive any error
                logger.warning("search-index refresh loop error: %s", e)
            await asyncio.sleep(self._search_index_interval)
