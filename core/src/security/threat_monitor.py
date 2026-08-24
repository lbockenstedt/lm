"""Threat monitor — detect brute-force / faked-credential attacks on the hub API
and (optionally) auto-block the source IP via the Azure NSG deny rule.

Signals fed in from the auth layer (api.py):
  * failed logins            (``record_failure(ip, "login", username)``)
  * present-but-invalid       session cookie / API token
    credential ("faked key")  (``record_failure(ip, "session")``)
  * spoke-onboarding probes   (``record_failure(ip, "spoke_auth")``) — a wrong
    onboarding PSK, an invalid session secret, or a malformed/incomplete
    ``/ws/spoke`` auth frame (fed from main.handle_connection). The hub serves
    ``/ws/spoke`` directly, so the WebSocket peer is the real client IP.

Policy (all configurable via ``global_config["threat_monitor"]``):
  * ``> threshold`` failures from one IP within ``window_s`` → BLOCK (default: >5).
  * A block auto-expires after ``ttl_s`` (default 24h) unless it is permanent.
  * Repeat offender: an IP blocked → auto-released → re-blocked
    ``permanent_after`` times becomes a PERMANENT block (never expires).
  * ``auto_block`` toggles whether a block reaches Azure (log-only when off).

Self-lockout safeguards — an IP is NEVER auto-blocked when it is:
  * on the shared trusted / allow-list (``global_config["azure_nsg"]["entries"]``),
  * a recent successful-login IP (within ``success_grace_s``).

SHARED TRUSTED LIST — the "never auto-block" list and the Azure NSG allow-list
are ONE list, canonically ``global_config["azure_nsg"]["entries"]`` (shape
``[{ip, description}]``). An entry is BOTH never-auto-blocked AND allowed through
the NSG. The list itself is never gated on ``azure_nsg.enabled`` (never-block
works even when Azure is unused); the allow-rule reconcile only reaches ARM when
azure_nsg is enabled + configured. The legacy private ``_never`` list is merged
into this shared list once on load (see ``_migrate_never_to_entries``) and then
left empty. Both the Azure NSG tile and the Security never-block tile edit this
same list.

NSG shape: blocks are reconciled — one prefix per IP — onto a dedicated DENY
rule (``block_rule_name``). Priority ordering invariant (Azure evaluates LOWER
priority numbers FIRST): the ALLOW rule is evaluated first, the DENY rule sits
just ABOVE it (a HIGHER number), and both sit below Azure's default allow on 443
(priority 1000) — i.e. ``allow_priority < block_priority < 1000``. See
``validate_nsg_priorities``. Per-IP "why" descriptions are kept hub-local here (Azure rules
carry one description each) and surfaced in the WebUI Security view. A leaf-ish
module: stdlib + azure_nsg.
"""
import asyncio
import ipaddress
import json
import logging
import os
import time
from collections import deque
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ThreatMonitor")
sec_log = logging.getLogger("Security")  # dedicated audit stream (relayed + on-box)

_DEFAULTS = {
    "enabled": True,          # detect + log
    "auto_block": False,      # actually edit the NSG (opt-in; log-only until on)
    "threshold": 5,           # > this many failures in the window → block
    "window_s": 600,          # failure counting window (10 min)
    "ttl_s": 86400,           # temporary block lifetime (24h)
    "permanent_after": 3,     # re-blocks after auto-release → permanent
    "success_grace_s": 3600,  # a recently-authenticated IP is exempt for this long
    "block_rule_name": "lm-threat-block",
    # Allow is evaluated first; Deny sits just above it (a HIGHER number), both
    # below the 1000 default-allow on 443 → allow(300) < block(400) < 1000.
    "block_priority": 400,
}
_EVENTS_MAX = 500


def _bound_meta(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Clamp a structured-evidence dict so a hostile client can't bloat the
    persisted state file: at most 32 keys, key names <=64 chars, and each
    non-numeric value coerced to a <=512-char string. Returns {} for empties."""
    if not meta:
        return {}
    out: Dict[str, Any] = {}
    for k, v in list(meta.items())[:32]:
        out[str(k)[:64]] = v if isinstance(v, (int, float, bool)) else str(v)[:512]
    return out


def _now() -> float:
    return time.time()


_DEFAULT_ALLOW_ON_443 = 1000  # Azure's built-in AllowVnetInBound-style default


def validate_nsg_priorities(allow_priority: Any, block_priority: Any) -> tuple:
    """Validate the allow/deny NSG priority ordering. Azure evaluates LOWER
    priority numbers FIRST, so for an allow-list + block-list model the ALLOW
    rule must be evaluated before the DENY rule, and both must sit below Azure's
    default allow on 443 (priority 1000). The invariant is therefore:

        allow_priority < block_priority   AND   block_priority < 1000
        (which also implies allow_priority < 1000)

    Pure function. Returns ``(ok: bool, message: str)`` — ``ok`` iff the invariant
    holds; ``message`` names the exact violation(s) (empty when ok)."""
    try:
        ap = int(allow_priority)
        bp = int(block_priority)
    except (TypeError, ValueError):
        return (False, "Allow and Deny priorities must both be integers.")
    problems = []
    if not (ap < bp):
        problems.append(
            f"Allow priority ({ap}) must be LOWER than Deny priority ({bp}) — "
            f"Azure evaluates lower numbers first, so the allow rule must be "
            f"evaluated before the deny rule.")
    if not (bp < _DEFAULT_ALLOW_ON_443):
        problems.append(
            f"Deny priority ({bp}) must be below {_DEFAULT_ALLOW_ON_443} — "
            f"Azure's default allow on 443 is {_DEFAULT_ALLOW_ON_443}.")
    if not (ap < _DEFAULT_ALLOW_ON_443):
        problems.append(
            f"Allow priority ({ap}) must be below {_DEFAULT_ALLOW_ON_443} — "
            f"Azure's default allow on 443 is {_DEFAULT_ALLOW_ON_443}.")
    if problems:
        return (False, " ".join(problems))
    return (True, "")


def priority_conflict_warning(block_priority: Any, allow_priority: Any) -> str:
    """Back-compatible alias for legacy callers (arg order is ``(block, allow)``).
    Returns "" when the ordering is valid, else the violation message from
    ``validate_nsg_priorities``."""
    ok, message = validate_nsg_priorities(allow_priority, block_priority)
    return "" if ok else message


class ThreatMonitor:
    def __init__(self, hub) -> None:
        self.hub = hub
        self._events: deque = deque(maxlen=_EVENTS_MAX)   # recent auth failures
        self._ip_fails: Dict[str, List[float]] = {}       # ip -> [ts] in-window
        self._blocks: Dict[str, Dict[str, Any]] = {}      # ip -> block record
        self._recent_success: Dict[str, float] = {}       # ip -> last-success ts
        self._offense: Dict[str, int] = {}                # ip -> lifetime block count
        self._never: List[str] = []                       # legacy; merged into shared list on load
        # Durable cumulative counters — MONOTONIC lifetime tallies that survive
        # block expiry, unblock, and the bounded events deque rolling over. They
        # answer "is the system seeing/evaluating anything?" even when there are
        # zero *active* blocks. Never decremented.
        self._totals: Dict[str, Any] = {
            "signals": 0,        # every failure + anomaly ingested (things evaluated)
            "failures": 0,       # auth failures (record_failure)
            "anomalies": 0,      # note_anomaly calls
            "blocks_placed": 0,  # blocks ever created (auto + manual)
            "blocks_permanent": 0,
            "unblocks": 0,       # manual releases
            "by_kind": {},       # {kind: count} across failures + anomalies
            "since": _now(),     # first-init epoch
            "last_ts": 0.0,      # last signal epoch
        }
        self._cfg: Dict[str, Any] = dict(_DEFAULTS)
        self._nsg_dirty = False
        self._load()
        # The deny rule NAME last confirmed pushed to Azure — distinct from
        # self._cfg["block_rule_name"], which updates synchronously on every
        # set_config() call even before the async reconcile has actually run.
        # reconcile_nsg() compares against THIS to detect a rename and delete
        # the stale old-named rule (see reconcile_nsg's docstring for why that
        # matters: Azure NSG rules are keyed by name, so a rename that only
        # PUTs the new name leaves the old rule — same priority + direction —
        # still live, and ARM rejects the PUT with SecurityRuleConflict).
        # Best-effort assumption at boot: the last-persisted name is whatever
        # was live before the process restarted.
        self._nsg_live_rule_name: Optional[str] = self._cfg.get("block_rule_name")
        self._migrate_never_to_entries()  # one-time: fold legacy _never into shared entries

    # ── config ───────────────────────────────────────────────────────────────
    def config(self) -> Dict[str, Any]:
        return dict(self._cfg)

    def set_config(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        for k, default in _DEFAULTS.items():
            if k in patch:
                v = patch[k]
                if isinstance(default, bool):
                    self._cfg[k] = bool(v)
                elif isinstance(default, int):
                    try:
                        self._cfg[k] = max(0, int(v))
                    except (TypeError, ValueError):
                        pass
                else:
                    self._cfg[k] = str(v)
        self._cfg["threshold"] = max(1, int(self._cfg["threshold"]))
        self._persist()
        # A block_rule_name / block_priority / auto_block change must be re-pushed
        # so the ARM deny rule is (re)created with the new name/priority.
        self._nsg_dirty = True
        self._schedule_reconcile()
        return self.config()

    # ── durable cumulative counters ────────────────────────────────────────────
    def _bump_signal(self, kind: str, *, anomaly: bool) -> None:
        """Increment the monotonic lifetime tallies for one ingested signal.

        Called for every auth failure and every anomaly so the operator can tell
        the system is evaluating traffic even after all active blocks expire."""
        t = self._totals
        t["signals"] = int(t.get("signals", 0)) + 1
        t["anomalies" if anomaly else "failures"] = int(
            t.get("anomalies" if anomaly else "failures", 0)) + 1
        bk = t.setdefault("by_kind", {})
        k = kind or ("anomaly" if anomaly else "unknown")
        bk[k] = int(bk.get(k, 0)) + 1
        t["last_ts"] = _now()

    # ── ingest ─────────────────────────────────────────────────────────────────
    def record_failure(self, ip: str, kind: str, username: Optional[str] = None,
                        detail: str = "", meta: Optional[Dict[str, Any]] = None,
                        *, max_ttl_s: Optional[float] = None,
                        allow_permanent: bool = True) -> None:
        """Record an auth failure from ``ip``. Blocks the IP once it crosses the
        threshold within the window (unless exempt). Safe to call from sync code.

        ``meta`` is optional structured evidence (e.g. request path/method/
        user-agent) stored on the event so the operator can drill into exactly
        what failed from the Security UI; see :func:`_bound_meta`.

        ``max_ttl_s`` / ``allow_permanent`` bound the resulting block: an
        edge-*reported* signal (see the hub's ``_handle_edge_probe_report``)
        passes a short ``max_ttl_s`` and ``allow_permanent=False`` so that even a
        corroborated report can only ever place a short, self-expiring block —
        never a permanent one — capping the blast radius of a compromised edge."""
        ip = (ip or "").strip()
        if not ip or not self._cfg.get("enabled"):
            return
        now = _now()
        self._bump_signal(kind, anomaly=False)
        evt = {"ts": now, "ip": ip, "kind": kind,
               "username": username or "", "detail": detail, "anomaly": False}
        m = _bound_meta(meta)
        if m:
            evt["meta"] = m
        self._events.appendleft(evt)
        if ip in self._blocks or self._is_exempt(ip):
            return  # already blocked, or trusted — still logged above
        window = self._cfg["window_s"]
        hits = [t for t in self._ip_fails.get(ip, []) if t > now - window]
        hits.append(now)
        self._ip_fails[ip] = hits
        if len(self._ip_fails) > 4096:  # memory hygiene under spoofed-source rotation
            self._prune_fails()
        if len(hits) > self._cfg["threshold"]:
            self._block(ip, reason=self._reason(ip, kind, username, len(hits)),
                        kind=kind, source="auto",
                        max_ttl_s=max_ttl_s, allow_permanent=allow_permanent)

    def record_success(self, ip: str) -> None:
        ip = (ip or "").strip()
        if ip:
            self._recent_success[ip] = _now()
            self._ip_fails.pop(ip, None)

    def _reason(self, ip: str, kind: str, username: Optional[str], count: int) -> str:
        who = f" as '{username}'" if username else ""
        label = {"login": "failed logins", "session": "invalid session tokens",
                 "api_key": "invalid API keys",
                 "spoke_auth": "invalid spoke onboarding attempts",
                 "http_probe": "HTTPS-port scan probes (paths we never serve)",
                 "session_hijack": "concurrent admin session-cookie use"}.get(kind, f"{kind} failures")
        mins = max(1, int(self._cfg["window_s"] / 60))
        return f"{count} {label}{who} within {mins}m"

    # ── blocking ───────────────────────────────────────────────────────────────
    def _block(self, ip: str, reason: str, kind: str, source: str,
               *, max_ttl_s: Optional[float] = None,
               allow_permanent: bool = True) -> None:
        now = _now()
        self._offense[ip] = self._offense.get(ip, 0) + 1
        permanent = (source == "manual_perm"
                     or (allow_permanent
                         and self._offense[ip] >= self._cfg["permanent_after"]))
        ttl = self._cfg["ttl_s"]
        if max_ttl_s is not None:
            ttl = min(ttl, max_ttl_s)
        rec = {
            "ip": ip, "reason": reason, "kind": kind, "source": source,
            "blocked_at": now, "offense_count": self._offense[ip],
            "permanent": permanent,
            "expires_at": None if permanent else now + ttl,
        }
        self._blocks[ip] = rec
        self._ip_fails.pop(ip, None)
        self._totals["blocks_placed"] = int(self._totals.get("blocks_placed", 0)) + 1
        if permanent:
            self._totals["blocks_permanent"] = int(self._totals.get("blocks_permanent", 0)) + 1
        self._nsg_dirty = True
        self._persist()
        sec_log.warning("THREAT BLOCK %s (%s) — %s%s", ip, source, reason,
                        " [PERMANENT]" if permanent else
                        f" [expires {int(ttl) // 3600}h]")
        self._schedule_reconcile()

    def block_manual(self, ip: str, reason: str = "", permanent: bool = False) -> Dict[str, Any]:
        ip = (ip or "").strip()
        if not ip:
            return {"status": "ERROR", "message": "ip required"}
        self._block(ip, reason or "manually blocked",
                    kind="manual", source="manual_perm" if permanent else "manual")
        return {"status": "SUCCESS", "block": self._blocks.get(ip)}

    def block_ip_unless_trusted(self, ip: str, reason: str = "",
                                kind: str = "session_hijack") -> Dict[str, Any]:
        """Immediately block ``ip`` UNLESS it is exempt (allow-listed/trusted, or
        inside the recent-successful-login grace).

        The admin session-hijack response: a concurrent two-IP use of one admin
        cookie is ambiguous — we can't be certain which IP is the attacker — so
        we block every *involved* source that isn't trusted. That spares a
        trusted or freshly-authenticated roaming admin IP while still cutting off
        a non-allowlisted attacker. (``block_manual`` deliberately bypasses the
        exemption; this wrapper is the exemption-respecting variant.)

        ``kind`` labels the block record for the Security tally/tiles; it
        defaults to ``session_hijack`` for the original caller, but any anomaly
        source (see :meth:`note_anomaly`) can attribute its own kind."""
        ip = (ip or "").strip()
        if not ip:
            return {"status": "ERROR", "message": "ip required"}
        if self._is_exempt(ip):
            sec_log.warning(
                "THREAT hijack-response: %s SPARED (trusted/allow-listed or "
                "recent login) — %s", ip, reason)
            return {"status": "SUCCESS", "spared": ip, "reason": "trusted"}
        self._block(ip, reason or "concurrent admin session-cookie use",
                    kind=kind, source="auto")
        return {"status": "SUCCESS", "block": self._blocks.get(ip)}

    def note_anomaly(self, kind: str, detail: str = "",
                     ip: Optional[str] = None, severity: str = "warning",
                     meta: Optional[Dict[str, Any]] = None) -> None:
        """Record a non-auth security anomaly (e.g. from the in-process
        :mod:`security.sentinel` tripwire — a contract breach, canary trip, or
        vault-read volume spike).

        Always lands in the ``Security`` audit stream + the recent-events feed.
        When an ``ip`` is attributable and the signal is ``critical``, it also
        drives an exemption-respecting NSG block (reusing the hijack response) so
        a remote attacker is cut off; a purely local signal (no IP) is CRITICAL-
        logged for the operator/host-layer response. Safe to call from sync code;
        never raises into the caller.

        ``meta`` is an optional dict of structured evidence about the signal
        (e.g. the offending request's method/path/headers) that the operator can
        drill into from the Security UI. It is stored verbatim on the event and
        persisted with it, so keep it small and JSON-serializable."""
        try:
            now = _now()
            self._bump_signal(kind, anomaly=True)
            evt = {"ts": now, "ip": (ip or "").strip(),
                   "kind": kind, "username": "",
                   "detail": detail, "severity": severity, "anomaly": True}
            m = _bound_meta(meta)
            if m:
                evt["meta"] = m
            self._events.appendleft(evt)
            level = logging.ERROR if severity == "critical" else logging.WARNING
            sec_log.log(level, "SECURITY ANOMALY %s [%s]%s — %s", kind, severity,
                        f" from {ip}" if ip else "", detail)
            if severity == "critical" and (ip or "").strip():
                self.block_ip_unless_trusted(ip, reason=f"{kind}: {detail}", kind=kind)
        except Exception:
            sec_log.exception("note_anomaly failed for kind=%s", kind)

    def self_test(self) -> Dict[str, Any]:
        """Operator-initiated detection self-test: record ONE synthetic signal so
        the full pipeline (ingest → tally → persist → snapshot → Security view) can
        be verified end-to-end without a real attack.

        Deliberately benign: severity ``warning`` and no attributable IP, so it
        NEVER places an NSG block. It increments the lifetime tallies under the
        ``selftest`` kind (clearly labelled, easy to discount) and lands in the
        recent-events feed. Returns the post-test totals for immediate display."""
        self.note_anomaly("selftest", "operator-initiated detection self-test "
                          "(synthetic; no IP → never blocks)", ip=None, severity="warning")
        t = dict(self._totals)
        sec_log.warning("SECURITY SELF-TEST recorded — pipeline OK (signals=%s)",
                        t.get("signals"))
        return {"status": "SUCCESS", "totals": t}

    def unblock(self, ip: str) -> Dict[str, Any]:
        ip = (ip or "").strip()
        existed = self._blocks.pop(ip, None)
        if existed:
            self._totals["unblocks"] = int(self._totals.get("unblocks", 0)) + 1
            self._nsg_dirty = True
            self._persist()
            sec_log.info("THREAT UNBLOCK %s (manual)", ip)
            self._schedule_reconcile()
        return {"status": "SUCCESS", "removed": bool(existed)}

    # ── shared trusted / allow list (== global_config["azure_nsg"]["entries"]) ──
    def _shared_entries(self) -> List[Dict[str, str]]:
        """The canonical shared list, normalized ([{ip: CIDR, description}])."""
        try:
            import azure_nsg as _nsg
            gc = self.hub.state.system_state.get("global_config", {}) or {}
            entries = (gc.get("azure_nsg", {}) or {}).get("entries") or []
            return _nsg.normalize_entries(entries)
        except Exception:  # noqa: BLE001
            return []

    def _save_shared_entries(self, entries: List[Dict[str, str]]) -> None:
        gc = self.hub.state.system_state.get("global_config", {})
        az = dict(gc.get("azure_nsg", {}) or {})
        az["entries"] = entries
        gc["azure_nsg"] = az
        self.hub.state.system_state["global_config"] = gc
        try:
            self.hub.state._mark_dirty()
        except Exception:  # noqa: BLE001
            pass

    def _migrate_never_to_entries(self) -> None:
        """One-time: merge any legacy private ``_never`` CIDRs into the shared
        ``azure_nsg.entries`` (union, dedup by CIDR, normalized; new ones tagged
        'migrated from never-block' — existing descriptions preserved), then empty
        ``_never`` so the shared list is the sole source of truth going forward."""
        if not self._never:
            return
        try:
            import azure_nsg as _nsg
        except Exception:  # noqa: BLE001
            return
        try:
            entries = _nsg.normalize_entries(self._shared_entries())
            have = {e["ip"] for e in entries}
            added = 0
            for c in self._never:
                try:
                    norm = _nsg.normalize_entries(
                        [{"ip": c, "description": "migrated from never-block"}])
                except Exception:  # noqa: BLE001
                    continue
                if norm and norm[0]["ip"] not in have:
                    entries.append(norm[0])
                    have.add(norm[0]["ip"])
                    added += 1
            self._save_shared_entries(entries)
            self._never = []
            self._persist()
            logger.info("threat_monitor: migrated legacy never-block list into "
                        "shared azure_nsg.entries (%d new, %d total)", added, len(entries))
        except Exception as e:  # noqa: BLE001
            logger.warning("threat_monitor never-block migration failed: %s", e)

    def add_trusted(self, ip: str, description: str = "") -> Dict[str, Any]:
        """Add an IP/CIDR to the shared trusted list (never-block + NSG allow).
        Immediately unblocks any now-exempt IP and marks the deny/allow rules for
        reconcile. Callers should ``await reconcile_allow()`` to push to Azure."""
        raw = (ip or "").strip()
        if not raw:
            return {"status": "ERROR", "message": "ip required"}
        try:
            import azure_nsg as _nsg
            entries = _nsg.normalize_entries(
                self._shared_entries() + [{"ip": raw, "description": description or ""}])
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}
        self._save_shared_entries(entries)
        # An IP that becomes exempt is immediately unblocked.
        ips = [e["ip"] for e in entries]
        for bip in list(self._blocks):
            if self._in_cidr(bip, ips):
                self._blocks.pop(bip, None)
                self._nsg_dirty = True
        self._persist()
        self._schedule_reconcile()  # deny rule (any unblocked IPs removed)
        return {"status": "SUCCESS", "entries": entries}

    def remove_trusted(self, ip: str) -> Dict[str, Any]:
        """Remove an IP/CIDR from the shared trusted list. Callers should
        ``await reconcile_allow()`` to close the NSG hole in Azure."""
        raw = (ip or "").strip()
        try:
            import azure_nsg as _nsg
            target = _nsg.normalize_entries([{"ip": raw}])
        except Exception:  # noqa: BLE001
            target = []
        tip = target[0]["ip"] if target else raw
        entries = [e for e in self._shared_entries() if e["ip"] != tip]
        self._save_shared_entries(entries)
        self._persist()
        return {"status": "SUCCESS", "entries": entries}

    # Legacy aliases (private ``_never`` is retired; these now edit the shared list).
    def add_never(self, cidr: str) -> Dict[str, Any]:
        return self.add_trusted(cidr)

    def remove_never(self, cidr: str) -> Dict[str, Any]:
        return self.remove_trusted(cidr)

    def allow_priority(self) -> int:
        """The Azure NSG allow rule's priority (for Deny<Allow ordering checks)."""
        try:
            gc = self.hub.state.system_state.get("global_config", {}) or {}
            return int((gc.get("azure_nsg", {}) or {}).get("priority") or 300)
        except Exception:  # noqa: BLE001
            return 300

    # ── exemptions ─────────────────────────────────────────────────────────────
    def _is_exempt(self, ip: str) -> bool:
        # (1) recent successful login
        last = self._recent_success.get(ip)
        if last and last > _now() - self._cfg["success_grace_s"]:
            return True
        # (2) shared trusted / Azure NSG allow-list (the sole never-block source)
        if self._in_cidr(ip, self._allowlist_ips()):
            return True
        return False

    def _allowlist_ips(self) -> List[str]:
        return [e["ip"] for e in self._shared_entries() if e.get("ip")]

    @staticmethod
    def _in_cidr(ip: str, cidrs: List[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for c in cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _prune_fails(self) -> None:
        now = _now()
        window = self._cfg["window_s"]
        self._ip_fails = {ip: hs for ip, hs in self._ip_fails.items()
                          if any(t > now - window for t in hs)}

    # ── sweep + NSG reconcile ──────────────────────────────────────────────────
    def sweep(self) -> None:
        """Expire temporary blocks whose TTL has elapsed; mark NSG dirty when the
        block set changed. Called on a timer from the hub."""
        now = _now()
        expired = [ip for ip, r in self._blocks.items()
                   if not r.get("permanent") and r.get("expires_at") and r["expires_at"] <= now]
        for ip in expired:
            self._blocks.pop(ip, None)
            self._nsg_dirty = True
            sec_log.info("THREAT AUTO-RELEASE %s (24h TTL elapsed; offense #%d)",
                         ip, self._offense.get(ip, 0))
        # Evict stale success stamps.
        grace = self._cfg["success_grace_s"]
        self._recent_success = {ip: t for ip, t in self._recent_success.items()
                                if t > now - grace}
        # Always flush: persists the recent-events evidence feed (signals / auth
        # failures / anomalies and their drill-down meta) at least once per sweep
        # so it survives a restart even when no block changed this tick.
        self._persist()

    def _schedule_reconcile(self) -> None:
        try:
            asyncio.get_running_loop().create_task(self.reconcile_nsg())
        except RuntimeError:
            pass  # no loop (e.g. under sync test) — the sweep loop will catch up

    def _schedule_allow_reconcile(self) -> None:
        try:
            asyncio.get_running_loop().create_task(self.reconcile_allow())
        except RuntimeError:
            pass  # no loop (e.g. under sync test)

    async def reconcile_allow(self) -> Dict[str, Any]:
        """Push the shared trusted list onto the Azure NSG ALLOW rule (the same
        rule the Azure NSG tile manages). No-op unless azure_nsg is enabled +
        configured — the trusted list itself is never gated on ``enabled`` (so
        never-block always works), only the reach-to-ARM step is."""
        try:
            import azure_nsg as _nsg
            from security.oidc import get_oidc_config
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"nsg import: {e}"}
        gc = self.hub.state.system_state.get("global_config", {}) or {}
        azcfg = dict(gc.get("azure_nsg", {}) or {})
        if not azcfg.get("enabled"):
            return {"status": "SKIPPED", "message": "Azure NSG disabled — list saved, not applied"}
        if not all(azcfg.get(k) for k in ("subscription_id", "resource_group", "nsg_name")):
            return {"status": "SKIPPED", "message": "Azure NSG not configured"}
        ips = _nsg.entries_to_ips(azcfg.get("entries") or [])
        try:
            res = await _nsg.reconcile_allowlist(get_oidc_config(self.hub), azcfg, ips)
            sec_log.info("THREAT NSG allow-rule reconciled: %d IP(s) on %s/%s",
                         len(ips), azcfg.get("nsg_name"),
                         azcfg.get("rule_name") or "lm-allowlist")
            return {"status": "SUCCESS", "count": len(ips), **res}
        except Exception as e:  # noqa: BLE001
            logger.warning("threat allow-rule reconcile failed: %s", e)
            return {"status": "ERROR", "message": str(e)}

    async def reconcile_nsg(self) -> Dict[str, Any]:
        """Push the current blocked-IP set onto the Azure NSG deny rule (one
        prefix per IP). No-op unless auto_block is ON and azure_nsg is configured.
        Empty set → the deny rule is deleted (reconcile_allowlist semantics).

        If ``block_rule_name`` changed since the last successful reconcile,
        the OLD-named rule is deleted FIRST. Azure NSG rules are keyed by
        name: a rename that only PUTs the new name leaves the old rule (same
        priority + direction) still live in the NSG, and ARM rejects the new
        PUT with ``SecurityRuleConflict`` — "Rules cannot have the same
        Priority and Direction." ``self._nsg_live_rule_name`` (not
        ``self._cfg``, which updates synchronously on every ``set_config()``
        call regardless of whether this async reconcile has run yet) tracks
        the name actually confirmed pushed, so a burst of rapid renames
        before a reconcile fires still deletes the ORIGINAL live name, not
        an intermediate one that was never actually created in Azure."""
        if not self._nsg_dirty:
            return {"status": "SKIPPED", "message": "no change"}
        self._nsg_dirty = False
        if not self._cfg.get("auto_block"):
            return {"status": "SKIPPED", "message": "auto-block off (log-only)"}
        try:
            import azure_nsg as _nsg
            from security.oidc import get_oidc_config
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"nsg import: {e}"}
        gc = self.hub.state.system_state.get("global_config", {}) or {}
        azcfg = dict(gc.get("azure_nsg", {}) or {})
        if not all(azcfg.get(k) for k in ("subscription_id", "resource_group", "nsg_name")):
            return {"status": "SKIPPED", "message": "Azure NSG not configured — logged only"}
        deny_cfg = dict(azcfg)
        new_name = self._cfg.get("block_rule_name") or "lm-threat-block"
        deny_cfg["rule_name"] = new_name
        deny_cfg["access"] = "Deny"
        deny_cfg["direction"] = "Inbound"
        deny_cfg["priority"] = int(self._cfg.get("block_priority") or 400)
        ips = sorted(self._blocks.keys())
        old_name = self._nsg_live_rule_name
        block_prio = int(self._cfg.get("block_priority") or 400)
        try:
            # Clear whatever rule currently occupies the deny slot
            # (block_priority + Inbound) under ANY name other than the one we're
            # about to write. Azure enforces uniqueness on (priority, direction),
            # not name, so a renamed / older-version / hand-made rule sitting in
            # this slot (e.g. 'Threat-Monitor-Blocked') makes the PUT fail with
            # SecurityRuleConflict. This "drop the slot, then recreate" sweep is
            # 404-tolerant and supersedes the tracked-name delete below (kept as
            # belt-and-suspenders for the empty-IP DELETE-by-name path).
            try:
                cleared = await _nsg.clear_priority_slot(
                    get_oidc_config(self.hub), deny_cfg,
                    priority=block_prio, direction="Inbound", keep_name=new_name)
                if cleared:
                    sec_log.info("THREAT NSG deny-slot cleared conflicting rule(s) %s "
                                 "at priority %d before writing '%s'",
                                 cleared, block_prio, new_name)
            except Exception as e:  # noqa: BLE001 — slot-clear is best-effort
                logger.warning("threat NSG deny-slot clear failed: %s", e)
            if old_name and old_name != new_name:
                # Delete is 404-tolerant (reconcile_allowlist treats a missing
                # rule as already-gone), so this is safe even if the old rule
                # was never actually created (e.g. auto_block was off).
                old_cfg = dict(deny_cfg)
                old_cfg["rule_name"] = old_name
                await _nsg.reconcile_allowlist(get_oidc_config(self.hub), old_cfg, [])
                sec_log.info("THREAT NSG deny-rule renamed: deleted old rule '%s' before creating '%s'",
                             old_name, new_name)
            res = await _nsg.reconcile_allowlist(get_oidc_config(self.hub), deny_cfg, ips)
            self._nsg_live_rule_name = new_name
            sec_log.info("THREAT NSG deny-rule reconciled: %d IP(s) on %s/%s",
                         len(ips), deny_cfg.get("nsg_name"), new_name)
            return {"status": "SUCCESS", "count": len(ips), **res}
        except Exception as e:  # noqa: BLE001
            logger.warning("threat NSG reconcile failed: %s", e)
            return {"status": "ERROR", "message": str(e)}

    # ── snapshot for the WebUI ─────────────────────────────────────────────────
    def snapshot(self) -> Dict[str, Any]:
        blocks = list(self._blocks.values())
        trusted = self._shared_entries()  # shared list [{ip, description}]
        gc = self.hub.state.system_state.get("global_config", {}) or {}
        az = gc.get("azure_nsg", {}) or {}
        allow_rule = {
            "name": az.get("rule_name") or "lm-allowlist",
            "priority": self.allow_priority(),
            "enabled": bool(az.get("enabled")),
        }
        return {
            "config": self.config(),
            "permanent": [b for b in blocks if b.get("permanent")],
            "temporary": [b for b in blocks if not b.get("permanent")],
            "manual": [b for b in blocks if str(b.get("source", "")).startswith("manual")],
            # Shared trusted list: full entries (with descriptions) + a bare-IP
            # list for back-compat. Both editors (Azure NSG tile / Security tile)
            # read/write the SAME underlying azure_nsg.entries.
            "trusted": trusted,
            "never_block": [e["ip"] for e in trusted],
            "allow_rule": allow_rule,
            "events": list(self._events)[:200],
            "counts": {"blocked": len(blocks), "permanent": sum(1 for b in blocks if b.get("permanent")),
                       "never": len(trusted), "events": len(self._events)},
            # Durable lifetime tallies (survive expiry/unblock/deque-rollover) so
            # the operator can confirm the pipeline is evaluating traffic even with
            # zero active blocks. Includes currently-active for at-a-glance context.
            "totals": {**dict(self._totals),
                       "currently_blocked": len(blocks),
                       "currently_permanent": sum(1 for b in blocks if b.get("permanent"))},
        }

    # ── persistence ─────────────────────────────────────────────────────────────
    def _file(self) -> str:
        return os.path.join(self.hub.state.data_dir, "threat_monitor.json")

    def _persist(self) -> None:
        try:
            with open(self._file(), "w", encoding="utf-8") as f:
                json.dump({"config": self._cfg, "blocks": self._blocks,
                           "offense": self._offense, "never": self._never,
                           "totals": self._totals,
                           # Retain the recent-events evidence feed (newest-first,
                           # capped at the deque bound) so a wire-trip / hijack /
                           # auth-failure and its drill-down details survive a
                           # hub restart.
                           "events": list(self._events)}, f)
        except Exception as e:  # noqa: BLE001
            logger.debug("threat_monitor persist failed: %s", e)

    def _load(self) -> None:
        try:
            with open(self._file(), encoding="utf-8") as f:
                data = json.load(f) or {}
            self._cfg.update({k: v for k, v in (data.get("config") or {}).items() if k in _DEFAULTS})
            self._blocks = data.get("blocks") or {}
            self._offense = data.get("offense") or {}
            self._never = data.get("never") or []
            _saved_totals = data.get("totals") or {}
            if isinstance(_saved_totals, dict):
                # Merge over defaults so a counter added in a later version starts
                # at 0 rather than KeyError-ing, while preserving the running tally.
                self._totals.update({k: v for k, v in _saved_totals.items()
                                     if k in self._totals or k == "by_kind"})
                self._totals.setdefault("by_kind", {})
            _saved_events = data.get("events")
            if isinstance(_saved_events, list):
                # Rehydrate newest-first into a fresh bounded deque (drops the
                # oldest if the persisted list somehow exceeds the cap).
                self._events = deque(_saved_events, maxlen=_EVENTS_MAX)
            self._nsg_dirty = True  # re-push on boot so Azure matches our state
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.warning("threat_monitor load failed: %s", e)
