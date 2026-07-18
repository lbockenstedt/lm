"""Threat monitor — detect brute-force / faked-credential attacks on the hub API
and (optionally) auto-block the source IP via the Azure NSG deny rule.

Signals fed in from the auth layer (api.py):
  * failed logins            (``record_failure(ip, "login", username)``)
  * present-but-invalid       session cookie / API token
    credential ("faked key")  (``record_failure(ip, "session")``)

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
        self._cfg: Dict[str, Any] = dict(_DEFAULTS)
        self._nsg_dirty = False
        self._load()
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

    # ── ingest ─────────────────────────────────────────────────────────────────
    def record_failure(self, ip: str, kind: str, username: Optional[str] = None,
                        detail: str = "") -> None:
        """Record an auth failure from ``ip``. Blocks the IP once it crosses the
        threshold within the window (unless exempt). Safe to call from sync code."""
        ip = (ip or "").strip()
        if not ip or not self._cfg.get("enabled"):
            return
        now = _now()
        self._events.appendleft({"ts": now, "ip": ip, "kind": kind,
                                 "username": username or "", "detail": detail})
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
                        kind=kind, source="auto")

    def record_success(self, ip: str) -> None:
        ip = (ip or "").strip()
        if ip:
            self._recent_success[ip] = _now()
            self._ip_fails.pop(ip, None)

    def _reason(self, ip: str, kind: str, username: Optional[str], count: int) -> str:
        who = f" as '{username}'" if username else ""
        label = {"login": "failed logins", "session": "invalid session tokens",
                 "api_key": "invalid API keys"}.get(kind, f"{kind} failures")
        mins = max(1, int(self._cfg["window_s"] / 60))
        return f"{count} {label}{who} within {mins}m"

    # ── blocking ───────────────────────────────────────────────────────────────
    def _block(self, ip: str, reason: str, kind: str, source: str) -> None:
        now = _now()
        self._offense[ip] = self._offense.get(ip, 0) + 1
        permanent = (source == "manual_perm"
                     or self._offense[ip] >= self._cfg["permanent_after"])
        rec = {
            "ip": ip, "reason": reason, "kind": kind, "source": source,
            "blocked_at": now, "offense_count": self._offense[ip],
            "permanent": permanent,
            "expires_at": None if permanent else now + self._cfg["ttl_s"],
        }
        self._blocks[ip] = rec
        self._ip_fails.pop(ip, None)
        self._nsg_dirty = True
        self._persist()
        sec_log.warning("THREAT BLOCK %s (%s) — %s%s", ip, source, reason,
                        " [PERMANENT]" if permanent else
                        f" [expires {self._cfg['ttl_s'] // 3600}h]")
        self._schedule_reconcile()

    def block_manual(self, ip: str, reason: str = "", permanent: bool = False) -> Dict[str, Any]:
        ip = (ip or "").strip()
        if not ip:
            return {"status": "ERROR", "message": "ip required"}
        self._block(ip, reason or "manually blocked",
                    kind="manual", source="manual_perm" if permanent else "manual")
        return {"status": "SUCCESS", "block": self._blocks.get(ip)}

    def unblock(self, ip: str) -> Dict[str, Any]:
        ip = (ip or "").strip()
        existed = self._blocks.pop(ip, None)
        if existed:
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
        if expired:
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
        Empty set → the deny rule is deleted (reconcile_allowlist semantics)."""
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
        deny_cfg["rule_name"] = self._cfg.get("block_rule_name") or "lm-threat-block"
        deny_cfg["access"] = "Deny"
        deny_cfg["direction"] = "Inbound"
        deny_cfg["priority"] = int(self._cfg.get("block_priority") or 400)
        ips = sorted(self._blocks.keys())
        try:
            res = await _nsg.reconcile_allowlist(get_oidc_config(self.hub), deny_cfg, ips)
            sec_log.info("THREAT NSG deny-rule reconciled: %d IP(s) on %s/%s",
                         len(ips), deny_cfg.get("nsg_name"), deny_cfg["rule_name"])
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
        }

    # ── persistence ─────────────────────────────────────────────────────────────
    def _file(self) -> str:
        return os.path.join(self.hub.state.data_dir, "threat_monitor.json")

    def _persist(self) -> None:
        try:
            with open(self._file(), "w", encoding="utf-8") as f:
                json.dump({"config": self._cfg, "blocks": self._blocks,
                           "offense": self._offense, "never": self._never}, f)
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
            self._nsg_dirty = True  # re-push on boot so Azure matches our state
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.warning("threat_monitor load failed: %s", e)
