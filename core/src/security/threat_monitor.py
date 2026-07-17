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
  * on the Azure NSG allow-list (``global_config["azure_nsg"]["entries"]``),
  * a recent successful-login IP (within ``success_grace_s``), or
  * inside a CIDR on the manual never-block list.

NSG shape: blocks are reconciled — one prefix per IP — onto a dedicated DENY
rule (``block_rule_name``, higher priority than the allow rule). Per-IP "why"
descriptions are kept hub-local here (Azure rules carry one description each) and
surfaced in the WebUI Security view. A leaf-ish module: stdlib + azure_nsg.
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
    "block_priority": 200,    # < the allow rule's priority so Deny wins
}
_EVENTS_MAX = 500


def _now() -> float:
    return time.time()


class ThreatMonitor:
    def __init__(self, hub) -> None:
        self.hub = hub
        self._events: deque = deque(maxlen=_EVENTS_MAX)   # recent auth failures
        self._ip_fails: Dict[str, List[float]] = {}       # ip -> [ts] in-window
        self._blocks: Dict[str, Dict[str, Any]] = {}      # ip -> block record
        self._recent_success: Dict[str, float] = {}       # ip -> last-success ts
        self._offense: Dict[str, int] = {}                # ip -> lifetime block count
        self._never: List[str] = []                       # manual never-block CIDRs
        self._cfg: Dict[str, Any] = dict(_DEFAULTS)
        self._nsg_dirty = False
        self._load()

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
        self._nsg_dirty = True  # auto_block toggle may have changed
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

    # ── never-block list ─────────────────────────────────────────────────────
    def add_never(self, cidr: str) -> Dict[str, Any]:
        c = (cidr or "").strip()
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            return {"status": "ERROR", "message": f"invalid IP/CIDR: {cidr}"}
        if c not in self._never:
            self._never.append(c)
            # An IP that becomes exempt is immediately unblocked.
            for ip in list(self._blocks):
                if self._in_cidr(ip, [c]):
                    self._blocks.pop(ip, None)
                    self._nsg_dirty = True
            self._persist()
            self._schedule_reconcile()
        return {"status": "SUCCESS", "never_block": list(self._never)}

    def remove_never(self, cidr: str) -> Dict[str, Any]:
        c = (cidr or "").strip()
        if c in self._never:
            self._never.remove(c)
            self._persist()
        return {"status": "SUCCESS", "never_block": list(self._never)}

    # ── exemptions ─────────────────────────────────────────────────────────────
    def _is_exempt(self, ip: str) -> bool:
        # (1) recent successful login
        last = self._recent_success.get(ip)
        if last and last > _now() - self._cfg["success_grace_s"]:
            return True
        # (2) manual never-block CIDRs
        if self._in_cidr(ip, self._never):
            return True
        # (3) Azure NSG allow-list IPs (trusted sources)
        if self._in_cidr(ip, self._allowlist_ips()):
            return True
        return False

    def _allowlist_ips(self) -> List[str]:
        try:
            gc = self.hub.state.system_state.get("global_config", {}) or {}
            entries = (gc.get("azure_nsg", {}) or {}).get("entries", []) or []
            return [e.get("ip", "") for e in entries if isinstance(e, dict) and e.get("ip")]
        except Exception:  # noqa: BLE001
            return []

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
        deny_cfg["priority"] = int(self._cfg.get("block_priority") or 200)
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
        return {
            "config": self.config(),
            "permanent": [b for b in blocks if b.get("permanent")],
            "temporary": [b for b in blocks if not b.get("permanent")],
            "manual": [b for b in blocks if str(b.get("source", "")).startswith("manual")],
            "never_block": list(self._never),
            "events": list(self._events)[:200],
            "counts": {"blocked": len(blocks), "permanent": sum(1 for b in blocks if b.get("permanent")),
                       "never": len(self._never), "events": len(self._events)},
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
