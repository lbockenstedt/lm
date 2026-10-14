"""Persisted Direct Port Access (DPA) configuration — the console role's on/off
knob and transport settings.

Precedence (lowest → highest): built-in defaults → the role's LOAD_ROLE config
(``console_dpa_*`` keys, applied at load only) → ``dpa.json`` in the console
state dir, written by ``CONSOLE_SET_DPA`` (the Console page's Direct Port Access
modal). The file survives agent restarts and config-less hub re-adopts, which is
what made the old load-time-only switch revert to OFF.

The SSH password is held only as a scrypt hash (``password_hash``) and is never
returned by :meth:`DpaConfigStore.public`.
"""
import ipaddress
import json
import logging
import os
import socket
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

try:
    from dpa import DEFAULT_SSH_BASE, DEFAULT_TELNET_BASE, parse_allow
    from dpa_ssh import hash_password, validate_authorized_keys
except ImportError:  # loaded as a package by the agent role loader
    from .dpa import DEFAULT_SSH_BASE, DEFAULT_TELNET_BASE, parse_allow  # type: ignore
    from .dpa_ssh import hash_password, validate_authorized_keys  # type: ignore

logger = logging.getLogger(__name__)

DEFAULTS: Dict[str, Any] = {
    "enabled": False,
    "ssh_enabled": True,
    "ssh_bind": "0.0.0.0",
    "ssh_base": DEFAULT_SSH_BASE,
    "telnet_enabled": False,
    "telnet_bind": "127.0.0.1",
    "telnet_base": DEFAULT_TELNET_BASE,
    "allow": [],
    "advertise_host": "",
    "password_hash": "",
    "authorized_keys": "",
}

_BOOL = ("enabled", "ssh_enabled", "telnet_enabled")
_STR = ("ssh_bind", "telnet_bind", "advertise_host", "authorized_keys")
_INT = ("ssh_base", "telnet_base")


def from_role_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Map legacy LOAD_ROLE keys. ``console_dpa_enabled`` historically meant
    "telnet listeners on", so it still turns telnet on (with its bind/allow)
    unless ``console_dpa_telnet`` says otherwise."""
    c = config or {}
    out: Dict[str, Any] = {}
    if "console_dpa_enabled" in c:
        on = bool(c.get("console_dpa_enabled"))
        out["enabled"] = on
        out["telnet_enabled"] = bool(c.get("console_dpa_telnet", on))
    elif "console_dpa_telnet" in c:
        out["telnet_enabled"] = bool(c.get("console_dpa_telnet"))
    if "console_dpa_ssh" in c:
        out["ssh_enabled"] = bool(c.get("console_dpa_ssh"))
    for src, dst in (("console_dpa_bind", "telnet_bind"), ("console_dpa_base", "telnet_base"),
                     ("console_dpa_ssh_bind", "ssh_bind"), ("console_dpa_ssh_base", "ssh_base"),
                     ("console_dpa_advertise_host", "advertise_host"),
                     ("console_dpa_allow", "allow")):
        if c.get(src) not in (None, ""):
            out[dst] = c[src]
    return out


def _valid_bind(v: str) -> bool:
    if v in ("", "0.0.0.0", "::", "localhost"):
        return True
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _valid_host(v: str) -> bool:
    if not v:
        return True
    if len(v) > 253 or any(ch.isspace() for ch in v):
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return all(part and len(part) <= 63 and all(ch.isalnum() or ch == "-" for ch in part)
                   for part in v.rstrip(".").split("."))


def detect_advertise_host(hub_url: str = "") -> str:
    """Best-effort LAN address of this host: the source IP the kernel would use
    to reach the hub (or a public address when the hub is unknown). A UDP
    ``connect`` sends no packets."""
    targets = []
    host = ""
    if hub_url:
        try:
            host = urlsplit(hub_url if "://" in hub_url else f"wss://{hub_url}").hostname or ""
        except ValueError:
            host = ""
    if host:
        targets.append(host)
    targets.append("192.0.2.1")  # TEST-NET; only used for route selection
    for t in targets:
        try:
            fam = socket.AF_INET6 if ":" in t else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((t, 9))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127.") and ip != "::1":
                    return ip
        except OSError:
            continue
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


class DpaConfigStore:
    def __init__(self, path: Path, role_config: Optional[Dict[str, Any]] = None):
        self.path = path
        self._role = from_role_config(role_config or {})
        self._saved: Dict[str, Any] = {}
        try:
            self._saved = json.loads(path.read_text())
            if not isinstance(self._saved, dict):
                self._saved = {}
        except FileNotFoundError:
            pass
        except Exception as e:  # noqa: BLE001
            logger.warning("DPA config %s unreadable (%s) — using defaults", path, e)

    def effective(self) -> Dict[str, Any]:
        cfg = {**DEFAULTS, **self._role, **self._saved}
        cfg["allow"] = [str(n) for n in parse_allow(cfg.get("allow"))]
        for k in _INT:
            try:
                cfg[k] = int(cfg[k])
            except (TypeError, ValueError):
                cfg[k] = DEFAULTS[k]
        return cfg

    def public(self) -> Dict[str, Any]:
        cfg = self.effective()
        cfg["has_password"] = bool(cfg.pop("password_hash", ""))
        return cfg

    def update(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate + persist a partial update. Returns ``(ok, error)``."""
        new = dict(self._saved)
        for k in _BOOL:
            if k in data:
                new[k] = bool(data[k])
        for k in _STR:
            if k in data and data[k] is not None:
                new[k] = str(data[k]).strip() if k != "authorized_keys" else str(data[k])
        for k in ("ssh_bind", "telnet_bind"):
            if new.get(k) == "":
                new.pop(k)  # blank → default (never "all interfaces" by accident)
        for k in _INT:
            if k in data and data[k] not in (None, ""):
                try:
                    v = int(data[k])
                except (TypeError, ValueError):
                    return False, f"{k} must be an integer"
                if not (1024 <= v <= 65335):  # base + 200-port window ≤ 65535
                    return False, f"{k} must be 1024-65335"
                new[k] = v
        if "allow" in data:
            raw = data["allow"]
            entries = raw.replace(",", " ").split() if isinstance(raw, str) else list(raw or [])
            nets = parse_allow(entries)
            if len(nets) != len([e for e in entries if str(e).strip()]):
                return False, "allow-list has an invalid IP/CIDR"
            new["allow"] = [str(n) for n in nets]
        for k in ("ssh_bind", "telnet_bind"):
            if k in new and not _valid_bind(new[k]):
                return False, f"{k} must be an IP address (or 0.0.0.0)"
        if not _valid_host(new.get("advertise_host", "")):
            return False, "advertise_host must be a hostname or IP"
        if "authorized_keys" in new:
            err = validate_authorized_keys(new["authorized_keys"])
            if err:
                return False, err
        if data.get("clear_password"):
            new["password_hash"] = ""
        pw = data.get("password")
        if pw:
            if len(str(pw)) < 8:
                return False, "password must be at least 8 characters"
            new["password_hash"] = hash_password(str(pw))
        merged = {**DEFAULTS, **self._role, **new}
        if merged.get("telnet_enabled") and merged.get("ssh_enabled"):
            tb, sb = int(merged["telnet_base"]), int(merged["ssh_base"])
            if abs(tb - sb) < 200:
                return False, "ssh_base and telnet_base windows overlap (keep them 200+ apart)"
        tb = merged.get("telnet_bind") or ""
        if merged.get("telnet_enabled") and tb not in ("127.0.0.1", "localhost", "::1") \
                and not merged.get("allow"):
            return False, "telnet is unauthenticated: set a source allow-list before binding beyond 127.0.0.1"
        self._saved = new
        self._save()
        return True, ""

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._saved, f, indent=2)
        os.replace(tmp, self.path)
