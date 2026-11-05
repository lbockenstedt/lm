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
# ipaddress: validate bind addresses and advertise hosts that are IP literals.
import ipaddress
# json: read and write the dpa.json settings file.
import json
# logging: warn when the saved settings file cannot be read.
import logging
# os: create the settings file with private permissions and replace it atomically.
import os
# socket: discover this host's LAN address for advertise_host.
import socket
# Path: filesystem path type for the settings file.
from pathlib import Path
# Type hints describing the settings dicts and return tuples.
from typing import Any, Dict, Optional, Tuple
# urlsplit: extract the hub's hostname from its URL.
from urllib.parse import urlsplit

# Import siblings as top-level modules when run from the role's directory...
try:
    from dpa import DEFAULT_SSH_BASE, DEFAULT_TELNET_BASE, parse_allow
    from dpa_ssh import hash_password, validate_authorized_keys
# ...or relatively when the agent's role loader imports this folder as a package.
except ImportError:  # loaded as a package by the agent role loader
    from .dpa import DEFAULT_SSH_BASE, DEFAULT_TELNET_BASE, parse_allow  # type: ignore
    from .dpa_ssh import hash_password, validate_authorized_keys  # type: ignore

# Module-level logger for this file.
logger = logging.getLogger(__name__)

# Built-in defaults (lowest precedence). DPA is off by default; SSH is the preferred
# transport and listens on all interfaces; telnet (unauthenticated) is off and loopback-only.
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

# Setting names grouped by type, so update() knows how to coerce each incoming value.
_BOOL = ("enabled", "ssh_enabled", "telnet_enabled")
_STR = ("ssh_bind", "telnet_bind", "advertise_host", "authorized_keys")
_INT = ("ssh_base", "telnet_base")


def from_role_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Map legacy LOAD_ROLE keys. ``console_dpa_enabled`` historically meant
    "telnet listeners on", so it still turns telnet on (with its bind/allow)
    unless ``console_dpa_telnet`` says otherwise."""
    # Treat a missing config as empty; collect only the keys the role actually set.
    c = config or {}
    out: Dict[str, Any] = {}
    # Legacy master switch: it also turns telnet on unless console_dpa_telnet overrides it.
    if "console_dpa_enabled" in c:
        on = bool(c.get("console_dpa_enabled"))
        out["enabled"] = on
        out["telnet_enabled"] = bool(c.get("console_dpa_telnet", on))
    # Telnet switch given on its own.
    elif "console_dpa_telnet" in c:
        out["telnet_enabled"] = bool(c.get("console_dpa_telnet"))
    # Separate SSH switch.
    if "console_dpa_ssh" in c:
        out["ssh_enabled"] = bool(c.get("console_dpa_ssh"))
    # Copy simple renamed keys (legacy role key -> stored setting name) when non-empty.
    for src, dst in (("console_dpa_bind", "telnet_bind"), ("console_dpa_base", "telnet_base"),
                     ("console_dpa_ssh_bind", "ssh_bind"), ("console_dpa_ssh_base", "ssh_base"),
                     ("console_dpa_advertise_host", "advertise_host"),
                     ("console_dpa_allow", "allow")):
        if c.get(src) not in (None, ""):
            out[dst] = c[src]
    return out


def _valid_bind(v: str) -> bool:
    """Return True if v is acceptable as a listener bind address (wildcard, localhost or an IP)."""
    # Blank (use default), all-interfaces (v4/v6) and localhost are always allowed.
    if v in ("", "0.0.0.0", "::", "localhost"):
        return True
    # Otherwise it must parse as an IPv4/IPv6 address.
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _valid_host(v: str) -> bool:
    """Return True if v is blank, an IP address, or a syntactically valid DNS hostname."""
    # Blank means "auto-detect", which is fine.
    if not v:
        return True
    # DNS names max out at 253 characters and never contain whitespace.
    if len(v) > 253 or any(ch.isspace() for ch in v):
        return False
    # An IP literal is valid as-is.
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        # Otherwise every dot-separated label must be 1-63 letters/digits/hyphens
        # (a single trailing dot is allowed).
        return all(part and len(part) <= 63 and all(ch.isalnum() or ch == "-" for ch in part)
                   for part in v.rstrip(".").split("."))


def detect_advertise_host(hub_url: str = "") -> str:
    """Best-effort LAN address of this host: the source IP the kernel would use
    to reach the hub (or a public address when the hub is unknown). A UDP
    ``connect`` sends no packets."""
    # Addresses to "route towards"; the first one that yields a usable local IP wins.
    targets = []
    host = ""
    # Pull the hostname out of the hub URL (adding a scheme if one is missing).
    if hub_url:
        try:
            host = urlsplit(hub_url if "://" in hub_url else f"wss://{hub_url}").hostname or ""
        except ValueError:
            host = ""
    # Prefer the route to the hub, since that is the network clients most likely share.
    if host:
        targets.append(host)
    # Fallback target from the reserved documentation range: any default route will do.
    targets.append("192.0.2.1")  # TEST-NET; only used for route selection
    # For each target, ask the kernel which local address it would send from.
    for t in targets:
        try:
            # Pick IPv6 for addresses containing ":", else IPv4.
            fam = socket.AF_INET6 if ":" in t else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                # A UDP connect just selects a route; port 9 (discard) is arbitrary and no data is
                # sent.
                s.connect((t, 9))
                ip = s.getsockname()[0]
                # Ignore loopback answers; they are useless to remote clients.
                if ip and not ip.startswith("127.") and ip != "::1":
                    return ip
        # No route to this target; try the next one.
        except OSError:
            continue
    # Last resort: resolve our own hostname (may be empty if that fails too).
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


class DpaConfigStore:
    """Load, merge, validate and save the DPA settings for the console role."""
    def __init__(self, path: Path, role_config: Optional[Dict[str, Any]] = None):
        """Remember where dpa.json lives and load any previously saved settings.

        Args:
            path: location of dpa.json in the console state directory.
            role_config: the LOAD_ROLE config, whose legacy console_dpa_* keys are mapped in.
        """
        # Settings file path, plus the role config translated into stored-setting names.
        self.path = path
        self._role = from_role_config(role_config or {})
        # Settings previously saved from the UI (highest precedence); empty until loaded.
        self._saved: Dict[str, Any] = {}
        # Load the saved file; a missing file just means nothing saved yet.
        try:
            self._saved = json.loads(path.read_text())
            # A file that is valid JSON but not an object is ignored.
            if not isinstance(self._saved, dict):
                self._saved = {}
        except FileNotFoundError:
            pass
        # Corrupt or unreadable file: warn and fall back to defaults rather than crash.
        except Exception as e:  # noqa: BLE001
            logger.warning("DPA config %s unreadable (%s) — using defaults", path, e)

    def effective(self) -> Dict[str, Any]:
        """Return the merged settings (defaults < role config < saved), with normalised types."""
        # Later dicts override earlier ones, giving the documented precedence.
        cfg = {**DEFAULTS, **self._role, **self._saved}
        # Normalise the allow-list into a list of canonical network strings.
        cfg["allow"] = [str(n) for n in parse_allow(cfg.get("allow"))]
        # Port bases must be integers; bad values fall back to the defaults.
        for k in _INT:
            try:
                cfg[k] = int(cfg[k])
            except (TypeError, ValueError):
                cfg[k] = DEFAULTS[k]
        return cfg

    def public(self) -> Dict[str, Any]:
        """Return effective settings safe for the UI (password hash replaced by a flag)."""
        # Never expose the hash; just say whether a password is set.
        cfg = self.effective()
        cfg["has_password"] = bool(cfg.pop("password_hash", ""))
        return cfg

    def update(self, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate + persist a partial update. Returns ``(ok, error)``."""
        # Start from the currently saved settings; only keys present in data change.
        new = dict(self._saved)
        # Booleans: coerce whatever was sent to True/False.
        for k in _BOOL:
            if k in data:
                new[k] = bool(data[k])
        # Strings: trim whitespace, except authorized_keys whose line layout must be kept.
        for k in _STR:
            if k in data and data[k] is not None:
                new[k] = str(data[k]).strip() if k != "authorized_keys" else str(data[k])
        # A blank bind address is removed so the default applies.
        for k in ("ssh_bind", "telnet_bind"):
            if new.get(k) == "":
                new.pop(k)  # blank → default (never "all interfaces" by accident)
        # Port bases: must be integers in range.
        for k in _INT:
            if k in data and data[k] not in (None, ""):
                try:
                    v = int(data[k])
                except (TypeError, ValueError):
                    return False, f"{k} must be an integer"
                # Upper limit leaves room for the 200-port window above the base.
                if not (1024 <= v <= 65335):  # base + 200-port window ≤ 65535
                    return False, f"{k} must be 1024-65335"
                new[k] = v
        # Allow-list: accept a comma/space string or a list.
        if "allow" in data:
            raw = data["allow"]
            entries = raw.replace(",", " ").split() if isinstance(raw, str) else list(raw or [])
            # Parse entries; if any non-blank entry was dropped, one was invalid.
            nets = parse_allow(entries)
            if len(nets) != len([e for e in entries if str(e).strip()]):
                return False, "allow-list has an invalid IP/CIDR"
            # Store the canonical text form of each network.
            new["allow"] = [str(n) for n in nets]
        # Bind addresses must be IPs (or wildcard/localhost).
        for k in ("ssh_bind", "telnet_bind"):
            if k in new and not _valid_bind(new[k]):
                return False, f"{k} must be an IP address (or 0.0.0.0)"
        # The advertised host must be a valid hostname or IP.
        if not _valid_host(new.get("advertise_host", "")):
            return False, "advertise_host must be a hostname or IP"
        # SSH public keys must be in valid authorized_keys format.
        if "authorized_keys" in new:
            err = validate_authorized_keys(new["authorized_keys"])
            if err:
                return False, err
        # Explicit request to remove the SSH password.
        if data.get("clear_password"):
            new["password_hash"] = ""
        # A new password: enforce a minimum length and store only its scrypt hash.
        pw = data.get("password")
        if pw:
            if len(str(pw)) < 8:
                return False, "password must be at least 8 characters"
            new["password_hash"] = hash_password(str(pw))
        # Validate the combined result as it would actually take effect.
        merged = {**DEFAULTS, **self._role, **new}
        # When both transports are on, their 200-port ranges must not overlap.
        if merged.get("telnet_enabled") and merged.get("ssh_enabled"):
            tb, sb = int(merged["telnet_base"]), int(merged["ssh_base"])
            if abs(tb - sb) < 200:
                return False, "ssh_base and telnet_base windows overlap (keep them 200+ apart)"
        # Telnet has no login, so binding it beyond loopback requires a source allow-list.
        tb = merged.get("telnet_bind") or ""
        if merged.get("telnet_enabled") and tb not in ("127.0.0.1", "localhost", "::1") \
                and not merged.get("allow"):
            return False, "telnet is unauthenticated: set a source allow-list before binding beyond 127.0.0.1"
        # All checks passed: keep the new settings in memory and write them to disk.
        self._saved = new
        self._save()
        return True, ""

    def _save(self) -> None:
        """Write the saved settings to dpa.json atomically with owner-only permissions."""
        # Make sure the state directory exists.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temp file created with mode 0600 (it holds the password hash)...
        tmp = self.path.with_suffix(".json.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._saved, f, indent=2)
        # ...then swap it into place so a crash never leaves a half-written file.
        os.replace(tmp, self.path)
