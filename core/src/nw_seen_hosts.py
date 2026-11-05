"""Registry of hosts the nw scan/sweep found answering, per tenant.

Every host that answers a ping, a TCP probe or SNMP during a scheduled scan or
the background sweep is recorded here with ``first_seen``/``last_seen`` and
what it answered with (hostname, ports, SNMP, probe ``profile``). The registry
drives three things:

* NetBox: each run's responders are pushed as sightings (source
  "Network Sweep"), which refreshes ``last_seen`` there. A host that stops
  answering is no longer pushed, so NetBox's staleness sweep tombstones it
  after 7 days and deletes it after 30.
* Zabbix: hosts seen within ``MONITOR_WINDOW`` are added to the monitoring
  inventory; once they drop out Zabbix ages them out on the same clock.
* Scan targets: every known host is re-tried each scheduled scan, so a
  sweep-found host keeps being pinged and profiled.

Pure functions over plain dicts (``{ip: entry}`` per tenant).
"""
import ipaddress
from typing import Any, Dict, Iterable, List, Set

KEEP_SECONDS = 37 * 86400       # NetBox deletes after 7d + 30d unseen
MONITOR_WINDOW = 24 * 3600      # in Zabbix while seen within a day
_FIELDS = ("hostname", "object_type", "snmp_credential_id")


def _clean_ip(value: Any) -> str:
    ip = str(value or "").split("/")[0].strip()
    try:
        return ip if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address) else ""
    except ValueError:
        return ""


def record(registry: Dict[str, Dict[str, Any]], hosts: Iterable[Dict[str, Any]],
           now: float) -> List[str]:
    """Merge scan results (``{address, hostname, open_ports, snmp_ok, profile, …}``,
    or a bare ``{address}`` for a ping-only answer) into ``registry``. A newer
    empty value never erases an older one. Returns the IPs recorded."""
    seen = []
    for h in hosts or []:
        if not isinstance(h, dict):
            continue
        ip = _clean_ip(h.get("address"))
        if not ip:
            continue
        e = registry.setdefault(ip, {"address": ip, "first_seen": now})
        e["last_seen"] = now
        for k in _FIELDS:
            v = h.get(k)
            if v and str(v).strip() != ip:
                e[k] = v
        if h.get("open_ports"):
            e["open_ports"] = list(h["open_ports"])
        if h.get("snmp_ok"):
            e["snmp_ok"] = True
        if isinstance(h.get("profile"), dict) and h["profile"]:
            e["profile"] = {**(e.get("profile") or {}), **h["profile"]}
        seen.append(ip)
    return seen


def prune(registry: Dict[str, Dict[str, Any]], now: float,
          keep: float = KEEP_SECONDS) -> int:
    """Drop entries unseen for ``keep`` seconds. Returns how many."""
    old = [ip for ip, e in registry.items() if now - float(e.get("last_seen") or 0) > keep]
    for ip in old:
        registry.pop(ip, None)
    return len(old)


def netbox_records(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NETBOX_SYNC_DEVICES rows: IP-keyed sightings with hostname + profile."""
    out = []
    for e in entries:
        row: Dict[str, Any] = {"ip": e["address"], "mac": "",
                               "hostname": str(e.get("hostname") or "")}
        if e.get("profile"):
            row["profile"] = e["profile"]
        out.append(row)
    return out


def unidentified(registry: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Hosts nothing has named or classified yet, newest first, with whatever
    evidence the probes gathered (ports, SNMP, ``profile``) for a human or AB
    to work out what they are."""
    rows = [e for e in (registry or {}).values()
            if not e.get("hostname") and not e.get("object_type")]
    return sorted(rows, key=lambda e: -float(e.get("last_seen") or 0))


def monitor_rows(by_tenant: Dict[str, Dict[str, Dict[str, Any]]], now: float,
                 skip_addresses: Set[str], skip_names: Set[str],
                 window: float = MONITOR_WINDOW) -> List[Dict[str, Any]]:
    """Monitoring inventory rows (``nw_monitor_neighbors`` shape) for hosts
    seen within ``window`` that aren't already monitored (by address or name).
    Hosts without a working SNMP community get the ping template."""
    out = []
    for tid, reg in (by_tenant or {}).items():
        for ip, e in (reg or {}).items():
            if now - float(e.get("last_seen") or 0) > window or ip in skip_addresses:
                continue
            name = str(e.get("hostname") or ip)
            if name.casefold() in skip_names:
                name = ip
            out.append({"tenant_id": tid, "name": name, "address": ip,
                        "type": str(e.get("object_type") or "host"),
                        "snmp_ok": bool(e.get("snmp_ok") and e.get("snmp_credential_id")),
                        "snmp_secret": e.get("snmp_credential_id") or ""})
    return out
