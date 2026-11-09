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
# ipaddress validates host addresses; typing hints document the dict shapes.
import ipaddress
from typing import Any, Dict, Iterable, List, Set

# Keep entries 37 days: NetBox tombstones after 7 days unseen and deletes 30 days later,
# so the registry must outlive that. Hosts seen in the last 24 hours are monitored.
KEEP_SECONDS = 37 * 86400       # NetBox deletes after 7d + 30d unseen
MONITOR_WINDOW = 24 * 3600      # in Zabbix while seen within a day
# An unchanged host is re-pushed to NetBox at most hourly (its 7-day staleness clock
# only needs an occasional refresh); every sweep pass re-pushing it overloads NetBox.
PUSH_EVERY = 3600
# Identity fields copied from a scan result into the registry entry.
_FIELDS = ("hostname", "object_type", "snmp_credential_id")


def _clean_ip(value: Any) -> str:
    """Return the IPv4 address part of value (any /prefix removed), or "" if not IPv4."""
    # Drop any /prefix length and whitespace.
    ip = str(value or "").split("/")[0].strip()
    # Only IPv4 addresses are tracked; anything else (or garbage) yields "".
    try:
        return ip if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address) else ""
    except ValueError:
        return ""


def monitor_type(host: Dict[str, Any], default: str) -> str:
    """Monitoring type of an SNMP host: picks its Zabbix template. Appliances
    the scanner does not manage are recognised from their sysDescr."""
    descr = str((host.get("profile") or {}).get("sys_descr") or "").lower()
    if descr.startswith(("truenas", "freenas")):
        return "truenas"
    return str(host.get("object_type") or default)


def record(registry: Dict[str, Dict[str, Any]], hosts: Iterable[Dict[str, Any]],
           now: float) -> List[str]:
    """Merge scan results (``{address, hostname, open_ports, snmp_ok, profile, …}``,
    or a bare ``{address}`` for a ping-only answer) into ``registry``. A newer
    empty value never erases an older one. Returns the IPs recorded."""
    # IPs recorded in this call.
    seen = []
    # Merge each scan result into the registry.
    for h in hosts or []:
        # Skip malformed rows and rows without a valid IPv4 address.
        if not isinstance(h, dict):
            continue
        ip = _clean_ip(h.get("address"))
        if not ip:
            continue
        # Create the entry on first sight, then stamp last_seen.
        e = registry.setdefault(ip, {"address": ip, "first_seen": now})
        e["last_seen"] = now
        # Copy identity fields only when non-empty and not just the IP repeated.
        for k in _FIELDS:
            v = h.get(k)
            if v and str(v).strip() != ip:
                e[k] = v
        # Ports and SNMP success are only ever added, never cleared by an empty result.
        if h.get("open_ports"):
            e["open_ports"] = list(h["open_ports"])
        if h.get("snmp_ok"):
            e["snmp_ok"] = True
        # Merge the probe profile over what was known before.
        if isinstance(h.get("profile"), dict) and h["profile"]:
            e["profile"] = {**(e.get("profile") or {}), **h["profile"]}
        seen.append(ip)
    return seen


def prune(registry: Dict[str, Dict[str, Any]], now: float,
          keep: float = KEEP_SECONDS) -> int:
    """Drop entries unseen for ``keep`` seconds. Returns how many."""
    # Find entries whose last_seen is older than keep seconds, then remove them.
    old = [ip for ip, e in registry.items() if now - float(e.get("last_seen") or 0) > keep]
    for ip in old:
        registry.pop(ip, None)
    return len(old)


def _push_sig(entry: Dict[str, Any]) -> str:
    """What NetBox gets for the entry, so a changed hostname/profile is re-pushed at once."""
    return repr(netbox_records([entry])[0])


def due_for_push(registry: Dict[str, Dict[str, Any]], ips: Iterable[str], now: float,
                 every: float = PUSH_EVERY) -> List[str]:
    """The ``ips`` (sorted) that NetBox needs: never pushed, changed since the
    last push, or last pushed ``every`` seconds ago or more."""
    out = []
    for ip in sorted(set(ips)):
        e = registry.get(ip)
        if not e:
            continue
        if (e.get("pushed_sig") != _push_sig(e)
                or now - float(e.get("pushed_at") or 0) >= every):
            out.append(ip)
    return out


def mark_pushed(registry: Dict[str, Dict[str, Any]], ips: Iterable[str], now: float) -> None:
    """Remember that NetBox accepted these hosts as they are now."""
    for ip in ips:
        e = registry.get(ip)
        if e:
            e["pushed_at"] = now
            e["pushed_sig"] = _push_sig(e)


def netbox_records(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """NETBOX_SYNC_DEVICES rows: IP-keyed sightings with hostname + profile."""
    # Build one sighting row per entry, with no MAC (the sweep only knows IPs).
    out = []
    for e in entries:
        row: Dict[str, Any] = {"ip": e["address"], "mac": "",
                               "hostname": str(e.get("hostname") or "")}
        # Attach the probe profile when there is one.
        if e.get("profile"):
            row["profile"] = e["profile"]
        out.append(row)
    return out


def unidentified(registry: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Hosts nothing has named or classified yet, newest first, with whatever
    evidence the probes gathered (ports, SNMP, ``profile``) for a human or AB
    to work out what they are."""
    # Entries with neither hostname nor object type.
    rows = [e for e in (registry or {}).values()
            if not e.get("hostname") and not e.get("object_type")]
    # Newest sighting first.
    return sorted(rows, key=lambda e: -float(e.get("last_seen") or 0))


def monitor_rows(by_tenant: Dict[str, Dict[str, Dict[str, Any]]], now: float,
                 skip_addresses: Set[str], skip_names: Set[str],
                 window: float = MONITOR_WINDOW) -> List[Dict[str, Any]]:
    """Monitoring inventory rows (``nw_monitor_neighbors`` shape) for hosts
    seen within ``window`` that aren't already monitored (by address or name).
    Only hosts that answered SNMP with a vault credential are returned; a
    ping-only host is never monitored."""
    # One row per recently seen, not yet monitored host across all tenants.
    out = []
    for tid, reg in (by_tenant or {}).items():
        for ip, e in (reg or {}).items():
            # Skip hosts outside the window or already monitored by address.
            if now - float(e.get("last_seen") or 0) > window or ip in skip_addresses:
                continue
            # Skip hosts that never answered SNMP with a known credential.
            if not (e.get("snmp_ok") and e.get("snmp_credential_id")):
                continue
            # Only hosts named by sysName: a name already monitored is the same box
            # at another address (e.g. a switch SVI), and no name means SNMP identity
            # was incomplete; neither becomes a host of its own.
            name = str(e.get("hostname") or "").strip()
            if not name or name.casefold() in skip_names:
                continue
            out.append({"tenant_id": tid, "name": name, "address": ip,
                        "type": monitor_type(e, "host"),
                        "snmp_ok": True, "snmp_secret": e["snmp_credential_id"]})
    return out
