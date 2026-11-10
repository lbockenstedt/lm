"""Network Devices → NetBox device-discovery sync subsystem for the Hub.

Mirrors ``fw_discovery_sync.py`` (NetBox is the **sink**, payload carries
``replace=True``, per-tenant loop, tenant-scoped replace-delete, prefix-
containment attribution, drop+count unattributed). ``api.py`` routes call
``hub.NW_DISCOVERY_SOURCES``, ``hub.sync_tenant_devices()`` (nw variant),
``hub.run_nw_discovery_sync_all()``, ``hub._nw_discovery_source()``,
``hub._nw_discovery_cfg()`` — all resolve via inheritance once
``NwDiscoverySyncMixin`` is added to ``LabManagerHub`` bases.

The nw spoke manages a fleet of switches + gateways (AOS-S / AOS-CX / Juniper
EX / Aruba-HPE gateway). Each device's **ARP table** is the IP↔MAC source of
truth for what is on the network (the MAC table alone has no IP, so it can't be
attributed by prefix). Each cycle the hub pulls ``NW_GET_ARP`` from every
device on every connected nw spoke, merges/dedups, **attributes each record to
a tenant by prefix containment** (the device IP must sit inside one of the
tenant's NetBox prefixes), and pushes per-tenant to the netbox spoke via
``NETBOX_SYNC_DEVICES`` with ``source="Network Devices"`` so the netbox sink
tags the records nw-owned (and replace-deletes only nw-owned records, never
touching opnsense-discovered ones). Unmatched IPs are dropped + counted —
NetBox stays tenant-authoritative, no orphan devices.

Like firewall discovery, nw discovery is **not tenant-scoped at the source**
(ARP is per-device, per-subnet), so the hub pulls once per cycle, attributes by
prefix, then pushes per-tenant. Adding another network-device product is a
one-entry addition to ``NW_DISCOVERY_SOURCES`` + a spoke implementing the arp
command.

This module is a **leaf**: it imports only stdlib + ``access`` helpers
(``fetch_tenant_prefixes`` / ``attribute_by_prefix`` / ``norm_mac`` — sibling
leaves that import neither ``main`` nor ``api``). It MUST NOT import ``main``
or ``api`` (dependency direction is ``main → nw_discovery_sync`` only).

Audience: Hub developers.
"""

from __future__ import annotations

# asyncio for concurrent per-device fetches and the background loop; datetime for
# timestamps in reports; logging for progress; re for the IPv4 matcher; time for epochs.
import asyncio
import datetime as _dt
import logging
import re
import time
# Type hints only; they document the shapes of values passed around.
from typing import Any, Dict, List, Optional, Tuple

# Tenant-attribution helpers from the access leaf. Guarded so this module can still be
# imported in isolation (tests/tools); callers check for None before using them.
try:
    from access import attribute_by_prefix, norm_mac, nw_spoke_tenant, spoke_owner_tenant  # sibling leaf (no main/api back-import)
# Import failed: mark each helper unavailable so callers can skip attribution.
except Exception:  # pragma: no cover - access always importable in-app
    attribute_by_prefix = None  # type: ignore
    norm_mac = None  # type: ignore
    nw_spoke_tenant = None  # type: ignore
    spoke_owner_tenant = None  # type: ignore
# unwrap_spoke strips the spoke response envelope down to its payload.
from access import unwrap_spoke  # sibling leaf (no main/api back-import)
# Device spec lookup (e.g. object type defaults) from the device_specs leaf.
from device_specs import get_spec as get_device_spec  # sibling leaf
import hw_serial_links  # sibling leaf: serial matcher for controller<->host stitching
# Shared scheduling helpers for the periodic discovery loop.
from sync_loop import next_schedule_delay, run_sync_loop  # sibling leaf

# Logs under the shared "Hub" logger so discovery messages appear with other hub output.
logger = logging.getLogger("Hub")

# Matches a dotted IPv4 address, used to tell an IP "name" from a real hostname.
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def nw_short_name(name: Any) -> str:
    """Hostname used to match the same box across addresses: case-folded with
    the domain suffix dropped (an IP address is kept whole)."""
    # Normalize, then keep IPs whole but cut hostnames at the first dot.
    n = str(name or "").strip().casefold()
    return n if _IP_RE.match(n) else n.split(".")[0]


def nw_hardware_primaries(devices: List[Dict[str, Any]],
                          identity: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    """Map every nw device id → the id of the row that represents its physical
    box. Discovery adds a switch once per SVI address it answers on; those rows
    are the SAME hardware and must yield ONE NetBox device / ONE Zabbix host.

    Grouped within a tenant by chassis serial, else by short hostname (domain
    suffix dropped) + object type — names are reconciled to the box hostname
    each poll. A serial-less row only joins a name group whose serial doesn't
    contradict it. Base MAC is deliberately NOT a key: VSX peers can present a
    shared system MAC yet are two boxes that must stay separate (their chassis
    serials and hostnames differ). The primary is the first configured row that
    has poll data (stable across cycles), else the first row."""
    def _t(d):
        """Tenant key of a device row, case-folded, defaulting to "default"."""
        return str(d.get("tenant_id") or d.get("tenant") or "default").casefold()

    def _serial(did):
        """Chassis serial for a device id from the identity cache (empty if unknown)."""
        return str((identity.get(did) or {}).get("serial") or "").strip().casefold()

    def _name(d):
        """Short hostname of a device row."""
        return nw_short_name(d.get("name"))

    # groups holds each physical box's rows; by_key maps a serial/name key to its group.
    groups: List[List[Dict[str, Any]]] = []
    by_key: Dict[str, List[Dict[str, Any]]] = {}
    # Walk every configured device row and place it into a hardware group.
    for d in devices or []:
        # Skip malformed rows without an id.
        if not isinstance(d, dict) or not d.get("id"):
            continue
        did = str(d["id"])
        # Build the serial key (if a serial is known) and the type+short-name key.
        sk = f"{_t(d)}|s|{str(d.get('object_type') or '').casefold()}|{_serial(did)}" if _serial(did) else ""
        nk = f"{_t(d)}|n|{str(d.get('object_type') or '').casefold()}|{_name(d)}" if _name(d) else ""
        # Join an existing group by serial first.
        g = by_key.get(sk) if sk else None
        # Otherwise join the name group, unless this row's serial contradicts a member's serial.
        if g is None and nk and nk in by_key:
            cand = by_key[nk]
            if not (_serial(did) and any(_serial(str(m["id"])) and _serial(str(m["id"])) != _serial(did)
                                         for m in cand)):
                g = cand
        # No matching group: start a new one.
        if g is None:
            g = []
            groups.append(g)
        # Add the row and register its keys so later rows can find this group.
        g.append(d)
        for k in (sk, nk):
            if k and k not in by_key:
                by_key[k] = g
    # Pick each group's primary (first row with poll identity, else the first row).
    out: Dict[str, str] = {}
    for g in groups:
        primary = next((m for m in g if identity.get(str(m["id"]))), g[0])
        # Map every member of the group to that primary id.
        for m in g:
            out[str(m["id"])] = str(primary["id"])
    return out


# Interface names of a switch's out-of-band management port (Aruba CX "mgmt",
# AOS-S "oobm", Cisco "mgmt0"/"Management", Juniper "fxp0"/"me0").
_OOBM_IFACE_RE = re.compile(r"^(mgmt\d*|oobm\d*|management\d*|me0|fxp0|em0)$", re.I)


def nw_oobm_address(device: Dict[str, Any], interfaces: Any) -> str:
    """The device address that sits on its out-of-band management port, or "".
    A box found at several addresses (SVIs, loopbacks, OOBM) is monitored over the
    OOBM one when polled interface data shows which address that is; ``interfaces``
    is the cached interface rows ({name, ip}) or the envelope holding them."""
    if isinstance(interfaces, dict):
        interfaces = interfaces.get("data", interfaces)
        if isinstance(interfaces, dict):
            interfaces = interfaces.get("interfaces") or interfaces.get("rows")
    mine = {str(a or "").split("/")[0].strip()
            for a in [device.get("address")] + list(device.get("alt_addresses") or [])} - {""}
    for r in interfaces or []:
        if not isinstance(r, dict) or not _OOBM_IFACE_RE.match(str(r.get("name") or "").strip()):
            continue
        ip = str(r.get("ip") or "").split("/")[0].strip()
        if ip in mine:
            return ip
    return ""


class NwDiscoverySyncMixin:
    """Pulls the ARP table from every device on every connected nw spoke,
    attributes each IP↔MAC record to a tenant by prefix containment, and pushes
    the per-tenant device set to the netbox (IPAM) spoke via
    ``NETBOX_SYNC_DEVICES`` so NetBox DCIM devices + IP records mirror what the
    switches/gateways actually see on the network — tenant-tagged, with
    ``custom_fields.mac_address`` on the IP (which feeds the IPAM→CPPM endpoint
    sync). The nw source is selectable via ``source`` (default "nw"); adding a
    network-device product is a one-entry addition to ``NW_DISCOVERY_SOURCES``
    + a spoke implementing the arp command. The devices are the source of
    truth: each sync is authoritative for the tenant (replace=True → the sink
    overwrites that tenant's nw-discovered-device set to match, deleting stale
    records). The netbox write handler lives in the external netbox spoke repo.
    """

    # NW_DISCOVERY_SOURCES maps a source name → how the hub talks to that
    # product:
    #   module_type   : spoke module type to resolve (get_all_spokes_by_type)
    #   arp_command   : command to fetch a device's ARP table (request
    #                   {"device_id": <id>}; response {"status":"SUCCESS",
    #                   "data":[{ip, mac, interface}, ...]})
    #   mac_command   : command to fetch a device's MAC table (same request/
    #                   response shape; rows are {mac, vlan, interface} — NO ip,
    #                   so they can't be tenant-attributed and are pushed
    #                   UNSCOPED so the MAC is still recorded on a global device
    #                   carrying its source switch/port). Optional — a product
    #                   with no MAC-table command is ARP-only.
    #   label         : human label for the WebUI source selector + the push
    #                   payload's ``source`` field (used by the netbox sink as
    #                   the discovered_from ownership tag).
    # Registry of supported nw discovery sources (only the "nw" spoke today).
    NW_DISCOVERY_SOURCES: Dict[str, Dict[str, str]] = {
        "nw": {
            "module_type": "nw",
            "arp_command": "NW_GET_ARP",
            "mac_command": "NW_GET_MAC_TABLE",
            "label": "Network Devices",
        },
    }

    # NetBox (IPAM spoke) is the device-record writer. Fixed today.
    # Spoke module that writes device records, the command it handles, and the
    # global_config key holding this sync's settings.
    _NW_DISCOVERY_TARGET_MODULE = "ipam"
    _NW_DISCOVERY_PUSH_COMMAND = "NETBOX_SYNC_DEVICES"
    _NW_DISCOVERY_CFG_KEY = "nw_netbox_device_sync"

    # POLL NOW: per-device full poll (probe+info+interfaces+arp+mac) + push the
    # device + its interfaces to NetBox as a dcim.device inventory record (a
    # different sink from the ARP-neighbor→endpoint NETBOX_SYNC_DEVICES flow).
    _NW_POLL_COMMAND = "NW_POLL"
    _NW_DEVICE_PUSH_COMMAND = "NETBOX_SYNC_NW_DEVICE"

    # ── config helpers ──────────────────────────────────────────────────────

    def _nw_discovery_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh (enabled/source/mode/interval/daily_time/
        defaults)."""
        # Read global_config fresh each call so UI changes apply without a restart.
        return (self.state.system_state.get("global_config", {})
                .get(self._NW_DISCOVERY_CFG_KEY, {})) or {}

    def _nw_discovery_source(self) -> Dict[str, str]:
        """Resolve the configured nw source registry entry (falls back to "nw")."""
        # Look up the configured source name, defaulting to "nw" for unknown names.
        name = str(self._nw_discovery_cfg().get("source", "nw")).strip().lower()
        return self.NW_DISCOVERY_SOURCES.get(name) or self.NW_DISCOVERY_SOURCES["nw"]

    def _nw_identity_cache(self) -> Dict[str, Dict[str, Any]]:
        """{device id: cached info datums} from the warm per-device cache."""
        # Build {device id: info dict} from the cached "info" envelope of every configured device.
        out: Dict[str, Dict[str, Any]] = {}
        getter = getattr(self, "nw_cache_get_device", None)
        # Iterate the configured nw devices from global_config.
        for d in (self.state.system_state.get("global_config", {})
                  .get("nw_devices", []) or []):
            # Skip malformed rows, or everything if the cache getter is not mixed in.
            if not isinstance(d, dict) or not d.get("id") or not callable(getter):
                continue
            # Pull the cached info payload and keep it only if it is a non-empty dict.
            env = getter(str(d["id"]), "info")
            info = env.get("data") if isinstance(env, dict) else None
            if isinstance(info, dict) and info:
                out[str(d["id"])] = info
        return out

    def nw_hardware_primary_of(self, device_id: str) -> str:
        """The id of the row representing this device's physical box (itself
        when it is the primary or has no duplicates)."""
        # Group all configured devices and return this device's primary (itself if none).
        devices = (self.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        return nw_hardware_primaries(devices, self._nw_identity_cache()).get(
            str(device_id), str(device_id))

    # ── cross-tenant relocation ─────────────────────────────────────────────
    # A device record stays with the tenant that created it. When its agent is
    # moved to another tenant (or deleted) the record is "unanchored": it is
    # moved to the tenant that finds it again, once that sighting is verified
    # (IP + hostname, the same agent at the same IP, or chassis serial/MAC).
    # Anchored records (their agent still belongs to their tenant) never move,
    # so two tenants that both see a box can't bounce it back and forth.

    @staticmethod
    def _nw_shared_tid() -> str:
        """Return the id of the shared tenant (falls back to "shared")."""
        # access is imported lazily; if it is unavailable assume the default "shared" id.
        try:
            from access import shared_tenant_id
            return str(shared_tenant_id() or "shared")
        except Exception:  # noqa: BLE001
            return "shared"

    def _nw_prior_identity(self, device_id: str) -> Dict[str, Any]:
        """Return a copy of the cached device-info payload for a device ({} if not cached)."""
        # Read the cached "info" envelope when the cache mixin is present.
        getter = getattr(self, "nw_cache_get_device", None)
        env = getter(str(device_id), "info") if callable(getter) else None
        # Unwrap the payload and copy it so callers cannot mutate the cache.
        data = env.get("data") if isinstance(env, dict) else None
        return dict(data) if isinstance(data, dict) else {}

    def nw_device_anchored(self, device: Dict[str, Any]) -> bool:
        """True while the device's own nw agent still belongs to its tenant
        (or the record has no agent binding / the agent has no owner)."""
        # A record with no agent binding is always treated as anchored.
        sid = str(device.get("spoke_id") or "").strip()
        if not sid:
            return True
        # Look up the agent in module metadata; a missing agent means it was deleted.
        md = self.state.system_state.get("module_metadata", {}) or {}
        if sid not in md:
            return False  # agent deleted
        # Anchored when the agent has no owner or still belongs to the record's tenant.
        owner = str((md.get(sid) or {}).get("tenant_id") or "")
        return not owner or owner == str(device.get("tenant_id") or "")

    def nw_relocatable(self, device: Dict[str, Any], to_tenant: str) -> bool:
        """True when the device may move to to_tenant.

        Only unanchored records may move, never to or from the shared tenant, and never to the
        tenant that already owns them.
        """
        # Current owner of the record.
        tid = str(device.get("tenant_id") or "")
        return (bool(to_tenant) and tid != to_tenant and tid != self._nw_shared_tid()
                and to_tenant != self._nw_shared_tid() and not self.nw_device_anchored(device))

    def nw_relocate_device(self, device: Dict[str, Any], to_tenant: str, to_spoke: str,
                           evidence: List[str], cred_set: Optional[Dict[str, Any]] = None
                           ) -> Dict[str, Any]:
        """Move ``device`` (in place, same id) to ``to_tenant``/``to_spoke``.
        ``cred_set`` (the scan credential that just authenticated to it) replaces
        the old tenant's credential reference. Returns a report row."""
        # Remember where the record came from for the report.
        old_t = str(device.get("tenant_id") or "")
        old_s = str(device.get("spoke_id") or "")
        # Reassign the tenant, and the agent too when one is given.
        device["tenant_id"] = to_tenant
        if to_spoke:
            device["spoke_id"] = to_spoke
        # Swap in the credential that just authenticated, so the old tenant's vault entry is
        # no longer referenced.
        if cred_set and cred_set.get("vault_credential"):
            device["vault_credential"] = cred_set["vault_credential"]
            device["username"] = (cred_set.get("username") or cred_set.get("user")
                                  or device.get("username") or "")
        # Record the move (origin, time, evidence) on the device for auditing.
        device["moved_from"] = {"tenant_id": old_t, "spoke_id": old_s,
                                "at": int(time.time()), "evidence": list(evidence)}
        # Persist the change; a state object without _mark_dirty must not break the move.
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001
            pass
        # Warn-level so every cross-tenant move is visible in the logs with its evidence.
        logger.warning("nw: moved device %s '%s' (%s) from tenant %s to %s (agent %s -> %s); "
                       "verified by %s", device.get("id"), device.get("name"), device.get("address"),
                       old_t or "-", to_tenant, old_s[:8] or "-", (to_spoke or old_s)[:8] or "-",
                       "+".join(evidence))
        # Report row describing the move for the caller/UI.
        return {"id": device.get("id"), "name": device.get("name"),
                "address": device.get("address"), "from_tenant": old_t,
                "to_tenant": to_tenant, "from_spoke": old_s, "evidence": list(evidence)}

    def nw_find_relocation(self, devices: List[Dict[str, Any]], tenant_id: str, spoke_id: str,
                           address: str, hostname: str, object_type: str = ""
                           ) -> Optional[Tuple[Dict[str, Any], List[str]]]:
        """An unanchored device in another tenant that a ``tenant_id`` scan
        through ``spoke_id`` just identified at ``address`` as ``hostname``:
        same IP plus the same short hostname, or the same agent at the same IP."""
        # Without an address there is nothing to match against.
        address = str(address or "").strip()
        if not address:
            return None
        # Short hostname the scan reported, for name comparison.
        name = nw_short_name(hostname)
        # Check every other tenant's movable record.
        for d in devices or []:
            # Skip malformed rows and records that may not move to this tenant.
            if not isinstance(d, dict) or not self.nw_relocatable(d, tenant_id):
                continue
            # The record must answer on this address (primary or an alternate).
            addrs = {str(a or "").strip() for a in [d.get("address")] + list(d.get("alt_addresses") or [])}
            if address not in addrs:
                continue
            # Different object types only match when the hostnames also agree.
            ot = str(d.get("object_type") or "")
            if object_type and ot and object_type != ot and name != nw_short_name(d.get("name")):
                continue
            # Same IP + same hostname is strong enough evidence.
            if name and name == nw_short_name(d.get("name")):
                return d, ["ip", "hostname"]
            # Same IP seen through the same agent is also enough.
            if spoke_id and str(d.get("spoke_id") or "") == spoke_id:
                return d, ["ip", "same agent"]
        return None

    async def nw_reconcile_tenant_after_poll(self, device_cfg: Dict[str, Any],
                                             device_info: Dict[str, Any], reachable: bool,
                                             prior_identity: Optional[Dict[str, Any]] = None
                                             ) -> List[Dict[str, Any]]:
        """Poll-time relocation. (1) The polled record is unanchored and its
        agent now belongs to another tenant: the agent reached it at its address
        and the hostname or serial matches → move it to the agent's tenant.
        (2) Another tenant's unanchored record has this box's chassis serial
        (or, both serial-less, the same base MAC and hostname) → fold it into
        this one (its addresses become alt_addresses; the stale row is removed).
        Returns the moves made. Best-effort, never raises."""
        # Collected move report rows; the whole body is best-effort (errors only logged).
        moves: List[Dict[str, Any]] = []
        try:
            # Read the polled identity and the current device list.
            info = device_info if isinstance(device_info, dict) else {}
            gc = self.state.system_state.get("global_config", {}) or {}
            devices = [d for d in (gc.get("nw_devices") or []) if isinstance(d, dict)]
            # Normalized identity of the polled box: serial, base MAC, and short hostname.
            serial = str(info.get("serial") or "").strip().casefold()
            mac = (norm_mac(info.get("mac")) if norm_mac else str(info.get("mac") or "")).strip().casefold() \
                if info.get("mac") else ""
            host = nw_short_name(info.get("hostname"))
            # Tenant that owns the agent which polled this device.
            sid = str(device_cfg.get("spoke_id") or "")
            owner = nw_spoke_tenant(self, sid) if (nw_spoke_tenant and sid) else ""
            # Case 1: the agent now belongs to another tenant and the record is unanchored.
            if reachable and owner and self.nw_relocatable(device_cfg, owner):
                # Compare with the identity recorded before this poll.
                prev = prior_identity if isinstance(prior_identity, dict) else {}
                prev_serial = str(prev.get("serial") or "").strip().casefold()
                ev = []
                # Same serial as before, or the polled hostname matches the record's name, is the
                # evidence needed to move it.
                if serial and prev_serial == serial:
                    ev = ["ip", "serial"]
                elif host and host == nw_short_name(device_cfg.get("name")):
                    ev = ["ip", "hostname"]
                # Move the record to the agent's tenant.
                if ev:
                    moves.append(self.nw_relocate_device(device_cfg, owner, sid, ev + ["agent"]))
            # Case 2 needs a serial or MAC, and never folds records into the shared tenant.
            tid = str(device_cfg.get("tenant_id") or "")
            if not (serial or mac) or tid == self._nw_shared_tid():
                return moves
            # Look for other tenants' movable records that are this same box.
            identity = self._nw_identity_cache()
            stale = []
            # Skip this record itself and records that may not move here.
            for d in devices:
                if d is device_cfg or d.get("id") == device_cfg.get("id") or not self.nw_relocatable(d, tid):
                    continue
                # Identity of the candidate record from the cache.
                di = identity.get(str(d.get("id"))) or {}
                ds = str(di.get("serial") or "").strip().casefold()
                dm = (norm_mac(di.get("mac")) if norm_mac else str(di.get("mac") or "")).strip().casefold() \
                    if di.get("mac") else ""
                # Same serial is a match; with no serials, same MAC plus same hostname is a match.
                # A controller shares its server's serial: never fold across object types.
                if str(d.get("object_type") or "").lower() != str(device_cfg.get("object_type") or "").lower():
                    continue
                if serial and ds == serial:
                    stale.append((d, ["serial"]))
                elif not serial and not ds and mac and dm == mac and host and host == nw_short_name(d.get("name")):
                    stale.append((d, ["mac", "hostname"]))
            # Fold each matching stale record into this one.
            if stale:
                # Ids to remove, and the merged set of alternate addresses.
                gone = {str(d.get("id")) for d, _ in stale}
                alts = set(device_cfg.get("alt_addresses") or [])
                # Collect each stale record's addresses and record the move (on a copy).
                for d, ev in stale:
                    alts |= {a for a in [d.get("address")] + list(d.get("alt_addresses") or []) if a}
                    row = self.nw_relocate_device(dict(d), tid, sid, ev)
                    row["merged_into"] = device_cfg.get("id")
                    moves.append(row)
                # The primary address is never also an alternate.
                alts.discard(device_cfg.get("address"))
                device_cfg["alt_addresses"] = sorted(a for a in alts if a)
                # Drop the stale rows from the device list and persist.
                gc["nw_devices"] = [d for d in (gc.get("nw_devices") or [])
                                    if not (isinstance(d, dict) and str(d.get("id")) in gone)]
                self.state.system_state["global_config"] = gc
                self.state._mark_dirty()
            # Re-send the fleet list to every agent affected so they stop/start polling the moved
            # rows.
            if moves:
                pusher = getattr(self, "nw_push_fleet", None)
                for s in {m.get("from_spoke") for m in moves} | {sid}:
                    if s and callable(pusher):
                        try:
                            await pusher(s)
                        # A failed re-push is logged; the next regular push will catch up.
                        except Exception as e:  # noqa: BLE001
                            logger.warning("nw relocate: re-push to %s failed: %s", s, e)
        # Relocation must never break a poll; just log the failure.
        except Exception as e:  # noqa: BLE001
            logger.warning("nw relocate after poll of %s failed: %s", device_cfg.get("id"), e)
        return moves

    async def merge_nw_hardware_duplicates(self, apply: bool = False) -> Dict[str, Any]:
        """Fold rows that are the same physical box into its primary row (the
        one NetBox and Zabbix already use), keeping the extra addresses as the
        primary's ``alt_addresses``. Grouping is ``nw_hardware_primaries``; a
        row is merged only when a poll confirms it: same chassis serial, else
        (no serial on either) the same base MAC. Name-only matches are
        reported, never removed. ``apply=False`` is a dry run."""
        # Load the device list, the cached identities, and the computed primaries.
        gc = self.state.system_state.get("global_config", {})
        devices = [d for d in (gc.get("nw_devices", []) or []) if isinstance(d, dict)]
        identity = self._nw_identity_cache()
        prim = nw_hardware_primaries(devices, identity)
        # Index device rows by id.
        by_id = {str(d.get("id")): d for d in devices if d.get("id")}

        def _id(did, key):
            """Normalized identity field (serial or mac) for a device id."""
            return str((identity.get(did) or {}).get(key) or "").strip().casefold()

        def _confirmed(did, pid):
            """True when a poll confirms the duplicate: same serial, else same base MAC."""
            # If either side has a serial, the serials must match.
            if _id(did, "serial") or _id(pid, "serial"):
                return _id(did, "serial") == _id(pid, "serial")
            # With no serials, both base MACs must be present and equal.
            return bool(_id(did, "mac")) and _id(did, "mac") == _id(pid, "mac")

        def _row(d):
            """Small summary row (id, name, address) for the report."""
            return {"id": d.get("id"), "name": d.get("name"), "address": d.get("address")}

        # Group non-primary rows under their primary, split into confirmed and unconfirmed.
        groups: Dict[str, Dict[str, Any]] = {}
        for did, pid in prim.items():
            # Primaries themselves are not duplicates.
            if did == pid:
                continue
            g = groups.setdefault(pid, {"primary": _row(by_id[pid]), "merged": [], "unconfirmed": []})
            g["merged" if _confirmed(did, pid) else "unconfirmed"].append(_row(by_id[did]))

        # Ids of rows that would be (or will be) removed.
        removed = {str(r["id"]) for g in groups.values() for r in g["merged"]}
        # Only change anything when applying and there is something to merge.
        if apply and removed:
            spokes = set()
            # For each group, fold the merged rows' addresses into the primary.
            for pid, g in groups.items():
                if not g["merged"]:
                    continue
                # Collect all addresses of the merged rows, excluding the primary's own address.
                p = by_id[pid]
                alts = [a for a in (p.get("alt_addresses") or []) + [r["address"] for r in g["merged"]]
                        + [a for r in g["merged"] for a in (by_id[str(r["id"])].get("alt_addresses") or [])]
                        if a and a != p.get("address")]
                # Store them deduplicated and sorted; remember which agents must be re-pushed.
                p["alt_addresses"] = sorted(set(alts))
                spokes.update(by_id[str(r["id"])].get("spoke_id") for r in g["merged"])
            # Drop the merged rows from the device list and persist.
            gc["nw_devices"] = [d for d in (gc.get("nw_devices", []) or [])
                                if not (isinstance(d, dict) and str(d.get("id")) in removed)]
            self.state.system_state["global_config"] = gc
            self.state._mark_dirty()
            # Re-push the fleet list to affected agents so they stop polling removed rows.
            pusher = getattr(self, "nw_push_fleet", None)
            for sid in filter(None, spokes):
                try:
                    if callable(pusher):
                        await pusher(sid)
                # A failed re-push is logged; the next regular push will catch up.
                except Exception as e:  # noqa: BLE001
                    logger.warning("nw dedupe: re-push to %s failed: %s", sid, e)
            # Summary of what was merged.
            logger.warning("nw dedupe: merged %d duplicate row(s) into %d device(s)",
                           len(removed), sum(1 for g in groups.values() if g["merged"]))
        # Report: whether it applied, how many rows were removed, and the groups found.
        return {"applied": bool(apply), "removed": len(removed),
                "groups": [g for g in groups.values() if g["merged"] or g["unconfirmed"]]}

    def _nw_spokes(self) -> List[str]:
        """Connected nw spoke ids to pull from this cycle."""
        # Ask the hub for every connected spoke of type "nw".
        return list(self.get_all_spokes_by_type("nw") or [])

    def _nw_devices_for_spoke(self, spoke_id: str) -> List[Dict[str, Any]]:
        """Devices bound to this nw spoke (or unbound devices when none are
        bound to it — single-product deployments don't bind spoke_id). Read
        from global_config so there's no extra round-trip."""
        # Prefer devices explicitly bound to this spoke.
        devices = (self.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
        # None bound: fall back to unbound devices (single-spoke setups).
        if not mine:
            mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
        return mine

    def _nw_discovery_concurrency(self) -> int:
        """Max tenants pushed in parallel per cycle. Clamp 1..8; default 4."""
        # Read the configured concurrency, defaulting to 4 on bad values.
        try:
            n = int(self._nw_discovery_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        # Keep it between 1 and 8 so a bad value cannot stall or flood spokes.
        return max(1, min(8, n))

    # ── pull / attribute / push ─────────────────────────────────────────────

    async def _nw_pull_discovered(self) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
        """Pull the ARP table (and MAC table, when the source provides a
        ``mac_command``) from every device on every connected nw spoke, merge +
        dedup. Returns ``(records, pull_info)`` where each record is
        ``{ip, mac, hostname, source_switch_name, source_switch_ip,
        source_switch_port}`` (mac normalized) and ``pull_info`` is
        ``{"errors": [...]}``. ARP/MAC tables carry no hostname, so each record
        is cross-referenced against LM's DHCP (Kea) + DNS modules
        (``_nw_identity_index``): hostname by MAC, else by IP; a MAC-only
        sighting also takes its lease/reservation IP. Opt out with
        ``nw_netbox_device_sync.enrich_from_dhcp = false``.

        The source-switch identity (device name + mgmt IP) + the port the MAC
        was seen on are attached to EVERY record so NetBox answers "where is
        this MAC?" — the device's switch_name/switch_ip/switch_port custom
        fields. MAC-table rows have no IP → they surface here as MAC-only
        records (``ip == ""``); the entry points split them off and push them
        UNSCOPED (no tenant) since prefix attribution needs an IP. Dedup by MAC
        (primary) then IP; a MAC seen on the MAC table that later shows an IP in
        ARP merges into one IP-bearing record (so the device gets its tenant).
        """
        # Source settings, connected nw spokes, and accumulators for rows and errors.
        se = self._nw_discovery_source()
        spokes = self._nw_spokes()
        raw: List[Dict[str, str]] = []
        errors: List[str] = []
        # No spoke connected means nothing to pull; report why.
        if not spokes:
            return [], {"errors": ["no nw spoke connected"]}

        # Bound the fetch phase so a single spoke backing M devices doesn't get
        # M concurrent request_response calls (2M if mac_command set: ARP+MAC).
        # The push phase at the bottom already uses this semaphore; the fetch
        # phase didn't — that was the only true stampede-to-one-spoke in the
        # codebase.
        fetch_sem = asyncio.Semaphore(self._nw_discovery_concurrency())

        async def _fetch(sid: str, device: Dict[str, Any]) -> None:
            """Fetch ARP (and MAC) rows for one device on one spoke and append them to raw."""
            # Device id, display name, and management address.
            did = device.get("id", "")
            dname = device.get("name", did)
            daddr = str(device.get("address") or "").strip()
            # Switch identity carried on every record so the NetBox device
            # records where the MAC was last seen.
            sw = {"source_switch_name": dname, "source_switch_ip": daddr}
            # Tenant of the agent that saw the row: tenants overlap address
            # space, so attribution prefers this tenant's VRF. A dedicated
            # agent's rows are its tenant's outright (no prefix check).
            # Prefer the agent owner's tenant, then the device's tenant, then the spoke's tenant.
            owner = spoke_owner_tenant(self, sid) if spoke_owner_tenant else None
            src_tid = owner or str(device.get("tenant_id") or "").strip() or (
                nw_spoke_tenant(self, sid) if nw_spoke_tenant else "")
            # Commands to run: ARP always, the MAC table when the source supports it.
            cmds = [se.get("arp_command", "NW_GET_ARP")]
            mac_cmd = se.get("mac_command")
            if mac_cmd:
                cmds.append(mac_cmd)
            # Run each command and collect its rows.
            for cmd in cmds:
                if not cmd:
                    continue
                # Fetch under the semaphore so one spoke is not flooded with requests.
                try:
                    async with fetch_sem:
                        r = await self.request_response(sid, cmd, {"device_id": did},
                                                        timeout=30.0)
                    # Unwrap the envelope; an ERROR status is recorded and the command skipped.
                    d = unwrap_spoke(r) if isinstance(r, dict) else {}
                    if isinstance(d, dict) and d.get("status") == "ERROR":
                        errors.append(f"{cmd}({dname}@{sid}): "
                                      f"{d.get('message', 'error')}")
                        continue
                    # The data list holds the table rows.
                    rows = (d.get("data") if isinstance(d, dict) else None) or []
                    # Turn each table row into a normalized sighting record.
                    for row in rows or []:
                        if not isinstance(row, dict):
                            continue
                        # Read the IP; spokes report "unknown" for MAC-table rows, which means no
                        # IP.
                        ip = str(row.get("ip") or "").strip()
                        if ip == "unknown":
                            ip = ""
                        # Normalize the MAC and read the port the row was seen on.
                        mac = norm_mac(row.get("mac")) if norm_mac else \
                            str(row.get("mac") or "")
                        port = str(row.get("interface") or row.get("port") or "").strip()
                        # A row with neither IP nor MAC identifies nothing.
                        if not ip and not mac:
                            continue
                        # Build the record and attach the switch identity, port, and tenant hints.
                        rec: Dict[str, str] = {"ip": ip, "mac": mac, "hostname": ""}
                        rec.update(sw)
                        if port:
                            rec["source_switch_port"] = port
                        if src_tid:
                            rec["source_tenant_id"] = src_tid
                        if owner:
                            rec["owner_tenant_id"] = owner
                        # Keep the raw sighting for the merge step.
                        raw.append(rec)
                # Any failure for one device/command is recorded and the rest continue.
                except Exception as e:
                    errors.append(f"{cmd}({dname}@{sid}): {e}")

        # Queue one fetch per (spoke, device) pair and run them all concurrently.
        fetches = []
        for sid in spokes:
            for device in self._nw_devices_for_spoke(sid):
                fetches.append(_fetch(sid, device))
        await asyncio.gather(*fetches, return_exceptions=True)

        # Merge + dedup: key by MAC (primary), else by ip:<ip>, per discovering
        # tenant — the same IP (or a VRRP/default-gateway MAC) in two tenants'
        # VRFs is two devices. Preserve the source-switch fields (fill from
        # whichever sighting carried them) so a MAC-only sighting later
        # enriched with an IP keeps its switch/port.
        # Walk every raw sighting and merge it into a per-tenant MAC/IP key.
        merged: Dict[str, Dict[str, str]] = {}
        # A MAC is learned on every switch along its path (uplinks, peer links),
        # and fetch completion order is random, so "first sighting wins" made the
        # recorded switch flap. Order sightings so the access port (fewest MACs
        # learned on it) wins, ties broken by switch name/port: stable per run.
        port_macs: Dict[Tuple[str, str], set] = {}
        for rec in raw:
            if rec.get("mac") and rec.get("source_switch_port"):
                port_macs.setdefault((rec.get("source_switch_name", ""),
                                      rec["source_switch_port"]), set()).add(rec["mac"])
        raw.sort(key=lambda r: (
            len(port_macs.get((r.get("source_switch_name", ""),
                               r.get("source_switch_port", "")), ())) or 10 ** 9,
            r.get("source_switch_name", ""), r.get("source_switch_port", "")))
        for rec in raw:
            mac, ip = rec.get("mac", ""), rec.get("ip", "")
            # Key by MAC when known, else by IP; rows with neither are skipped.
            key = mac if mac else (f"ip:{ip}" if ip else "")
            if not key:
                continue
            # Prefix the key with the discovering tenant so overlapping address space stays
            # separate.
            key = f"{rec.get('source_tenant_id', '')}|{key}"
            # First sighting for this key is stored as-is.
            ex = merged.get(key)
            if ex is None:
                merged[key] = dict(rec)
            # Later sightings only fill gaps (IP, MAC, switch fields) in the stored record.
            else:
                if not ex.get("ip") and ip:
                    ex["ip"] = ip
                if not ex.get("mac") and mac:
                    ex["mac"] = mac
                for k in ("source_switch_name", "source_switch_ip",
                          "source_switch_port", "owner_tenant_id"):
                    if not ex.get(k) and rec.get(k):
                        ex[k] = rec[k]
        # Merged, deduplicated records.
        records = list(merged.values())
        # ARP/MAC tables carry no hostname: cross-reference LM's DHCP + DNS
        # modules so NetBox gets a named device (and MAC-only sightings get
        # their lease IP → tenant attribution) instead of device-<mac>.
        by_mac, by_ip = await self._nw_identity_index()
        # Only enrich when the index found anything, then log what it filled.
        if by_mac or by_ip:
            stats = self._nw_apply_identity(records, by_mac, by_ip,
                                            getattr(self, "_nw_ip_host_src", None))
            logger.info("nw discovery: identity cross-reference named=%d ip_filled=%d "
                        "(index: %d MACs, %d IPs)", stats["named"], stats["ip_filled"],
                        len(by_mac), len(by_ip))
        # Return the records plus any per-device errors.
        return records, {"errors": errors}

    async def _nw_identity_index(self) -> Tuple[Dict[str, Dict[str, str]], Dict[str, str]]:
        """Cross-reference LM's DHCP (Kea reservations, then leases) and DNS
        (Unbound A records) identity so ARP/MAC-table sightings, which carry no
        hostname, get one — and MAC-only sightings get their lease IP. Returns
        ``(by_mac, by_ip)``; higher-priority sources win. Never raises."""
        # DHCP/DNS enrichment can be turned off in the sync config.
        use_dhcp = self._nw_discovery_cfg().get("enrich_from_dhcp", True) is not False
        # by_mac maps MAC -> {ip, hostname}; by_ip maps IP -> hostname.
        by_mac: Dict[str, Dict[str, str]] = {}
        by_ip: Dict[str, str] = {}
        # hostname_source per entry: "reservation"/"dns" are operator
        # assertions, "lease" is the device's own DHCP hostname.
        src_of = {"DHCP_LIST_RES": "reservation", "DHCP_LIST_LEASES": "lease",
                  "DNS_LIST": "dns"}
        # Remember which source named each IP; stored on self for _nw_apply_identity.
        self._nw_ip_host_src = ip_src = {}

        def _ip(v: Any) -> str:
            """Clean an IP value: drop any /prefix and treat "unknown" as empty."""
            s = str(v or "").strip().split("/")[0].strip()
            return "" if s.lower() in ("", "unknown") else s

        def _mac(v: Any) -> str:
            """Normalize a MAC address string."""
            return norm_mac(v) if norm_mac else str(v or "").strip().lower()

        def _host(v: Any) -> str:
            """Clean a hostname: drop a trailing dot and treat "unknown" as empty."""
            s = str(v or "").strip().rstrip(".")
            return "" if s.lower() in ("", "unknown") else s

        # (command, module_type, list_key) in PRIORITY order.
        plan = [("DHCP_LIST_RES", "dhcp", "reservations"),
                ("DHCP_LIST_LEASES", "dhcp", "leases"),
                ("DNS_LIST", "dns", "records")]
        # Build one job per (command, spoke) for every DHCP and DNS spoke.
        jobs = []  # (command, spoke_id, list_key)
        for cmd, mtype, key in (plan if use_dhcp else []):
            # dict.fromkeys de-duplicates spoke ids while keeping order.
            for sid in dict.fromkeys(self.get_all_spokes_by_type(mtype) or []):
                jobs.append((cmd, sid, key))

        async def _one(cmd: str, sid: str):
            """Run one list command on one spoke; failures are logged and return None."""
            try:
                return await self.request_response(sid, cmd, {}, timeout=30.0)
            except Exception as e:
                logger.warning("nw identity index: %s(%s) failed: %s", cmd, sid, e)
                return None

        # Run all list commands concurrently; results line up with jobs.
        results = await asyncio.gather(*[_one(c, s) for c, s, _ in jobs])

        # Process results in priority order so earlier sources win.
        for (cmd, sid, key), raw in zip(jobs, results):
            # Skip failed calls and ERROR envelopes.
            if raw is None:
                continue
            d = unwrap_spoke(raw) if isinstance(raw, dict) else None
            if not isinstance(d, dict) or str(d.get("status") or "").upper() == "ERROR":
                continue
            # The rows are under the command's list key, or "data" as a fallback.
            rows = d.get(key)
            if not isinstance(rows, list):
                rows = d.get("data")
            if not isinstance(rows, list):
                continue
            # Index each row by MAC and/or IP.
            for row in rows:
                if not isinstance(row, dict):
                    continue
                # DNS: only A records map an IP to a hostname.
                if cmd == "DNS_LIST":
                    if str(row.get("type") or "").upper() != "A":
                        continue
                    ip = _ip(row.get("value"))
                    host = _host(row.get("name"))
                    if ip and host and ip not in by_ip:
                        by_ip[ip] = host
                        ip_src[ip] = "dns"
                    continue
                # Leases: only active leases (state 0/absent) count.
                if cmd == "DHCP_LIST_LEASES" and row.get("state") not in (None, 0, "0"):
                    continue
                # Read IP, MAC, and hostname using Kea's alternate field names as fallbacks.
                ip = _ip(row.get("ip") or row.get("ip-address"))
                mac = _mac(row.get("mac") or row.get("hw-address"))
                host = _host(row.get("hostname"))
                # Fill the MAC entry's missing IP and hostname (first source wins).
                if mac:
                    ent = by_mac.setdefault(mac, {"ip": "", "hostname": ""})
                    if ip and not ent["ip"]:
                        ent["ip"] = ip
                    if host and not ent["hostname"]:
                        ent["hostname"] = host
                        ent["hostname_source"] = src_of[cmd]
                # Fill the IP -> hostname map if this IP is not named yet.
                if ip and host and ip not in by_ip:
                    by_ip[ip] = host
                    ip_src[ip] = src_of[cmd]
        # Add identities the network devices report themselves (LLDP, fleet names).
        self._nw_add_device_identities(by_mac, by_ip, ip_src)
        return by_mac, by_ip

    def _nw_add_device_identities(self, by_mac: Dict[str, Dict[str, str]],
                                  by_ip: Dict[str, str],
                                  ip_src: Dict[str, str]) -> None:
        """Fill identity-index GAPS from what the network devices themselves
        report: LLDP neighbour advertisements (system name + mgmt IP + chassis
        MAC) and the NW fleet's own polled names. A static infrastructure box
        (gateway, switch, AP) has no DHCP lease or DNS record, so without this
        its ARP sighting reaches NetBox nameless and becomes ``DEVICE-<mac>``.
        DHCP/DNS entries already present always win."""
        # LLDP advertisements fill missing MAC and IP entries, tagged as source "lldp".
        for ident in self._nw_lldp_identities():
            mac, ip, name = ident["mac"], ident["ip"], ident["name"]
            if mac:
                ent = by_mac.setdefault(mac, {"ip": "", "hostname": ""})
                if ip and not ent["ip"]:
                    ent["ip"] = ip
                if name and not ent["hostname"]:
                    ent["hostname"] = name
                    ent["hostname_source"] = "lldp"
            if ip and name and ip not in by_ip:
                by_ip[ip] = name
                ip_src[ip] = "lldp"
        # Configured fleet device names fill missing IP names. Lazy import avoids a cycle.
        try:
            from nw_topology import _is_real_hostname
            fleet = (self.state.system_state.get("global_config", {})
                     .get("nw_devices", []) or [])
            # Use each device's address and name when the name is a real hostname.
            for dev in fleet:
                if not isinstance(dev, dict):
                    continue
                ip = str(dev.get("address") or "").strip().split("/")[0].strip()
                name = str(dev.get("name") or "").strip()
                if ip and _is_real_hostname(name) and ip not in by_ip:
                    by_ip[ip] = name
                    ip_src[ip] = "nw"
        # Enrichment is optional; failures are only logged at debug level.
        except Exception as e:  # noqa: BLE001 - enrichment is best-effort
            logger.debug("nw identity index: fleet names skipped: %s", e)

    def _nw_lldp_self_identity(self, address: str) -> Dict[str, str]:
        """What neighbours' LLDP says about the box managed at ``address``:
        ``{"name", "mac"}`` from the advertisement whose management IP is that
        address (empty values when none / ambiguous)."""
        # Strip any /prefix, then collect names/MACs advertised for this address.
        address = str(address or "").strip().split("/")[0].strip()
        names, macs = set(), set()
        if address:
            for ident in self._nw_lldp_identities():
                if ident["ip"] == address:
                    if ident["name"]:
                        names.add(ident["name"])
                    if ident["mac"]:
                        macs.add(ident["mac"])
        # Only return a value when exactly one distinct name/MAC was seen (no guessing).
        return {"name": next(iter(names)) if len(names) == 1 else "",
                "mac": next(iter(macs)) if len(macs) == 1 else ""}

    def _nw_lldp_identities(self) -> List[Dict[str, str]]:
        """Every identity the nw LLDP cache has learned about a neighbour: one
        ``{"mac", "ip", "name"}`` per distinct advertisement (system name,
        management IP, chassis MAC). Lets ARP/MAC sightings and polls that
        carry no hostname borrow the name the box advertises itself (e.g. an
        ArubaOS gateway whose poll returns neither hostname nor base MAC).
        Reads only the in-memory cache; never raises."""
        # Read the in-memory device cache; anything unexpected means no identities.
        cache = getattr(self, "nw_device_cache", None) or {}
        if not isinstance(cache, dict):
            return []
        # Collected identities and a seen set to dedupe them.
        out = []
        seen = set()
        # Lazy import avoids a cycle with nw_topology.
        try:
            from nw_topology import _is_real_hostname
            # Walk each device's cached LLDP neighbour table.
            for entry in list(cache.values()):
                if not isinstance(entry, dict):
                    continue
                env = entry.get("lldp")
                rows = env.get("data") if isinstance(env, dict) else None
                if not isinstance(rows, list):
                    continue
                # Pull a cleaned name, management IP, and chassis MAC from each advertisement.
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    # Short hostname (IPs kept whole); placeholder names are discarded.
                    name = str(row.get("remote_name") or "").strip().rstrip(".")
                    if name and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", name):
                        name = name.split(".", 1)[0]
                    if not _is_real_hostname(name):
                        name = ""
                    # Only keep a valid, non-0.x IPv4 management address.
                    ip = str(row.get("remote_mgmt_ip") or "").strip().split("/")[0].strip()
                    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) or ip.startswith("0."):
                        ip = ""
                    # Only keep a well-formed colon-separated MAC.
                    raw = str(row.get("remote_chassis") or "").strip()
                    mac = (norm_mac(raw) if norm_mac else raw.lower()) if raw else ""
                    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac or ""):
                        mac = ""
                    # Useful only with a name or with both a MAC and an IP.
                    if not name and not (mac and ip):
                        continue
                    # Skip duplicate advertisements.
                    key = (mac, ip, name.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({"mac": mac, "ip": ip, "name": name})
        # Never raise from enrichment; just log at debug level.
        except Exception as e:
            logger.debug("nw lldp identities: %s", e)
        return out

    @staticmethod
    def _nw_apply_identity(records: List[Dict[str, str]],
                           by_mac: Dict[str, Dict[str, str]],
                           by_ip: Dict[str, str],
                           ip_src: Optional[Dict[str, str]] = None) -> Dict[str, int]:
        """Fill each sighting's missing ``ip`` (from its MAC's DHCP lease/
        reservation) and ``hostname`` (by MAC, else by IP) in place. Never
        overwrites a value the sighting already carries, and never fills an IP
        another sighting already holds (a stale lease must not steal a live
        ARP address). Returns ``{"named", "ip_filled"}`` counts."""
        # Counters returned to the caller for logging.
        result = {"named": 0, "ip_filled": 0}
        # IPs already held by a live sighting; a lease IP may not be reused for another record.
        taken = {r.get("ip") for r in records if isinstance(r, dict) and r.get("ip")}

        # Enrich each record in place.
        for rec in records:
            if not isinstance(rec, dict):
                continue

            # Look up DHCP/DNS identity by the record's MAC.
            mac = rec.get("mac", "")
            ident = by_mac.get(mac) if mac else None

            # MAC-only sighting: borrow the MAC's lease/reservation IP if no other record has it.
            if (not rec.get("ip") and ident and ident.get("ip")
                    and ident["ip"] not in taken):
                rec["ip"] = ident["ip"]
                taken.add(ident["ip"])
                result["ip_filled"] += 1

            # Name an unnamed record by MAC first, else by its IP, keeping the name's source.
            if not rec.get("hostname"):
                hostname, h_src = None, ""
                if ident and ident.get("hostname"):
                    hostname = ident["hostname"]
                    h_src = ident.get("hostname_source", "")
                elif rec.get("ip"):
                    hostname = by_ip.get(rec["ip"])
                    h_src = (ip_src or {}).get(rec["ip"], "")

                # Store the found name and count it.
                if hostname:
                    rec["hostname"] = hostname
                    if h_src:
                        rec["hostname_source"] = h_src
                    result["named"] += 1

        return result

    async def _nw_attribute(self, records: List[Dict[str, str]]
                            ) -> Tuple[Dict[str, List[Dict[str, str]]], int]:
        """Bucket discovered records by tenant via prefix containment (delegate
        to the shared ``access.attribute_by_prefix``). Records with no IP, an
        unparseable IP, or an IP no tenant owns are ``dropped`` (counted)."""
        # Without the access helper nothing can be attributed; count everything as dropped.
        if attribute_by_prefix is None:  # pragma: no cover - access importable in-app
            return {}, len(records)
        # Shared prefix-containment attribution returns ({tenant: records}, dropped_count).
        return await attribute_by_prefix(self, records)

    async def _nw_push_unscoped_mac_sightings(self, devices: List[Dict[str, str]]
                                              ) -> Dict[str, Any]:
        """Push MAC-only sightings (no IP → no tenant) to NetBox UNSCOPED
        (``tenant_slug=""``, ``replace=False``) so a MAC seen on a switch MAC
        table but with no known IP is still recorded in NetBox, carrying its
        source switch/port (the "where is this MAC" answer).

        Only-add-missing (``replace=False``): a later IP sighting for that MAC
        adopts the device via the netbox sink's MAC-match tier and assigns the
        IP + tenant. Best-effort: never raises. Not persisted to the per-tenant
        store (it is global, not tenant-scoped) — logged + returned only.
        """
        # UTC timestamp for the status report.
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Find the NetBox spoke; without it report an error instead of pushing.
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            return {"mac_only_total": len(devices), "last_sync_ts": now,
                    "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "message": "NetBox spoke not connected"}
        # Nothing to send is a success with zero counts.
        if not devices:
            return {"mac_only_total": 0, "last_sync_ts": now, "status": "success",
                    "pushed": 0, "errors": 0, "skipped": 0, "deleted": 0,
                    "message": "no MAC-only sightings"}
        # Unscoped payload: blank tenant fields and replace=False (only add missing records).
        defaults = self._nw_discovery_cfg().get("defaults", {}) or {}
        payload = {"tenant_id": "", "tenant_slug": "", "tenant_name": "",
                   "source": self._nw_discovery_source().get("label", "Network Devices"),
                   "replace": False, "devices": devices, "defaults": defaults}
        # Send to NetBox and read back its counters; any exception is reported as an error.
        try:
            rr = await self.request_response(netbox, self._NW_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=120.0)
            # Unwrap the reply and coerce each counter to an int.
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", 0) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            rstate = "success" if rstatus != "ERROR" else "error"
            # Warn on any error so it shows in the sync-error feed; otherwise log at info.
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] nw-discovery mac-only unscoped "
                               "sent=%d status=%s pushed=%d skipped=%d errors=%d — %s",
                               len(devices), rstate, pushed, skipped, errors,
                               message or "NetBox error")
            else:
                logger.info("nw discovery sync mac-only unscoped sent=%d pushed=%d "
                            "skipped=%d", len(devices), pushed, skipped)
            # Return the summary for the caller.
            return {"mac_only_total": len(devices), "last_sync_ts": now,
                    "status": rstate, "pushed": pushed, "errors": errors,
                    "skipped": skipped, "deleted": deleted,
                    "message": message or (f"{len(devices)} MAC-only sighting(s) sent"
                                            if rstatus != "ERROR" else "NetBox error")}
        # The push itself failed (timeout, disconnect); report it without raising.
        except Exception as e:
            logger.warning("[sync-error] nw-discovery mac-only unscoped push failed: %s", e)
            return {"mac_only_total": len(devices), "last_sync_ts": now,
                    "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "message": str(e)}

    async def _nw_push_tenant(self, tenant_id: str,
                              devices: List[Dict[str, str]]) -> Dict[str, Any]:
        """Push one tenant's nw-discovered devices to NetBox via
        NETBOX_SYNC_DEVICES. Records per-tenant last-sync status. Payload
        carries ``replace=True`` + ``source="Network Devices"`` (the netbox
        sink tags records nw-owned and replace-deletes only nw-owned records).
        Best-effort: never raises."""
        # UTC timestamp and the tenant's display name and NetBox slug.
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        # Fields shared by every status this function can return.
        base = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                "last_sync_ts": now, "discovered_total": len(devices)}
        # Without the NetBox spoke, record and return an error status.
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": "NetBox spoke not connected"}
            await self.simulations_store.set_nw_discovery_sync_status(tenant_id, status)
            return status
        # A tenant not linked to a NetBox tenant cannot be pushed; record it as skipped.
        if not netbox_slug:
            status = {**base, "status": "skipped", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0,
                      "message": "tenant not bound to NetBox (no netbox_tenant_slug)"}
            await self.simulations_store.set_nw_discovery_sync_status(tenant_id, status)
            return status
        # Tenant-scoped authoritative payload (replace=True lets NetBox delete stale records).
        defaults = self._nw_discovery_cfg().get("defaults", {}) or {}
        payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                   "tenant_name": tenant_name,
                   "source": self._nw_discovery_source().get("label", "Network Devices"),
                   "replace": True, "devices": devices, "defaults": defaults}
        # Send to NetBox and read back its counters; any exception is reported as an error.
        try:
            rr = await self.request_response(netbox, self._NW_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=120.0)
            # Unwrap the reply and coerce each counter to an int.
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(devices)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            rstate = "success" if rstatus != "ERROR" else "error"
            # Warn on any error so it shows in the sync-error feed; otherwise log at info.
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] nw-discovery tenant=%s(%s) status=%s "
                               "sent=%d pushed=%d skipped=%d deleted=%d errors=%d — %s",
                               tenant_id, tenant_name, rstate, len(devices),
                               pushed, skipped, deleted, errors, message or "NetBox error")
            else:
                logger.info("nw discovery sync tenant=%s(%s) result status=%s sent=%d "
                            "pushed=%d skipped=%d deleted=%d errors=%d",
                            tenant_id, tenant_name, rstate,
                            len(devices), pushed, skipped, deleted, errors)
            # Build the status from NetBox's counters.
            status = {**base, "status": rstate,
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted,
                      "message": message or (f"{len(devices)} device(s) sent"
                                              if rstatus != "ERROR" else "NetBox error")}
        # The push itself failed (timeout, disconnect); record an error status.
        except Exception as e:
            logger.warning("[sync-error] nw-discovery tenant=%s push failed: %s",
                           tenant_id, e)
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": str(e)}
        # Save the per-tenant status for the UI and return it.
        await self.simulations_store.set_nw_discovery_sync_status(tenant_id, status)
        return status

    # ── entry points ────────────────────────────────────────────────────────

    async def push_nw_device_inventory(self, device_cfg: Dict[str, Any],
                                       device_info: Dict[str, Any],
                                       interfaces: List[Dict[str, Any]]
                                       ) -> "tuple[Dict[str, Any], List[str], str]":
        """Push one nw device + its interfaces to NetBox as a dcim.device
        inventory record from **already-gathered** poll data (no re-poll).

        Shared by the manual ``poll_nw_device`` (Poll Now) and the spoke-driven
        auto-poll (NW_POLL_RESULT handler) so a device's inventory syncs to
        NetBox on its own ``poll_interval`` cadence. Tenant is attributed by the
        device's mgmt-address prefix containment. Returns
        ``(netbox_push_summary, errors, tenant_slug)`` — the resolved slug is
        threaded back so callers (poll_nw_device) can report it without
        re-attributing; best-effort — never raises.
        """
        # Error list for the caller, plus the device id (name as fallback).
        errors: List[str] = []
        device_info = device_info or {}
        device_id = str(device_cfg.get("id", "") or device_cfg.get("name", ""))

        # The same box discovered at another address: only its primary row
        # writes the NetBox device, so one switch is one NetBox record with a
        # stable primary IP (not one per SVI, re-pointed every poll).
        primary = self.nw_hardware_primary_of(device_id)
        # Not the primary row of its box: skip so the box is only written once.
        if primary != device_id:
            logger.debug("nw device push %s (%s): same hardware as %s — skipped",
                         device_id, device_cfg.get("name"), primary)
            return {"status": "SKIPPED", "pushed": 0, "errors": 0, "skipped": 1,
                    "deleted": 0, "interfaces_total": 0,
                    "message": f"same hardware as {primary}"}, errors, ""

        # Attribute tenant by the device's mgmt-address prefix containment,
        # preferring the tenant the device (or its nw spoke) belongs to so an
        # address that exists in several tenants' VRFs lands in its own.
        # Empty slug means push without a tenant.
        tenant_slug = ""
        # Only attribute when the device has an address and the helper is available.
        if device_cfg.get("address") and attribute_by_prefix is not None:
            try:
                # Tenant hints: device/spoke tenant and the agent's owner tenant.
                src_tid = str(device_cfg.get("tenant_id") or "").strip() or (
                    nw_spoke_tenant(self, device_cfg.get("spoke_id"))
                    if nw_spoke_tenant and device_cfg.get("spoke_id") else "")
                owner = (spoke_owner_tenant(self, device_cfg.get("spoke_id"))
                         if spoke_owner_tenant else None)
                # Attribute the management address as if it were a sighting.
                buckets, _dropped = await attribute_by_prefix(
                    self, [{"ip": str(device_cfg.get("address")), "mac": "",
                            "hostname": "", "source_tenant_id": src_tid,
                            "owner_tenant_id": owner or ""}])
                # Use the first matching tenant's NetBox slug.
                tid = next(iter(buckets), None)
                if tid:
                    tcfg = self.state.get_tenant(tid) or {}
                    tenant_slug = str(tcfg.get("netbox_tenant_slug") or "").strip()
            # Attribution is best-effort; push untenanted on failure.
            except Exception as e:
                logger.debug("nw device push tenant attribution for %s: %s",
                             device_id, e)

        # Without the NetBox spoke the poll data cannot be pushed.
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            errors.append("NetBox spoke not connected — poll only (no push)")
            return {}, errors, tenant_slug

        # Base MAC from the poll, else from what LLDP neighbours advertise for this address.
        base_mac = str(device_info.get("mac", "") or "")
        if not base_mac:
            base_mac = self._nw_lldp_self_identity(
                device_cfg.get("address", "")).get("mac", "")
        # Stitch a management controller to its host OS by hardware serial (no-op for
        # other types); the link rides to NetBox so both records point at each other.
        linked_host: Dict[str, Any] = {}
        if str(device_cfg.get("object_type") or "").lower() == "ipmi":
            fresh = {device_id: str(device_info.get("serial", "") or "")} if device_info.get("serial") else None
            hw_serial_links.refresh_hw_serial_links(self, fresh)
            linked_host = hw_serial_links.controller_link_for(
                device_cfg, str(device_info.get("serial", "") or ""))
        # Inventory payload: device identity, hardware spec, interfaces, and tenant slug.
        payload = {
            "device": {
                "id": device_cfg.get("id", device_id),
                "name": device_cfg.get("name", "") or device_id,
                "address": device_cfg.get("address", ""),
                "object_type": device_cfg.get("object_type", ""),
                "model": str(device_info.get("model", "") or ""),
                "serial": str(device_info.get("serial", "") or ""),
                "mac": base_mac,
                "firmware": str(device_info.get("firmware", "") or ""),
                "host_model": str(device_info.get("host_model", "") or ""),
                "linked_host": linked_host,
                # A controller is racked with its server, so size it by the server's model.
                "spec": await get_device_spec(
                    self, str(device_info.get("host_model")
                              or device_info.get("model", "") or ""),
                    str(device_cfg.get("object_type", "") or ""),
                    [i.get("name") for i in interfaces or [] if isinstance(i, dict)]),
            },
            "interfaces": interfaces or [],
            "tenant_slug": tenant_slug,
            "defaults": self._nw_discovery_cfg().get("defaults", {}) or {},
            "source": self._nw_discovery_source().get("label", "Network Devices"),
        }
        # Send the inventory and summarize NetBox's reply; failures are recorded, not raised.
        try:
            rr = await self.request_response(netbox, self._NW_DEVICE_PUSH_COMMAND,
                                             payload, timeout=120.0)
            # Unwrap the reply and coerce each counter.
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            netbox_push = {
                "status": str((rd or {}).get("status") or "").upper(),
                "pushed": int((rd or {}).get("pushed", 0) or 0),
                "errors": int((rd or {}).get("errors", 0) or 0),
                "skipped": int((rd or {}).get("skipped", 0) or 0),
                "deleted": int((rd or {}).get("deleted", 0) or 0),
                "interfaces_total": int((rd or {}).get("interfaces_total", 0) or 0),
                "message": (rd or {}).get("message", ""),
            }
            # Remember which NetBox site the device landed in.
            self._nw_record_site(device_cfg, (rd or {}).get("site"))
            # Surface a NetBox-side error to the caller and the log.
            if netbox_push["status"] == "ERROR" or netbox_push["errors"]:
                errors.append(f"netbox: {netbox_push['message'] or 'error'}")
                logger.warning("nw device push %s (%s) -> NetBox %s: %s",
                               device_id, payload["device"]["name"],
                               netbox_push["status"] or "error",
                               netbox_push["message"] or "no message")
            # With the device written, check whether NetBox holds look-alike stubs of it.
            if netbox_push["status"] == "SUCCESS" and not netbox_push["errors"]:
                asyncio.ensure_future(self.nw_merge_stubs_by_live_poll(
                    device_cfg, str(device_info.get("serial", "") or "")))
            # Return the summary, any errors, and the tenant slug used.
            return netbox_push, errors, tenant_slug
        # The push call itself failed; report it without raising.
        except Exception as e:
            errors.append(f"netbox push: {e}")
            return {"status": "ERROR", "message": str(e)}, errors, tenant_slug

    _NW_STUB_PROBE_TTL_S = 86400
    _NW_STUB_PROBE_MAX = 5

    async def nw_merge_stubs_by_live_poll(self, device_cfg: Dict[str, Any], serial: str) -> int:
        """Fold NetBox stubs of this box into its record, proven by a live poll.

        Another feeder (firewall ARP/DHCP) can file a switch's VLAN address as a
        device of its own with no serial. For each such stub in the same /16, ask
        the nw spoke to read device info from the stub's IP using THIS device's
        credentials; when the IP answers with this device's serial it is the same
        box, and NetBox merges the stub into the polled device (keeping its
        history). Each (stub, device) pair is tried at most once a day. Never raises."""
        merged = 0
        try:
            import ipaddress
            addr = str(device_cfg.get("address") or "").strip()
            spoke_id = str(device_cfg.get("spoke_id") or "").strip()
            if (not serial or not addr or str(device_cfg.get("object_type") or "").lower() == "ipmi"):
                return 0
            nw_spokes = list(self.get_all_spokes_by_type("nw") or [])
            if not spoke_id or spoke_id not in nw_spokes:
                spoke_id = nw_spokes[0] if nw_spokes else ""
            netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
            if not (spoke_id and netbox):
                return 0
            net = ipaddress.ip_network(f"{addr}/16", strict=False)
            rr = await self.request_response(netbox, "NETBOX_LIST_STUBS", {}, timeout=120.0)
            stubs = (unwrap_spoke(rr) or {}).get("stubs") or []
            cache = self.__dict__.setdefault("_nw_stub_probe_cache", {})
            now = time.time()
            probes = 0
            for st in stubs:
                ip = str(st.get("ip") or "")
                try:
                    inside = ipaddress.ip_address(ip) in net
                except ValueError:
                    continue
                key = (st.get("id"), device_cfg.get("id"))
                if not inside or ip == addr or now - cache.get(key, 0) < self._NW_STUB_PROBE_TTL_S:
                    continue
                if probes >= self._NW_STUB_PROBE_MAX:
                    break
                probes += 1
                cache[key] = now
                info = unwrap_spoke(await self.request_response(
                    spoke_id, "NW_GET_DEVICE_INFO",
                    {"device_id": device_cfg.get("id"), "address": ip}, timeout=60.0)) or {}
                got = str((info.get("data") or {}).get("serial") or "").strip() \
                    if isinstance(info.get("data"), dict) else ""
                if not got or got.casefold() != serial.casefold():
                    continue
                res = unwrap_spoke(await self.request_response(
                    netbox, "NETBOX_MERGE_STUB",
                    {"stub_id": st.get("id"), "nw_device_id": device_cfg.get("id"),
                     "serial": serial}, timeout=120.0)) or {}
                if res.get("merged"):
                    merged += 1
                    logger.info("nw: merged NetBox stub %s (%s) into %s by live poll (serial %s)",
                                st.get("name"), ip, device_cfg.get("name"), serial)
        except Exception as e:  # best-effort
            logger.debug("nw stub merge for %s: %s", device_cfg.get("id"), e)
        return merged

    def _nw_record_site(self, device_cfg: Dict[str, Any], site: Any) -> None:
        """Keep the NetBox site (from the site-scoped prefix of its address)
        on the fleet record so LM shows where the device is."""
        # Only act on a site dict that carries a slug.
        if not (isinstance(site, dict) and site.get("slug")):
            return
        # Keep just slug and name; skip if nothing changed.
        site = {"slug": str(site["slug"]), "name": str(site.get("name") or site["slug"])}
        if device_cfg.get("site") == site:
            return
        # Store the site and persist; a persistence error is only logged.
        device_cfg["site"] = site
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001 - persistence is best-effort
            logger.debug("nw site record: mark_dirty failed", exc_info=True)
        # Note where the device lives.
        logger.info("nw: device %s is in NetBox site %s", device_cfg.get("id"), site["slug"])

    async def apply_nw_auto_poll(self, device_id: str,
                                 pdata: Dict[str, Any]) -> None:
        """Handle a spoke-driven auto-poll result (NW_POLL_RESULT): warm the
        per-device cache so sub-views load instantly, then push the device +
        interfaces to NetBox on this device's own poll cadence (per-device
        inventory sync). Best-effort — a NetBox miss never blocks cache-warming.
        """
        # Ignore malformed poll payloads.
        if not isinstance(pdata, dict):
            return
        # Snapshot the identity before the cache is overwritten, for relocation checks.
        prior_identity = self._nw_prior_identity(device_id)
        # Warm the cache first; a failure here must not stop the NetBox push.
        try:
            await self.nw_cache_set_poll(device_id, pdata)
        except Exception as e:
            logger.debug("nw auto-poll cache-warm %s failed: %s", device_id, e)
        # Per-device NetBox inventory sync (the "sync process" for nw devices).
        devices = (self.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        # Find this device's config row; unknown devices are not pushed.
        device_cfg = next((d for d in devices if isinstance(d, dict)
                           and d.get("id") == device_id), None)
        if not device_cfg:
            return
        # Reconcile the stored display name to the hostname actually configured
        # on the box (best-effort; only when the poll read one and it differs).
        self.reconcile_nw_device_name(device_cfg, pdata.get("device_info") or {})
        # Move or merge the record across tenants if the poll proves it belongs elsewhere.
        await self.nw_reconcile_tenant_after_poll(
            device_cfg, pdata.get("device_info") or {}, bool(pdata.get("reachable")), prior_identity)
        # Push inventory to NetBox; failures are logged and never propagate.
        try:
            _push, errs, _slug = await self.push_nw_device_inventory(
                device_cfg, pdata.get("device_info") or {},
                pdata.get("interfaces") or [])
            if errs:
                logger.debug("nw auto-poll NetBox push %s: %s", device_id, errs)
        except Exception as e:
            logger.warning("[sync-error] nw auto-poll NetBox push %s: %s",
                           device_id, e)

    def reconcile_nw_device_name(self, device_cfg: Dict[str, Any],
                                 device_info: Dict[str, Any]) -> bool:
        """Reset a device's stored NW Devices display ``name`` to the hostname
        actually configured on the box, read from a poll/info gather
        (``device_info["hostname"]`` — AOS-S 'System Name', SNMP sysName, or the
        CLI prompt token). No-op when the poll read no hostname or it already
        matches. The hub config is the authoritative display name; the list
        route overlays it onto the served rows so the change shows immediately.
        Returns True iff the name changed (persisted via ``_mark_dirty``)."""
        # Nothing to compare without a dict.
        if not isinstance(device_info, dict):
            return False
        # Hostname from the poll and the current stored name.
        hostname = str(device_info.get("hostname") or "").strip()
        current = str(device_cfg.get("name") or "").strip()
        src = "device hostname"
        if not hostname and (not current or re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}", current)):
            # The poll read no hostname and the device is still known only by
            # its IP: adopt the system name its LLDP neighbours report for
            # that management address.
            hostname = self._nw_lldp_self_identity(
                device_cfg.get("address") or current).get("name", "")
            src = "LLDP neighbour advertisement"
        # Still no hostname, or it already matches: nothing to change.
        if not hostname:
            return False
        if hostname == current:
            return False
        # Store the new name and persist; a persistence error is only logged.
        device_cfg["name"] = hostname
        try:
            self.state._mark_dirty()
        except Exception:  # noqa: BLE001 - persistence is best-effort
            logger.debug("nw name reconcile: mark_dirty failed", exc_info=True)
        # Log the rename and where the name came from.
        logger.info("nw: reset device %s display name '%s' -> '%s' (%s)",
                    device_cfg.get("id"), current or "(unset)", hostname, src)
        return True

    async def poll_nw_device(self, device_id: str) -> Dict[str, Any]:
        """POLL NOW for one network device: send ``NW_POLL`` to the owning nw
        spoke, then push the device + its interfaces to NetBox via
        ``NETBOX_SYNC_NW_DEVICE`` (a dcim.device inventory upsert — distinct
        from the ARP-neighbor→endpoint ``NETBOX_SYNC_DEVICES`` flow).

        Tenant attribution is by the device's **management address** prefix
        containment (same ``attribute_by_prefix`` helper the discovery sync
        uses, applied to a one-record set). Unattributed → empty tenant_slug
        (global/unassigned in NetBox).

        Returns ``{status, reachable, latency_ms, device_info, interfaces, arp,
        mac_table, netbox_push, tenant_slug, errors, message}``. Best-effort:
        a NetBox push failure doesn't mask the poll results.
        """
        # Error list for the report; find the device's config row.
        errors: List[str] = []
        cfg = (self.state.system_state.get("global_config", {})
               .get("nw_devices", []) or [])
        device_cfg = next((d for d in cfg if isinstance(d, dict)
                           and d.get("id") == device_id), None)
        # Unknown device id: return an error report.
        if not device_cfg:
            return {"status": "ERROR", "reachable": False, "errors":
                    [f"device {device_id} not in nw_devices config"],
                    "message": f"device {device_id} not configured"}

        # Resolve the owning connected nw spoke (prefer the device's bound
        # spoke_id; else any connected nw spoke).
        # Pick the spoke: the bound one if connected, else the first connected nw spoke.
        spoke_id = ""
        bound = str(device_cfg.get("spoke_id") or "").strip()
        nw_spokes = list(self.get_all_spokes_by_type("nw") or [])
        if bound and bound in nw_spokes:
            spoke_id = bound
        elif nw_spokes:
            spoke_id = nw_spokes[0]
        # No connected spoke means the device cannot be polled.
        if not spoke_id:
            return {"status": "ERROR", "reachable": False, "errors":
                    ["no nw spoke connected"], "message": "no nw spoke connected"}

        # Identity before this poll, used later for relocation evidence.
        prior_identity = self._nw_prior_identity(device_id)
        # 1) Poll.
        poll_res: Dict[str, Any] = {}
        # Ask the spoke to poll; ERROR replies and exceptions become empty data plus an error.
        try:
            rr = await self.request_response(spoke_id, self._NW_POLL_COMMAND,
                                             {"device_id": device_id}, timeout=60.0)
            poll_res = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            if isinstance(poll_res, dict) and poll_res.get("status") == "ERROR":
                errors.append(f"poll: {poll_res.get('message', 'error')}")
                poll_res = {"data": {}}
        except Exception as e:
            errors.append(f"poll: {e}")
            poll_res = {"data": {}}

        # Pull each section out of the poll data, defaulting to empty values.
        pdata = poll_res.get("data") if isinstance(poll_res, dict) else None
        if not isinstance(pdata, dict):
            pdata = {}
        reachable = bool(pdata.get("reachable"))
        latency_ms = pdata.get("latency_ms")
        device_info = pdata.get("device_info") or {}
        interfaces = pdata.get("interfaces") or []
        arp = pdata.get("arp") or []
        mac_table = pdata.get("mac_table") or []
        endpoints = pdata.get("endpoints") or []
        vlans = pdata.get("vlans") or []
        # Merge per-step errors the spoke reported.
        poll_errors = poll_res.get("errors") if isinstance(poll_res, dict) else None
        if isinstance(poll_errors, list):
            errors.extend(poll_errors)

        # 2+3) Attribute tenant + push the device inventory to NetBox (shared
        # with the spoke-driven auto-poll via push_nw_device_inventory, which
        # also returns the resolved tenant_slug for the poll report).
        # Fix the display name, reconcile tenant ownership, and push inventory to NetBox.
        self.reconcile_nw_device_name(device_cfg, device_info)
        moves = await self.nw_reconcile_tenant_after_poll(
            device_cfg, device_info, reachable, prior_identity)
        netbox_push, push_errors, tenant_slug = await self.push_nw_device_inventory(
            device_cfg, device_info, interfaces)
        # Collect push errors; a reachable device also triggers an LLDP topology push.
        errors.extend(push_errors)
        if reachable:
            self.schedule_lldp_netbox_push(device_cfg.get("tenant_id") or "")

        # SUCCESS when reachable with no errors, PARTIAL when reachable with errors, else ERROR.
        status = "SUCCESS" if (reachable and not errors) else (
            "PARTIAL" if reachable else "ERROR")
        # Full poll report, with a one-line human summary in "message".
        return {
            "status": status,
            "reachable": reachable,
            "latency_ms": latency_ms,
            "device_info": device_info,
            "interfaces": interfaces,
            "arp": arp,
            "mac_table": mac_table,
            "endpoints": endpoints,
            "vlans": vlans,
            "netbox_push": netbox_push,
            "tenant_slug": tenant_slug,
            "tenant_moves": moves,
            "errors": errors,
            "message": (f"reachable={reachable}, "
                        f"{len(interfaces) if isinstance(interfaces, list) else 0} "
                        f"interface(s), "
                        f"{len(arp) if isinstance(arp, list) else 0} arp, "
                        f"{len(mac_table) if isinstance(mac_table, list) else 0} mac"
                        + (f", NetBox={netbox_push.get('status','n/a')}"
                           if netbox_push else "")
                        + (f", errors={len(errors)}" if errors else "")),
        }

    async def sync_tenant_nw_devices(self, tenant_id: str) -> Dict[str, Any]:
        """On-demand single-tenant NW → NetBox sync ('Sync now' for one tenant).

        Named ``sync_tenant_nw_devices`` (not ``sync_tenant_devices``) to avoid
        an MRO clash with ``FwDiscoverySyncMixin.sync_tenant_devices`` — both
        mixins are mixed into ``LabManagerHub`` together. Pulls globally,
        attributes by prefix, pushes only ``tenant_id``.
        """
        # Pull all sightings across every nw spoke.
        records, pull = await self._nw_pull_discovered()
        # On-demand single-tenant sync is IP-bearing only — MAC-only sightings
        # are global (no tenant) and are pushed by the full cycle, not here.
        ip_records = [r for r in records if r.get("ip")]
        # Attribute by prefix, then push only the requested tenant's bucket.
        buckets, dropped = await self._nw_attribute(ip_records)
        status = await self._nw_push_tenant(tenant_id, buckets.get(tenant_id, []))
        # Add global context so the UI can explain counts.
        status["discovered_total_global"] = len(records)
        status["dropped_unattributed"] = dropped
        status["pull_errors"] = pull.get("errors", [])
        return status

    async def run_nw_discovery_sync_all(self) -> Dict[str, Any]:
        """Full cycle: pull → attribute → push every attributed tenant
        concurrently (bounded). Returns ``{"results": [...],
        "dropped_unattributed": N, "discovered_total": M}``."""
        # Pull all sightings across every nw spoke.
        records, pull = await self._nw_pull_discovered()
        # Split IP-bearing (tenant-attributable) from MAC-only sightings (no IP
        # → no tenant). A MAC seen on a switch MAC table with no IP is pushed
        # unscoped so NetBox still records it with its switch/port; a later IP
        # sighting for that MAC adopts the device and assigns the tenant.
        ip_records = [r for r in records if r.get("ip")]
        mac_only = [r for r in records if not r.get("ip") and r.get("mac")]
        # Attribute IP-bearing records to tenants.
        buckets, dropped = await self._nw_attribute(ip_records)
        tids = list(buckets.keys())
        # Nothing to push: still refresh LLDP topology, log, and return empty results.
        if not tids and not mac_only:
            self.schedule_lldp_netbox_push()
            logger.info("nw discovery sync cycle: %d records pulled, 0 tenants matched, "
                        "%d dropped unattributed", len(records), dropped)
            return {"results": [], "dropped_unattributed": dropped,
                    "discovered_total": len(records), "mac_only_total": 0}
        # Limit how many tenants are pushed at once.
        sem = asyncio.Semaphore(self._nw_discovery_concurrency())

        async def _one(tid: str):
            """Push one tenant's bucket under the semaphore; errors return None."""
            async with sem:
                try:
                    return await self._nw_push_tenant(tid, buckets.get(tid, []))
                except Exception as e:  # _nw_push_tenant swallows; never kill the gather
                    logger.debug("nw discovery gather tenant=%s: %s", tid, e)
                    return None

        # Push all tenants concurrently and keep the non-empty results.
        results = await asyncio.gather(*(_one(tid) for tid in tids))
        out = [r for r in results if r]
        # Totals across tenants for the cycle log.
        pushed = sum(int(r.get("pushed", 0)) for r in out)
        errs = sum(int(r.get("errors", 0)) for r in out)
        # MAC-only sightings pushed unscoped (global, only-add-missing).
        mac_only_status = await self._nw_push_unscoped_mac_sightings(mac_only)
        # Warn when any tenant or the MAC-only push had errors; otherwise log at info.
        merrs = int(mac_only_status.get("errors", 0) or 0)
        if errs > 0 or merrs > 0:
            logger.warning("[sync-error] nw-discovery cycle: %d records, %d tenants, "
                           "%d pushed, %d errors, %d dropped unattributed, "
                           "%d mac-only unscoped",
                           len(records), len(out), pushed, errs, dropped, len(mac_only))
        else:
            logger.info("nw discovery sync cycle: %d records, %d tenants, %d pushed, "
                        "%d dropped unattributed, %d mac-only unscoped",
                        len(records), len(out), pushed, dropped, len(mac_only))
        # Upserted NW-discovered devices into NetBox — refresh netbox_devices so
        # a non-admin viewer sees them immediately. Only when the cycle pushed.
        if pushed > 0:
            self.refresh_module_cache("netbox_devices")
        # LLDP adjacencies -> NetBox cables (and LLDP-only neighbours -> devices).
        # Push LLDP links to NetBox as cables; a failure is reported but does not fail the cycle.
        try:
            lldp_status = await self.push_lldp_links_to_netbox()
        except Exception as e:
            logger.warning("nw discovery sync: LLDP -> NetBox failed: %s", e)
            lldp_status = {"status": "ERROR", "message": str(e)}
        # Cycle summary: tenant results, drops, LLDP and MAC-only push statuses.
        return {"results": out, "dropped_unattributed": dropped,
                "lldp_status": lldp_status,
                "discovered_total": len(records),
                "mac_only_total": len(mac_only),
                "mac_only_status": mac_only_status}

    def schedule_lldp_netbox_push(self, tenant_id: str = None,
                                  max_age_s: float = 300.0) -> bool:
        """Fire-and-forget :meth:`push_lldp_links_to_netbox` for one tenant
        (``None`` = all). Coalesced: while a push for that scope is running a
        new request is dropped, so a scan that polls 40 new devices sends one
        LLDP sync, not 40. Returns whether a push was started."""
        # Per-scope task registry, stored on the instance and created on first use.
        tasks = self.__dict__.setdefault("_lldp_netbox_tasks", {})
        # Scope key: "*" for all tenants, else the case-folded tenant id.
        key = "*" if tenant_id is None else (str(tenant_id).strip() or "default").casefold()
        # A push for this scope is still running, so drop the request (coalescing).
        running = tasks.get(key)
        if running is not None and not running.done():
            return False
        # Start the push on the running event loop; no loop (sync caller) means no push.
        try:
            tasks[key] = asyncio.get_running_loop().create_task(
                self.push_lldp_links_to_netbox(tenant_id, max_age_s=max_age_s))
        except RuntimeError:
            return False
        return True

    async def push_lldp_links_to_netbox(self, tenant_id: str = None,
                                        max_age_s: float = 3600.0) -> Dict[str, Any]:
        """Record LLDP-confirmed links in NetBox as cables (``NETBOX_SYNC_LLDP``).

        One topology graph and one request per tenant: the same merge the
        NW → Topology map uses (reciprocal naming, SVI folding), so NetBox gets
        the switch tree the operator sees. LLDP older than ``max_age_s`` is
        re-read first (bounded fan-out). Best-effort end to end.
        """
        # Lazy import avoids a cycle with nw_topology.
        from nw_topology import build_topology, netbox_lldp_links

        def _s(x):
            """Return x as a stripped string (None becomes "")."""
            return str(x or "").strip()

        # NetBox must be connected to receive cables.
        netbox = self.get_spoke_by_type("ipam")
        if not netbox:
            return {"status": "SKIPPED", "message": "no NetBox (ipam) spoke"}
        # All configured devices with an id.
        devices = [d for d in ((self.state.system_state.get("global_config", {}) or {})
                               .get("nw_devices", []) or [])
                   if isinstance(d, dict) and d.get("id")]
        # Group devices by case-folded tenant, keeping the original tenant id for lookups.
        groups: Dict[str, Tuple[str, List[Dict[str, Any]]]] = {}
        for d in devices:
            tid = _s(d.get("tenant_id")) or "default"
            groups.setdefault(tid.casefold(), (tid, []))[1].append(d)
        # Restrict to one tenant when requested.
        if tenant_id is not None:
            want = (_s(tenant_id) or "default").casefold()
            groups = {k: v for k, v in groups.items() if k == want}

        # Connected nw spokes, and at most 4 concurrent LLDP refreshes.
        nw_spokes = list(self.get_all_spokes_by_type("nw") or [])
        sem = asyncio.Semaphore(4)

        async def _refresh(d, spoke):
            """Re-read one device's LLDP neighbours through its spoke and update the cache."""
            async with sem:
                # Pass the tenant along so the spoke resolves the right credentials.
                payload = {"device_id": d["id"]}
                if d.get("tenant_id"):
                    payload["tenant"] = d["tenant_id"]
                # A failed refresh just leaves the older cached LLDP data in place.
                try:
                    res = await self.request_response(spoke, "NW_GET_LLDP_NEIGHBORS",
                                                      payload, timeout=30.0)
                    await self.nw_cache_set_device(d["id"], "lldp", unwrap_spoke(res))
                except Exception as e:
                    logger.debug("nw lldp->netbox: refresh %s: %s", d["id"], e)

        # Queue refreshes for devices whose cached LLDP data is older than max_age_s.
        jobs = []
        for _tid, devs in groups.values():
            for d in devs:
                # Use the bound spoke if connected, else the only spoke when exactly one exists.
                spoke = (d.get("spoke_id") if d.get("spoke_id") in nw_spokes
                         else (nw_spokes[0] if len(nw_spokes) == 1 else ""))
                if spoke and time.time() - self.nw_cache_device_fetched_at(d["id"]) > max_age_s:
                    jobs.append(_refresh(d, spoke))
        # Run all refreshes concurrently.
        if jobs:
            await asyncio.gather(*jobs, return_exceptions=True)

        # Build a topology per tenant and push its links to NetBox.
        results = []
        for key, (tid, devs) in groups.items():
            # Gather each device's cached LLDP rows.
            lldp_by_device = {}
            for d in devs:
                env = self.nw_cache_get_device(d["id"], "lldp")
                rows = env.get("data") if isinstance(env, dict) else None
                lldp_by_device[d["id"]] = rows if isinstance(rows, list) else []
            # Build the same topology the UI map shows (LLDP only, no MAC inference).
            graph = build_topology(fleet=devs, lldp_by_device=lldp_by_device,
                                   macs_by_device={}, infer_from_macs=False)
            # Turn the graph into NetBox cable links; nothing to send means skip the tenant.
            links = netbox_lldp_links(graph)
            if not links:
                results.append({"tenant": key, "status": "SKIPPED", "links": 0})
                continue
            # Tenant's NetBox slug for scoping the cables.
            slug = _s((self.state.get_tenant(tid) or {}).get("netbox_tenant_slug"))
            # Send the links; log the outcome and the first few errors.
            try:
                res = unwrap_spoke(await self.request_response(
                    netbox, "NETBOX_SYNC_LLDP",
                    {"links": links, "tenant_slug": slug}, timeout=180.0)) or {}
                logger.info("nw lldp->netbox tenant=%s: %d links: %s", key, len(links),
                            res.get("message") or res.get("status"))
                if res.get("errors") and res.get("details"):
                    logger.warning("nw lldp->netbox tenant=%s errors: %s", key,
                                   "; ".join(str(m) for m in res["details"][:5]))
            # A failed request is logged and recorded for this tenant only.
            except Exception as e:
                logger.warning("nw lldp->netbox tenant=%s failed: %s", key, e)
                res = {"status": "ERROR", "message": str(e)}
            # Per-tenant result with NetBox's counters.
            results.append({"tenant": key, "links": len(links),
                            **{k: res.get(k) for k in ("status", "message", "cabled",
                                                       "created", "unchanged",
                                                       "skipped", "renamed",
                                                       "errors")}})
        return {"status": "SUCCESS", "results": results}

    async def run_nw_discovery_sync_loop(self):
        """Periodically sync nw-discovered devices → NetBox per schedule.

        Reads config fresh each cycle so a WebUI change takes effect without a
        restart. Disabled → short sleep + re-check. Skips a cycle if no nw
        spoke or NetBox is offline. Staggered ~75s after the fw-discovery loop
        (60s) so the heavy syncs don't simultaneous-fire on startup.
        """
        def _guard() -> bool:
            """Run a cycle only when enabled, an nw spoke is connected, and NetBox is online."""
            cfg = self._nw_discovery_cfg()
            return bool(cfg.get("enabled", False)
                        and self._nw_spokes()
                        and self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE))

        def _delay() -> float:
            """Seconds until the next cycle: 60s re-check when disabled, else per the schedule."""
            cfg = self._nw_discovery_cfg()
            if not cfg.get("enabled", False):
                return 60
            return next_schedule_delay(cfg, default_daily_time="02:30",
                                       log_name="nw discovery sync")

        # stagger 75s: let spokes connect; stagger after fw-discovery
        await run_sync_loop(stagger=75, guard=_guard,
                            body=self.run_nw_discovery_sync_all, delay=_delay,
                            error_label="nw-discovery loop cycle failed")

    # ── NetBox → NW fleet import (NetBox is source of truth) ─────────────────
    # Reverse of the discovery/inventory push: devices already in NetBox whose
    # role matches the configured category are imported into the nw fleet so the
    # nw module manages them. A user who adds a device manually still gets it
    # written to NetBox (add_nw_device → push_nw_device_inventory), so NetBox
    # stays complete/authoritative either way.

    @staticmethod
    def _nw_role_norm(s: Any) -> str:
        """Normalize a role name/slug for case/space/hyphen-insensitive matching."""
        # Lower-case and remove spaces, underscores, and hyphens.
        return re.sub(r"[\s_-]+", "", str(s or "").strip().lower())

    def _nw_import_cfg(self) -> Dict[str, Any]:
        """Module-level NetBox→NW import config from
        ``global_config.nw_netbox_import`` with defaults."""
        # Read the saved import config.
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get("nw_netbox_import", {}) or {}
        # Fill defaults; interval defaults to 900 seconds (15 minutes).
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "roles": [str(r).strip() for r in (cfg.get("roles") or []) if str(r).strip()],
            "object_type_map": dict(cfg.get("object_type_map") or {}),
            "default_object_type": str(cfg.get("default_object_type") or "gateway"),
            "interval": int(cfg.get("interval") or 900),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }

    def _nw_import_object_type(self, cfg: Dict[str, Any], role: str,
                              device_type: str) -> str:
        """Map a NetBox role/device_type to an nw object_type via the config map
        (case-insensitive on role then device_type), else the default."""
        # Allowed nw object types.
        valid = {"aos_switch", "cx_switch", "ex_switch", "gateway", "ipmi"}
        # Normalize the map keys so lookups ignore case and separators.
        norm_map = {self._nw_role_norm(k): v for k, v in cfg["object_type_map"].items()}
        # Try the role first, then the device type.
        for key in (role, device_type):
            mv = norm_map.get(self._nw_role_norm(key))
            if mv in valid:
                return mv
        # Fall back to the configured default (or gateway if that is invalid).
        dot = cfg["default_object_type"]
        return dot if dot in valid else "gateway"

    async def run_nw_netbox_import_all(self) -> Dict[str, Any]:
        """Pull NetBox devices, keep those whose role matches the configured
        category, and upsert them into the nw fleet (``source="netbox"``).

        NetBox is source of truth: name/address/object_type track NetBox each
        cycle, but a device's user-entered credentials / poll_interval / bound
        spoke are preserved. NetBox-sourced devices that no longer match (deleted
        or re-roled in NetBox) are removed; manually-added devices are untouched.
        Pushes the updated fleet to every connected nw spoke.
        """
        # Skip unless enabled with at least one role to import.
        cfg = self._nw_import_cfg()
        if not cfg["enabled"] or not cfg["roles"]:
            return {"status": "SKIPPED", "reason": "disabled or no roles configured"}
        # NetBox must be connected to read devices from.
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            return {"status": "ERROR", "message": "NetBox (ipam) spoke not connected"}

        # Fetch all NetBox devices; tolerate a missing or malformed list.
        rr = await self.request_response(netbox, "NETBOX_GET_DEVICES", {}, timeout=60.0)
        data = unwrap_spoke(rr) if isinstance(rr, dict) else {}
        devices = data.get("devices") if isinstance(data, dict) else []
        if not isinstance(devices, list):
            devices = []
        # Keep devices whose role matches a configured role (normalized).
        roles_norm = {self._nw_role_norm(r) for r in cfg["roles"]}
        matched = [d for d in devices if isinstance(d, dict)
                   and self._nw_role_norm(d.get("role")) in roles_norm]

        # New imports bind to the configured spoke, else the first connected nw spoke.
        nw_spokes = list(self.get_all_spokes_by_type("nw") or [])
        target_spoke = cfg["spoke_id"] or (nw_spokes[0] if nw_spokes else "")

        # Load the fleet and index it by id.
        gc = self.state.system_state.get("global_config", {})
        fleet = gc.get("nw_devices", []) or []
        by_id = {d.get("id"): d for d in fleet if isinstance(d, dict)}
        # Track imported ids and add/update counters.
        seen, added, updated = set(), 0, 0
        # Upsert each matched NetBox device under a stable "nbimport-<id>" id.
        for d in matched:
            did = f"nbimport-{d.get('id')}"
            seen.add(did)
            # Address without prefix length, and the mapped object type.
            addr = str(d.get("primary_ip") or "").split("/")[0]
            ot = self._nw_import_object_type(cfg, d.get("role"), d.get("device_type"))
            # Existing row: update only NetBox-owned fields.
            existing = by_id.get(did)
            if existing:
                # NetBox owns name/address/object_type/role; keep user creds etc.
                changed = False
                for k, v in (("name", d.get("name") or existing.get("name")),
                             ("address", addr or existing.get("address")),
                             ("object_type", ot),
                             ("netbox_role", d.get("role") or "")):
                    if existing.get(k) != v:
                        existing[k] = v
                        changed = True
                # Count the row as updated only if a field changed.
                updated += 1 if changed else 0
            # New row: add it as a NetBox-sourced device with auto transport.
            else:
                fleet.append({
                    "id": did, "name": d.get("name") or did, "address": addr,
                    "object_type": ot, "transport": "auto", "source": "netbox",
                    "netbox_id": d.get("id"), "netbox_role": d.get("role") or "",
                    "spoke_id": target_spoke, "poll_interval": None,
                })
                added += 1

        # Prune NetBox-sourced devices that no longer match (NetBox = SoT). Never
        # touch manually-added / discovery devices (source != "netbox").
        # Remove NetBox-sourced rows no longer present in the matched set.
        before = len(fleet)
        fleet[:] = [d for d in fleet if not (isinstance(d, dict)
                    and d.get("source") == "netbox" and d.get("id") not in seen)]
        removed = before - len(fleet)

        # Save the fleet and persist.
        gc["nw_devices"] = fleet
        self.state.system_state["global_config"] = gc
        self.state._mark_dirty()

        # Push the updated fleet to every connected nw spoke; a failed push is only logged.
        pushed = 0
        for sid in nw_spokes:
            try:
                await self.push_config_to_spoke(sid)
                pushed += 1
            except Exception as e:  # noqa: BLE001
                logger.debug("nw import fleet push to %s failed: %s", sid, e)

        # Log and return the import summary.
        logger.info("nw netbox import: %d device(s) matched role(s) %s → +%d added, "
                    "~%d updated, -%d removed; pushed %d spoke(s)",
                    len(matched), cfg["roles"], added, updated, removed, pushed)
        return {"status": "SUCCESS", "matched": len(matched), "added": added,
                "updated": updated, "removed": removed, "pushed": pushed}

    async def run_nw_netbox_import_loop(self):
        """Periodic NetBox→NW fleet import per the configured interval. Reads
        config fresh each cycle; disabled → short re-check. Staggered ~110s after
        boot so it doesn't stampede with the discovery/fw loops."""
        def _guard() -> bool:
            """Run an import only when enabled with roles, an nw spoke, and NetBox connected."""
            cfg = self._nw_import_cfg()
            return bool(cfg["enabled"] and cfg["roles"]
                        and self.get_all_spokes_by_type("nw")
                        and self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE))

        def _delay() -> float:
            """Seconds until the next import: the interval (at least 60s), or 120s when disabled."""
            cfg = self._nw_import_cfg()
            return max(60, cfg["interval"]) if cfg["enabled"] else 120

        # stagger 110s: don't stampede with the discovery/fw loops at boot
        await run_sync_loop(stagger=110, guard=_guard,
                            body=self.run_nw_netbox_import_all, delay=_delay,
                            error_label="nw netbox import loop failed",
                            error_delay=120)

    # ── Recurring per-tenant network scans ───────────────────────────────────
    async def run_nw_scan_schedule_loop(self):
        """Drive per-tenant recurring network scans.

        A tenant with its own nw spoke is scheduled automatically (6h, adding
        what it finds); the tenant may change or disable it from Network → Scan
        (``nw_tenant_cfg[tenant].scan_schedule``, ``interval_seconds`` ≥ 1h).
        This loop checks every 5 min and runs a tenant's scan once its interval
        has elapsed. The last run time is persisted (``nw_scan_last_run``) so a
        hub restart resumes the cadence instead of re-scanning; a tenant that
        has never been scanned runs ~10 min after first sight. The scan itself is executed by
        ``hub.run_nw_scheduled_scan`` (wired up in ``routes/nw.py`` at route
        registration) so the credential/target/auto-add pipeline is shared with
        the interactive scan — this loop only decides *when*.
        """
        await asyncio.sleep(150)  # stagger after boot (let spokes connect)
        # Monotonic time of each tenant's last scheduled scan.
        last_run: Dict[str, float] = {}
        # Wall-clock view of the same state, published on the hub so the Scan
        # tab can show operators WHEN each schedule last ran and when it is next
        # due. In-memory only (like last_run itself): a hub restart clears it and
        # every schedule re-defers one interval, which the UI labels as such.
        # Publish the runtime view on the hub for the Scan tab.
        runtime: Dict[str, Dict[str, Any]] = {}
        self.nw_scan_runtime = runtime
        # Check every 300s (5 min); first scan of a never-scanned tenant after 600s (10 min).
        CHECK_INTERVAL = 300
        FIRST_SCAN_DELAY = 600
        # Run forever; each tick is wrapped so an error never ends the loop.
        while True:
            try:
                # The scan runner and schedule lookup are wired up by routes/nw.py; wait until they
                # exist and an nw spoke is connected.
                runner = getattr(self, "run_nw_scheduled_scan", None)
                sched_for = getattr(self, "nw_scan_schedule_for_tenant", None)
                if runner and sched_for and self.get_all_spokes_by_type("nw"):
                    # Every known tenant id.
                    tenants = list((getattr(self.state, "tenant_state", {}) or {})
                                   .get("tenants", {}) or {})
                    now = time.monotonic()
                    # Decide for each tenant whether its scan is due.
                    for tid in tenants:
                        # A tenant whose schedule cannot be read is skipped this tick.
                        try:
                            sc = sched_for(tid)
                        except Exception:
                            continue
                        # Disabled or zero-interval schedule: forget its timers.
                        if not sc.get("enabled") or int(sc.get("interval_seconds") or 0) <= 0:
                            last_run.pop(tid, None)
                            runtime.pop(tid, None)
                            continue
                        # Interval in seconds, and the persisted wall-clock last-run map.
                        interval = int(sc["interval_seconds"])
                        gc = self.state.system_state.setdefault("global_config", {})
                        persisted = gc.setdefault("nw_scan_last_run", {})
                        # First sight of this tenant in this process: seed its timer and wait.
                        if tid not in last_run:
                            # Resume the persisted cadence across hub restarts; a
                            # tenant that has never been scanned runs shortly.
                            prev = persisted.get(tid)
                            # Use the persisted last run if known, else make it due FIRST_SCAN_DELAY
                            # from now.
                            if prev:
                                elapsed = max(0.0, time.time() - float(prev))
                            else:
                                elapsed = max(0, interval - FIRST_SCAN_DELAY)
                            # Backdate the monotonic timer by the elapsed time and publish the
                            # runtime view.
                            last_run[tid] = now - elapsed
                            runtime[tid] = {"last_run_at": prev or None, "last_status": None,
                                            "last_added": 0, "last_error": "",
                                            "next_due_at": time.time() + max(0.0, interval - elapsed)}
                            continue
                        # Not due yet.
                        if (now - last_run[tid]) < interval:
                            continue
                        # Due: record the run time (memory and persisted) before running.
                        last_run[tid] = now
                        persisted[tid] = time.time()
                        self.state._mark_dirty()
                        # Update the runtime view shown in the UI.
                        rt = runtime.setdefault(tid, {})
                        rt["last_run_at"] = time.time()
                        rt["next_due_at"] = time.time() + interval
                        # Run the scan and record its outcome; a failure is recorded and logged.
                        try:
                            res = await runner(tid)
                            rt["last_status"] = (res or {}).get("status")
                            rt["last_added"] = len((res or {}).get("added", []) or [])
                            rt["last_identified"] = len((res or {}).get("identified", []) or [])
                            rt["last_error"] = ""
                            logger.info("nw scheduled scan tenant=%s status=%s added=%d",
                                        tid, (res or {}).get("status"),
                                        len((res or {}).get("added", []) or []))
                        except Exception as e:  # noqa: BLE001
                            rt["last_status"] = "error"
                            rt["last_error"] = str(e)
                            logger.warning("nw scheduled scan tenant=%s failed: %s", tid, e)
            # Any unexpected tick error is logged; the loop keeps going.
            except Exception as e:  # noqa: BLE001 - loop must never die
                logger.debug("nw scan schedule loop tick error: %s", e)
            # Wait before the next check.
            await asyncio.sleep(CHECK_INTERVAL)

    async def run_nw_sweep_loop(self):
        """Tier-2 background supernet sweep: one small batch per opted-in tenant
        every ~3 min, so a /16 completes over many hours without ever competing
        with the targeted scheduled scans (a separate task, own probe budget).
        The work is ``hub.run_nw_sweep_step`` (wired in routes/nw.py)."""
        # Wait 240s after boot so spokes can connect first.
        await asyncio.sleep(240)
        # Run forever; each tick is wrapped so an error never ends the loop.
        while True:
            try:
                # The step and opt-in check are wired up by routes/nw.py; wait until they exist.
                step = getattr(self, "run_nw_sweep_step", None)
                enabled = getattr(self, "nw_sweep_enabled_for_tenant", None)
                if step and enabled and self.get_all_spokes_by_type("nw"):
                    # Run one sweep batch per opted-in tenant; one tenant's failure does not stop
                    # others.
                    for tid in list((getattr(self.state, "tenant_state", {}) or {})
                                    .get("tenants", {}) or {}):
                        try:
                            if enabled(tid):
                                await step(tid)
                        except Exception as e:  # noqa: BLE001
                            logger.warning("nw sweep tenant=%s failed: %s", tid, e)
            # Any unexpected tick error is logged; the loop keeps going.
            except Exception as e:  # noqa: BLE001 - loop must never die
                logger.debug("nw sweep loop tick error: %s", e)
            # Next batch in 180s (3 minutes).
            await asyncio.sleep(180)
