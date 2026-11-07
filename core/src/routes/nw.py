"""Network-devices routes + multi-instance product CRUD (_instance_crud)."""
import asyncio
import ipaddress
import time

import instance_vault
import nw_seen_hosts
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access, get_spoke_or_503,
    logger, uuid,
)
from nw_topology import build_topology, netbox_lldp_links
from nw_discovery_sync import nw_short_name
from routes.role_pool import PRODUCT_ROLE, ensure_role_loaded, maybe_unload_orphaned_role


# ── cache-first (stale-while-revalidate) read path ───────────────────────────
# The Network Devices read routes serve the local nw cache FIRST (the JSON-
# persisted store warmed continuously by spoke poll telemetry — apply_nw_auto_
# poll) instead of blocking every page load on live SSH. A cached hit returns
# immediately; if the data is older than _NW_SERVE_MAX_AGE_S and a spoke is
# connected, a single background revalidate is kicked off (deduped) so the NEXT
# load is fresh — the spoke's own poll cadence is the primary revalidator. Only
# a cold miss (or an explicit ?refresh=1) falls through to a blocking live
# fetch. This trades a bounded staleness window for an instant, poll-free UI.
_NW_SERVE_MAX_AGE_S = 60.0

# In-flight guard so rapid navigation coalesces to at most one background
# revalidate per key (fleet: "__fleet__"; device: "<id>:<endpoint>"). The task
# set keeps a strong ref so the fire-and-forget tasks aren't GC'd mid-flight.
_NW_BG_INFLIGHT: set = set()
# tenant -> IPs waiting for the seen-hosts NetBox push (drained by one task).
_NW_SEEN_PENDING: dict = {}
_NW_BG_TASKS: set = set()


def _nw_truthy(v) -> bool:
    """True when a query-string style value means yes ("1", "true", "yes" or "on")."""
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _nw_spawn_refresh(key, coro_factory) -> None:
    """Fire ONE background revalidate for ``key`` (deduped). ``coro_factory`` is
    a zero-arg callable returning the coroutine — built INSIDE the guard so a
    skipped spawn never leaves an un-awaited coroutine. No running loop (sync
    test path) → no-op."""
    # A refresh for this key is already running.
    if key in _NW_BG_INFLIGHT:
        return
    # No running event loop (sync test path): do nothing.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    # Mark the key as in flight before starting.
    _NW_BG_INFLIGHT.add(key)

    async def _run():
        """Run the refresh, log any failure, and always clear the in-flight mark."""
        try:
            await coro_factory()
        except Exception as e:  # noqa: BLE001 - best-effort revalidate
            logger.debug("nw bg refresh [%s] failed: %s", key, e)
        finally:
            _NW_BG_INFLIGHT.discard(key)

    # Start the task and keep a reference until it finishes.
    t = loop.create_task(_run())
    _NW_BG_TASKS.add(t)
    t.add_done_callback(_NW_BG_TASKS.discard)


# A device a scan auto-adds is polled as part of that discovery (MAC/ARP/LLDP,
# hostname, interfaces) rather than waiting hours for its first scheduled poll.
_NW_DISCOVERY_POLL_CONCURRENCY = 4
_NW_DISCOVERY_POLL_ATTEMPTS = 3
_NW_DISCOVERY_POLL_RETRY_S = 5.0


async def _nw_poll_discovered(hub, device_ids) -> None:
    """Poll each newly discovered device through the same path as POLL NOW
    (``hub.poll_nw_device``): renames it to the polled hostname, pushes it to
    NetBox, and warms the nw cache. Retries "not found" briefly in case the
    spoke hasn't applied the UPDATE_CONFIG carrying the new device yet."""
    # Limit how many devices are polled at once.
    sem = asyncio.Semaphore(_NW_DISCOVERY_POLL_CONCURRENCY)

    async def _one(did):
        """Poll one device, retrying briefly while the spoke does not know it yet, then cache the
        result.
        """
        async with sem:
            res = None
            # Retry only on "not found" errors, up to the attempt limit.
            for attempt in range(_NW_DISCOVERY_POLL_ATTEMPTS):
                try:
                    res = await hub.poll_nw_device(did)
                except Exception as e:  # noqa: BLE001 - best-effort per device
                    logger.warning("nw discovery poll %s failed: %s", did, e)
                    return
                errs = " ".join(str(x) for x in (res or {}).get("errors") or [])
                if "not found" in errs and attempt + 1 < _NW_DISCOVERY_POLL_ATTEMPTS:
                    await asyncio.sleep(_NW_DISCOVERY_POLL_RETRY_S)
                    continue
                break
            # Store the poll result in the nw cache.
            if isinstance(res, dict):
                await hub.nw_cache_set_poll(did, res)
                logger.info("nw discovery poll %s -> %s", did, res.get("message"))

    # Poll every device in parallel.
    await asyncio.gather(*(_one(d) for d in device_ids), return_exceptions=True)


async def _nw_bg_refresh_fleet(hub) -> None:
    """Whole-fleet revalidate: query every connected+approved nw spoke for the
    full inventory ({} = no tenant filter) and refresh the global fleet cache.
    Server-side (no session) — writes only the authoritative whole-fleet
    snapshot the offline/cache-first read path filters per-reader."""
    # Connected and approved nw spokes; none means nothing to refresh.
    spokes = [s for s in (hub.get_all_spokes_by_type("nw") or [])
              if s in hub.active_connections and hub.approved_modules.get(s, False)]
    if not spokes:
        return
    # Merged device rows, ids already seen, and how many spokes answered.
    merged, seen, answered = [], set(), 0
    # Ask each spoke for its device list and merge the rows, de-duplicated by id.
    # All spokes at once; merged in spoke order, so duplicates resolve as before.
    results = await asyncio.gather(
        *(hub.request_response(sid, "NW_LIST_DEVICES", {}, timeout=20.0) for sid in spokes),
        return_exceptions=True)
    for sid, result in zip(spokes, results):
        try:
            if isinstance(result, BaseException):
                raise result
            env = access.unwrap_spoke(result)
            rows = env.get("data") if isinstance(env, dict) else None
            if isinstance(rows, list):
                answered += 1
                for r in rows:
                    if isinstance(r, dict) and r.get("id") and r["id"] not in seen:
                        seen.add(r["id"])
                        merged.append(r)
        except Exception as e:  # noqa: BLE001
            logger.debug("nw bg fleet refresh: spoke %s failed: %s", sid, e)
    if not answered:
        # Every spoke errored (e.g. draining for an update): keep the
        # last-known snapshot rather than caching an empty fleet.
        logger.info("nw bg fleet refresh: no spoke answered — keeping cached fleet")
        return
    # Save the merged fleet as the cached snapshot.
    env = {"status": "SUCCESS", "data": merged, "message": f"{len(merged)} device(s)"}
    try:
        await hub.nw_cache_set_fleet(env)
    except Exception:  # noqa: BLE001
        logger.debug("nw bg fleet cache set failed", exc_info=True)


async def _nw_bg_refresh_device(hub, device_id, endpoint, spoke_id, spoke_cmd,
                                relay_payload, timeout) -> None:
    """Per-device endpoint revalidate: re-run the live spoke fetch and refresh
    the cache so the next cache-first serve is fresh. Best-effort; the on-demand
    poll button + spoke poll telemetry are the primary refreshers."""
    # Fetch live from the spoke and cache the unwrapped result.
    result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                        timeout=timeout)
    data = access.unwrap_spoke(result)
    await hub.nw_cache_set_device(device_id, endpoint, data)


async def _nw_sync_lldp_netbox(hub, netbox_spoke, links, tenant_slug="") -> None:
    """Push the map's LLDP-confirmed links into NetBox in ONE
    ``NETBOX_SYNC_LLDP`` request. The spoke resolves each end SERIAL/MAC-first
    (name last, case-insensitive, domain stripped), creates an LLDP-only
    neighbour as a discovered device, and never overwrites a human's cable.
    Detached from the request/response cycle; failures are logged, never
    raised (a NetBox hiccup must not be visible in the topology UI)."""
    # Send all the links in one request and log the outcome.
    try:
        result = await hub.request_response(
            netbox_spoke, "NETBOX_SYNC_LLDP",
            {"links": links, "tenant_slug": tenant_slug}, timeout=180.0)
        data = access.unwrap_spoke(result) or {}
        logger.info("nw_topology: NetBox LLDP sync (%d links): %s", len(links),
                    data.get("message") or data.get("status"))
    except Exception as e:
        logger.info("nw_topology: NetBox LLDP sync (%d links) failed: %s",
                    len(links), e)


def validate_nw_address(addr):
    """Validate a network device's management address: it must be PRESENT and a
    properly-formatted IPv4 address. Anything else — empty, a hostname, a
    partial address, or a typo'd octet like ``1721.6.1.90`` — is rejected with a
    clear 400 instead of failing opaquely on the spoke (an unresolvable value
    surfaces there as ``Name or service not known``). ``ipaddress.IPv4Address``
    enforces exactly four 0-255 octets and rejects leading-zero octets. Shared
    by the ``/setup/nw-devices`` (admin) and ``/tenant/devices/nw-devices``
    (tenant-admin) CRUD paths so both enforce the same rule."""
    # The address is required.
    a = str(addr or "").strip()
    if not a:
        raise HTTPException(status_code=400,
                            detail="Management IP address is required")
    # It must parse as an IPv4 address.
    try:
        ipaddress.IPv4Address(a)
    except ipaddress.AddressValueError:
        raise HTTPException(
            status_code=400,
            detail=f"'{a}' is not a valid IPv4 address")


def nw_scan_spoke_choices(hub, tenant_id, shared_tenant_id):
    """The nw spokes a tenant may run a scan with: the ones BOUND to the tenant
    ("own"), or, only when it has none, the ones bound to the shared tenant
    ("shared").

    This is the whole allowlist — a spoke bound to some OTHER tenant is never
    offered and never resolved. Scanning through another tenant's agent probes
    that tenant's network from that tenant's vantage point and attributes the
    results here, which is the cross-tenant leak this list closes.

    Returns UI-ready dicts (``scope`` is ``own``/``shared``) ordered own first,
    then shared; connected entries ahead of disconnected ones within each scope
    so the default pick is a usable agent. ``shared_tenant_id`` is passed in
    (rather than read from ``access``) so this stays pure + unit-testable."""
    # Spoke tenant bindings and display names.
    md = hub.state.system_state.get("module_metadata", {}) or {}
    names = hub.state.system_state.get("module_names", {}) or {}
    out = []
    # Ids reach here with differing spelling ("Default" from the picker vs the
    # "default" a spoke is bound to), so compare canonicalised (strip+casefold).
    def _n(x):
        """Canonical form of an id for comparison."""
        return str(x or "").strip().casefold()
    want, shared_n = _n(tenant_id), _n(shared_tenant_id)
    # Check every approved nw spoke and classify it as the tenant's own, shared, or neither.
    for sid in (hub.get_all_spokes_by_type("nw") or []):
        if not hub.approved_modules.get(hub._primary_key(sid), False):
            continue
        owner = (md.get(sid, {}) or {}).get("tenant_id") or ""
        if want and _n(owner) == want:
            scope = "own"
        elif shared_n and _n(owner) == shared_n:
            scope = "shared"
        else:
            continue
        # A UI-ready entry for the spoke.
        out.append({
            "spoke_id": sid,
            "name": names.get(sid, sid),
            "tenant_id": owner,
            "scope": scope,
            "connected": hub._primary_key(sid) in hub.active_connections,
        })
    # A tenant with its own nw spoke is out of the shared nw environment.
    if access.tenant_left_shared(hub, tenant_id, "nw") or (
            any(c["scope"] == "own" for c in out) and access.tenant_shared_access(hub, tenant_id) == "auto"):
        out = [c for c in out if c["scope"] == "own"]
    # Own first, then connected, then by name.
    out.sort(key=lambda s: (s["scope"] != "own", not s["connected"], s["name"]))
    return out


def resolve_nw_scan_spoke(hub, tenant_id, requested_spoke_id, shared_tenant_id):
    """The connected nw spoke a scan should run on, constrained to the tenant's
    own + shared spokes (see ``nw_scan_spoke_choices``).

    An explicit ``requested_spoke_id`` is honored only if it is in that
    allowlist AND connected. A request naming a spoke outside the allowlist
    (e.g. a stale global ``nw_scan.spoke_id`` inherited from the admin card that
    points at another tenant's agent) is IGNORED and we fall through to the
    tenant's own/shared preference — never used as-is. With no usable request,
    prefer the tenant's OWN connected spoke, else (a tenant with no own spoke)
    a connected shared one.

    There is deliberately no "any connected nw spoke" fallback: it silently ran
    an Admin-tenant scan on whichever single nw agent happened to be online
    (another tenant's), so the targets and results came from that tenant."""
    # Connected spokes the tenant may use.
    live = [c for c in nw_scan_spoke_choices(hub, tenant_id, shared_tenant_id)
            if c["connected"]]
    # Honor the requested spoke only if it is in that list.
    if requested_spoke_id:
        for c in live:
            if c["spoke_id"] == requested_spoke_id:
                return requested_spoke_id
    # Otherwise prefer the tenant's own spoke, then a shared one.
    for scope in ("own", "shared"):
        for c in live:
            if c["scope"] == scope:
                return c["spoke_id"]
    # No usable spoke.
    return ""


# Absolute ceiling on one scan's total target list, and how many batches run
# at once. Anything over the per-request batch size (``max_targets``) is split.
# Leaf-prefix hosts dropped at the ceiling are not swept either (the sweep skips
# leaves), so it must cover a large tenant's leaves: dxp has ~33k.
_NW_SCAN_MAX_TOTAL = 65536
_NW_SCAN_PARALLEL_BATCHES = 3
# Recurring-scan cadence a tenant gets automatically once it has its own nw spoke.
_NW_SCAN_DEFAULT_INTERVAL = 21600
# TCP ports the sweep probes on hosts that answered its ping: SSH, Telnet,
# HTTP, HTTPS, NETCONF, Aruba controller UI, alternate HTTP/HTTPS. SNMP (UDP
# 161) is tried separately with the tenant's vault communities.
_NW_SWEEP_PORTS = (22, 23, 80, 443, 830, 4343, 8080, 8443)
# Hosts pinged per sweep tick (a tick runs every few minutes per tenant); only
# the ones that answer are port-probed.
_NW_SWEEP_BATCH = 1024
# /24 blocks checked per gateway-sweep tick (two pings each: .1 and .254), and
# how long a finished gateway pass waits before it runs again.
_NW_GW_SWEEP_BLOCKS = 1024
_NW_GW_RESWEEP_SECONDS = 7 * 86400
# Responders are pushed to NetBox under their own source tag (never
# replace-deleted by the ARP push), at most this many pings per request, and at
# most this many ping-only hosts get the SNMP/port follow-up per scan.
_NW_SEEN_SOURCE = "Network Sweep"
_NW_PING_CHUNK = 2048
_NW_PINGED_PROBE_MAX = 1024


# A prefix wider than this (more than 1024 hosts) is never expanded by the
# targeted scan even if it has no children; the background sweep covers it.
_NW_MAX_LEAF_PREFIXLEN = 22


def split_leaf_and_supernets(prefixes):
    """Split IPv4 CIDR strings into ``(leaves, supernets)`` ``IPv4Network`` lists.
    A supernet is a prefix that CONTAINS another prefix in the set, or is wider
    than /22 (too big for a targeted scan); invalid and
    IPv6 entries are ignored and duplicates collapsed."""
    # Parse each entry into a unique IPv4 network, skipping invalid and IPv6 ones.
    nets = []
    for p in (prefixes or []):
        try:
            n = ipaddress.ip_network(str(p).strip(), strict=False)
        except ValueError:
            continue
        if isinstance(n, ipaddress.IPv4Network) and n not in nets:
            nets.append(n)
    # Supernets: wider than /22, or containing another prefix in the set.
    supers = [n for n in nets
              if n.prefixlen < _NW_MAX_LEAF_PREFIXLEN
              or any(o.prefixlen > n.prefixlen and o.subnet_of(n) for o in nets)]
    # Everything else is a leaf.
    return [n for n in nets if n not in supers], supers


def sweep_ranges(supernets, leaves):
    """Inclusive ``(first, last)`` integer host ranges covering every supernet
    minus the leaf prefixes carved out of it (those belong to the targeted
    scan, not the sweep). Sorted and non-overlapping; stable across calls so a
    persisted cursor stays valid while the prefix set is unchanged."""
    # Process supernets in address order so the output is stable.
    out = []
    for sn in sorted(supernets, key=lambda n: (int(n.network_address), n.prefixlen)):
        # Carve every leaf inside this supernet out of it.
        pieces = [sn]
        for leaf in leaves:
            if leaf.subnet_of(sn):
                nxt = []
                for piece in pieces:
                    if leaf.subnet_of(piece):
                        nxt.extend(piece.address_exclude(leaf))
                    elif not piece.subnet_of(leaf):
                        nxt.append(piece)
                pieces = nxt
        # Turn each remaining piece into an integer host range.
        for piece in pieces:
            lo, hi = int(piece.network_address), int(piece.broadcast_address)
            # Leave out the network and broadcast addresses of real subnets (not /31 or /32).
            if sn.prefixlen < 31:
                if lo == int(sn.network_address):
                    lo += 1
                if hi == int(sn.broadcast_address):
                    hi -= 1
            if hi >= lo:
                out.append((lo, hi))
    # Sort the ranges and merge any that overlap or touch.
    out.sort()
    merged = []
    for lo, hi in out:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def sweep_take(ranges, cursor, n, skip=frozenset()):
    """Next ``n`` host IPs (strings, minus ``skip``) from ``ranges`` starting at
    absolute index ``cursor`` of the concatenated space. Returns
    ``(ips, new_cursor, total)``; ``new_cursor`` is ``0`` after wrapping past
    the end (a full cycle completed)."""
    # Total number of hosts across all ranges; none means nothing to take.
    total = sum(hi - lo + 1 for lo, hi in ranges)
    if total <= 0:
        return [], 0, 0
    # Restart from 0 when the cursor is past the end.
    cursor = max(0, int(cursor)) % total if cursor < total else 0
    ips, idx, consumed = [], 0, cursor
    # Walk the ranges, skipping whole ranges that lie before the cursor.
    for lo, hi in ranges:
        size = hi - lo + 1
        if cursor >= idx + size:
            idx += size
            continue
        # Take hosts from this range until n have been consumed.
        start = lo + max(0, cursor - idx)
        for v in range(start, hi + 1):
            consumed += 1
            ip = str(ipaddress.IPv4Address(v))
            if ip not in skip:
                ips.append(ip)
            if consumed - cursor >= n:
                break
        idx += size
        if consumed - cursor >= n:
            break
    # A cursor that reached the end wraps back to 0.
    return ips, (consumed if consumed < total else 0), total


def gateway_take(supernets, cursor, n, skip=frozenset()):
    """Next ``n`` /24 blocks (``IPv4Network``) of the top-level ``supernets``,
    starting at block index ``cursor``. Blocks whose ``/24 number``
    (``int(address) >> 8``) is in ``skip`` are passed over but still advance
    the cursor. Returns ``(blocks, new_cursor, total_blocks)``; ``new_cursor``
    is ``0`` once the end is reached."""
    # Top-level supernets of /24 or wider (not inside another), in address order.
    tops = sorted((s for s in supernets if s.prefixlen <= 24
                   and not any(o != s and s.subnet_of(o) for o in supernets)),
                  key=lambda s: int(s.network_address))
    # Total number of /24 blocks they hold; none means nothing to take.
    total = sum(2 ** (24 - s.prefixlen) for s in tops)
    if not total:
        return [], 0, 0
    cursor = cursor if 0 <= cursor < total else 0
    blocks, idx, pos = [], 0, cursor
    # Walk each supernet's /24 blocks from the cursor until n have been passed.
    for s in tops:
        size = 2 ** (24 - s.prefixlen)
        first = int(s.network_address) >> 8
        while idx <= pos < idx + size and pos - cursor < n:
            num = first + pos - idx
            if num not in skip:
                blocks.append(ipaddress.IPv4Network((num << 8, 24)))
            pos += 1
        idx += size
    # A cursor that reached the end wraps back to 0.
    return blocks, (pos if pos < total else 0), total


def covered_blocks(leaves, supernets):
    """/24 numbers that already have a NetBox prefix: every /24 inside a leaf,
    and every /24 holding a prefix of /24 or longer."""
    out = set()
    # Prefixes of /24 or longer cover their own /24; leaves cover every /24 inside them.
    for n in list(leaves) + list(supernets):
        first = int(n.network_address) >> 8
        if n.prefixlen >= 24:
            out.add(first)
        elif n in leaves:
            out.update(range(first, first + 2 ** (24 - n.prefixlen)))
    return out


def build_scan_target_pool(targets, subnets, cap):
    """Pure IPv4 host-IP pool builder for the network scanner: explicit
    ``targets`` + expanded CIDRs (``subnets``), deduped, IPv4-only, bounded to
    ``cap`` total hosts. Returns ``(ordered_ips, per_source_counts)``. Large
    prefixes are expanded host-by-host until the cap is hit (a /8 won't blow up
    the scan). Shared by ``_aggregate_scan_targets`` so the risky bounded
    expansion is unit-testable without a spoke.

    An entry in ``targets`` may be a bare host IP, a CIDR (``10.0.0.0/24``), or
    an inclusive range (``10.0.0.10-20`` / ``10.0.0.10-10.0.0.20``) — all three
    are expanded to host IPs. Previously a CIDR typed into the targets box had
    its mask silently stripped and scanned as the single network address, so
    "scan this range" quietly scanned one host."""
    # The ordered pool, a set for fast duplicate checks, and counts per source.
    seen = []
    seen_set = set()
    per_source = {}

    def _add(ip):
        """Add one IPv4 host (mask stripped) to the pool; returns False for blanks, duplicates and
        non-IPv4.
        """
        ip = str(ip or "").split("/")[0].strip()
        if not ip or ip in seen_set:
            return False
        try:
            if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                return False
        except ValueError:
            return False
        seen_set.add(ip)
        seen.append(ip)
        return True

    def _expand_cidr(text):
        """Expand an IPv4 CIDR to host IPs (bounded by ``cap``). 0 if not one."""
        # Must parse as an IPv4 network.
        try:
            net = ipaddress.ip_network(str(text).strip(), strict=False)
        except ValueError:
            return 0
        if not isinstance(net, ipaddress.IPv4Network):
            return 0
        # Usable hosts, or the one address of a /31 or /32.
        hosts = net.hosts() if net.prefixlen < 31 else iter([net.network_address])
        n = 0
        for host in hosts:
            if len(seen) >= cap:
                break
            if _add(str(host)):
                n += 1
        return n

    def _expand_range(text):
        """Expand ``a.b.c.d-e`` / ``a.b.c.d-a.b.c.e`` inclusively. 0 if not one."""
        # Split on the dash; no second half means this is not a range.
        lo_s, _, hi_s = str(text).strip().partition("-")
        lo_s, hi_s = lo_s.strip(), hi_s.strip()
        if not hi_s:
            return 0
        if "." not in hi_s:  # shorthand last octet: 10.0.0.10-20
            hi_s = lo_s.rsplit(".", 1)[0] + "." + hi_s
        # Both ends must be IPv4 and in order.
        try:
            lo = ipaddress.ip_address(lo_s)
            hi = ipaddress.ip_address(hi_s)
        except ValueError:
            return 0
        if not (isinstance(lo, ipaddress.IPv4Address)
                and isinstance(hi, ipaddress.IPv4Address)) or int(hi) < int(lo):
            return 0
        # Add every address in between, stopping at the cap.
        n = 0
        for v in range(int(lo), int(hi) + 1):
            if len(seen) >= cap:
                break
            if _add(str(ipaddress.IPv4Address(v))):
                n += 1
        return n

    # Expand the explicit targets (range, CIDR, or single IP), stopping at the cap.
    c = 0
    for t in (targets or []):
        if len(seen) >= cap:
            break
        text = str(t or "").strip()
        if not text:
            continue
        if "-" in text:
            c += _expand_range(text)
        elif "/" in text:
            c += _expand_cidr(text)
        elif _add(text):
            c += 1
    if c:
        per_source["explicit"] = c

    # Then expand the subnets, stopping at the cap.
    c = 0
    for s in (subnets or []):
        if len(seen) >= cap:
            break
        c += _expand_cidr(s)
    if c:
        per_source["subnets"] = c
    return seen, per_source


def _nw_norm_mac(mac):
    """Lowercase hex-only MAC for comparison (drops ``:``/``-``/``.``). Empty
    string for anything without 12 hex digits so a blank never false-matches."""
    # Keep only hex digits; anything but 12 of them is not a MAC.
    h = "".join(ch for ch in str(mac or "").lower() if ch in "0123456789abcdef")
    return h if len(h) == 12 else ""


def correlate_nw_records(devices, device_cache, ip=None, mac=None):
    """Pure cross-module stitch for the NW module: given the configured
    ``nw_devices`` list + the hub's per-device cache
    (``{device_id: {arp|macs|interfaces|endpoints: {"data": [...]}}}``), return
    every NW device that KNOWS about ``ip``/``mac`` — either because it IS that
    device (its mgmt address == ip → ``is_self``) or because a cached
    ARP/MAC/endpoint/interface row references the ip/mac (i.e. the host lives on
    that switch, on a specific port/VLAN).

    Used to add an ``nw`` leg to ``/api/device-detail`` so a searched IP is
    stitched to where it physically sits on the switched network. Pure (no hub,
    no I/O) so it is unit-testable without a spoke. Rows are returned verbatim
    (they already carry ``ip``/``mac``/``interface``/``vlan``)."""
    # Normalized search values.
    ip = (str(ip).strip() if ip else "") or None
    norm = _nw_norm_mac(mac) if mac else ""

    def _rows(entry, ep):
        """The cached data rows for one endpoint of a device (empty when none)."""
        env = entry.get(ep)
        data = env.get("data") if isinstance(env, dict) else None
        return data if isinstance(data, list) else []

    def _match(r):
        """True when a row has the searched IP or MAC."""
        if ip and str(r.get("ip", "")).strip() == ip:
            return True
        if norm and _nw_norm_mac(r.get("mac", "")) == norm:
            return True
        return False

    # Check each configured device against its cached rows.
    hits = []
    for dev in (devices or []):
        if not isinstance(dev, dict):
            continue
        did = dev.get("id")
        entry = (device_cache or {}).get(did) or {}
        # The device itself has this IP as its management address.
        is_self = bool(ip and str(dev.get("address", "")).strip() == ip)
        # Rows on this device that mention the IP or MAC.
        matched = {
            "arp":        [r for r in _rows(entry, "arp") if _match(r)],
            "mac":        [r for r in _rows(entry, "macs") if _match(r)],
            "endpoints":  [r for r in _rows(entry, "endpoints") if _match(r)],
            "interfaces": [r for r in _rows(entry, "interfaces") if _match(r)],
        }
        # Keep devices that match in any way.
        if is_self or any(matched.values()):
            hits.append({
                "device_id":   did,
                "name":        dev.get("name"),
                "address":     dev.get("address"),
                "object_type": dev.get("object_type"),
                "tenant_id":   dev.get("tenant_id"),
                "is_self":     is_self,
                **matched,
            })
    return hits


def dns_members_from_instances(instances, spoke_id):
    """Project Setup DNS records for one management spoke into worker members."""
    # Build a member for each DNS server on this spoke.
    members = []
    seen = set()
    for inst in instances or []:
        if not isinstance(inst, dict) or inst.get("spoke_id") != spoke_id:
            continue
        # The worker id and host are required.
        member_id = str(inst.get("member_id") or inst.get("name") or "").strip()
        host = str(inst.get("host") or "").strip()
        if not member_id or not host:
            raise HTTPException(
                status_code=400,
                detail="Each DNS server requires a Worker ID and host/IP.")
        # Worker ids must be unique.
        if member_id in seen:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate DNS Worker ID: {member_id}")
        seen.add(member_id)
        members.append({"id": member_id, "host": host})
    return members


async def sync_dns_instance_topology(hub, instances, spoke_id,
                                     worker_secret=""):
    """Push Setup's DNS server list to its connected DNS Management spoke."""
    # Nothing to push when the spoke is not connected.
    if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
        return False
    # The member list, plus the worker secret when given.
    payload = {"members": dns_members_from_instances(instances, spoke_id)}
    if worker_secret:
        payload["worker_secret"] = worker_secret
    # Send it to the spoke; anything but SUCCESS/PARTIAL is a 502.
    result = await hub.request_response(
        spoke_id, "DNS_CLUSTER_CONFIG", payload, timeout=30.0)
    data = _unwrap_spoke(result)
    if data.get("status") not in ("SUCCESS", "PARTIAL"):
        raise HTTPException(
            status_code=502,
            detail=data.get("message", "DNS worker configuration failed"))
    return True


def register(app, hub, ctx):
    """Register nw routes on the Hub app."""
    # Pull the shared session and filter helpers out of ctx once for the route closures below.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin
    _filter_nw = ctx._filter_nw

    def _shared_nw_hidden(request, tenant=None):
        """The viewer's tenant has its own nw spoke, so shared nw devices and
        the shared nw spoke are hidden from it."""
        # Use the tenant from the query string when none is given.
        if tenant is None:
            tenant = request.query_params.get("tenant")
        return access.tenant_left_shared(
            hub, access.request_effective_tenant(_session_user(request), request, tenant), "nw")

    def _validate_nw_address(addr):
        """Validate a management IP address (see validate_nw_address)."""
        return validate_nw_address(addr)

    def _enforce_tenant_bind(request, cfg, kind):
        """Shared add/edit gate for tenant-scoped device/instance creation. A
        tenant-admin may bind ``cfg`` ONLY to a spoke in their own tenant (via
        ``cfg['spoke_id']``) and the record is bound to that tenant; Global Admin
        is unrestricted (record tenant defaults to the spoke's tenant). Plain
        users are rejected. Mutates ``cfg['tenant_id']`` in place. Raises 403 on
        violation."""
        # The caller and the spoke being bound to.
        sess = _session_user(request)
        spoke_id = cfg.get("spoke_id")
        # Non-admins must be tenant admins binding to their own tenant's spoke; the record takes
        # that tenant.
        if not _is_admin(sess):
            if not _is_tenant_admin(sess):
                raise HTTPException(status_code=403, detail=f"Tenant-admin access required to add a {kind}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403,
                                    detail=f"You can only bind a {kind} to a spoke assigned to your tenant")
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
        # Admins: default the record's tenant to the spoke's tenant.
        elif spoke_id and not cfg.get("tenant_id"):
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

    def _nw_devices_for_spoke(hub, spoke_id: str):
        """The device slice a spoke should receive (bound-to-it, else unbound)."""
        # Devices bound to this spoke, else all unbound devices.
        devices = (hub.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
        if not mine:
            mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
        return mine

    def _project_nw_devices_for_push(devices):
        """Copy device dicts for the spoke payload (creds retained — runtime
        only). Mirrors main.py ``_project_nw_devices``."""
        import copy
        return [copy.deepcopy(d) for d in devices if isinstance(d, dict)]

    async def _nw_push_fleet(hub, spoke_id: str):
        """Re-push the bound device slice to a connected nw spoke."""
        # Nothing to push when the spoke is not connected.
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # Overlay any per-device Credential Vault secret (password / enable
        # secret / API token / SNMP community) just before the push, so the
        # plaintext lives only in the vault, not in global_config.
        slice_ = await instance_vault.overlay_many(
            hub, _nw_devices_for_spoke(hub, spoke_id), "nw_devices")
        # Per-tenant poll knobs overlaid on the global defaults for the spoke's
        # owning tenant (see access.nw_poll_cfg_for_tenant).
        poll_cfg = access.nw_poll_cfg_for_tenant(hub, access.nw_spoke_tenant(hub, spoke_id))
        # The UPDATE_CONFIG payload: devices, the shared tenant id, and the poll settings.
        payload = {"devices": _project_nw_devices_for_push(slice_),
                   "shared_tenant_id": access.shared_tenant_id() or "",
                   **poll_cfg}
        # Send it to the spoke.
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _authz_nw_device(request, device_id, write=False):
        """Authorize + classify a per-device nw op by the device's OWNING
        tenant. Returns ``(dev, scope, spoke_id)``. Raises 404 (unknown id) /
        403 (no access). Mirrors ``_authz_firewall`` (firewall.py:17-46).

        ``scope`` folds the caller's tier with the device's tenancy
        (access.read_scope / write_scope): ``"full"`` (admin, or a device
        DEDICATED to the caller's own tenant → whole device), ``"filtered"``
        (a SHARED device → only the caller's tenant subnet slice via
        ``_filter_nw``), ``"deny"`` → 403. ``spoke_id`` resolves from the
        RECORD's ``spoke_id`` (per-tenant spokes), falling back to
        ``get_nw_spoke_for_tenant`` / ``get_nw_spoke_for_shared`` — never an
        unassigned fallback (no cross-tenant leak). Empty ``spoke_id`` → the
        caller raises 503 (device's spoke not connected)."""
        # Find the device; unknown ids are a 404.
        hub = app.state.hub
        devices = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        dev = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        if not dev:
            raise HTTPException(status_code=404, detail="Network device not found")
        # The caller's access level for the device's tenant; denied (or hidden shared) is a 403.
        sess = _session_user(request)
        tid = dev.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny" or (scope == "filtered" and _shared_nw_hidden(request)):
            raise HTTPException(status_code=403,
                                detail="You do not have access to this network device")
        # Resolve the spoke from the record's spoke_id (per-tenant); if it's
        # unset/disconnected, fall back to the tenant/shared resolver (which
        # returns only a connected, approved, tenant-bound spoke — or None).
        spoke_id = dev.get("spoke_id") or ""
        if (not spoke_id
                or hub._primary_key(spoke_id) not in hub.active_connections):
            spoke_id = (hub.get_nw_spoke_for_shared()
                        if access.tenant_is_shared(tid)
                        else hub.get_nw_spoke_for_tenant(tid)) or ""
        if spoke_id and hub._primary_key(spoke_id) not in hub.active_connections:
            spoke_id = ""
        return dev, scope, spoke_id

    async def _filter_nw_optional(scope, request, data, endpoint, tenant,
                                  dedicated=False, spoke_id=None):
        """Apply the nw subnet filter ONLY when the reader is scoped or
        acting-as. A ``"full"``-scope reader (admin, or a device DEDICATED to
        the caller's own tenant) with no explicit ``?tenant=`` gets the whole
        device — preserves admin/own-tenant behavior. ``"filtered"`` (shared
        device) or an explicit ``?tenant=`` (admin acting-as) applies
        ``_filter_nw`` (shared → the viewer's session-tenant slice; acting-as
        → the named tenant's slice).

        ``dedicated`` — the device is bound to ONE tenant (not the shared
        tenant). A dedicated device's ENTIRE dataset belongs to that tenant, so
        it is never subnet-filtered: the subnet filter only makes sense on a
        SHARED device where many tenants' clients coexist and each sees only its
        own subnet slice. Without this, a dedicated gateway whose owning tenant
        has no (or non-covering) NetBox prefixes fails closed to an EMPTY view
        even though every record is legitimately theirs (mirrors the own-CPPM
        NAC bypass). ``spoke_id`` is the device's nw agent: an agent dedicated
        to a tenant makes the data that tenant's too (see access.filter_nw)."""
        # Dedicated devices and full-scope readers with no acting tenant get everything.
        if dedicated:
            return data
        if scope == "full" and not tenant:
            return data
        # Otherwise apply the tenant subnet filter.
        return await _filter_nw(request, data, endpoint, tenant, spoke_id=spoke_id)

    @app.get("/api/nw/devices")
    async def nw_list_devices(request: Request, tenant: str = None):
        """List the nw fleet, tenant-scoped. Admin → the whole fleet (all
        connected nw spokes). Non-admin → own-tenant + shared devices only
        (the shared-tenant-flag invariant); other-tenant / unassigned devices
        are admin-only. The hub config (``nw_devices``, tenant-stamped) is the
        AUTHORITATIVE visibility gate: live spoke rows are intersected with the
        reader's visible config set so a stale/leaky spoke can't surface a
        device the reader can't see (the cross-tenant leak this closes).

        Cache-first: serves the last-known whole-fleet snapshot tenant-filtered
        (``nw_cache_get_fleet_filtered``) WITHOUT blocking on live SSH — the
        cache is warmed continuously by spoke poll telemetry. When the snapshot
        is aging and a spoke is connected, a single background revalidate
        refreshes it for the next load; ``?refresh=1`` forces a live fetch. A
        cold miss with a connected spoke falls through to a blocking live fetch
        (which also seeds the cache, admin-only). No spoke + no cache → 503.
        ``?tenant=`` is accepted for signature compat (the fleet list is
        inventory, no IP to subnet-filter on)."""
        # The caller and whether they are a Global Admin.
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        # ADMIN (default) tenant EXPLICITLY selected in the picker (the WebUI
        # always sends ?tenant=<currentTenant>, and 'default' is the built-in
        # ADMIN scope): do NOT accumulate every tenant's devices into one
        # fleet-wide firehose. A Global Admin selects a SPECIFIC tenant to see
        # that tenant's devices; the default/ADMIN scope shows nothing on its
        # own. Clean + flagged so the UI prompts "select a tenant". Device
        # MANAGEMENT (add/edit/assign) lives on Setup → Network Devices
        # (/setup/nw-devices), which stays fleet-wide, so this only affects the
        # inventory/stats view. A truly unscoped admin call (tenant is None —
        # not the picker) still returns the whole fleet for programmatic
        # callers / the fleet cache warm path.
        # Tenant selector scoping: when the caller explicitly selects a SPECIFIC
        # tenant (the WebUI tenant picker sends ``?tenant=``; ``default`` is the
        # built-in global/"All tenants" scope, NOT a real tenant), scope the
        # fleet to that tenant — even for a Global Admin. Without this an admin
        # sees the whole fleet regardless of the selector (the cross-tenant leak
        # this closes). Only honored when the caller may access that tenant
        # (always true for a Global Admin; a tenant-admin/user is bounded to
        # their own tenants). ``default``/blank → no acting scope (global view).
        acting_tenant = None
        if tenant and tenant != "default" and access.check_tenant_access(sess, tenant):
            acting_tenant = tenant
        elif is_admin and tenant == "default":
            # The ADMIN scope is the ``default`` tenant itself (its own scanner,
            # subnets and scan-added devices): scope to that tenant's devices
            # (plus unassigned and shared), never the cross-tenant firehose.
            acting_tenant = "default"

        # Whether shared devices are hidden from this tenant.
        hide_shared = _shared_nw_hidden(request, acting_tenant or "")

        def _row_visible(tid):
            """Whether an nw_devices row (by ``tenant_id``) is visible to this
            request. Acting-as a specific tenant → only that tenant's dedicated
            devices + shared devices. Otherwise the existing rule: admin → all,
            non-admin → own-tenant + shared (``spoke_visible_to_session``)."""
            # Shared devices hidden from this tenant are never visible.
            if hide_shared and access.tenant_is_shared(tid):
                return False
            # Acting as a tenant: that tenant's devices, shared devices, and (for default)
            # unassigned ones.
            if acting_tenant is not None:
                if acting_tenant == "default" and not str(tid or "").strip():
                    return True
                return (str(tid or "").casefold() == str(acting_tenant).casefold()
                        or access.tenant_is_shared(tid))
            # Otherwise admins see everything, others their own tenants plus shared.
            return is_admin or access.spoke_visible_to_session(sess, tid)

        # Authoritative visibility: the hub config is the source of truth for
        # the device list (addresses/creds/tenant_id); the spoke adds live
        # reachability. A row is visible iff its tenant_id is admin / shared /
        # the reader's own (spoke_visible_to_session) — or, when acting-as a
        # selected tenant, only that tenant's + shared devices.
        all_devs = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        visible = [d for d in all_devs if isinstance(d, dict)
                   and _row_visible(d.get("tenant_id", ""))]
        visible_ids = {d.get("id") for d in visible if d.get("id")}

        # The hub config ``name`` is authoritative for the DISPLAY name (it's
        # reconciled to the box's real hostname on each poll —
        # reconcile_nw_device_name). Overlay it onto the served rows so a name
        # reset shows immediately, regardless of what the spoke row / cache
        # still carries. Builds fresh row dicts (never mutates the cache).
        name_by_id = {d.get("id"): str(d.get("name")).strip()
                      for d in visible
                      if d.get("id") and str(d.get("name") or "").strip()}

        # Surface the box's identity datums (serial / base MAC / model / firmware
        # / hostname) captured on each poll, so an operator can positively ID the
        # physical device from the fleet list / detail without opening a session.
        # Pulled from the warm per-device cache (poll → device_info, mirrored to
        # the ``info`` envelope); absent until the device is first polled.
        def _device_identity(did):
            """The identity details (serial, MAC, model, firmware, hostname) cached from the
            device's last poll.
            """
            # The cached device info; none means no identity yet.
            env = hub.nw_cache_get_device(did, "info")
            info = (env or {}).get("data") if isinstance(env, dict) else None
            if not isinstance(info, dict):
                return {}
            # Keep only the fields that have a value.
            out = {}
            for k in ("serial", "mac", "model", "firmware", "hostname"):
                v = info.get(k)
                if v not in (None, ""):
                    out[k] = v
            return out

        # Identity details for every visible device.
        info_by_id = {did: _device_identity(did) for did in visible_ids}
        # NetBox site (from the site-scoped prefix of the address), recorded on each poll.
        for d in visible:
            if d.get("id") and isinstance(d.get("site"), dict):
                info_by_id.setdefault(d["id"], {})["site"] = d["site"]

        def _overlay_names(env):
            """Return a copy of the envelope with each row's name and identity details taken from
            the hub config.
            """
            # Leave anything that is not an envelope alone.
            if not isinstance(env, dict):
                return env
            rows = env.get("data")
            if isinstance(rows, list):
                def _merge(r):
                    """Return a copy of one row with the hub's name and identity details applied."""
                    if not isinstance(r, dict):
                        return r
                    rid = r.get("id")
                    extra = {}
                    if name_by_id.get(rid):
                        extra["name"] = name_by_id[rid]
                    extra.update(info_by_id.get(rid) or {})
                    return {**r, **extra} if extra else r
                # Replace the rows with the merged copies.
                env = {**env, "data": [_merge(r) for r in rows]}
            return env

        # Resolve the connected, approved nw spoke(s) to query for live data.
        # Admin → every connected nw spoke (whole fleet per spoke, no tenant
        # filter). Non-admin → the spoke(s) bound to the reader's own tenant(s)
        # + the shared-tenant spoke (shared devices live there); the spoke-side
        # tenant filter returns own+shared from each. No shared tenant → no
        # shared spoke (never the global fallback, which would leak the fleet).
        if is_admin:
            spokes = [s for s in (hub.get_all_spokes_by_type("nw") or [])
                      if s in hub.active_connections
                      and hub.approved_modules.get(s, False)]
            # Admins query with no tenant filter.
            spoke_to_tid = {s: "" for s in spokes}
        else:
            # Non-admins: the spoke for each of their tenants, plus the shared spoke unless hidden.
            spoke_to_tid = {}
            for t in ((sess or {}).get("user", {}).get("tenants") or []):
                s = hub.get_nw_spoke_for_tenant(t)
                if s:
                    spoke_to_tid[s] = t
            shared_tid = access.shared_tenant_id()
            if shared_tid and not hide_shared:
                s = hub.get_nw_spoke_for_shared()
                if s:
                    spoke_to_tid[s] = shared_tid
            # Keep only connected, approved spokes.
            spoke_to_tid = {s: t for s, t in spoke_to_tid.items()
                            if s in hub.active_connections
                            and hub.approved_modules.get(s, False)}
            spokes = list(spoke_to_tid)

        # Cache-first: serve the last-known fleet snapshot (tenant-filtered)
        # WITHOUT blocking on live SSH, then revalidate in the background when
        # it's aging and a spoke is up. ``?refresh=1`` forces a live fetch.
        force = _nw_truthy(request.query_params.get("refresh"))
        # Authoritative gate, the same for cached and live rows: only devices in
        # the reader's visible hub config. A device removed from the config
        # (or re-tenanted) vanishes at once, even from an older snapshot. When
        # acting-as a tenant we gate even with no visible devices, so an empty
        # scope yields an empty list rather than the unfiltered fleet.
        gate_by_config = bool(visible_ids) or acting_tenant is not None

        def _row_served(r):
            """Whether a row may be served: in the visible config when gating by config, else by
            tenant.
            """
            if gate_by_config:
                return r.get("id") in visible_ids
            return _row_visible(r.get("tenant_id", ""))

        # The cached fleet filtered to this reader (skipped when refresh is forced).
        cached = None if force else hub.nw_cache_get_fleet_filtered(_row_served)
        if cached is not None:
            # Serve the cache, with hub names applied and marked as cached.
            out = dict(_overlay_names(dict(cached.get("devices") or {})))
            out["cached"] = True
            out["fetched_at"] = cached.get("fetched_at")
            if not spokes:
                # Offline: no live spoke for the reader's slice. The cached rows
                # still carry their LAST up/down, which is now unknowable (the
                # spoke that probes them is gone) — showing it stale would badge
                # a since-crashed box as 'up'. Flip every served row to UNKNOWN
                # (reachable=None → the UI's yellow 'unknown' badge) so the
                # operator sees "can't tell" rather than a stale green. Fresh
                # dicts — never mutate the shared cache.
                rows = out.get("data")
                if isinstance(rows, list):
                    out["data"] = [
                        {**r, "reachable": None, "latency_ms": None}
                        if isinstance(r, dict) else r
                        for r in rows
                    ]
                out["stale"] = True
                out["message"] = (
                    "Network Devices spoke offline — reachability unknown "
                    "(showing last-known inventory)")
            else:
                # Spoke online: refresh in the background if the snapshot is getting old.
                age = time.time() - float(cached.get("fetched_at") or 0.0)
                if age > _NW_SERVE_MAX_AGE_S:
                    _nw_spawn_refresh("__fleet__", lambda: _nw_bg_refresh_fleet(hub))
            return out

        if not spokes:
            # Cold miss AND no live spoke → nothing to serve.
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")

        # Merged rows, ids already seen, and how many spokes answered.
        # Fan out NW_LIST_DEVICES (admin: {} = whole fleet per spoke; non-admin:
        # {"tenant": tid} = own+shared from that spoke) + merge rows by id.
        merged, seen, answered = [], set(), 0
        # Ask each spoke for its devices (filtered to the reader's tenant) and merge them by id.
        # All spokes at once; merged in spoke order, so duplicates resolve as before.
        def _payload(sid):
            tid = spoke_to_tid.get(sid, "")
            return {"tenant": tid} if tid else {}
        results = await asyncio.gather(
            *(hub.request_response(sid, "NW_LIST_DEVICES", _payload(sid), timeout=20.0)
              for sid in spokes),
            return_exceptions=True)
        for sid, result in zip(spokes, results):
            try:
                if isinstance(result, BaseException):
                    raise result
                env = access.unwrap_spoke(result)
                rows = env.get("data") if isinstance(env, dict) else None
                if isinstance(rows, list):
                    answered += 1
                    for r in rows:
                        if isinstance(r, dict) and r.get("id") and r["id"] not in seen:
                            seen.add(r["id"])
                            merged.append(r)
            except Exception as e:
                logger.warning("nw_list_devices: spoke %s fetch failed: %s", sid, e)

        # Drop rows the reader may not see.
        if gate_by_config:
            merged = [r for r in merged if _row_served(r)]

        # The merged result.
        env = {"status": "SUCCESS", "data": merged,
               "message": f"{len(merged)} device(s)"}
        # The global cache holds the WHOLE fleet (last admin fetch) so the
        # offline path serves a complete, filterable snapshot — only update it
        # from a whole-fleet (admin) fetch, never a non-admin subset NOR an
        # admin acting-as a single tenant (``env`` is a scoped subset there).
        if is_admin and acting_tenant is None and answered:
            try:
                await hub.nw_cache_set_fleet(env)
            except Exception:
                logger.debug("nw_list_devices: cache set failed", exc_info=True)
        # Return it with hub names applied.
        return _overlay_names(env)

    # ── topology ─────────────────────────────────────────────────────────────
    # Registered BEFORE /api/nw/{device_id}/{endpoint}: FastAPI matches in
    # registration order, so "/api/nw/topology/manual" would otherwise be
    # swallowed by the two-segment device catch-all as device_id="topology".

    def _nw_topology_cfg(hub, tid):
        """Operator-declared devices + links for one tenant.

        These are the whole point of the feature: a lot of lab gear (unmanaged
        switches, media converters, PDUs, older APs) speaks no LLDP and would
        otherwise be invisible on the map."""
        # This tenant's saved topology config.
        gc = hub.state.system_state.get("global_config", {}) or {}
        cur = (((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("topology") or {})
        # Only dict entries are kept.
        return {
            "devices": [d for d in (cur.get("devices") or []) if isinstance(d, dict)],
            "links": [l for l in (cur.get("links") or []) if isinstance(l, dict)],
        }

    def _nw_cached_rows(hub, device_id, endpoint):
        """Rows from the warm per-device cache, or [] on a cold miss."""
        # The cached envelope's data rows, if it is a list.
        env = hub.nw_cache_get_device(device_id, endpoint)
        rows = env.get("data") if isinstance(env, dict) else None
        return rows if isinstance(rows, list) else []

    @app.get("/api/nw/topology")
    async def nw_topology(request: Request, tenant: str = None):
        """The network map: nodes and links assembled from LLDP adjacencies,
        NetBox inventory, switch MAC tables and operator-declared gear.

        Tenant-scoped exactly like ``/api/nw/devices``: a Global Admin sitting in
        the ADMIN (``default``) scope maps the default tenant's OWN devices
        (never every tenant's topology fused into one mesh — a map is only
        coherent within one tenant's slice). An explicit
        ``?tenant=`` scopes even an admin to that tenant; a non-admin sees their
        own + shared devices.

        Cache-first, like every other nw read: built from the warm per-device
        LLDP/MAC cache WITHOUT blocking on live SSH, kicking off a background
        revalidate for aging entries. ``?refresh=1`` gathers live from every
        visible device first (bounded concurrency) — expensive, so it is the
        explicit "Refresh topology" button, not the page load.

        ``?infer=0`` drops MAC-table inference and shows only links something
        actually asserted (LLDP or a human)."""
        # The caller and whether they are a Global Admin.
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        # The result for an empty map.
        empty = {"nodes": [], "edges": [], "trunks": [],
                 "stats": {"nodes": 0, "edges": 0, "trunks": 0,
                           "trunk_ports": 0, "nodes_without_lldp": 0,
                           "edges_by_source": {}}}
        # ADMIN (default) tenant explicitly selected in the picker: the WebUI
        # always sends ?tenant=<currentTenant> and 'default' is the built-in
        # ADMIN scope. Same rule as the device inventory — see nw_list_devices.
        acting_tenant = None
        if tenant and tenant != "default" and access.check_tenant_access(sess, tenant):
            acting_tenant = tenant
        elif is_admin and tenant == "default":
            # The ADMIN scope is the ``default`` tenant itself (its own scanner,
            # subnets and scan-added devices): scope to that tenant's devices
            # (plus unassigned and shared), never the cross-tenant firehose.
            acting_tenant = "default"

        # Whether shared devices are hidden from this tenant.
        hide_shared = _shared_nw_hidden(request, acting_tenant or "")

        def _row_visible(tid):
            """Whether a device of tenant tid is visible to this request (same rule as the device
            list).
            """
            if hide_shared and access.tenant_is_shared(tid):
                return False
            if acting_tenant is not None:
                if acting_tenant == "default" and not str(tid or "").strip():
                    return True
                return (str(tid or "").casefold() == str(acting_tenant).casefold()
                        or access.tenant_is_shared(tid))
            return is_admin or access.spoke_visible_to_session(sess, tid)

        # Visible devices from the hub config.
        all_devs = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        fleet = [d for d in all_devs if isinstance(d, dict)
                 and _row_visible(d.get("tenant_id", ""))]

        # Per-device authorization is re-run through _authz_nw_device (rather
        # than trusted from _row_visible alone) so the topology can never widen
        # what a caller may read from a device — and it hands back the spoke.
        authed, spoke_by_id, scope_by_id = [], {}, {}
        for dev in fleet:
            did = dev.get("id")
            if not did:
                continue
            try:
                _d, scope, spoke_id = _authz_nw_device(request, did)
            except HTTPException:
                continue
            authed.append(dev)
            spoke_by_id[did] = spoke_id
            scope_by_id[did] = scope
        fleet = authed

        # Whether to fetch live first, and whether to infer links from MAC tables.
        force = _nw_truthy(request.query_params.get("refresh"))
        infer = not (request.query_params.get("infer") in ("0", "false", "no"))

        async def _gather(device_id, endpoint, spoke_cmd, timeout):
            """Live-fetch one device endpoint and seed the cache. Never raises:
            one unreachable switch must not blank the whole map."""
            # No connected spoke for this device: nothing to fetch.
            spoke_id = spoke_by_id.get(device_id) or ""
            if not spoke_id:
                return
            # Send the device's tenant along with the request.
            dev = next((d for d in fleet if d.get("id") == device_id), {})
            payload = {"device_id": device_id}
            if dev.get("tenant_id"):
                payload["tenant"] = dev["tenant_id"]
            # Fetch from the spoke and cache the unwrapped result.
            try:
                result = await hub.request_response(spoke_id, spoke_cmd, payload,
                                                    timeout=timeout)
                await hub.nw_cache_set_device(device_id, endpoint,
                                              access.unwrap_spoke(result))
            except Exception as e:
                logger.warning("nw_topology: live %s for %s failed: %s",
                               endpoint, device_id, e)

        if force:
            # Bounded fan-out: a big fleet would otherwise open one SSH session
            # per device per datum all at once and starve the spoke.
            sem = asyncio.Semaphore(4)

            async def _one(device_id, endpoint, cmd, timeout):
                """Fetch one device endpoint, at most 4 at a time."""
                async with sem:
                    await _gather(device_id, endpoint, cmd, timeout)

            # LLDP neighbours for every device, plus MAC tables when inferring links.
            jobs = []
            for dev in fleet:
                did = dev["id"]
                jobs.append(_one(did, "lldp", "NW_GET_LLDP_NEIGHBORS", 30.0))
                if infer:
                    jobs.append(_one(did, "macs", "NW_GET_MAC_TABLE", 30.0))
            if jobs:
                await asyncio.gather(*jobs, return_exceptions=True)

        async def _scoped(dev, endpoint, rows):
            """Apply the same per-device subnet filter the per-device views use.

            LLDP rows carry the REMOTE device's management IP, so on a SHARED
            switch an unfiltered map would hand a scoped tenant another
            tenant's gear. A DEDICATED device's whole dataset belongs to its
            tenant and is never filtered (the subnet filter only makes sense
            where many tenants' clients coexist).
            """
            # Dedicated: bound to one tenant that is not the shared tenant.
            tid = dev.get("tenant_id", "")
            dedicated = bool(tid) and not access.tenant_is_shared(tid)
            out = await _filter_nw_optional(scope_by_id.get(dev["id"], "full"),
                                            request, {"data": rows}, endpoint,
                                            acting_tenant, dedicated, dev.get("spoke_id"))
            # Only dict rows survive.
            got = out.get("data") if isinstance(out, dict) else None
            return [r for r in (got or []) if isinstance(r, dict)]

        # Collect each device's cached (and tenant-filtered) LLDP and MAC rows.
        lldp_by_device, macs_by_device = {}, {}
        for dev in fleet:
            did = dev["id"]
            lldp_by_device[did] = await _scoped(
                dev, "lldp", _nw_cached_rows(hub, did, "lldp"))
            if infer:
                macs_by_device[did] = await _scoped(
                    dev, "macs", _nw_cached_rows(hub, did, "macs"))
            # No background refresh after a forced live fetch, or without a spoke.
            if force or not spoke_by_id.get(did):
                continue
            # Stale-while-revalidate: refresh aging entries for the NEXT load.
            age = time.time() - hub.nw_cache_device_fetched_at(did)
            if age <= _NW_SERVE_MAX_AGE_S:
                continue
            # Refresh each stale endpoint in the background, sending the device's tenant along.
            payload = {"device_id": did}
            if dev.get("tenant_id"):
                payload["tenant"] = dev["tenant_id"]
            for endpoint, cmd in (("lldp", "NW_GET_LLDP_NEIGHBORS"),
                                  ("macs", "NW_GET_MAC_TABLE")):
                if endpoint == "macs" and not infer:
                    continue
                _nw_spawn_refresh(
                    f"{did}:{endpoint}",
                    (lambda d=did, e=endpoint, c=cmd, s=spoke_by_id[did], p=payload:
                     _nw_bg_refresh_device(hub, d, e, s, c, p, 30.0)))

        # NetBox inventory: gear the nw fleet never logs into (PDUs, patch
        # panels, APs) still belongs on the map. Best-effort — no IPAM spoke, a
        # timeout or a NetBox error degrades to "no inventory", never a 500.
        netbox = None
        netbox_devices = []
        netbox_cables = []
        try:
            netbox = hub.get_spoke_by_type("ipam")
            if netbox:
                rr = await hub.request_response(netbox, "NETBOX_GET_DEVICES", {},
                                                timeout=60.0)
                rows = (access.unwrap_spoke(rr) or {}).get("devices") or []
                netbox_devices = [r for r in rows if isinstance(r, dict)]
                # Cables carry no IP of their own and are resolved purely by
                # device NAME against nodes already on the map, so a cable
                # whose end was filtered out below (another tenant's gear)
                # harmlessly fails to resolve rather than needing its own
                # tenant filter.
                cr = await hub.request_response(netbox, "NETBOX_GET_CABLES", {},
                                                timeout=60.0)
                crows = (access.unwrap_spoke(cr) or {}).get("cables") or []
                netbox_cables = [r for r in crows if isinstance(r, dict)]
        except Exception as e:
            logger.info("nw_topology: NetBox inventory unavailable (%s)", e)

        if netbox_devices:
            # NetBox is a FLEET-WIDE inventory with no LM tenant stamp, so it is
            # the one input that could leak another tenant's gear onto a scoped
            # reader's map. Narrow it to the reader's prefixes by IP; a row with
            # no IP can't be placed in a tenant and is dropped (fails closed).
            for row in netbox_devices:
                row["ip"] = str(row.get("primary_ip") or "").split("/")[0]
            filtered = await _filter_nw(request, {"data": netbox_devices},
                                        "netbox_devices", acting_tenant)
            rows = filtered.get("data") if isinstance(filtered, dict) else None
            netbox_devices = [r for r in (rows or []) if isinstance(r, dict)]

        # The tenant whose declared devices and links are added to the map.
        cfg_tid = acting_tenant or _nw_caller_tenant(sess, None)
        manual = _nw_topology_cfg(hub, cfg_tid)

        # Build the map from every source.
        graph = build_topology(
            fleet=fleet,
            lldp_by_device=lldp_by_device,
            macs_by_device=macs_by_device,
            netbox_devices=netbox_devices,
            netbox_cables=netbox_cables,
            manual_devices=manual["devices"],
            manual_links=manual["links"],
            infer_from_macs=infer,
        )
        graph["status"] = "SUCCESS"
        graph["tenant_id"] = cfg_tid
        graph["netbox"] = bool(netbox_devices)

        # Write LLDP's live truth back into NetBox as real cables, so it
        # persists past nw's in-memory cache — but only on an explicit scan
        # (``?refresh=1``), never on a routine page load, and only for
        # "lldp"-sourced edges (a real, confirmed adjacency — never a "mac"
        # guess). Fire-and-forget: a slow/broken NetBox must never make the
        # topology view itself slow or fail.
        if force and netbox:
            links = netbox_lldp_links(graph)
            if links:
                slug = str((hub.state.get_tenant(cfg_tid) or {}).get(
                    "netbox_tenant_slug") or "").strip() if cfg_tid else ""
                asyncio.create_task(_nw_sync_lldp_netbox(hub, netbox, links, slug))

        # Return the map.
        return graph

    @app.get("/api/nw/topology/manual")
    async def nw_topology_manual_get(request: Request, tenant: str = None):
        """The operator-declared devices and links for a tenant (the editable
        half of the map)."""
        # The caller's tenant (an explicit "default" counts as none).
        hub = app.state.hub
        sess = _session_user(request)
        tid = _nw_caller_tenant(sess, tenant if tenant != "default" else None)
        return {"status": "ok", "tenant_id": tid, **_nw_topology_cfg(hub, tid)}

    @app.post("/api/nw/topology/manual")
    async def nw_topology_manual_set(request: Request):
        """Replace a tenant's declared topology. Body:
        ``{"tenant": "...", "devices": [...], "links": [...]}`` — either list may
        be omitted to leave that half untouched.

        A declared device is ``{name, mac?, ip?, kind?, note?}``; ``mac``/``ip``
        are what let MAC-table inference recognise the far end of a port and
        name it, which is how a device that speaks no LLDP gets onto the map.
        A declared link is ``{a, a_port?, b, b_port?, note?}`` where ``a``/``b``
        are a device id, name, IP or MAC."""
        hub = app.state.hub
        sess = _session_user(request)
        # Admins or tenant admins only.
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        # Read the JSON body; a bad body counts as empty, and it must be an object.
        try:
            data = await request.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="body must be an object")
        # The tenant whose topology is being replaced.
        tid = _nw_caller_tenant(sess, data.get("tenant"))

        def _clean(items, keys, required):
            """Return the dict items with the given keys as trimmed strings, dropping ones missing a
            required key and giving each an id.
            """
            if not isinstance(items, list):
                raise HTTPException(status_code=400,
                                    detail="devices/links must be lists")
            out = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                row = {k: str(item.get(k) or "").strip() for k in keys}
                if any(not row.get(k) for k in required):
                    continue
                row["id"] = str(item.get("id") or "").strip() or uuid.uuid4().hex[:12]
                out.append(row)
            return out

        # Copy the tenant's stored config so it is replaced as a whole.
        gc = hub.state.system_state.get("global_config", {})
        tmap = dict(gc.get("nw_tenant_cfg") or {})
        cur = dict(tmap.get(tid) or {})
        topo = dict(cur.get("topology") or {})
        # Replace whichever lists were sent.
        if "devices" in data:
            topo["devices"] = _clean(
                data["devices"], ("name", "mac", "ip", "kind", "note"), ("name",))
        if "links" in data:
            topo["links"] = _clean(
                data["links"], ("a", "a_port", "b", "b_port", "note"), ("a", "b"))
        # Save it back.
        cur["topology"] = topo
        tmap[tid] = cur
        gc["nw_tenant_cfg"] = tmap
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "tenant_id": tid, **_nw_topology_cfg(hub, tid)}

    @app.get("/api/nw/{device_id}/{endpoint}")
    async def nw_get_device_data(request: Request, device_id: str, endpoint: str,
                                 tenant: str = None):
        """Per-device nw data (info|macs|arp|interfaces|endpoints|vlans),
        tenant-gated. ``_authz_nw_device`` resolves the device record, classifies
        the read scope, and resolves the spoke from the record's ``spoke_id``
        (per-tenant) — 404 unknown, 403 other-tenant/unassigned, 503 spoke down.

        ``endpoint`` selects the device sub-resource → the NW_GET_<X> command.
        Results are subnet-filtered via ``_filter_nw`` ONLY when the reader is
        scoped (shared device → ``"filtered"``) or acting-as (``?tenant=``); a
        ``"full"``-scope reader (admin, or a device dedicated to the caller's
        own tenant) with no explicit tenant gets the whole device (preserves
        admin/own-tenant behavior). MAC/ARP/interfaces carry IPs; info does not.

        Cache-first: serves the last-known raw per-device endpoint envelope
        (scope-filtered) WITHOUT blocking on live SSH — the cache is warmed by
        spoke poll telemetry. When the entry is aging and the spoke is up, a
        single background revalidate refreshes it for the next load;
        ``?refresh=1`` (or the per-device poll button) forces a live fetch. A
        cold miss with a connected spoke falls through to a blocking live fetch
        (which also seeds the cache). The cache is gated by the same
        ``_authz_nw_device`` check, so a non-admin can't fetch another tenant's
        device cache."""
        # The spoke command for each supported endpoint.
        hub = app.state.hub
        command_map = {
            "info":       "NW_GET_DEVICE_INFO",
            "macs":       "NW_GET_MAC_TABLE",
            "arp":        "NW_GET_ARP",
            "interfaces": "NW_GET_INTERFACES",
            "endpoints":  "NW_GET_ENDPOINTS",  # fused ARP+MAC unique IP/MAC list
            "vlans":      "NW_GET_VLANS",       # per-VLAN rollup
            "lldp":       "NW_GET_LLDP_NEIGHBORS",  # adjacencies for the map
        }
        # Unsupported endpoints are a 400.
        spoke_cmd = command_map.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported by nw module")
        logger.debug("relay GET /api/nw/%s/%s tenant=%s", device_id, endpoint, tenant)
        # Authorize the read; this also finds the device's spoke.
        dev, scope, spoke_id = _authz_nw_device(request, device_id)
        tid = dev.get("tenant_id", "")
        # A device bound to ONE (non-shared) tenant is DEDICATED: its whole
        # dataset belongs to that tenant, so it is never subnet-filtered (the
        # subnet filter only makes sense on a SHARED device). Without this, a
        # dedicated gateway whose owning tenant has no (or non-covering) NetBox
        # prefixes fails closed to an empty view even under an explicit
        # ``?tenant=`` — mirrors the own-CPPM NAC bypass.
        dedicated = bool(tid) and not access.tenant_is_shared(tid)
        # Defense-in-depth: re-check on the spoke via the tenant filter (the
        # spoke rejects a device whose tenant_id is neither the passed tenant
        # nor the shared tenant — Stage 1).
        relay_payload = {"device_id": device_id}
        if tid:
            relay_payload["tenant"] = tid
        # Live timeout for this endpoint.
        # endpoints/vlans run three sequential SSH gathers (arp+mac+interfaces)
        # on the spoke, so the 5s default relay timeout is far too short — give
        # them room; lldp walks every port's neighbour detail and is slow on a
        # big chassis; the single-datum views get a comfortable margin too.
        timeout = 45.0 if endpoint in ("endpoints", "vlans") else (
            30.0 if endpoint == "lldp" else 20.0)

        # Cache-first: serve the last-known endpoint value WITHOUT blocking on
        # live SSH, then revalidate in the background when it's aging and the
        # spoke is up. ``?refresh=1`` forces a live fetch (cold path below).
        force = _nw_truthy(request.query_params.get("refresh"))
        # The cached value (skipped when refresh is forced).
        cached = None if force else hub.nw_cache_get_device(device_id, endpoint)
        if cached is not None:
            # Serve it tenant-filtered and marked as cached (stale when the spoke is down).
            filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant, dedicated,
                                                   dev.get("spoke_id"))
            fetched_at = hub.nw_cache_device_fetched_at(device_id)
            if isinstance(filtered, dict):
                filtered = dict(filtered)
                filtered["cached"] = True
                filtered["fetched_at"] = fetched_at
                if not spoke_id:
                    filtered["stale"] = True
            # Refresh it in the background when it is getting old.
            if spoke_id and (time.time() - fetched_at) > _NW_SERVE_MAX_AGE_S:
                _nw_spawn_refresh(
                    f"{device_id}:{endpoint}",
                    lambda: _nw_bg_refresh_device(hub, device_id, endpoint,
                                                  spoke_id, spoke_cmd, relay_payload, timeout))
            return filtered

        if not spoke_id:
            # Cold miss AND no live spoke → nothing to serve.
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        # Fetch live, cache the result, and return it tenant-filtered.
        try:
            result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.nw_cache_set_device(device_id, endpoint, data)
            return await _filter_nw_optional(scope, request, data, endpoint, tenant, dedicated,
                                              dev.get("spoke_id"))
        # Pass HTTP errors through.
        except HTTPException:
            raise
        except Exception as e:
            # A slow/timed-out live fetch shouldn't blank the tab — serve the
            # last-known cached value (marked stale, scope-filtered) if we have
            # one, so a heavy gateway that occasionally overruns still shows data.
            cached = hub.nw_cache_get_device(device_id, endpoint)
            if cached is not None:
                logger.warning("nw_get_device_data live fetch failed (%s/%s: %s)"
                               " — serving cached", device_id, endpoint, e)
                filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant, dedicated,
                                                   dev.get("spoke_id"))
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
            # No cached copy either: report a 500.
            logger.exception("nw_get_device_data failed (%s/%s)", device_id, endpoint)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/config")
    async def nw_run_config(device_id: str, request: Request):
        """Apply a CLI/REST config snippet to a device. Body:
        ``{"commands": ["...", ...]}``. Returns the spoke's applied/errors lists.

        Tenant-scoped via ``_authz_nw_device(write=True)``: a Global Admin may
        configure any device; a tenant admin may configure devices DEDICATED to
        its own tenant (and, as a shared-infra writer, the shared device) — any
        other/unassigned device is denied. Resolves the spoke from the device
        record's ``spoke_id`` (per-tenant) so a config push lands on the spoke
        that owns the device."""
        hub = app.state.hub
        # Read the JSON body; a bad body counts as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # The command list must be a list.
        commands = (data or {}).get("commands", []) if isinstance(data, dict) else []
        if not isinstance(commands, list):
            raise HTTPException(status_code=400, detail="commands must be a list")
        # Authorize the write; this also finds the device's spoke.
        dev, _scope, spoke_id = _authz_nw_device(request, device_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        # Send the commands to the spoke and return its reply.
        try:
            result = await hub.request_response(spoke_id, "NW_RUN_CONFIG",
                                                {"device_id": device_id,
                                                 "commands": commands,
                                                 "tenant": dev.get("tenant_id", "")})
            return access.unwrap_spoke(result)
        # Pass HTTP errors through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_run_config failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/poll")
    async def nw_poll_device(device_id: str, request: Request):
        """POLL NOW for one network device: run a full probe+info+interfaces+
        arp+mac poll on the spoke, then upsert the device + its interfaces into
        NetBox via ``NETBOX_SYNC_NW_DEVICE``. Returns the poll results + a NetBox
        push summary. Driven by the WebUI "Poll Now" button on the Devices table.

        Tenant-scoped via ``_authz_nw_device``: a Global Admin may poll any
        device; a tenant admin may poll devices it can see (own-tenant + shared);
        other/unassigned devices are denied."""
        hub = app.state.hub
        _authz_nw_device(request, device_id, write=False)  # 404/403 by tenant ownership
        # Run the poll (and NetBox push) through the hub.
        try:
            result = await hub.poll_nw_device(device_id)
            # Fold the poll's rich result into the per-device cache so a later
            # page load (spoke offline) still reflects the last probe.
            if isinstance(result, dict):
                await hub.nw_cache_set_poll(device_id, result)
            return result
        # Pass HTTP errors through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_poll_device failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/nw-devices")
    async def get_nw_devices(request: Request):
        """Return the configured network devices visible to the caller."""
        hub = app.state.hub
        devices = hub.state.system_state.get("global_config", {}).get("nw_devices", [])
        # Tenant-scope the device list (shared + own visible; other/unassigned
        # admin-only). Object-level IP filtering + the write gate are unchanged.
        sess = _session_user(request)
        if not _is_admin(sess):
            devices = [d for d in devices
                       if access.spoke_visible_to_session(sess, (d or {}).get("tenant_id", ""))]
        return {"nw_devices": devices}

    @app.get("/setup/nw-poll-config")
    async def get_nw_poll_config(request: Request):
        """Module-level nw poll cadence + anti-stampede knobs. ``default_poll_interval``
        (seconds) is the fallback each nw spoke applies to any device that doesn't
        set its own (device-level always wins); null/absent → the spoke's built-in
        6h. ``poll_jitter_frac`` (0..0.9), ``max_poll_per_tick`` (1..100) and
        ``max_poll_concurrency`` (1..50) tune the spoke's stampede protection;
        null → the spoke's built-in defaults."""
        hub = app.state.hub
        # Read the stored settings (None means the spoke default).
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"default_poll_interval": gc.get("nw_poll_default_interval"),
                "poll_jitter_frac": gc.get("nw_poll_jitter_frac"),
                "max_poll_per_tick": gc.get("nw_poll_max_per_tick"),
                "max_poll_concurrency": gc.get("nw_poll_max_concurrency"),
                "ping_interval": gc.get("nw_ping_interval")}

    @app.post("/setup/nw-poll-config")
    async def set_nw_poll_config(request: Request):
        """Save the module-level nw poll settings and re-push every nw spoke (admin only)."""
        # Admins only.
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read and validate the default poll interval (an integer, or null for the spoke default).
        data = await request.json()
        raw = data.get("default_poll_interval")
        try:
            val = None if raw in (None, "", "null") else int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="default_poll_interval must be an integer or null")

        def _opt_num(key, cast, lo, hi):
            """Parse an optional numeric knob: null/absent → None (spoke default),
            else cast + clamp to [lo, hi]."""
            # Null or blank means use the spoke default.
            v = data.get(key)
            if v in (None, "", "null"):
                return None
            try:
                return max(lo, min(cast(v), hi))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} must be numeric or null")

        # Read and clamp the optional anti-stampede settings.
        jitter = _opt_num("poll_jitter_frac", float, 0.0, 0.9)
        per_tick = _opt_num("max_poll_per_tick", int, 1, 100)
        concurrency = _opt_num("max_poll_concurrency", int, 1, 50)
        # Reachability sweep cadence: 0 disables the ICMP ping sweep, else
        # clamp to a sane [30s, 24h] band; null → the spoke's 5-min default.
        ping_raw = data.get("ping_interval")
        if ping_raw in (None, "", "null"):
            ping_interval = None
        else:
            try:
                ping_interval = int(ping_raw)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400,
                                    detail="ping_interval must be an integer or null")
            if ping_interval != 0:
                ping_interval = max(30, min(ping_interval, 86400))

        # Save everything to the global config.
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_poll_default_interval"] = val
        gc["nw_poll_jitter_frac"] = jitter
        gc["nw_poll_max_per_tick"] = per_tick
        gc["nw_poll_max_concurrency"] = concurrency
        gc["nw_ping_interval"] = ping_interval
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Re-push every connected nw spoke so the new module config takes effect.
        pushed = 0
        for sid in (hub.get_all_spokes_by_type("nw") or []):
            if await _nw_push_fleet(hub, sid):
                pushed += 1
        # Report the saved values and how many spokes were updated.
        return {"status": "ok", "default_poll_interval": val,
                "poll_jitter_frac": jitter, "max_poll_per_tick": per_tick,
                "max_poll_concurrency": concurrency,
                "ping_interval": ping_interval, "pushed": pushed}

    @app.get("/setup/nw-netbox-import")
    async def get_nw_netbox_import(request: Request):
        """NetBox→NW import config (NetBox = fleet source of truth): which NetBox
        device roles get imported into the nw fleet, object_type mapping, cadence."""
        # Read the stored import config.
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"nw_netbox_import": gc.get("nw_netbox_import", {}) or {}}

    @app.post("/setup/nw-netbox-import")
    async def set_nw_netbox_import(request: Request):
        """Save the NetBox-to-NW import config (admin only)."""
        # Admins only.
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read the config (wrapped in "config" or bare); roles may be a comma-separated string.
        data = await request.json()
        cfg = data.get("config", data) or {}
        roles = cfg.get("roles")
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        # Normalize every field, with defaults.
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "roles": [str(r).strip() for r in (roles or []) if str(r).strip()],
            "object_type_map": dict(cfg.get("object_type_map") or {}),
            "default_object_type": str(cfg.get("default_object_type") or "gateway"),
            "interval": int(cfg.get("interval") or 900),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        # Save it.
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_netbox_import"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_netbox_import": clean}

    @app.post("/setup/nw-netbox-import/run")
    async def run_nw_netbox_import(request: Request):
        """On-demand 'Import now' — run one NetBox→NW import cycle."""
        # Admins only.
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Run one import cycle; failures are logged and returned as a 500.
        try:
            return await hub.run_nw_netbox_import_all()
        except Exception as e:
            logger.exception("run_nw_netbox_import failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Network scan (fingerprint discovery) ────────────────────────────────
    _SCAN_OBJECT_TYPES = ("aos_switch", "cx_switch", "ex_switch", "gateway", "ipmi")

    async def _nw_netbox_prefix_split(hub, tenant_id):
        """The tenant's NetBox IPv4 prefixes split into ``(leaf, supernets)``.
        A supernet is any prefix that CONTAINS another of the tenant's prefixes
        (e.g. a /16 carved into /24s); everything else is a leaf. Leaves are
        what a targeted scan expands; supernets are left to the background sweep."""
        # The tenant's prefixes (empty when they cannot be fetched).
        try:
            prefixes = await access.fetch_tenant_prefixes(hub, tenant_id)
        except Exception:
            prefixes = []
        return split_leaf_and_supernets(prefixes)

    def _seen_registry(tid):
        """``{ip: entry}`` of hosts seen answering for the tenant (nw_seen_hosts)."""
        # Created on first use.
        gc = hub.state.system_state.setdefault("global_config", {})
        return gc.setdefault("nw_seen_hosts", {}).setdefault(tid, {})

    async def _nw_netbox_known_ips(tid):
        """Every IP NetBox records for the tenant (or tenant group). [] when
        the tenant has no NetBox mapping or NetBox is unreachable."""
        # The tenant's NetBox scope as a request (tenant group, else tenant).
        scope = access.netbox_tenant_scope(hub, tid)
        req = ({"tenant_group": scope["tenant_group"]} if scope.get("tenant_group")
               else {"tenant": scope["tenant"]} if scope.get("tenant") else None)
        nb = access.get_netbox_spoke(hub)
        # No NetBox mapping or no NetBox spoke: nothing known.
        if not req or not nb:
            return []
        # Fetch the IPs; any failure means nothing known.
        try:
            res = access.unwrap_spoke(await hub.request_response(
                nb, "NETBOX_GET_IPS", req, timeout=60.0)) or {}
        except Exception as e:  # noqa: BLE001
            logger.warning("scan aggregate tenant=%s known NetBox IPs skipped: %s", tid, e)
            return []
        # Just the address part of each IP.
        return [str(r.get("address") or "").split("/")[0]
                for r in (res.get("ip_addresses") or []) if isinstance(r, dict)]

    async def _aggregate_scan_targets(hub, tenant_id, sources, extra_subnets,
                                      extra_targets, cap):
        """Build the candidate host-IP list for a tenant scan, in priority order
        (each tier fully included before the next; deduped, IPv4-only):

          0. known hosts (with ``netbox``): every IP NetBox records for the
          tenant plus every host the scan/sweep has seen answer
          (``nw_seen_hosts``), so each known device is re-checked every cycle,
          1. DNS records (``dns``), 2. DHCP leases (``dhcp``), 3. NAC endpoints
          (``nac``), 4. NetBox LEAF prefixes (``netbox`` — prefixes that contain
          other prefixes are supernets, left to the background sweep), 5. the
          user's explicit ``extra_targets`` / ``extra_subnets``.

        ``cap`` is the TOTAL ceiling for the list (the caller splits it into
        batches). Returns ``(targets, per_source)``; ``per_source`` counts each
        tier's contribution and ``"truncated"`` is the number of IPs dropped
        because the total ceiling was hit."""
        # The enabled sources, the ordered pool, a set for duplicate checks, per-source counts, and
        # how many were dropped at the cap.
        sources = set(sources or [])
        seen, seen_set, per_source = [], set(), {}
        dropped = 0

        def _add(ip):
            """Add one IPv4 host to the pool (counting it as dropped once the cap is reached);
            returns True if added.
            """
            nonlocal dropped
            ip = str(ip or "").split("/")[0].strip()
            if not ip or ip in seen_set:
                return False
            try:
                if not isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                    return False
            except ValueError:
                return False
            if len(seen) >= cap:
                dropped += 1
                return False
            seen_set.add(ip)
            seen.append(ip)
            return True

        async def _pull(source, spoke_getter, command, payload=None):
            """Add every IP from one source's spoke (DNS, DHCP or NAC) to the pool, if that source
            is enabled.
            """
            # Skip sources that are not enabled.
            if source not in sources:
                return
            # Ask the tenant's spoke for this source; a missing or failed spoke just skips it.
            try:
                sid = spoke_getter(tenant_id) if tenant_id else None
                if not sid or hub._primary_key(sid) not in hub.active_connections:
                    return
                result = await hub.request_response(sid, command, payload or {}, timeout=30.0)
                data = access.unwrap_spoke(result)
            except Exception as e:
                logger.warning("scan aggregate tenant=%s %s skipped: %s", tenant_id, source, e)
                return
            # Find the row list under whichever key this spoke uses.
            rows = []
            if isinstance(data, dict):
                for key in ("endpoints", "leases", "records", "data", "results"):
                    if isinstance(data.get(key), list):
                        rows = data[key]
                        break
            elif isinstance(data, list):
                rows = data
            # Add each row's IP (whichever field it is in).
            c = 0
            for r in rows:
                if not isinstance(r, dict):
                    continue
                ip = (r.get("ip") or r.get("ip_address") or r.get("ip-address")
                      or r.get("address") or r.get("value"))
                if _add(ip):
                    c += 1
            if c:
                per_source[source] = c
            logger.info("scan aggregate tenant=%s %s spoke=%s: %d rows, %d new targets%s",
                        tenant_id, source, sid, len(rows), c,
                        "" if rows else " (resp=%s)" % str(data)[:200])

        # Tier 0: known hosts from NetBox and from earlier scans.
        if "netbox" in sources and tenant_id:
            c = 0
            for ip in (await _nw_netbox_known_ips(tenant_id)) + list(_seen_registry(tenant_id)):
                c += _add(ip)
            if c:
                per_source["known"] = c
        # Tiers 1-3: DNS records, DHCP leases and NAC endpoints.
        await _pull("dns", hub.get_dns_spoke_for_tenant, "DNS_LIST")
        await _pull("dhcp", hub.get_dhcp_spoke_for_tenant, "DHCP_LIST_LEASES")
        await _pull("nac", hub.get_cppm_spoke_for_tenant, "LIST_ENDPOINTS")

        # Tier 4: every host in the tenant's NetBox leaf prefixes.
        if "netbox" in sources and tenant_id:
            leaves, _supers = await _nw_netbox_prefix_split(hub, tenant_id)
            logger.info("scan aggregate tenant=%s netbox: %d leaf prefix(es), %d supernet(s)",
                        tenant_id, len(leaves), len(_supers))
            c = 0
            for net in leaves:
                hosts = net.hosts() if net.prefixlen < 31 else iter([net.network_address])
                for host in hosts:
                    if _add(str(host)):
                        c += 1
            if c:
                per_source["netbox"] = c

        # User extras last. Pool is built with a generous bound and merged
        # through _add so the shared total ceiling and dedup apply.
        extras, extra_counts = build_scan_target_pool(extra_targets, extra_subnets, cap)
        for ip in extras:
            _add(ip)
        for k, v in extra_counts.items():
            per_source[k] = v
        # Record how many were dropped at the cap.
        if dropped:
            per_source["truncated"] = dropped
        return seen, per_source

    def _nw_scan_config(hub, tenant_id=None):
        """Effective scan config. Base = global admin ``nw_scan`` (Setup card).
        When ``tenant_id`` is given and that tenant has a per-tenant override
        (``nw_tenant_cfg[tenant]['scan']``), its keys win — so a tenant manages
        its own scan settings without clobbering the shared/global config."""
        # Start from the global config.
        gc = hub.state.system_state.get("global_config", {}) or {}
        cfg = dict(gc.get("nw_scan", {}) or {})
        # Overlay the tenant's own settings (non-null values only).
        if tenant_id:
            ov = (((gc.get("nw_tenant_cfg") or {}).get(tenant_id) or {}).get("scan") or {})
            for k, v in ov.items():
                if v is not None:
                    cfg[k] = v
        # Defaults for anything still unset.
        cfg.setdefault("enabled", False)
        cfg.setdefault("crawl", False)
        cfg.setdefault("auto_add", True)
        cfg.setdefault("credential_ids", [])
        cfg.setdefault("ip_sources", ["netbox"])
        cfg.setdefault("tcp_ports", [22, 443, 80, 23])
        cfg.setdefault("try_snmp", True)
        cfg.setdefault("use_nmap", False)
        cfg.setdefault("max_targets", 1024)
        cfg.setdefault("concurrency", 32)
        cfg.setdefault("spoke_id", "")
        return cfg

    @app.get("/setup/nw-scan-config")
    async def get_nw_scan_config(request: Request):
        """Network-scan configuration: whether the nw spoke may scan/crawl, the
        selected scan-credential set ids, IP sources, ports + bounds. Read by the
        WebUI scan card."""
        return {"nw_scan": _nw_scan_config(app.state.hub)}

    @app.post("/setup/nw-scan-config")
    async def set_nw_scan_config(request: Request):
        """Save the global network-scan config (admin or tenant admin)."""
        # Admins or tenant admins only.
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        # Read the config (wrapped in "config" or bare).
        data = await request.json()
        cfg = data.get("config", data) or {}
        # TCP ports may be a list or a comma-separated string; all must be integers.
        ports = cfg.get("tcp_ports")
        if isinstance(ports, str):
            ports = [p.strip() for p in ports.split(",") if p.strip()]
        try:
            ports = [int(p) for p in (ports or [22, 443, 80, 23])]
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="tcp_ports must be integers")
        # Normalize every field, clamping the limits.
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "crawl": bool(cfg.get("crawl", False)),
            "auto_add": bool(cfg.get("auto_add", True)),
            "try_snmp": bool(cfg.get("try_snmp", True)),
            "use_nmap": bool(cfg.get("use_nmap", False)),
            "credential_ids": [str(x) for x in (cfg.get("credential_ids") or []) if str(x).strip()],
            "ip_sources": [str(x) for x in (cfg.get("ip_sources") or ["netbox"]) if str(x).strip()],
            "tcp_ports": ports,
            "max_targets": max(1, min(int(cfg.get("max_targets") or 1024), 4096)),
            "concurrency": max(1, min(int(cfg.get("concurrency") or 32), 128)),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        # Save it.
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_scan"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_scan": clean}

    def _nw_caller_tenant(sess, req_tenant):
        """Resolve+authorize the tenant a caller may configure. Admin: the named
        tenant or the shared tenant. Tenant-admin: only one of their own tenants.
        Raises 403/400 on violation."""
        # Admins: the named tenant, else the shared tenant.
        req_tenant = str(req_tenant or "").strip()
        if _is_admin(sess):
            return req_tenant or access.shared_tenant_id() or ""
        # Others: their own tenants only.
        own = ((sess or {}).get("user", {}).get("tenants")
               or [(sess or {}).get("user", {}).get("tenant_id")])
        own = [t for t in own if t]
        if req_tenant and req_tenant not in own:
            raise HTTPException(status_code=403, detail="You may only configure your own tenant")
        # Use the requested tenant, else the first one they own.
        tid = req_tenant or (own[0] if own else "")
        if not tid:
            raise HTTPException(status_code=400, detail="No tenant resolved")
        return tid

    def _tenant_owned_scan_sets(hub, tenant_id):
        """Scan credential sets the tenant owns: stored sets in its scope plus its vault-held sets.
        """
        gc = hub.state.system_state.get("global_config", {}) or {}
        owned = access.tenant_scope_ids(tenant_id)
        sets = [c for c in (gc.get("nw_scan_credentials") or []) if isinstance(c, dict)]
        return ([c for c in sets if owned is not None and access.in_tenant_scope(c.get("tenant_id"), owned)]
                + _vault_scan_sets(hub, tenant_id))

    def _tenant_has_own_nw_spoke(hub, tenant_id):
        """True when the tenant has an nw spoke of its own."""
        return any(c.get("scope") == "own"
                   for c in nw_scan_spoke_choices(hub, tenant_id, None))

    def _nw_scan_schedule(hub, tenant_id):
        """Per-tenant recurring-scan schedule from ``nw_tenant_cfg`` with defaults.

        LM discovers and integrates automatically: a tenant with its own nw
        spoke is scheduled (every ``_NW_SCAN_DEFAULT_INTERVAL``) and adds what it
        finds unless the tenant explicitly saved otherwise. ``interval_seconds``
        0 = off; ``dry_run`` true = preview only (opt-in)."""
        # The tenant's saved schedule.
        gc = hub.state.system_state.get("global_config", {}) or {}
        sc = (((gc.get("nw_tenant_cfg") or {}).get(tenant_id) or {}).get("scan_schedule") or {})
        # Nothing saved means automatic: enabled when the tenant has its own nw spoke.
        auto = "enabled" not in sc
        enabled = _tenant_has_own_nw_spoke(hub, tenant_id) if auto else bool(sc["enabled"])
        # A saved interval wins; otherwise the default when enabled, else off.
        iv = sc.get("interval_seconds")
        interval = int(iv or 0) if iv is not None else (_NW_SCAN_DEFAULT_INTERVAL if enabled else 0)
        return {
            "enabled": enabled,
            "interval_seconds": interval,
            "dry_run": bool(sc.get("dry_run", False)),
            "auto": auto,
        }

    def _migrate_nw_scan_autodiscover(hub):
        """One-time: scans used to default to preview-only, so the stored
        ``dry_run: true`` / ``auto_add: false`` values are old defaults, not
        choices. Drop them so every tenant inherits the auto-add default."""
        # Run only once.
        gc = hub.state.system_state.get("global_config")
        if not isinstance(gc, dict) or gc.get("nw_scan_autodiscover_v1"):
            return
        # Remove the old auto_add=false default from the global config.
        changed = []
        if (gc.get("nw_scan") or {}).get("auto_add") is False:
            gc["nw_scan"].pop("auto_add", None)
            changed.append("global")
        # Remove old dry_run=true and auto_add=false defaults from each tenant's config.
        for tid, cur in (gc.get("nw_tenant_cfg") or {}).items():
            if not isinstance(cur, dict):
                continue
            if (cur.get("scan_schedule") or {}).get("dry_run") is True:
                cur["scan_schedule"].pop("dry_run", None)
                changed.append(f"{tid}:dry_run")
            if (cur.get("scan") or {}).get("auto_add") is False:
                cur["scan"].pop("auto_add", None)
                changed.append(f"{tid}:auto_add")
        # Mark the migration as done.
        gc["nw_scan_autodiscover_v1"] = True
        hub.state._mark_dirty()
        logger.info("nw scan auto-discover migration: cleared preview/auto-add-off defaults %s",
                    changed or "(none)")

    # Run the migration at startup; a failure must not stop the routes registering.
    try:
        _migrate_nw_scan_autodiscover(hub)
    except Exception as e:  # noqa: BLE001 - never block route registration
        logger.warning("nw scan auto-discover migration failed: %s", e)

    @app.get("/api/nw/tenant-config")
    async def get_nw_tenant_config(request: Request):
        """Tenant-facing NW config surface (Network → Scan tab): effective scan
        settings, poll jitter/caps/cadence, and the recurring-scan schedule for
        the caller's tenant, plus a flag per poll knob showing whether the tenant
        overrides the global admin default."""
        hub = app.state.hub
        sess = _session_user(request)
        # Admins or tenant admins only.
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        tid = _nw_caller_tenant(sess, request.query_params.get("tenant"))
        # The tenant's own poll overrides, and the effective poll settings.
        gc = hub.state.system_state.get("global_config", {}) or {}
        poll_ov = (((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("poll") or {})
        eff = access.nw_poll_cfg_for_tenant(hub, tid)
        # The tenant's effective scan, poll and schedule settings.
        return {
            "tenant_id": tid,
            "scan": _nw_scan_config(hub, tid),
            # The nw agents this tenant may scan with (own + shared) — drives the
            # Scan tab's agent picker.
            "spokes": nw_scan_spoke_choices(hub, tid, access.shared_tenant_id()),
            "poll": {
                "default_interval": eff["default_poll_interval"],
                "jitter_frac": eff["poll_jitter_frac"],
                "max_per_tick": eff["max_poll_per_tick"],
                "max_concurrency": eff["max_poll_concurrency"],
                # True where the tenant overrides the global admin default.
                "overridden": {k: (poll_ov.get(k) is not None)
                               for k in ("default_interval", "jitter_frac",
                                         "max_per_tick", "max_concurrency")},
            },
            "scan_schedule": _nw_scan_schedule(hub, tid),
        }

    @app.get("/api/nw/scan-schedules")
    async def list_nw_scan_schedules(request: Request):
        """Every recurring network scan that is already set up, across the
        tenants the caller may see (a Global Admin sees all tenants; a
        tenant-admin only their own), narrowed to ``?tenant=`` when a tenant is
        selected. Answers "what scans are scheduled?"
        without having to switch tenant context and read one card at a time.

        Each row carries the schedule (enabled / interval / dry-run), a summary
        of the scan it will run (agent, credential sets, IP sources, auto-add),
        and the loop's runtime view (last run, next due, last outcome).

        The runtime fields are IN-MEMORY on the hub: a restart clears them and
        every schedule re-defers one full interval (anti-stampede), so a null
        ``last_run_at`` means "not since this hub started", not "never"."""
        hub = app.state.hub
        sess = _session_user(request)
        # Admins or tenant admins only.
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        # Admins see every tenant; tenant admins only their own.
        all_t = (getattr(hub.state, "tenant_state", {}) or {}).get("tenants", {}) or {}
        if _is_admin(sess):
            ids = list(all_t.keys())
        else:
            ids = [t for t in ((sess or {}).get("user", {}).get("tenants") or []) if t]
        # Narrow to the selected tenant, if any.
        selected = str(request.query_params.get("tenant") or "").strip()
        if selected:
            ids = [t for t in ids if t == selected]
        # Runtime status kept by the hub, and credential sets by id (for names).
        runtime = getattr(hub, "nw_scan_runtime", {}) or {}
        gc = hub.state.system_state.get("global_config", {}) or {}
        all_sets = gc.get("nw_scan_credentials", []) or []
        by_id = {c.get("id"): c for c in all_sets if isinstance(c, dict)}
        rows = []
        # One row per tenant: its schedule, scan summary and runtime status.
        for tid in ids:
            sched = _nw_scan_schedule(hub, tid)
            cfg = _nw_scan_config(hub, tid)
            cred_ids = [str(x) for x in (cfg.get("credential_ids") or [])]
            spoke_id = str(cfg.get("spoke_id") or "").strip()
            rt = runtime.get(tid) or {}
            rows.append({
                "tenant_id": tid,
                "tenant_name": (all_t.get(tid, {}) or {}).get("name") or tid,
                "enabled": bool(sched.get("enabled")),
                "interval_seconds": int(sched.get("interval_seconds") or 0),
                "dry_run": bool(sched.get("dry_run", False)),
                "auto_add": bool(cfg.get("auto_add", True)),
                "ip_sources": list(cfg.get("ip_sources") or []),
                "max_targets": int(cfg.get("max_targets") or 0),
                "spoke_id": spoke_id,
                "spoke_connected": bool(
                    spoke_id and hub._primary_key(spoke_id) in hub.active_connections),
                "credential_names": [
                    (by_id.get(cid, {}) or {}).get("name") or cid for cid in cred_ids],
                # No set selected and none owned → the scheduled run is a
                # discovery-only pass (reachability + open ports, no auto-add).
                "discovery_only": not cred_ids and not _tenant_owned_scan_sets(hub, tid),
                "last_run_at": rt.get("last_run_at"),
                "next_due_at": rt.get("next_due_at"),
                "last_status": rt.get("last_status"),
                "last_added": int(rt.get("last_added") or 0),
                "last_identified": int(rt.get("last_identified") or 0),
                "last_error": rt.get("last_error") or "",
            })
        # Enabled schedules first, then by tenant name.
        rows.sort(key=lambda r: (not r["enabled"], r["tenant_name"].lower()))
        return {"schedules": rows,
                "runtime_since_restart": bool(runtime),
                "configured": sum(1 for r in rows if r["enabled"])}

    @app.post("/api/nw/tenant-config")
    async def set_nw_tenant_config(request: Request):
        """Persist a tenant's NW overrides. Body: ``tenant`` (admin only),
        ``scan`` (partial scan config), ``poll`` (jitter/caps/cadence; null a key
        to clear the override → inherit global), ``scan_schedule``. Re-pushes the
        tenant's connected nw spoke(s) so poll changes take effect immediately."""
        hub = app.state.hub
        sess = _session_user(request)
        # Admins or tenant admins only.
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        # Read the body and resolve the tenant being configured.
        data = await request.json()
        tid = _nw_caller_tenant(sess, data.get("tenant"))

        # Copy the tenant's stored config so it is replaced as a whole.
        gc = hub.state.system_state.get("global_config", {})
        tmap = dict(gc.get("nw_tenant_cfg") or {})
        cur = dict(tmap.get(tid) or {})

        # ── scan (partial merge over the existing tenant scan override) ──
        if isinstance(data.get("scan"), dict):
            # Copy the tenant's scan override and apply each field that was sent.
            s = data["scan"]
            scan_ov = dict(cur.get("scan") or {})
            for k in ("enabled", "crawl", "auto_add", "try_snmp"):
                if k in s:
                    scan_ov[k] = bool(s[k])
            # Lists are stored as trimmed strings.
            if "ip_sources" in s:
                scan_ov["ip_sources"] = [str(x) for x in (s["ip_sources"] or []) if str(x).strip()]
            if "credential_ids" in s:
                scan_ov["credential_ids"] = [str(x) for x in (s["credential_ids"] or []) if str(x).strip()]
            if "subnets" in s:
                # Subnets may be a list or a string; each must be a valid network.
                subs = s["subnets"]
                if isinstance(subs, str):
                    subs = subs.replace(",", " ").split()
                clean_subs = []
                for sub in (subs or []):
                    try:
                        clean_subs.append(str(ipaddress.ip_network(str(sub).strip(), strict=False)))
                    except ValueError:
                        raise HTTPException(status_code=400, detail=f"invalid subnet: {sub}")
                scan_ov["subnets"] = clean_subs
            if "tcp_ports" in s:
                # TCP ports may be a list or a comma-separated string; all must be integers.
                ports = s["tcp_ports"]
                if isinstance(ports, str):
                    ports = [p.strip() for p in ports.split(",") if p.strip()]
                try:
                    scan_ov["tcp_ports"] = [int(p) for p in (ports or [])]
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="tcp_ports must be integers")
            # Limits are clamped.
            if "max_targets" in s:
                scan_ov["max_targets"] = max(1, min(int(s["max_targets"] or 1024), 4096))
            if "concurrency" in s:
                scan_ov["concurrency"] = max(1, min(int(s["concurrency"] or 32), 128))
            if "spoke_id" in s:
                scan_ov["spoke_id"] = str(s["spoke_id"] or "").strip()
            cur["scan"] = scan_ov

        # ── poll (null a key → clear override so it inherits the global) ──
        if isinstance(data.get("poll"), dict):
            # Copy the tenant's poll override.
            p = data["poll"]
            poll_ov = dict(cur.get("poll") or {})

            def _num_or_clear(key, cast, lo, hi):
                """Set (clamped) or clear one numeric poll override from the request."""
                # Not in the request: leave it alone.
                if key not in p:
                    return
                # Null or blank clears the override.
                v = p[key]
                if v in (None, "", "null"):
                    poll_ov.pop(key, None)
                    return
                try:
                    poll_ov[key] = max(lo, min(cast(v), hi))
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail=f"{key} must be numeric or null")

            # Apply each poll setting.
            _num_or_clear("default_interval", int, 0, 604800)
            _num_or_clear("jitter_frac", float, 0.0, 0.9)
            _num_or_clear("max_per_tick", int, 1, 100)
            _num_or_clear("max_concurrency", int, 1, 50)
            cur["poll"] = poll_ov

        # ── scan_schedule ──
        if isinstance(data.get("scan_schedule"), dict):
            # Copy the tenant's schedule and apply each field that was sent.
            ss = data["scan_schedule"]
            sched = dict(cur.get("scan_schedule") or {})
            if "enabled" in ss:
                sched["enabled"] = bool(ss["enabled"])
            if "interval_seconds" in ss:
                try:
                    iv = int(ss["interval_seconds"] or 0)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="interval_seconds must be an integer")
                # 0 = off; otherwise floor at 1h so a tenant can't hammer scans.
                sched["interval_seconds"] = 0 if iv <= 0 else max(3600, iv)
            if "dry_run" in ss:
                sched["dry_run"] = bool(ss["dry_run"])
            cur["scan_schedule"] = sched

        # Save the tenant's config.
        tmap[tid] = cur
        gc["nw_tenant_cfg"] = tmap
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

        # Re-push this tenant's connected nw spoke(s) so poll knobs apply now.
        pushed = 0
        md = hub.state.system_state.get("module_metadata", {}) or {}
        for sid in (hub.get_all_spokes_by_type("nw") or []):
            if (md.get(sid, {}) or {}).get("tenant_id") == tid:
                if await _nw_push_fleet(hub, sid):
                    pushed += 1
        # Report the effective settings and how many spokes were updated.
        return {"status": "ok", "tenant_id": tid, "pushed": pushed,
                "scan": _nw_scan_config(hub, tid),
                "scan_schedule": _nw_scan_schedule(hub, tid)}

    async def _execute_nw_scan(tenant_id, saved, *, sess, data):
        """Shared scan executor for BOTH the interactive route and the recurring
        scheduler. ``sess`` is the caller session for an interactive scan, or
        ``None`` for a system-initiated (scheduled) scan. Resolves the spoke,
        assembles + vault-overlays the credential sets, aggregates the tenant's
        candidate IPs, runs NW_SCAN on the spoke, then (unless dry-run) auto-adds
        the newly-identified manageable devices to the tenant fleet and re-pushes.

        Credential scoping: the chosen sets are always narrowed to ones owned by
        the scanned tenant (or the shared tenant), for every caller including a
        full admin — a scan runs with THAT tenant's vault credentials, never
        another tenant's. A tenant-admin is additionally limited to sets visible
        to their session."""
        # A scheduled (system) scan has no session.
        system = sess is None
        # The spoke to scan with: requested, else saved, limited to the tenant's own or shared
        # spokes.
        spoke_id = resolve_nw_scan_spoke(
            hub, tenant_id,
            str(data.get("spoke_id") or saved.get("spoke_id") or "").strip(),
            access.shared_tenant_id())
        # None available: a scheduled scan is skipped, an interactive one gets a 503.
        if not spoke_id:
            if system:
                return {"status": "skipped", "reason": "no nw spoke connected",
                        "tenant": tenant_id, "added": [], "identified": []}
            raise HTTPException(
                status_code=503,
                detail="No connected Network Devices agent for this tenant. "
                       "Deploy the nw module in this tenant, or pick the shared "
                       "agent, then retry.")

        # Assemble the candidate credential sets (from the request or saved
        # config), overlaying each set's vault secret just before the push.
        cred_ids = [str(x) for x in (data.get("credential_ids") or saved.get("credential_ids") or [])]
        all_sets = (hub.state.system_state.get("global_config", {}) or {}).get("nw_scan_credentials", []) or []
        all_sets = list(all_sets) + _vault_scan_sets(hub, tenant_id)
        # No sets picked → try every set the tenant owns (scoped below), so a
        # new tenant's scans identify + add devices without manual setup.
        use_all = not cred_ids
        chosen = [c for c in all_sets if isinstance(c, dict)
                  and (use_all or c.get("id") in set(cred_ids))]
        # Tenant-owned (or shared) credentials only — for every caller. On the
        # ADMIN (``default``) scope the admin's OWN sets are the unassigned /
        # ``default``-tagged ones, matching what the scan tab lists for default,
        # so a set the admin can see is a set the admin can actually scan with.
        owned = access.tenant_scope_ids(tenant_id)
        if owned is None:
            # A blank/None tenant_id (reachable here — the scheduler can pass
            # one, and admins resolve to "" when no shared tenant is set) must
            # still be scoped. tenant_scope_ids(None-ish) returns None, and
            # in_tenant_scope treats a None scope as UNRESTRICTED — that would
            # let a blank-tenant scan pick up every tenant's vault credentials,
            # exactly the leak this scoping exists to prevent. Fall back to the
            # ADMIN scope (unassigned + default-tagged + shared) instead.
            owned = access.tenant_scope_ids(access.ADMIN_TENANT_ID)
        # Keep only sets in that scope; tenant admins are also limited to sets they can see.
        chosen = [c for c in chosen if access.in_tenant_scope(c.get("tenant_id"), owned)]
        if not system and not _is_admin(sess):
            chosen = [c for c in chosen
                      if access.spoke_visible_to_session(sess, c.get("tenant_id", ""))]
        # The vault's SNMP communities ride along with every scan, so devices that
        # take no SSH login (e.g. a TOR switch) are still identified over SNMP and
        # the winning community is recorded.
        if saved.get("try_snmp", True):
            from routes.monitoring import vault_snmp_scan_sets
            have = {c.get("id") for c in chosen}
            chosen = chosen + [c for c in vault_snmp_scan_sets(hub, tenant_id)
                               if c["id"] not in have]
        if not chosen:
            # Credentials are OPTIONAL. With none selected the scan still runs
            # as a DISCOVERY-ONLY pass: every candidate IP is TCP-probed for
            # reachability + open management ports, so "what is on this subnet?"
            # is answerable without first creating a device account. Identify
            # (SSH/SNMP) is skipped, and because auto-add only ever fires for a
            # target classified into a manageable object_type, a credential-free
            # scan cannot mutate the fleet — it is preview-only by construction.
            logger.info("nw scan tenant=%s: no scan credentials — discovery-only pass",
                        tenant_id)
        # Fill in each set's secrets from the vault and shape them for the spoke.
        overlaid = await instance_vault.overlay_many(hub, chosen, "nw_scan_credentials")
        push_creds = [{
            "id": c.get("id"), "name": c.get("name") or c.get("id"),
            "username": c.get("username") or c.get("user") or "",
            "password": c.get("password") or "",
            "enable_secret": c.get("enable_secret") or "",
            "snmp_community": c.get("snmp_community") or "",
        } for c in overlaid]

        # Which IP sources to collect targets from.
        ip_sources = data.get("ip_sources") or saved.get("ip_sources") or ["netbox"]
        # ``max_targets`` is the per-request BATCH size: a longer target list is
        # split into batches (run a few in parallel) rather than truncated. Only
        # the absolute ceiling below truncates.
        cap = max(1, min(int(data.get("max_targets") or saved.get("max_targets") or 1024), 4096))
        # Collect the candidate targets from every source.
        targets, per_source = await _aggregate_scan_targets(
            hub, tenant_id, ip_sources,
            data.get("subnets") or saved.get("subnets") or [],
            data.get("targets") or [], _NW_SCAN_MAX_TOTAL)
        # Shared DNS/DHCP/NAC spokes list every tenant's addresses; never probe
        # (or adopt) an address NetBox assigns to another tenant — unless the
        # scan runs on the tenant's own agent, which only reaches its own VRF
        # (the same IP can exist in several tenants' VRFs).
        scan_owner = access.spoke_owner_tenant(hub, spoke_id)
        own_agent = bool(scan_owner) and access.tenant_in(scan_owner, tenant_id)
        foreign = set() if own_agent else await access.foreign_tenant_ips(hub, tenant_id, targets)
        if foreign:
            targets = [t for t in targets if t not in foreign]
            per_source["other_tenant"] = len(foreign)
        # Log the targets and sources for troubleshooting.
        logger.info("nw scan tenant=%s targets=%d sources=%s creds=%d cred_ids=%s",
                    tenant_id, len(targets), per_source, len(chosen),
                    [c.get("id") for c in chosen])
        logger.info("nw scan tenant=%s candidate targets (%d): %s", tenant_id, len(targets),
                    " ".join(sorted(str(t) for t in targets)))
        # No candidates: report that and stop.
        if not targets:
            return {"status": "ok", "message": "No candidate IPs found for this tenant "
                    "(no DNS/DHCP/NAC rows and no NetBox prefixes tagged to it). Add "
                    "subnets or targets under Network Scan.",
                    "tenant": tenant_id, "targets": 0, "sources": per_source,
                    "identified": [], "added": []}

        # Credential-free (discovery-only) scans: nmap service detection is the
        # only classifier left once SSH/SNMP identify is off the table, so
        # default it ON for that case. A per-request ``use_nmap`` always wins,
        # and the spoke's nmap augment silently no-ops when nmap isn't
        # installed, so this can never fail a scan.
        req_nmap = data.get("use_nmap")
        if req_nmap is not None:
            use_nmap = bool(req_nmap)
        elif not push_creds:
            use_nmap = True
        else:
            use_nmap = bool(saved.get("use_nmap", False))

        # Scan options sent to the spoke.
        options = {
            "tcp_ports": saved.get("tcp_ports") or [22, 443, 80, 23],
            "try_snmp": bool(saved.get("try_snmp", True)),
            "use_nmap": use_nmap,
            "concurrency": int(saved.get("concurrency") or 32),
            "crawl": bool(data.get("crawl", saved.get("crawl", False))),
            "max_targets": cap,
            "max_depth": int(data.get("max_depth") or 2),
        }
        # Ping every target too: a host that only answers ping is still a
        # device (NetBox + Zabbix), and a missed reply is what ages it out.
        alive = await _nw_ping_all(spoke_id, targets)
        # Split the targets into batches, a few running at once.
        batches = [targets[i:i + cap] for i in range(0, len(targets), cap)]
        sem = asyncio.Semaphore(_NW_SCAN_PARALLEL_BATCHES)

        async def _run_batch(batch):
            """Send one batch to the spoke (limited by the semaphore) and return its unwrapped
            result.
            """
            async with sem:
                result = await hub.request_response(
                    spoke_id, "NW_SCAN",
                    {"targets": batch, "credentials": push_creds, "options": options,
                     "tenant": tenant_id},
                    timeout=max(60.0, min(len(batch) * 2.0, 900.0)))
                return access.unwrap_spoke(result)

        # Run every batch; failed batches come back as exceptions.
        outcomes = await asyncio.gather(*(_run_batch(b) for b in batches),
                                        return_exceptions=True)
        failed = [o for o in outcomes if isinstance(o, BaseException)]
        # Every batch failed: a scheduled scan reports an error, an interactive one gets a 500.
        if len(failed) == len(outcomes):
            e = failed[0]
            logger.error("nw scan failed (tenant=%s): %s", tenant_id, e)
            if system:
                return {"status": "error", "reason": str(e), "tenant": tenant_id,
                        "added": [], "identified": []}
            raise HTTPException(status_code=500, detail=f"scan failed: {e}")
        # Some batches failed: log it and keep the rest.
        if failed:
            logger.warning("nw scan tenant=%s: %d of %d batch(es) failed: %s",
                           tenant_id, len(failed), len(outcomes), failed[0])
            per_source["failed_batches"] = len(failed)
        # Successful batch results.
        scans = [o for o in outcomes if isinstance(o, dict)]
        # Addresses that answered a probe, plus every address already in the fleet.
        answered = {str(d.get("address") or "").strip() for o in scans
                    for d in (o.get("reachable") or []) + (o.get("identified") or [])}
        answered |= {str(a or "").strip()
                     for d in (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices") or []
                     if isinstance(d, dict) for a in [d.get("address")] + list(d.get("alt_addresses") or [])}
        # Hosts that answered ping but nothing else.
        quiet = [ip for ip in targets if ip in alive and ip not in answered]
        # Results of probing those ping-only hosts.
        pinged = {}
        if quiet:
            # Answered ping but no management port: try SNMP + the profile
            # probe, least-known hosts first.
            reg = _seen_registry(tenant_id)
            quiet.sort(key=lambda ip: bool((reg.get(ip) or {}).get("hostname")
                                           or (reg.get(ip) or {}).get("profile")))
            try:
                # Recorded as sightings only: never auto-added or monitored as SNMP.
                pinged = await _nw_probe_pinged(tenant_id, spoke_id, quiet[:_NW_PINGED_PROBE_MAX],
                                                bool(saved.get("try_snmp", True)))
            except Exception as e:  # noqa: BLE001
                logger.warning("nw scan tenant=%s ping-only probe failed: %s", tenant_id, e)
        # Every identified device across all batches.
        identified = [d for o in scans for d in (o.get("identified") or [])]
        # Hosts that answered a TCP probe but were not classified into a device
        # family. Always reported now — on a discovery-only (credential-free)
        # scan this IS the result, and even on a credentialed scan it is the
        # actionable "something is here that I can't manage yet" list.
        # The spoke's ``reachable`` list includes identified hosts too; keep only
        # the unclassified ones so they aren't logged/handled as UNIDENTIFIED.
        reachable = [d for o in scans for d in (o.get("reachable") or [])
                     if not d.get("object_type")]
        # Total hosts scanned.
        scan = {"scanned": sum(int(o.get("scanned") or 0) for o in scans)}

        # The current fleet.
        gc = hub.state.system_state.get("global_config", {})
        devices = gc.get("nw_devices", []) or []
        # A device recorded under another tenant whose agent has since moved
        # (or been deleted) is relocated to this tenant when this scan verifies
        # it: same IP + hostname, or the same agent at the same IP. Explicit
        # preview scans only report it; a credential-free pass still moves it
        # (the record already carries working credentials).
        preview_only = bool(data.get("dry_run", False)) or not bool(
            data.get("auto_add", saved.get("auto_add", True)))
        # Moved devices, previews of moves, and the spokes they moved from.
        moved, move_preview, from_spokes = [], [], set()
        _scan_creds = {c.get("id"): c for c in chosen}
        _finder = getattr(hub, "nw_find_relocation", None)
        # Check each identified device for a record under another tenant that should move here.
        for dev in (identified if callable(_finder) else []):
            hit = _finder(devices, tenant_id, spoke_id, dev.get("address"),
                                         dev.get("hostname"), str(dev.get("object_type") or ""))
            if not hit:
                continue
            # Preview scans only report the move.
            d, evidence = hit
            if preview_only:
                move_preview.append({"id": d.get("id"), "name": d.get("name"),
                                     "address": d.get("address"), "from_tenant": d.get("tenant_id"),
                                     "to_tenant": tenant_id, "evidence": evidence})
                continue
            # Move the record to this tenant and this spoke.
            from_spokes.add(str(d.get("spoke_id") or ""))
            moved.append(hub.nw_relocate_device(d, tenant_id, spoke_id, evidence,
                                                _scan_creds.get(dev.get("credential_id"))))
        # Every address of the moved devices.
        moved_addrs = {str(a or "").strip() for m in moved for d in devices
                       if isinstance(d, dict) and d.get("id") == m["id"]
                       for a in [d.get("address")] + list(d.get("alt_addresses") or [])}
        if moved or move_preview:
            logger.info("nw scan tenant=%s relocated from other tenants: %s%s", tenant_id,
                        [(m["name"], m["address"], m["from_tenant"], "+".join(m["evidence"])) for m in moved],
                        f" (preview: {len(move_preview)})" if move_preview else "")
        # LLDP crawling can reach past the targets: never add an address NetBox
        # assigns to another tenant (a just-relocated device is still recorded
        # there until its next NetBox push).
        foreign = set() if own_agent else await access.foreign_tenant_ips(hub, tenant_id, {
            str(d.get("address") or "").strip() for d in identified + reachable}) - moved_addrs
        identified = [d for d in identified if str(d.get("address") or "").strip() not in foreign]
        reachable = [d for d in reachable if str(d.get("address") or "").strip() not in foreign]

        # Existing addresses for this tenant (dedup) — an identified device that
        # is already in the fleet (own or shared) is reported but not re-added.
        mine = [d for d in devices if isinstance(d, dict)
                and d.get("tenant_id", "") in (tenant_id, access.shared_tenant_id())]
        known = {str(a or "").strip() for d in mine
                 for a in [d.get("address")] + list(d.get("alt_addresses") or [])}
        # A switch answers on every SVI: an identified host whose hostname and
        # type match a tenant device is that box at another address, not a new
        # device (same name rule as nw_hardware_primaries).
        by_name = {(str(d.get("object_type") or ""), nw_short_name(d.get("name"))): d
                   for d in mine if nw_short_name(d.get("name"))}
        # Whether any alternate address was recorded, and credential sets by id.
        alt_added = False
        by_cred = {c.get("id"): c for c in chosen}

        dry_run = bool(data.get("dry_run", False)) or not bool(
            data.get("auto_add", saved.get("auto_add", True)))
        # A credential-free pass is preview-only, as documented. Scan credentials
        # are optional now, and the spoke turns nmap service detection on when
        # none are supplied — nmap CAN classify a host into a manageable
        # object_type, so without this gate an auto-add scan would write fleet
        # entries with an empty username and no vault_credential behind them:
        # devices the fleet can never actually manage.
        discovery_only = not push_creds
        dry_run = dry_run or discovery_only
        # Devices added, and devices that would be added in a preview.
        added, preview = [], []
        logger.info("nw scan tenant=%s result: scanned=%s identified=%d reachable-unidentified=%d dry_run=%s",
                    tenant_id, scan["scanned"], len(identified), len(reachable), dry_run)
        # Log each reachable host that could not be identified.
        for dev in reachable:
            logger.debug("nw scan tenant=%s UNIDENTIFIED %s ports=%s detail=%s", tenant_id,
                        dev.get("address"), dev.get("open_ports") or dev.get("ports"),
                        {k: dev.get(k) for k in ("reason", "error", "banner", "ssh_error") if dev.get(k)})
        # Decide what to do with each identified device.
        for dev in identified:
            # Skip addresses already in the fleet.
            addr = str(dev.get("address", "")).strip()
            if not addr or addr in known:
                logger.info("nw scan tenant=%s SKIP %s (%s): already in fleet", tenant_id, addr,
                            dev.get("hostname"))
                continue
            # Same hostname and type as an existing device: record it as another address of that
            # device.
            same = by_name.get((str(dev.get("object_type") or ""), nw_short_name(dev.get("hostname"))))
            if same is not None:
                logger.info("nw scan tenant=%s SKIP %s (%s): another address of %s",
                            tenant_id, addr, dev.get("hostname"), same.get("id"))
                known.add(addr)
                if not dry_run:
                    same["alt_addresses"] = sorted(set(same.get("alt_addresses") or []) | {addr})
                    alt_added = True
                continue
            # The credential set that worked (else the first chosen one), and a summary of the
            # device.
            cred_set = by_cred.get(dev.get("credential_id")) or (chosen[0] if chosen else {})
            entry = {
                "name": dev.get("hostname") or addr,
                "object_type": dev.get("object_type"),
                "address": addr,
                "os": dev.get("os", ""),
                "method": dev.get("method"),
                "credential_id": dev.get("credential_id"),
            }
            # Only manageable device types are added.
            if dev.get("object_type") not in _SCAN_OBJECT_TYPES:
                logger.info("nw scan tenant=%s SKIP %s (%s): object_type %r not auto-addable",
                            tenant_id, addr, dev.get("hostname"), dev.get("object_type"))
                continue
            # Preview: report it without adding.
            if dry_run:
                preview.append(entry)
                continue
            # Auto-add: build a fleet device that reuses the winning credential
            # set's vault reference (so future pushes overlay the same secret).
            new_dev = {
                "id": str(uuid.uuid4()),
                "name": entry["name"],
                "object_type": entry["object_type"],
                "address": addr,
                # Keep the transport the scan actually authenticated over; "auto"
                # would resolve a gateway to REST and every poll would time out.
                "transport": (dev.get("method") if dev.get("method") in ("ssh", "snmp") else "auto"),
                "username": cred_set.get("username") or cred_set.get("user") or "",
                "tenant_id": tenant_id,
                "spoke_id": spoke_id,
                "source": "scanned",
            }
            # Link the credential set's vault entry.
            ref = cred_set.get("vault_credential")
            if ref:
                new_dev["vault_credential"] = ref
            # Add it to the fleet.
            devices.append(new_dev)
            known.add(addr)
            added.append(new_dev)

        # Save any new devices or addresses and push the fleet to the spoke.
        if added or alt_added:
            gc["nw_devices"] = devices
            hub.state.system_state["global_config"] = gc
            hub.state._mark_dirty()
            await _nw_push_fleet(hub, spoke_id)
        # Moved devices: save, push to this spoke, and push to each spoke they left so it drops
        # them.
        if moved:
            hub.state._mark_dirty()
            if not (added or alt_added):
                await _nw_push_fleet(hub, spoke_id)
            for old_sid in from_spokes - {spoke_id, ""}:
                try:
                    await _nw_push_fleet(hub, old_sid)
                except Exception as e:  # noqa: BLE001
                    logger.warning("nw scan: re-push to former agent %s failed: %s", old_sid, e)

        # Hosts that answered SNMP but aren't an auto-addable platform (e.g. TOR
        # switches) are still monitorable: hand them to the monitoring sync.
        snmp_only = [d for d in reachable if d.get("snmp_ok") and d.get("snmp_credential_id")
                     and str(d.get("address") or "").strip() not in known]
        if snmp_only:
            # This tenant's monitor-only hosts by address; add or update each SNMP host.
            mine = {str(n.get("address")): n for n in (gc.get("nw_monitor_neighbors") or [])
                    if isinstance(n, dict) and n.get("tenant_id") == tenant_id}
            for d in snmp_only:
                addr = str(d["address"]).strip()
                mine[addr] = {"tenant_id": tenant_id, "name": d.get("hostname") or addr,
                              "address": addr, "type": "switch", "snmp_ok": True,
                              "snmp_secret": d["snmp_credential_id"]}
            # Replace this tenant's entries with the updated set.
            gc["nw_monitor_neighbors"] = [n for n in (gc.get("nw_monitor_neighbors") or [])
                                          if not (isinstance(n, dict) and n.get("tenant_id") == tenant_id)
                                          ] + list(mine.values())
            hub.state.system_state["global_config"] = gc
            hub.state._mark_dirty()
            logger.info("nw scan tenant=%s monitor-only SNMP hosts: %s", tenant_id,
                        [(d["address"], d.get("hostname")) for d in snmp_only])

        # Record every host that answered (not for preview scans).
        if not data.get("dry_run"):
            await _nw_note_responders(
                tenant_id, identified + reachable + (pinged.get("reachable") or [])
                + (pinged.get("identified") or []) + [{"address": ip} for ip in sorted(alive)],
                known)

        # Also backfill any device on THIS spoke that was auto-added by a scan
        # before the hostname never got read (display name still == its raw
        # address — the "source" discovery devices never named because the
        # discovery-poll hook above didn't exist yet, or a poll never landed
        # before the spoke/hub restarted and reset the in-memory scheduler).
        # Folding these into the same best-effort poll on every scan heals
        # them without waiting on the autonomous per-device cadence (3-9h,
        # reset by any spoke reconnect) or a manual "Poll Now".
        stale_ids = [d["id"] for d in devices
                     if isinstance(d, dict) and d.get("spoke_id") == spoke_id
                     and d.get("id") and d.get("id") not in {a["id"] for a in added}
                     and str(d.get("name") or "").strip()
                     == str(d.get("address") or "").strip()]
        # Poll the added, moved and unnamed devices in the background.
        poll_ids = list(dict.fromkeys([d["id"] for d in added] + [m["id"] for m in moved] + stale_ids))
        if poll_ids:
            _nw_spawn_refresh(f"discovery-poll:{poll_ids[0]}",
                              lambda: _nw_poll_discovered(hub, poll_ids))

        # The full scan result.
        return {
            "status": "ok",
            "tenant": tenant_id,
            "spoke_id": spoke_id,
            "targets": len(targets),
            "sources": per_source,
            "scanned": scan["scanned"],
            "batches": len(batches),
            "identified": identified,
            "reachable": reachable,
            "discovery_only": discovery_only,
            "dry_run": dry_run,
            "preview": preview,
            "added": added,
            "moved": moved,
            "move_preview": move_preview,
        }

    async def _run_nw_scheduled_scan(tenant_id, targets=None, dry_run=None):
        """System-initiated recurring scan for one tenant (called by the hub's
        run_nw_scan_schedule_loop). Uses the tenant's saved scan config +
        schedule; ``dry_run`` honors the schedule's preview flag (else the scan
        config's auto_add). Admin ops may pass explicit ``targets`` (scanned
        instead of the tenant's IP sources) and override ``dry_run``."""
        # The tenant's saved scan config and schedule.
        saved = _nw_scan_config(hub, tenant_id)
        sched = _nw_scan_schedule(hub, tenant_id)
        # Preview or add, per the schedule (or the caller's override).
        data = {"dry_run": bool(sched.get("dry_run", False)) if dry_run is None else bool(dry_run),
                "auto_add": bool(saved.get("auto_add", True))}
        # Explicit targets replace the tenant's IP sources.
        if targets:
            data["targets"] = list(targets)
            data["ip_sources"] = ["explicit"]  # no aggregated sources, targets only
        return await _execute_nw_scan(tenant_id, saved, sess=None, data=data)

    # Expose the system scan executor + schedule reader to the hub so the
    # background run_nw_scan_schedule_loop (a mixin method) can drive scans
    # without re-implementing the credential/target/add pipeline.
    # ── Tier 2: background supernet sweep ────────────────────────────────────
    # Opt-in per tenant, two passes per tick:
    #  1. Gateway pass: ping .1/.254 of every /24 in the tenant's supernets that
    #     has no NetBox prefix; each /24 that answers is added to NetBox so the
    #     scheduled scan covers it. Reruns weekly.
    #  2. Host sweep (once the gateway pass is done): walks the rest of the
    #     supernets MINUS anything the targeted scan already covers (DNS, DHCP,
    #     NAC, child prefixes, user extras, fleet devices), pings a batch per
    #     tick and probes only hosts that answer (_NW_SWEEP_PORTS + SNMP).
    #     Report-only: it never adds devices and never blocks a scheduled scan.
    def _sweep_enabled(hub, tid):
        """True when the tenant has turned on the background supernet sweep."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        return bool((((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("sweep") or {}).get("enabled", False))

    def _sweep_state(hub, tid):
        """The tenant's stored sweep progress, created with defaults on first use."""
        gc = hub.state.system_state.setdefault("global_config", {})
        return gc.setdefault("nw_sweep", {}).setdefault(tid, {
            "cursor": 0, "total": 0, "cycles": 0, "scanned": 0, "discovered": [],
            "last_run_at": None, "last_status": None, "last_error": ""})

    async def _nw_sweep_step(tid, *, force=False):
        """Probe the next batch of the tenant's sweep space. Returns the sweep
        state dict (or ``{"status": ...}`` when skipped)."""
        # Skip when the sweep is off (unless forced).
        if not force and not _sweep_enabled(hub, tid):
            return {"status": "disabled"}
        # The spoke to sweep with; none means skip.
        saved = _nw_scan_config(hub, tid)
        spoke_id = resolve_nw_scan_spoke(
            hub, tid, str(saved.get("spoke_id") or "").strip(), access.shared_tenant_id())
        if not spoke_id:
            return {"status": "skipped", "reason": "no nw spoke connected"}
        # Run the gateway pass first; it does one batch per tick until finished.
        gw = await _nw_gateway_sweep_step(tid, spoke_id)
        if gw.get("status") == "ok":
            return gw  # one batch per tick: finish the gateway pass first
        # The sweep progress, and the tenant's prefixes split into leaves and supernets.
        st = _sweep_state(hub, tid)
        leaves, supers = await _nw_netbox_prefix_split(hub, tid)
        # The directed (6h) scan already covers its leaf prefixes and the
        # tenant's saved scan subnets: never sweep those again.
        for sub in saved.get("subnets") or []:
            try:
                leaves.append(ipaddress.ip_network(str(sub).strip(), strict=False))
            except ValueError:
                pass
        # Integer host ranges to sweep: the supernets minus the leaves.
        ranges = sweep_ranges(supers, [n for n in leaves if n.version == 4])
        if not ranges:
            st.update(total=0, cursor=0, last_status="no-supernets", last_run_at=time.time())
            hub.state._mark_dirty()
            return {"status": "no-supernets"}
        # Addresses the targeted scan already covers, plus seen hosts and fleet devices, are
        # skipped.
        covered, _ps = await _aggregate_scan_targets(
            hub, tid, ["dns", "dhcp", "nac"], saved.get("subnets") or [], [], _NW_SCAN_MAX_TOTAL)
        gc = hub.state.system_state.get("global_config", {}) or {}
        covered = set(covered) | set(_seen_registry(tid)) | {
            str((d or {}).get("address", "")).strip()
            for d in (gc.get("nw_devices") or []) if isinstance(d, dict)}
        # The next batch to probe, and the new cursor.
        batch, cursor, total = sweep_take(ranges, st.get("cursor") or 0,
                                          _NW_SWEEP_BATCH, skip=frozenset(covered))
        # Probe options for the sweep.
        options = {"tcp_ports": list(_NW_SWEEP_PORTS), "try_snmp": True, "use_nmap": False,
                   "concurrency": 32, "crawl": False, "max_targets": _NW_SWEEP_BATCH,
                   "max_depth": 1}
        try:
            # Ping first; only hosts that answer get the port + SNMP probe. A
            # spoke without NW_PING_SWEEP (older version) probes the whole batch.
            alive = await _nw_ping(spoke_id, batch) if batch else []
            targets = batch if alive is None else alive
            options["pinged"] = alive is not None
            res = access.unwrap_spoke(await hub.request_response(
                spoke_id, "NW_SCAN",
                {"targets": targets, "credentials": await _nw_snmp_creds(tid),
                 "options": options, "tenant": tid},
                timeout=600.0)) if targets else {}
        # A failed batch is recorded and reported.
        except Exception as e:
            st.update(last_status="error", last_error=str(e), last_run_at=time.time())
            hub.state._mark_dirty()
            logger.warning("nw sweep tenant=%s batch failed: %s", tid, e)
            return {"status": "error", "reason": str(e)}
        # Merge what answered into the discovered list, keyed by address.
        now = time.time()
        found = {str(d.get("address")): d for d in (st.get("discovered") or []) if isinstance(d, dict)}
        for r in ((res or {}).get("reachable") or []) + ((res or {}).get("identified") or []):
            ip = str((r or {}).get("address") or "").strip()
            if not ip:
                continue
            prev = found.get(ip) or {"address": ip, "first_seen": now}
            prev.update(last_seen=now, open_ports=r.get("open_ports") or prev.get("open_ports") or [],
                        object_type=r.get("object_type") or prev.get("object_type"),
                        hostname=r.get("hostname") or prev.get("hostname") or "",
                        snmp=bool(r.get("snmp_ok")) or bool(prev.get("snmp")))
            found[ip] = prev
        # Every fleet address (not pushed to NetBox as a sighting).
        fleet = {str(a or "").strip() for d in (gc.get("nw_devices") or []) if isinstance(d, dict)
                 for a in [d.get("address")] + list(d.get("alt_addresses") or [])}
        # Everything that answered.
        heard = ((res or {}).get("reachable") or []) + ((res or {}).get("identified") or [])
        owner = access.spoke_owner_tenant(hub, spoke_id)
        if heard and not (owner and access.tenant_in(owner, tid)):
            # A shared agent can reach another tenant's nested prefix.
            foreign = await access.foreign_tenant_ips(
                hub, tid, {str(h.get("address") or "").strip() for h in heard})
            heard = [h for h in heard if str(h.get("address") or "").strip() not in foreign]
        # Record the responders.
        await _nw_note_responders(tid, heard, fleet)
        # Save progress, counting a completed pass when the cursor wraps.
        wrapped = cursor == 0 and bool(batch)
        st.update(cursor=cursor, total=total, scanned=int(st.get("scanned") or 0) + len(batch),
                  discovered=sorted(found.values(), key=lambda d: -d.get("last_seen", 0))[:2000],
                  last_run_at=now, last_status="ok", last_error="",
                  cycles=int(st.get("cycles") or 0) + (1 if wrapped else 0))
        hub.state._mark_dirty()
        return {"status": "ok", "probed": len(batch), "discovered": len(found)}

    async def _nw_snmp_creds(tid):
        """The tenant's vault SNMP communities as scan credentials (no logins:
        the sweep only reads SNMP, it never SSHes into unknown hosts)."""
        from routes.monitoring import vault_snmp_scan_sets
        # Fill in the secrets from the vault and keep only sets with a community.
        sets = await instance_vault.overlay_many(hub, vault_snmp_scan_sets(hub, tid),
                                                 "nw_scan_credentials")
        return [{"id": c.get("id"), "name": c.get("name"),
                 "snmp_community": c.get("snmp_community")}
                for c in sets if c.get("snmp_community")]

    async def _nw_ping(spoke_id, targets):
        """IPs from ``targets`` that answer a ping on the nw spoke, or None when
        the spoke can't ping (older spoke without NW_PING_SWEEP)."""
        # Ask the spoke to ping the targets.
        res = access.unwrap_spoke(await hub.request_response(
            spoke_id, "NW_PING_SWEEP", {"targets": targets}, timeout=300.0)) or {}
        if str(res.get("status", "")).upper() != "SUCCESS":
            return None
        return list(res.get("alive") or [])

    async def _nw_ping_all(spoke_id, targets):
        """Set of ``targets`` answering ping (empty when the spoke can't ping)."""
        # Ping the targets in chunks; stop at the first chunk the spoke cannot ping.
        alive = set()
        for i in range(0, len(targets), _NW_PING_CHUNK):
            try:
                got = await _nw_ping(spoke_id, targets[i:i + _NW_PING_CHUNK])
            except Exception as e:  # noqa: BLE001
                logger.warning("nw ping spoke=%s failed: %s", spoke_id, e)
                got = None
            if got is None:
                break
            alive.update(got)
        return alive

    async def _nw_probe_pinged(tid, spoke_id, ips, snmp=True):
        """NW_SCAN of hosts known to answer ping: sweep ports + SNMP + profile."""
        # Probe options: the sweep ports, plus SNMP if asked.
        options = {"tcp_ports": list(_NW_SWEEP_PORTS), "try_snmp": snmp, "use_nmap": False,
                   "concurrency": 32, "crawl": False, "max_targets": len(ips),
                   "max_depth": 1, "pinged": True}
        # Run the scan on the spoke and return its unwrapped result.
        return access.unwrap_spoke(await hub.request_response(
            spoke_id, "NW_SCAN", {"targets": ips,
                                  "credentials": await _nw_snmp_creds(tid) if snmp else [],
                                  "options": options, "tenant": tid},
            timeout=600.0)) or {}

    async def _nw_note_responders(tid, hosts, skip):
        """Record the hosts that answered in the tenant's seen-host registry
        and push the ones outside the fleet (``skip`` addresses) to NetBox."""
        # Record the hosts and prune old entries.
        reg = _seen_registry(tid)
        now = time.time()
        ips = set(nw_seen_hosts.record(reg, hosts, now))
        nw_seen_hosts.prune(reg, now)
        hub.state._mark_dirty()
        # Hosts not already in the fleet.
        fresh = ips - set(skip or ())
        if fresh:
            # A push already running picks these up when it finishes.
            _NW_SEEN_PENDING.setdefault(tid, set()).update(fresh)
            _nw_spawn_refresh(f"seen-push:{tid}", lambda: _nw_drain_seen(tid))

    async def _nw_drain_seen(tid):
        """Push pending sightings for the tenant to NetBox until none are left (new ones may arrive
        meanwhile).
        """
        while _NW_SEEN_PENDING.get(tid):
            # Take everything pending and push the matching registry entries.
            ips = _NW_SEEN_PENDING.pop(tid)
            reg = _seen_registry(tid)
            # Skip hosts NetBox already has as they are now and refreshed recently.
            due = nw_seen_hosts.due_for_push(reg, ips, time.time())
            if due and await _nw_push_seen(tid, [reg[ip] for ip in due]):
                nw_seen_hosts.mark_pushed(reg, due, time.time())
                hub.state._mark_dirty()

    async def _nw_push_seen(tid, entries):
        """Push sightings to NetBox (NETBOX_SYNC_DEVICES, own source tag, no
        replace): creates unknown hosts, refreshes ``last_seen`` on known ones.
        Returns True when NetBox accepted the push."""
        # The tenant's NetBox slug and the NetBox spoke; without both nothing is pushed.
        slug = access.netbox_tenant_scope(hub, tid).get("tenant")
        nb = access.get_netbox_spoke(hub)
        if not slug or not nb:
            logger.info("nw seen-hosts tenant=%s: %d host(s) not pushed (%s)", tid, len(entries),
                        "no NetBox tenant" if not slug else "NetBox spoke offline")
            return False
        # Sightings go under their own source tag and never replace other records.
        cfg = hub._nw_discovery_cfg() if callable(getattr(hub, "_nw_discovery_cfg", None)) else {}
        payload = {"tenant_id": tid, "tenant_slug": slug, "source": _NW_SEEN_SOURCE,
                   "replace": False, "devices": nw_seen_hosts.netbox_records(entries),
                   "defaults": (cfg or {}).get("defaults") or {}}
        # Push them; any failure is logged.
        try:
            res = access.unwrap_spoke(await hub.request_response(
                nb, "NETBOX_SYNC_DEVICES", payload, timeout=600.0)) or {}
            logger.info("nw seen-hosts tenant=%s NetBox push: sent=%d pushed=%s skipped=%s errors=%s %s",
                        tid, len(entries), res.get("pushed"), res.get("skipped"),
                        res.get("errors"), res.get("message") or "")
            return not res.get("errors")
        except Exception as e:  # noqa: BLE001
            logger.warning("[sync-error] nw seen-hosts tenant=%s NetBox push failed: %s", tid, e)
            return False

    def _gw_state(hub, tid):
        """The tenant's stored gateway-pass progress, created with defaults on first use."""
        gc = hub.state.system_state.setdefault("global_config", {})
        return gc.setdefault("nw_gw_sweep", {}).setdefault(tid, {
            "cursor": 0, "total": 0, "cycles": 0, "cycle_done_at": None,
            "found": [], "last_run_at": None, "last_status": None, "last_error": ""})

    async def _nw_add_subnet(tid, block, supers):
        """Create ``block`` in NetBox for the tenant (its VRF, under the
        narrowest supernet). Returns "" on success, else the reason."""
        # The tenant's NetBox slug and the NetBox spoke are both required.
        slug = access.netbox_tenant_scope(hub, tid).get("tenant")
        nb = access.get_netbox_spoke(hub)
        if not slug or not nb:
            return "no NetBox tenant" if not slug else "NetBox spoke offline"
        # Create it under the narrowest supernet that contains it.
        parent = max((s for s in supers if block.subnet_of(s)), key=lambda s: s.prefixlen)
        try:
            res = access.unwrap_spoke(await hub.request_response(nb, "NETBOX_ALLOCATE_PREFIX", {
                "parent_prefix": str(parent), "requested_prefix": str(block), "prefix_length": 24,
                "tenant": slug, "status": "active",
                "description": "Found by LM gateway sweep"}, timeout=30.0)) or {}
        except Exception as e:
            return str(e)[:200]
        return "" if str(res.get("status", "")).upper() == "SUCCESS" else str(res.get("message") or res)[:200]

    async def _nw_gateway_sweep_step(tid, spoke_id, *, force=False):
        """Gateway pass: ping .1 and .254 of each /24 in the tenant's supernets
        that has no NetBox prefix yet. Every /24 whose gateway answers is added
        to NetBox, so the scheduled scan sweeps it. A finished pass reruns
        after a week (or now with ``force``)."""
        # The pass progress.
        st = _gw_state(hub, tid)
        now = time.time()
        # A finished pass waits a week before running again (unless forced).
        if (not force and not st.get("cursor") and st.get("cycle_done_at")
                and now - st["cycle_done_at"] < _NW_GW_RESWEEP_SECONDS):
            return {"status": "idle"}
        # The next /24 blocks without a NetBox prefix.
        leaves, supers = await _nw_netbox_prefix_split(hub, tid)
        blocks, cursor, total = gateway_take(supers, st.get("cursor") or 0, _NW_GW_SWEEP_BLOCKS,
                                             skip=covered_blocks(leaves, supers))
        if not total:
            st.update(total=0, cursor=0, last_status="no-supernets", last_run_at=now)
            hub.state._mark_dirty()
            return {"status": "no-supernets"}
        # Map each block's .1 and .254 addresses back to the block.
        gateways = {}
        for b in blocks:
            gateways[str(b[1])] = b
            gateways[str(b[254])] = b
        # Ping them; failure or a spoke without ping support is recorded as an error.
        try:
            alive = await _nw_ping(spoke_id, list(gateways)) if gateways else []
        except Exception as e:
            alive, err = None, str(e)
        else:
            err = "nw spoke does not support ping sweep (update the spoke)"
        if alive is None:
            st.update(last_status="error", last_error=err, last_run_at=now)
            hub.state._mark_dirty()
            return {"status": "error", "reason": err}
        # Blocks that answered, with the first gateway that did.
        found = {}
        for ip in alive:
            found.setdefault(gateways[ip], ip)
        if len(blocks) >= 32 and len(found) == len(blocks):
            # Every gateway answering is a device replying for any address,
            # not real subnets — don't flood NetBox.
            st["last_error"] = f"all {len(blocks)} /24s answered — ignored as not real"
            found = {}
        else:
            st["last_error"] = ""
        # Add each answering block to NetBox and record the outcome (newest first, at most 2000).
        added = 0
        for block, ip in found.items():
            error = await _nw_add_subnet(tid, block, supers)
            added += not error
            st["found"] = ([{"prefix": str(block), "gateway": ip, "found_at": now, "error": error}]
                           + [f for f in st.get("found") or [] if f.get("prefix") != str(block)])[:2000]
        # New prefixes: clear the cached prefix list.
        if added:
            access.clear_prefix_cache(hub)
        # Save progress; a cursor back at 0 means the pass is finished.
        done = cursor == 0
        st.update(cursor=cursor, total=total, last_run_at=now, last_status="ok",
                  cycles=int(st.get("cycles") or 0) + done,
                  cycle_done_at=now if done else st.get("cycle_done_at"))
        hub.state._mark_dirty()
        return {"status": "ok", "checked": len(blocks), "added": added}

    # Expose the sweep step and the enabled check to the hub's background loop.
    hub.run_nw_sweep_step = _nw_sweep_step
    hub.nw_sweep_enabled_for_tenant = lambda tid: _sweep_enabled(hub, tid)

    @app.get("/api/nw/sweep")
    async def get_nw_sweep(request: Request, tenant: str = ""):
        """Return the tenant's sweep progress, gateway-pass state and unidentified hosts."""
        # The tenant being viewed.
        sess = _session_user(request)
        tid = _nw_caller_tenant(sess, tenant or None)
        # A copy of the progress, with the discovered list replaced by a count of hosts not in the
        # fleet.
        st = dict(_sweep_state(hub, tid))
        known = {str((d or {}).get("address", "")).strip()
                 for d in ((hub.state.system_state.get("global_config", {}) or {}).get("nw_devices") or [])
                 if isinstance(d, dict)}
        st["found"] = sum(1 for d in st.pop("discovered", None) or [] if d.get("address") not in known)
        st["enabled"] = _sweep_enabled(hub, tid)
        # The loop ticks every ~3 min; a batch can take up to ~10.
        st["running"] = st["enabled"] and time.time() - float(st.get("last_run_at") or 0) < 900
        st["tenant"] = tid
        st["gateway"] = dict(_gw_state(hub, tid))
        st["unidentified"] = nw_seen_hosts.unidentified(
            ((hub.state.system_state.get("global_config", {}) or {}).get("nw_seen_hosts") or {}).get(tid) or {})
        return st

    @app.post("/api/nw/sweep")
    async def post_nw_sweep(request: Request):
        """Body: ``tenant``, optional ``enabled`` (bool), ``run`` (bool, probe
        one batch now), ``find_subnets`` (bool, run one gateway-pass batch now),
        ``reset`` (bool, restart both cycles + clear findings)."""
        sess = _session_user(request)
        # Admins or tenant admins only.
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        # Read the body and resolve the tenant.
        data = await request.json()
        tid = _nw_caller_tenant(sess, data.get("tenant"))
        gc = hub.state.system_state.setdefault("global_config", {})
        # Turn the sweep on or off.
        if "enabled" in data:
            tmap = dict(gc.get("nw_tenant_cfg") or {})
            cur = dict(tmap.get(tid) or {})
            cur["sweep"] = {"enabled": bool(data["enabled"])}
            tmap[tid] = cur
            gc["nw_tenant_cfg"] = tmap
        # Reset clears both passes.
        if data.get("reset"):
            gc.setdefault("nw_sweep", {}).pop(tid, None)
            gc.setdefault("nw_gw_sweep", {}).pop(tid, None)
        hub.state._mark_dirty()
        out = {"status": "ok", "enabled": _sweep_enabled(hub, tid)}
        # Run one gateway-pass batch now.
        if data.get("find_subnets"):
            saved = _nw_scan_config(hub, tid)
            spoke_id = resolve_nw_scan_spoke(
                hub, tid, str(saved.get("spoke_id") or "").strip(), access.shared_tenant_id())
            out["run"] = (await _nw_gateway_sweep_step(tid, spoke_id, force=True) if spoke_id
                          else {"status": "skipped", "reason": "no nw spoke connected"})
        # Run one host-sweep batch now.
        if data.get("run"):
            out["run"] = await _nw_sweep_step(tid, force=True)
        return out

    # Expose the scheduled scan, fleet push and schedule reader to the hub.
    hub.run_nw_scheduled_scan = _run_nw_scheduled_scan
    hub.nw_push_fleet = lambda sid: _nw_push_fleet(hub, sid)
    hub.nw_scan_schedule_for_tenant = lambda tid: _nw_scan_schedule(hub, tid)

    @app.post("/setup/nw-scan/run")
    async def run_nw_scan(request: Request):
        """Run a fingerprint scan on the nw spoke and (optionally) auto-add the
        identified manageable devices to the tenant fleet.

        Body (all optional; falls back to the saved ``nw_scan`` config):
          ``tenant``, ``credential_ids``, ``ip_sources``, ``subnets`` (CIDRs),
          ``targets`` (explicit IPs), ``crawl``, ``dry_run`` (default false —
          identified devices are added; true = preview only), ``spoke_id``.

        Tenant-scoped: a tenant-admin scans only their own tenant (targets are
        aggregated from that tenant's inventory + they may only add devices bound
        to their tenant's spoke). Admin may scan any tenant / the shared tenant.
        Devices are added tagged ``source="scanned"`` with the winning scan
        credential's vault reference so future fleet pushes overlay the secret."""
        hub = app.state.hub
        sess = _session_user(request)
        # Admins or tenant admins only.
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        # Read the JSON body; a bad body counts as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}

        # Resolve the tenant to scan. A tenant-admin is pinned to their own
        # tenant; an admin may name any tenant (default: the shared tenant).
        req_tenant = str(data.get("tenant") or "").strip()
        if _is_admin(sess):
            tenant_id = req_tenant or access.shared_tenant_id() or ""
        else:
            own = ((sess or {}).get("user", {}).get("tenants")
                   or [(sess or {}).get("user", {}).get("tenant_id")])
            own = [t for t in own if t]
            if req_tenant and req_tenant not in own:
                raise HTTPException(status_code=403, detail="You may only scan your own tenant")
            tenant_id = req_tenant or (own[0] if own else "")
            if not tenant_id:
                raise HTTPException(status_code=400, detail="No tenant to scan")

        # Per-tenant scan config (falls back to the global admin config).
        saved = _nw_scan_config(hub, tenant_id)
        return await _execute_nw_scan(tenant_id, saved, sess=sess, data=data)

    @app.post("/setup/nw-devices")
    async def add_nw_device(request: Request):
        """Add a network device to the fleet (admin, or tenant admin for their own tenant's spoke).
        """
        hub = app.state.hub
        # Read the device; name and type are required, and the address must be a valid IPv4 address.
        try:
            data = await request.json()
            new_dev = data.get("device", {})
            if not new_dev.get("name") or not new_dev.get("object_type"):
                raise HTTPException(status_code=400, detail="Missing device name or object_type")
            _validate_nw_address(new_dev.get("address"))
            if new_dev.get("object_type") not in ("aos_switch", "cx_switch",
                                                   "ex_switch", "gateway", "ipmi"):
                raise HTTPException(status_code=400, detail="Invalid object_type")
            # Bind it to the caller's tenant and check its vault reference.
            _enforce_tenant_bind(request, new_dev, "network device")
            await instance_vault.validate_ref(
                hub, new_dev, _session_user(request),
                is_admin=_is_admin(_session_user(request)), storage_key="nw_devices")
            # Never store secrets inline.
            instance_vault.strip_inline_secrets(new_dev, "nw_devices")
            # Give it an id if it has none.
            if "id" not in new_dev:
                new_dev["id"] = str(uuid.uuid4())
            # A manually-added device is nw-owned (not a NetBox import) — tag it so
            # the NetBox→NW import loop never prunes it as a stale netbox record.
            new_dev.setdefault("source", "manual")

            # Save it to the fleet.
            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            devices.append(new_dev)
            global_config["nw_devices"] = devices
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # New device → push the bound slice so the spoke knows about it now.
            spoke_id = new_dev.get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False

            # NetBox is the fleet source of truth: write a manually-added device
            # back to NetBox (dcim.device) so it stays complete. Best-effort — a
            # NetBox miss must not fail the add. Skipped for netbox-imported rows.
            netbox_pushed = False
            if new_dev.get("source") != "netbox":
                try:
                    push, _errs, _slug = await hub.push_nw_device_inventory(new_dev, {}, [])
                    netbox_pushed = str((push or {}).get("status", "")).upper() in ("SUCCESS", "PARTIAL")
                except Exception as e:
                    logger.debug("add_nw_device NetBox write-back skipped: %s", e)
            return {"status": "ok", "device": new_dev, "pushed": pushed,
                    "netbox_pushed": netbox_pushed}
        # Pass HTTP errors through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("add_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/nw-devices/{device_id}")
    async def update_nw_device(device_id: str, request: Request):
        """Update a network device's config and re-push its spoke."""
        hub = app.state.hub
        try:
            # Read the changes.
            data = await request.json()
            update_data = data.get("config", {})

            # Find the device; unknown ids are a 404.
            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            idx = next((i for i, d in enumerate(devices)
                        if isinstance(d, dict) and d.get("id") == device_id), None)
            if idx is None:
                raise HTTPException(status_code=404, detail="Network device not found")

            # Validate the effective (post-merge) address BEFORE mutating the
            # stored record, so a rejected edit can't blank a good device.
            effective_addr = (update_data["address"] if "address" in update_data
                              else devices[idx].get("address"))
            _validate_nw_address(effective_addr)

            # Apply the changes, check the vault reference, and strip any inline secrets.
            devices[idx].update(update_data)
            await instance_vault.validate_ref(
                hub, devices[idx], _session_user(request),
                is_admin=_is_admin(_session_user(request)), storage_key="nw_devices")
            instance_vault.strip_inline_secrets(devices[idx], "nw_devices")
            # Save.
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Push the fleet to the device's spoke and report whether that worked.
            spoke_id = devices[idx].get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
            if pushed:
                return {"status": "ok",
                        "message": "Network device updated and pushed to spoke.",
                        "pushed": True}
            return {"status": "partial_success",
                    "message": "Configuration saved, but associated spoke is not connected.",
                    "pushed": False}
        # Pass HTTP errors through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/nw-devices/{device_id}")
    async def delete_nw_device(device_id: str):
        """Delete a network device and re-push its spoke."""
        hub = app.state.hub
        # Find the device being removed, then drop it from the list; unknown ids are a 404.
        global_config = hub.state.system_state.get("global_config", {})
        devices = global_config.get("nw_devices", [])
        victim = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        original_len = len(devices)
        devices[:] = [d for d in devices if not (isinstance(d, dict) and d.get("id") == device_id)]
        if len(devices) == original_len:
            raise HTTPException(status_code=404, detail="Network device not found")

        # Save.
        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        # Re-push so the spoke drops the deleted device from its fleet.
        spoke_id = victim.get("spoke_id") if isinstance(victim, dict) else None
        pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
        return {"status": "ok", "message": f"Network device {device_id} deleted.",
                "pushed": pushed}

    @app.post("/setup/nw-devices/dedupe")
    async def dedupe_nw_devices(request: Request):
        """Merge rows that are the same physical box (a switch discovered at each
        of its SVI addresses) into the row NetBox and Zabbix already use.
        Body ``{apply: bool}``; ``apply=false`` (default) is a dry run."""
        hub = app.state.hub
        # Admins only.
        if not _is_admin(_session_user(request)):
            raise HTTPException(status_code=403, detail="admin required")
        # Read the JSON body; a bad body counts as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        return await hub.merge_nw_hardware_duplicates(bool((body or {}).get("apply")))

    # ─── Multi-instance product connections (mirror firewalls) ────────────────
    # NAC / IPAM / LDAP / DNS / DHCP each manage a LIST of connection instances
    # (one per bound spoke) instead of a single config object, so the Setup
    # page can show a table with Add / Edit / Delete like Firewalls.

    async def _push_instance_config(hub, instance: dict, payload_fn, storage_key=None):
        """Send UPDATE_CONFIG to the instance's bound spoke, if connected.
        `payload_fn(instance)` returns the spoke-side config dict (or None for
        save-only products like DNS/DHCP). Returns True when a message was sent."""
        # Products without a spoke payload are save-only.
        if not payload_fn:
            return False
        # Nothing to send when the spoke is not connected.
        spoke_id = instance.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # Overlay a Credential Vault secret (e.g. ClearPass client secret) onto a
        # copy just before projecting the spoke payload — the plaintext is never
        # persisted in global_config, only resolved on demand at push time.
        if storage_key:
            instance = await instance_vault.overlay(hub, instance, storage_key)
        # Build the spoke payload; an empty one means nothing to send.
        payload = payload_fn(instance)
        if not payload:
            return False
        # Send it.
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _vault_scan_sets(hub, tenant_id):
        """Synthetic scan credential sets for the tenant's own Credential Vault
        bucket (login/console secrets, automation-readable), so a vault login is
        selectable on the scan tab without hand-creating a set. Ids are
        ``vault:<bucket>:<name>`` and resolve at scan time via the normal overlay."""
        # No tenant: no vault sets.
        tid = str(tenant_id or "").strip()
        if not tid:
            return []
        # The tenant's vault bucket (case-insensitive match); none means no sets.
        bucket = next((b for b in (
            (((hub.state.system_state.get("global_config", {}) or {})
              .get("cred_vault", {}) or {}).get("secrets", {}) or {}))
            if str(b).casefold() == tid.casefold()), None)
        if bucket is None:
            return []
        # One set per hub-mode login or console secret in the bucket.
        secrets = (hub.state.system_state["global_config"]["cred_vault"]["secrets"].get(bucket) or {})
        return [{
            "id": f"vault:{bucket}:{name}", "name": f"{name} (vault)", "username": "",
            "tenant_id": tid, "vault_credential": {"bucket": bucket, "name": name},
        } for name, m in sorted(secrets.items())
            if isinstance(m, dict) and m.get("mode") == "hub"
            and m.get("type") in ("login", "console")]

    def _instance_crud(route_prefix: str, storage_key: str, payload_fn=None,
                       legacy_key: str = None, legacy_to_instance=None,
                       topology_sync=None):
        """Register GET/POST/PUT/DELETE /setup/<route_prefix>[/id] for one
        multi-instance product, mirroring the firewalls CRUD. Each instance is
        a dict with an `id` and `spoke_id`; on add/update the config is pushed
        to the bound spoke when `payload_fn` is provided and the spoke is up.

        ``legacy_key``/``legacy_to_instance`` perform a one-shot migration of a
        pre-multi-instance single config (e.g. global_config.cppm / .netbox)
        into the instance list so deployments that configured CPPM/NetBox
        before the refactor still see their server on Setup → NAC /
        IPAM. The migrated entry is deduped by host/url and persisted so it
        becomes a normal editable instance."""
        # The hub, and an id-safe form of the route prefix for operation ids.
        hub = app.state.hub
        op = route_prefix.replace("-", "_")

        @app.get(f"/setup/{route_prefix}", operation_id=f"list_{op}")
        async def list_instances(request: Request):
            """List instances for this product (NAC/IPAM/Directory); folds in any legacy single-instance config."""
            # Copy the stored instance list.
            global_config = hub.state.system_state.get("global_config", {})
            instances = list(global_config.get(storage_key, []))
            # Move a legacy single config into the list once (unless it is already there).
            if legacy_key and legacy_to_instance:
                legacy = global_config.get(legacy_key)
                if isinstance(legacy, dict) and legacy:
                    inst = legacy_to_instance(legacy)
                    # Its identifying host or URL, and whether an instance already has it.
                    ident = inst.get("host") or inst.get("url") or inst.get("server_url")
                    already = any(
                        (inst.get("host") and i.get("host") == inst.get("host")) or
                        (inst.get("url") and i.get("url") == inst.get("url"))
                        for i in instances if isinstance(i, dict)
                    )
                    if ident and not already:
                        instances.append(inst)
                        global_config[storage_key] = instances
                        # Clear the legacy single-config so deleting the migrated
                        # instance doesn't re-migrate it on the next page load.
                        global_config[legacy_key] = {}
                        hub.state.system_state["global_config"] = global_config
                        hub.state._mark_dirty()
            # Tenant-scope the LIST: a non-admin sees only instances in the shared
            # tenant or their own tenant(s); other-tenant / unassigned instances
            # are admin-only. Object-level filtering + the add/write gates are
            # separate. Admins see all.
            sess = _session_user(request)
            if not _is_admin(sess):
                instances = [i for i in instances
                             if isinstance(i, dict) and access.spoke_visible_to_session(sess, i.get("tenant_id", ""))]
            # Narrow to an explicitly requested tenant (see above).
            # Optional explicit tenant scope (``?tenant=``): narrow to that
            # tenant's own instances plus shared ones. Opt-in and additive — no
            # caller that omits the param changes behavior. This is what lets a
            # tenant-scoped surface (e.g. the NW Scan tab) stop showing an ADMIN
            # every other tenant's entries just because admins bypass the
            # visibility filter above.
            #
            # ``default`` is the built-in Global-Admin scope (the tenant picker
            # sends ``?tenant=default`` for an admin). It is NOT a firehose: a
            # Global Admin on the ADMIN (``default``) tenant sees only their OWN
            # instances — unassigned (no ``tenant_id``) or explicitly
            # ``default``-tagged — plus shared ones, never every tenant's. To see
            # another tenant's entries the admin selects THAT tenant. This is the
            # same "ADMIN(default) must not accumulate across tenants" rule the
            # dashboards follow; it's what stops the NW Scan tab listing, e.g.,
            # another tenant's scan-credential sets under the ADMIN tenant.
            # (A non-admin never legitimately selects ``default`` — currentTenant
            # is their own tenant id — so leave their already visibility-filtered
            # list untouched in that case.)
            req_tenant = str(request.query_params.get("tenant") or "").strip()
            if req_tenant and (req_tenant.casefold() != "default" or _is_admin(sess)):
                scope = access.tenant_scope_ids(req_tenant)
                instances = [i for i in instances
                             if isinstance(i, dict) and access.in_tenant_scope(i.get("tenant_id"), scope)]
                if storage_key == "nw_scan_credentials":
                    instances = instances + _vault_scan_sets(hub, req_tenant)
            return {"instances": instances}

        @app.post(f"/setup/{route_prefix}", operation_id=f"add_{op}")
        async def add_instance(request: Request):
            """Add an instance and push its config to the bound spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                # Read the new instance; a name is required.
                data = await request.json()
                new_inst = dict(data.get("instance", {}))
                if not new_inst.get("name"):
                    raise HTTPException(status_code=400, detail="Missing instance name")
                # Take out the worker secret (sent to the spoke, never stored).
                worker_secret = str(new_inst.pop("worker_secret", "") or "")
                # Bind it to the caller's tenant.
                _enforce_tenant_bind(request, new_inst, route_prefix.split("-")[0])
                if new_inst.get("spoke_id") and route_prefix in PRODUCT_ROLE:
                    # Auto-load the matching coordinator role if the operator
                    # picked a bare base agent rather than an already-loaded
                    # role sub-spoke — removes the separate manual "Load Role"
                    # step. Resolves to the sub-spoke id actually pushed to.
                    role, module_type = PRODUCT_ROLE[route_prefix]
                    new_inst["spoke_id"] = await ensure_role_loaded(
                        hub, new_inst["spoke_id"], role, module_type)
                # Validate any Credential Vault reference up-front, then strip
                # inline secrets so only the {bucket,name} reference is stored.
                await instance_vault.validate_ref(
                    hub, new_inst, _session_user(request),
                    is_admin=_is_admin(_session_user(request)), storage_key=storage_key)
                instance_vault.strip_inline_secrets(new_inst, storage_key)
                # Give it an id if it has none.
                if "id" not in new_inst:
                    new_inst["id"] = str(uuid.uuid4())
                # The stored list plus the new instance.
                global_config = hub.state.system_state.get("global_config", {})
                instances = list(global_config.get(storage_key, []))
                candidate = [*instances, new_inst]
                # Push the whole server list (DNS) or just this instance's config to its spoke.
                pushed = (await topology_sync(
                    hub, candidate, new_inst.get("spoke_id"), worker_secret)
                    if topology_sync else
                    await _push_instance_config(
                        hub, new_inst, payload_fn, storage_key))
                # Save it.
                instances.append(new_inst)
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                # Report whether it was pushed.
                status = "ok" if pushed else "partial_success"
                msg = "Instance added and pushed to spoke." if pushed else "Instance added; spoke not connected."
                return {"status": status, "message": msg, "pushed": pushed, "instance": new_inst}
            # Pass HTTP errors through; anything else is logged and returned as a 500.
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("add_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.put(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"update_{op}")
        async def update_instance(instance_id: str, request: Request):
            """Update an instance and push to its spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                # Read the changes, taking out the worker secret.
                data = await request.json()
                update_data = dict(data.get("config", {}))
                worker_secret = str(update_data.pop("worker_secret", "") or "")
                # Find the instance; unknown ids are a 404.
                global_config = hub.state.system_state.get("global_config", {})
                instances = list(global_config.get(storage_key, []))
                idx = next((i for i, x in enumerate(instances) if x.get("id") == instance_id), None)
                if idx is None:
                    raise HTTPException(status_code=404, detail="Instance not found")
                # Moving to a different spoke: load the product's role on the new one if needed.
                old_spoke = instances[idx].get("spoke_id")
                new_spoke = update_data.get("spoke_id")
                if new_spoke and new_spoke != old_spoke and route_prefix in PRODUCT_ROLE:
                    role, module_type = PRODUCT_ROLE[route_prefix]
                    update_data["spoke_id"] = await ensure_role_loaded(hub, new_spoke, role, module_type)
                # Merge the changes into a copy of the instance.
                updated = dict(instances[idx])
                updated.update(update_data)
                # Validate/strip a Credential Vault reference on the merged record.
                await instance_vault.validate_ref(
                    hub, updated, _session_user(request),
                    is_admin=_is_admin(_session_user(request)), storage_key=storage_key)
                instance_vault.strip_inline_secrets(updated, storage_key)
                # Replace it in the list.
                instances[idx] = updated
                # DNS: push the whole server list to the new spoke (and to the old one if it moved).
                if topology_sync:
                    pushed = await topology_sync(
                        hub, instances, updated.get("spoke_id"), worker_secret)
                    if old_spoke and old_spoke != updated.get("spoke_id"):
                        old_pushed = await topology_sync(
                            hub, instances, old_spoke, "")
                        pushed = pushed and old_pushed
                # Others: push just this instance's config.
                else:
                    pushed = await _push_instance_config(
                        hub, updated, payload_fn, storage_key)
                # Save.
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                # Moved off a spoke: unload the role there if nothing else uses it.
                if route_prefix in PRODUCT_ROLE and old_spoke and old_spoke != updated.get("spoke_id"):
                    role, _mt = PRODUCT_ROLE[route_prefix]
                    await maybe_unload_orphaned_role(hub, old_spoke, role, instances)
                # Report whether it was pushed.
                if pushed:
                    return {"status": "ok", "message": "Instance updated and pushed to spoke.", "pushed": True}
                return {"status": "partial_success", "message": "Instance saved; associated spoke not connected.", "pushed": False}
            # Pass HTTP errors through; anything else is logged and returned as a 500.
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("update_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.delete(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"delete_{op}")
        async def delete_instance(instance_id: str):
            """Delete an instance; the spoke keeps its last config until re-pushed."""
            # Find the instance; unknown ids are a 404.
            global_config = hub.state.system_state.get("global_config", {})
            instances = list(global_config.get(storage_key, []))
            deleted = next((x for x in instances if x.get("id") == instance_id), None)
            if deleted is None:
                raise HTTPException(status_code=404, detail="Instance not found")
            # The list without it; DNS also pushes that list to the spoke.
            candidate = [x for x in instances if x.get("id") != instance_id]
            pushed = (await topology_sync(
                hub, candidate, deleted.get("spoke_id"), "")
                if topology_sync else False)
            # Save.
            instances = candidate
            global_config[storage_key] = instances
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            # Unload the product's role on its spoke if nothing else uses it.
            spoke_id = (deleted or {}).get("spoke_id")
            if route_prefix in PRODUCT_ROLE and spoke_id:
                role, _mt = PRODUCT_ROLE[route_prefix]
                await maybe_unload_orphaned_role(hub, spoke_id, role, instances)
            return {"status": "ok", "message": f"Instance {instance_id} deleted.",
                    "pushed": pushed}

    # ClearPass (NAC) instances, migrated from the old single "cppm" config.
    _instance_crud(
        "nac-instances", "nac_instances",
        lambda inst: {
            "host": inst.get("host"),
            "client_id": inst.get("client_id"),
            "client_secret": inst.get("client_secret"),
            "user": inst.get("user"),
            "password": inst.get("password"),
            "verify_ssl": inst.get("verify_ssl", True),
        },
        legacy_key="cppm",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": c.get("host") or "ClearPass",
            "spoke_id": "",
            "host": c.get("host"),
            "client_id": c.get("client_id"),
            "client_secret": c.get("client_secret"),
            "user": c.get("user"),
            "password": c.get("password"),
            "verify_ssl": c.get("verify_ssl", True),
        },
    )
    # NetBox (IPAM) instances, migrated from the old single "netbox" config.
    _instance_crud(
        "ipam-instances", "ipam_instances",
        lambda inst: {"netbox_url": inst.get("url"), "api_token": inst.get("api_token"), "netbox_verify_ssl": inst.get("verify_ssl")},
        legacy_key="netbox",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": "NetBox",
            "spoke_id": "",
            "url": c.get("url") or c.get("netbox_url"),
            "api_token": c.get("api_token") or c.get("token"),
        },
    )
    # Scan credential sets: per-tenant vault-backed SSH/SNMP credentials the
    # fingerprint scanner tries against discovered IPs. Save-only (no
    # payload_fn) — never pushed to a spoke as config; overlaid on demand at
    # scan time by /setup/nw-scan/run.
    _instance_crud("nw-scan-credentials", "nw_scan_credentials")

    @app.post("/setup/ipam/apply-schema", operation_id="ipam_apply_schema")
    async def ipam_apply_schema():
        """Apply the Lab Manager custom-field schema to the connected NetBox.

        Backs the "Apply schema changes" button on the Setup/IPAM NetBox
        instance modal. Sends NETBOX_PROVISION_CUSTOM_FIELDS to the connected
        ipam spoke, which runs the engine's idempotent _ensure_custom_fields
        (force=True) over the shared CUSTOM_FIELDS_SPEC — the same spec
        install.sh provisions on a fresh install, so a manual apply and a
        reinstall produce identical schemas. Re-runnable: never errors when the
        fields are already present (the engine get-or-creates + verifies each
        attachment). Returns the spoke's report
        (status/total/present/created/attached/already_attached/warnings).
        """
        # The connected IPAM spoke, or a 503.
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        try:
            # NETBOX_PROVISION_CUSTOM_FIELDS runs _ensure_custom_fields(force=True)
            # over the full CUSTOM_FIELDS_SPEC — get-or-creating each field then
            # verifying/attaching content_types. That is many NetBox API calls
            # (17+ fields × create+attach) and routinely exceeds the 5s default
            # request_response timeout, surfacing as "Timed out waiting for spoke
            # response". Give it a generous window; the UI fires-and-forgets with
            # a "started" toast and shows "completed" when this resolves.
            result = await hub.request_response(spoke_id,
                                                "NETBOX_PROVISION_CUSTOM_FIELDS", {},
                                                timeout=120.0)
            # Anything but SUCCESS/PARTIAL is a 502.
            data = _unwrap_spoke(result)
            if data.get("status") not in ("SUCCESS", "PARTIAL"):
                raise HTTPException(status_code=502,
                                    detail=data.get("message", "NetBox provisioning error"))
            return data
        # Pass HTTP errors through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ipam_apply_schema failed")
            raise HTTPException(status_code=500, detail=str(e))
    # LDAP directory instances.
    _instance_crud(
        "ldap-instances", "ldap_instances",
        lambda inst: {
            "LDAP_SERVER_URL": inst.get("server_url"),
            "LDAP_BASE_DN": inst.get("base_dn"),
            "LDAP_ADMIN_DN": inst.get("admin_dn"),
            "LDAP_ADMIN_PW": inst.get("admin_pw"),
        },
    )
    # DNS and DHCP instances (DNS pushes its server list to the spoke; DHCP is save-only).
    _instance_crud(
        "dns-instances", "dns_instances", None,
        topology_sync=sync_dns_instance_topology)
    _instance_crud("dhcp-instances", "dhcp_instances", None)
