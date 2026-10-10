"""Network-devices routes + multi-instance product CRUD (_instance_crud)."""
import asyncio
import ipaddress
import time

import instance_vault
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access, get_spoke_or_503,
    logger, uuid,
)
from nw_topology import build_topology, netbox_lldp_links
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
_NW_BG_TASKS: set = set()


def _nw_truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _nw_spawn_refresh(key, coro_factory) -> None:
    """Fire ONE background revalidate for ``key`` (deduped). ``coro_factory`` is
    a zero-arg callable returning the coroutine — built INSIDE the guard so a
    skipped spawn never leaves an un-awaited coroutine. No running loop (sync
    test path) → no-op."""
    if key in _NW_BG_INFLIGHT:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _NW_BG_INFLIGHT.add(key)

    async def _run():
        try:
            await coro_factory()
        except Exception as e:  # noqa: BLE001 - best-effort revalidate
            logger.debug("nw bg refresh [%s] failed: %s", key, e)
        finally:
            _NW_BG_INFLIGHT.discard(key)

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
    sem = asyncio.Semaphore(_NW_DISCOVERY_POLL_CONCURRENCY)

    async def _one(did):
        async with sem:
            res = None
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
            if isinstance(res, dict):
                await hub.nw_cache_set_poll(did, res)
                logger.info("nw discovery poll %s -> %s", did, res.get("message"))

    await asyncio.gather(*(_one(d) for d in device_ids), return_exceptions=True)


async def _nw_bg_refresh_fleet(hub) -> None:
    """Whole-fleet revalidate: query every connected+approved nw spoke for the
    full inventory ({} = no tenant filter) and refresh the global fleet cache.
    Server-side (no session) — writes only the authoritative whole-fleet
    snapshot the offline/cache-first read path filters per-reader."""
    spokes = [s for s in (hub.get_all_spokes_by_type("nw") or [])
              if s in hub.active_connections and hub.approved_modules.get(s, False)]
    if not spokes:
        return
    merged, seen, answered = [], set(), 0
    for sid in spokes:
        try:
            result = await hub.request_response(sid, "NW_LIST_DEVICES", {}, timeout=20.0)
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
    a = str(addr or "").strip()
    if not a:
        raise HTTPException(status_code=400,
                            detail="Management IP address is required")
    try:
        ipaddress.IPv4Address(a)
    except ipaddress.AddressValueError:
        raise HTTPException(
            status_code=400,
            detail=f"'{a}' is not a valid IPv4 address")


def nw_scan_spoke_choices(hub, tenant_id, shared_tenant_id):
    """The nw spokes a tenant may run a scan with: the ones BOUND to the tenant
    ("own") plus the ones bound to the shared tenant ("shared").

    This is the whole allowlist — a spoke bound to some OTHER tenant is never
    offered and never resolved. Scanning through another tenant's agent probes
    that tenant's network from that tenant's vantage point and attributes the
    results here, which is the cross-tenant leak this list closes.

    Returns UI-ready dicts (``scope`` is ``own``/``shared``) ordered own first,
    then shared; connected entries ahead of disconnected ones within each scope
    so the default pick is a usable agent. ``shared_tenant_id`` is passed in
    (rather than read from ``access``) so this stays pure + unit-testable."""
    md = hub.state.system_state.get("module_metadata", {}) or {}
    names = hub.state.system_state.get("module_names", {}) or {}
    out = []
    # Ids reach here with differing spelling ("Default" from the picker vs the
    # "default" a spoke is bound to), so compare canonicalised (strip+casefold).
    def _n(x):
        return str(x or "").strip().casefold()
    want, shared_n = _n(tenant_id), _n(shared_tenant_id)
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
        out.append({
            "spoke_id": sid,
            "name": names.get(sid, sid),
            "tenant_id": owner,
            "scope": scope,
            "connected": hub._primary_key(sid) in hub.active_connections,
        })
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
    prefer the tenant's OWN connected spoke, else a connected shared one.

    There is deliberately no "any connected nw spoke" fallback: it silently ran
    an Admin-tenant scan on whichever single nw agent happened to be online
    (another tenant's), so the targets and results came from that tenant."""
    live = [c for c in nw_scan_spoke_choices(hub, tenant_id, shared_tenant_id)
            if c["connected"]]
    if requested_spoke_id:
        for c in live:
            if c["spoke_id"] == requested_spoke_id:
                return requested_spoke_id
    for scope in ("own", "shared"):
        for c in live:
            if c["scope"] == scope:
                return c["spoke_id"]
    return ""


# Absolute ceiling on one scan's total target list, and how many batches run
# at once. Anything over the per-request batch size (``max_targets``) is split.
_NW_SCAN_MAX_TOTAL = 32768
_NW_SCAN_PARALLEL_BATCHES = 3
# Hosts probed per sweep tick (a tick runs every few minutes per tenant).
_NW_SWEEP_BATCH = 256


# A prefix wider than this (more than 1024 hosts) is never expanded by the
# targeted scan even if it has no children; the background sweep covers it.
_NW_MAX_LEAF_PREFIXLEN = 22


def split_leaf_and_supernets(prefixes):
    """Split IPv4 CIDR strings into ``(leaves, supernets)`` ``IPv4Network`` lists.
    A supernet is a prefix that CONTAINS another prefix in the set, or is wider
    than /22 (too big for a targeted scan); invalid and
    IPv6 entries are ignored and duplicates collapsed."""
    nets = []
    for p in (prefixes or []):
        try:
            n = ipaddress.ip_network(str(p).strip(), strict=False)
        except ValueError:
            continue
        if isinstance(n, ipaddress.IPv4Network) and n not in nets:
            nets.append(n)
    supers = [n for n in nets
              if n.prefixlen < _NW_MAX_LEAF_PREFIXLEN
              or any(o.prefixlen > n.prefixlen and o.subnet_of(n) for o in nets)]
    return [n for n in nets if n not in supers], supers


def sweep_ranges(supernets, leaves):
    """Inclusive ``(first, last)`` integer host ranges covering every supernet
    minus the leaf prefixes carved out of it (those belong to the targeted
    scan, not the sweep). Sorted and non-overlapping; stable across calls so a
    persisted cursor stays valid while the prefix set is unchanged."""
    out = []
    for sn in sorted(supernets, key=lambda n: (int(n.network_address), n.prefixlen)):
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
        for piece in pieces:
            lo, hi = int(piece.network_address), int(piece.broadcast_address)
            if sn.prefixlen < 31:
                if lo == int(sn.network_address):
                    lo += 1
                if hi == int(sn.broadcast_address):
                    hi -= 1
            if hi >= lo:
                out.append((lo, hi))
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
    total = sum(hi - lo + 1 for lo, hi in ranges)
    if total <= 0:
        return [], 0, 0
    cursor = max(0, int(cursor)) % total if cursor < total else 0
    ips, idx, consumed = [], 0, cursor
    for lo, hi in ranges:
        size = hi - lo + 1
        if cursor >= idx + size:
            idx += size
            continue
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
    return ips, (consumed if consumed < total else 0), total


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
    seen = []
    seen_set = set()
    per_source = {}

    def _add(ip):
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
        try:
            net = ipaddress.ip_network(str(text).strip(), strict=False)
        except ValueError:
            return 0
        if not isinstance(net, ipaddress.IPv4Network):
            return 0
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
        lo_s, _, hi_s = str(text).strip().partition("-")
        lo_s, hi_s = lo_s.strip(), hi_s.strip()
        if not hi_s:
            return 0
        if "." not in hi_s:  # shorthand last octet: 10.0.0.10-20
            hi_s = lo_s.rsplit(".", 1)[0] + "." + hi_s
        try:
            lo = ipaddress.ip_address(lo_s)
            hi = ipaddress.ip_address(hi_s)
        except ValueError:
            return 0
        if not (isinstance(lo, ipaddress.IPv4Address)
                and isinstance(hi, ipaddress.IPv4Address)) or int(hi) < int(lo):
            return 0
        n = 0
        for v in range(int(lo), int(hi) + 1):
            if len(seen) >= cap:
                break
            if _add(str(ipaddress.IPv4Address(v))):
                n += 1
        return n

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
    ip = (str(ip).strip() if ip else "") or None
    norm = _nw_norm_mac(mac) if mac else ""

    def _rows(entry, ep):
        env = entry.get(ep)
        data = env.get("data") if isinstance(env, dict) else None
        return data if isinstance(data, list) else []

    def _match(r):
        if ip and str(r.get("ip", "")).strip() == ip:
            return True
        if norm and _nw_norm_mac(r.get("mac", "")) == norm:
            return True
        return False

    hits = []
    for dev in (devices or []):
        if not isinstance(dev, dict):
            continue
        did = dev.get("id")
        entry = (device_cache or {}).get(did) or {}
        is_self = bool(ip and str(dev.get("address", "")).strip() == ip)
        matched = {
            "arp":        [r for r in _rows(entry, "arp") if _match(r)],
            "mac":        [r for r in _rows(entry, "macs") if _match(r)],
            "endpoints":  [r for r in _rows(entry, "endpoints") if _match(r)],
            "interfaces": [r for r in _rows(entry, "interfaces") if _match(r)],
        }
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
    members = []
    seen = set()
    for inst in instances or []:
        if not isinstance(inst, dict) or inst.get("spoke_id") != spoke_id:
            continue
        member_id = str(inst.get("member_id") or inst.get("name") or "").strip()
        host = str(inst.get("host") or "").strip()
        if not member_id or not host:
            raise HTTPException(
                status_code=400,
                detail="Each DNS server requires a Worker ID and host/IP.")
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
    if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
        return False
    payload = {"members": dns_members_from_instances(instances, spoke_id)}
    if worker_secret:
        payload["worker_secret"] = worker_secret
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
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin
    _filter_nw = ctx._filter_nw

    def _validate_nw_address(addr):
        return validate_nw_address(addr)

    def _enforce_tenant_bind(request, cfg, kind):
        """Shared add/edit gate for tenant-scoped device/instance creation. A
        tenant-admin may bind ``cfg`` ONLY to a spoke in their own tenant (via
        ``cfg['spoke_id']``) and the record is bound to that tenant; Global Admin
        is unrestricted (record tenant defaults to the spoke's tenant). Plain
        users are rejected. Mutates ``cfg['tenant_id']`` in place. Raises 403 on
        violation."""
        sess = _session_user(request)
        spoke_id = cfg.get("spoke_id")
        if not _is_admin(sess):
            if not _is_tenant_admin(sess):
                raise HTTPException(status_code=403, detail=f"Tenant-admin access required to add a {kind}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403,
                                    detail=f"You can only bind a {kind} to a spoke assigned to your tenant")
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
        elif spoke_id and not cfg.get("tenant_id"):
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

    def _get_nw_spoke(hub):
        """The connected nw spoke id, or raise 503 (single-instance resolver)."""
        return get_spoke_or_503(hub, "nw", "Network Devices")

    def _nw_devices_for_spoke(hub, spoke_id: str):
        """The device slice a spoke should receive (bound-to-it, else unbound)."""
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
        payload = {"devices": _project_nw_devices_for_push(slice_),
                   "shared_tenant_id": access.shared_tenant_id() or "",
                   **poll_cfg}
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
        hub = app.state.hub
        devices = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        dev = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        if not dev:
            raise HTTPException(status_code=404, detail="Network device not found")
        sess = _session_user(request)
        tid = dev.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
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
                                  dedicated=False):
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
        NAC bypass)."""
        if dedicated:
            return data
        if scope == "full" and not tenant:
            return data
        return await _filter_nw(request, data, endpoint, tenant)

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

        def _row_visible(tid):
            """Whether an nw_devices row (by ``tenant_id``) is visible to this
            request. Acting-as a specific tenant → only that tenant's dedicated
            devices + shared devices. Otherwise the existing rule: admin → all,
            non-admin → own-tenant + shared (``spoke_visible_to_session``)."""
            if acting_tenant is not None:
                if acting_tenant == "default" and not str(tid or "").strip():
                    return True
                return (str(tid or "").casefold() == str(acting_tenant).casefold()
                        or access.tenant_is_shared(tid))
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
            env = hub.nw_cache_get_device(did, "info")
            info = (env or {}).get("data") if isinstance(env, dict) else None
            if not isinstance(info, dict):
                return {}
            out = {}
            for k in ("serial", "mac", "model", "firmware", "hostname"):
                v = info.get(k)
                if v not in (None, ""):
                    out[k] = v
            return out

        info_by_id = {did: _device_identity(did) for did in visible_ids}

        def _overlay_names(env):
            if not isinstance(env, dict):
                return env
            rows = env.get("data")
            if isinstance(rows, list):
                def _merge(r):
                    if not isinstance(r, dict):
                        return r
                    rid = r.get("id")
                    extra = {}
                    if name_by_id.get(rid):
                        extra["name"] = name_by_id[rid]
                    extra.update(info_by_id.get(rid) or {})
                    return {**r, **extra} if extra else r
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
            spoke_to_tid = {s: "" for s in spokes}
        else:
            spoke_to_tid = {}
            for t in ((sess or {}).get("user", {}).get("tenants") or []):
                s = hub.get_nw_spoke_for_tenant(t)
                if s:
                    spoke_to_tid[s] = t
            shared_tid = access.shared_tenant_id()
            if shared_tid:
                s = hub.get_nw_spoke_for_shared()
                if s:
                    spoke_to_tid[s] = shared_tid
            spoke_to_tid = {s: t for s, t in spoke_to_tid.items()
                            if s in hub.active_connections
                            and hub.approved_modules.get(s, False)}
            spokes = list(spoke_to_tid)

        # Cache-first: serve the last-known fleet snapshot (tenant-filtered)
        # WITHOUT blocking on live SSH, then revalidate in the background when
        # it's aging and a spoke is up. ``?refresh=1`` forces a live fetch.
        force = _nw_truthy(request.query_params.get("refresh"))
        predicate = (lambda r: _row_visible(r.get("tenant_id", "")))
        cached = None if force else hub.nw_cache_get_fleet_filtered(predicate)
        if cached is not None:
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
                age = time.time() - float(cached.get("fetched_at") or 0.0)
                if age > _NW_SERVE_MAX_AGE_S:
                    _nw_spawn_refresh("__fleet__", lambda: _nw_bg_refresh_fleet(hub))
            return out

        if not spokes:
            # Cold miss AND no live spoke → nothing to serve.
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")

        # Fan out NW_LIST_DEVICES (admin: {} = whole fleet per spoke; non-admin:
        # {"tenant": tid} = own+shared from that spoke) + merge rows by id.
        merged, seen, answered = [], set(), 0
        for sid in spokes:
            tid = spoke_to_tid.get(sid, "")
            payload = {"tenant": tid} if tid else {}
            try:
                result = await hub.request_response(sid, "NW_LIST_DEVICES", payload,
                                                    timeout=20.0)
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

        # Authoritative gate: drop any row not in the reader's visible config
        # set (defense-in-depth against a stale/leaky spoke). When acting-as a
        # selected tenant we ALWAYS gate — even if the tenant has zero visible
        # devices (empty ``visible_ids``) — so an empty scope yields an empty
        # list rather than falling through to the unfiltered fleet.
        if visible_ids or acting_tenant is not None:
            merged = [r for r in merged if r.get("id") in visible_ids]

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
        gc = hub.state.system_state.get("global_config", {}) or {}
        cur = (((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("topology") or {})
        return {
            "devices": [d for d in (cur.get("devices") or []) if isinstance(d, dict)],
            "links": [l for l in (cur.get("links") or []) if isinstance(l, dict)],
        }

    def _nw_cached_rows(hub, device_id, endpoint):
        """Rows from the warm per-device cache, or [] on a cold miss."""
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
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
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

        def _row_visible(tid):
            if acting_tenant is not None:
                if acting_tenant == "default" and not str(tid or "").strip():
                    return True
                return (str(tid or "").casefold() == str(acting_tenant).casefold()
                        or access.tenant_is_shared(tid))
            return is_admin or access.spoke_visible_to_session(sess, tid)

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

        force = _nw_truthy(request.query_params.get("refresh"))
        infer = not (request.query_params.get("infer") in ("0", "false", "no"))

        async def _gather(device_id, endpoint, spoke_cmd, timeout):
            """Live-fetch one device endpoint and seed the cache. Never raises:
            one unreachable switch must not blank the whole map."""
            spoke_id = spoke_by_id.get(device_id) or ""
            if not spoke_id:
                return
            dev = next((d for d in fleet if d.get("id") == device_id), {})
            payload = {"device_id": device_id}
            if dev.get("tenant_id"):
                payload["tenant"] = dev["tenant_id"]
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
                async with sem:
                    await _gather(device_id, endpoint, cmd, timeout)

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
            tid = dev.get("tenant_id", "")
            dedicated = bool(tid) and not access.tenant_is_shared(tid)
            out = await _filter_nw_optional(scope_by_id.get(dev["id"], "full"),
                                            request, {"data": rows}, endpoint,
                                            acting_tenant, dedicated)
            got = out.get("data") if isinstance(out, dict) else None
            return [r for r in (got or []) if isinstance(r, dict)]

        lldp_by_device, macs_by_device = {}, {}
        for dev in fleet:
            did = dev["id"]
            lldp_by_device[did] = await _scoped(
                dev, "lldp", _nw_cached_rows(hub, did, "lldp"))
            if infer:
                macs_by_device[did] = await _scoped(
                    dev, "macs", _nw_cached_rows(hub, did, "macs"))
            if force or not spoke_by_id.get(did):
                continue
            # Stale-while-revalidate: refresh aging entries for the NEXT load.
            age = time.time() - hub.nw_cache_device_fetched_at(did)
            if age <= _NW_SERVE_MAX_AGE_S:
                continue
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

        cfg_tid = acting_tenant or _nw_caller_tenant(sess, None)
        manual = _nw_topology_cfg(hub, cfg_tid)

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

        return graph

    @app.get("/api/nw/topology/manual")
    async def nw_topology_manual_get(request: Request, tenant: str = None):
        """The operator-declared devices and links for a tenant (the editable
        half of the map)."""
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
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            raise HTTPException(status_code=400, detail="body must be an object")
        tid = _nw_caller_tenant(sess, data.get("tenant"))

        def _clean(items, keys, required):
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

        gc = hub.state.system_state.get("global_config", {})
        tmap = dict(gc.get("nw_tenant_cfg") or {})
        cur = dict(tmap.get(tid) or {})
        topo = dict(cur.get("topology") or {})
        if "devices" in data:
            topo["devices"] = _clean(
                data["devices"], ("name", "mac", "ip", "kind", "note"), ("name",))
        if "links" in data:
            topo["links"] = _clean(
                data["links"], ("a", "a_port", "b", "b_port", "note"), ("a", "b"))
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
        spoke_cmd = command_map.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported by nw module")
        logger.debug("relay GET /api/nw/%s/%s tenant=%s", device_id, endpoint, tenant)
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
        cached = None if force else hub.nw_cache_get_device(device_id, endpoint)
        if cached is not None:
            filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant, dedicated)
            fetched_at = hub.nw_cache_device_fetched_at(device_id)
            if isinstance(filtered, dict):
                filtered = dict(filtered)
                filtered["cached"] = True
                filtered["fetched_at"] = fetched_at
                if not spoke_id:
                    filtered["stale"] = True
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
        try:
            result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.nw_cache_set_device(device_id, endpoint, data)
            return await _filter_nw_optional(scope, request, data, endpoint, tenant, dedicated)
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
                filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant, dedicated)
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
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
        try:
            data = await request.json()
        except Exception:
            data = {}
        commands = (data or {}).get("commands", []) if isinstance(data, dict) else []
        if not isinstance(commands, list):
            raise HTTPException(status_code=400, detail="commands must be a list")
        dev, _scope, spoke_id = _authz_nw_device(request, device_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NW_RUN_CONFIG",
                                                {"device_id": device_id,
                                                 "commands": commands,
                                                 "tenant": dev.get("tenant_id", "")})
            return access.unwrap_spoke(result)
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
        try:
            result = await hub.poll_nw_device(device_id)
            # Fold the poll's rich result into the per-device cache so a later
            # page load (spoke offline) still reflects the last probe.
            if isinstance(result, dict):
                await hub.nw_cache_set_poll(device_id, result)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_poll_device failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/nw-devices")
    async def get_nw_devices(request: Request):
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
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"default_poll_interval": gc.get("nw_poll_default_interval"),
                "poll_jitter_frac": gc.get("nw_poll_jitter_frac"),
                "max_poll_per_tick": gc.get("nw_poll_max_per_tick"),
                "max_poll_concurrency": gc.get("nw_poll_max_concurrency"),
                "ping_interval": gc.get("nw_ping_interval")}

    @app.post("/setup/nw-poll-config")
    async def set_nw_poll_config(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        raw = data.get("default_poll_interval")
        try:
            val = None if raw in (None, "", "null") else int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="default_poll_interval must be an integer or null")

        def _opt_num(key, cast, lo, hi):
            """Parse an optional numeric knob: null/absent → None (spoke default),
            else cast + clamp to [lo, hi]."""
            v = data.get(key)
            if v in (None, "", "null"):
                return None
            try:
                return max(lo, min(cast(v), hi))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} must be numeric or null")

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
        return {"status": "ok", "default_poll_interval": val,
                "poll_jitter_frac": jitter, "max_poll_per_tick": per_tick,
                "max_poll_concurrency": concurrency,
                "ping_interval": ping_interval, "pushed": pushed}

    @app.get("/setup/nw-netbox-import")
    async def get_nw_netbox_import(request: Request):
        """NetBox→NW import config (NetBox = fleet source of truth): which NetBox
        device roles get imported into the nw fleet, object_type mapping, cadence."""
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"nw_netbox_import": gc.get("nw_netbox_import", {}) or {}}

    @app.post("/setup/nw-netbox-import")
    async def set_nw_netbox_import(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        cfg = data.get("config", data) or {}
        roles = cfg.get("roles")
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "roles": [str(r).strip() for r in (roles or []) if str(r).strip()],
            "object_type_map": dict(cfg.get("object_type_map") or {}),
            "default_object_type": str(cfg.get("default_object_type") or "gateway"),
            "interval": int(cfg.get("interval") or 900),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_netbox_import"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_netbox_import": clean}

    @app.post("/setup/nw-netbox-import/run")
    async def run_nw_netbox_import(request: Request):
        """On-demand 'Import now' — run one NetBox→NW import cycle."""
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            return await hub.run_nw_netbox_import_all()
        except Exception as e:
            logger.exception("run_nw_netbox_import failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Network scan (fingerprint discovery) ────────────────────────────────
    _SCAN_OBJECT_TYPES = ("aos_switch", "cx_switch", "ex_switch", "gateway")

    async def _nw_netbox_prefix_split(hub, tenant_id):
        """The tenant's NetBox IPv4 prefixes split into ``(leaf, supernets)``.
        A supernet is any prefix that CONTAINS another of the tenant's prefixes
        (e.g. a /16 carved into /24s); everything else is a leaf. Leaves are
        what a targeted scan expands; supernets are left to the background sweep."""
        try:
            prefixes = await access.fetch_tenant_prefixes(hub, tenant_id)
        except Exception:
            prefixes = []
        return split_leaf_and_supernets(prefixes)

    async def _aggregate_scan_targets(hub, tenant_id, sources, extra_subnets,
                                      extra_targets, cap):
        """Build the candidate host-IP list for a tenant scan, in priority order
        (each tier fully included before the next; deduped, IPv4-only):

          1. DNS records (``dns``), 2. DHCP leases (``dhcp``), 3. NAC endpoints
          (``nac``), 4. NetBox LEAF prefixes (``netbox`` — prefixes that contain
          other prefixes are supernets, left to the background sweep), 5. the
          user's explicit ``extra_targets`` / ``extra_subnets``.

        ``cap`` is the TOTAL ceiling for the list (the caller splits it into
        batches). Returns ``(targets, per_source)``; ``per_source`` counts each
        tier's contribution and ``"truncated"`` is the number of IPs dropped
        because the total ceiling was hit."""
        sources = set(sources or [])
        seen, seen_set, per_source = [], set(), {}
        dropped = 0

        def _add(ip):
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
            if source not in sources:
                return
            try:
                sid = spoke_getter(tenant_id) if tenant_id else None
                if not sid or hub._primary_key(sid) not in hub.active_connections:
                    return
                result = await hub.request_response(sid, command, payload or {}, timeout=30.0)
                data = access.unwrap_spoke(result)
            except Exception as e:
                logger.warning("scan aggregate tenant=%s %s skipped: %s", tenant_id, source, e)
                return
            rows = []
            if isinstance(data, dict):
                for key in ("endpoints", "leases", "records", "data", "results"):
                    if isinstance(data.get(key), list):
                        rows = data[key]
                        break
            elif isinstance(data, list):
                rows = data
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

        await _pull("dns", hub.get_dns_spoke_for_tenant, "DNS_LIST")
        await _pull("dhcp", hub.get_dhcp_spoke_for_tenant, "DHCP_LIST_LEASES")
        await _pull("nac", hub.get_cppm_spoke_for_tenant, "LIST_ENDPOINTS")

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
        if dropped:
            per_source["truncated"] = dropped
        return seen, per_source

    def _nw_scan_config(hub, tenant_id=None):
        """Effective scan config. Base = global admin ``nw_scan`` (Setup card).
        When ``tenant_id`` is given and that tenant has a per-tenant override
        (``nw_tenant_cfg[tenant]['scan']``), its keys win — so a tenant manages
        its own scan settings without clobbering the shared/global config."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        cfg = dict(gc.get("nw_scan", {}) or {})
        if tenant_id:
            ov = (((gc.get("nw_tenant_cfg") or {}).get(tenant_id) or {}).get("scan") or {})
            for k, v in ov.items():
                if v is not None:
                    cfg[k] = v
        cfg.setdefault("enabled", False)
        cfg.setdefault("crawl", False)
        cfg.setdefault("auto_add", False)
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
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        data = await request.json()
        cfg = data.get("config", data) or {}
        ports = cfg.get("tcp_ports")
        if isinstance(ports, str):
            ports = [p.strip() for p in ports.split(",") if p.strip()]
        try:
            ports = [int(p) for p in (ports or [22, 443, 80, 23])]
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="tcp_ports must be integers")
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "crawl": bool(cfg.get("crawl", False)),
            "auto_add": bool(cfg.get("auto_add", False)),
            "try_snmp": bool(cfg.get("try_snmp", True)),
            "use_nmap": bool(cfg.get("use_nmap", False)),
            "credential_ids": [str(x) for x in (cfg.get("credential_ids") or []) if str(x).strip()],
            "ip_sources": [str(x) for x in (cfg.get("ip_sources") or ["netbox"]) if str(x).strip()],
            "tcp_ports": ports,
            "max_targets": max(1, min(int(cfg.get("max_targets") or 1024), 4096)),
            "concurrency": max(1, min(int(cfg.get("concurrency") or 32), 128)),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_scan"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_scan": clean}

    def _nw_caller_tenant(sess, req_tenant):
        """Resolve+authorize the tenant a caller may configure. Admin: the named
        tenant or the shared tenant. Tenant-admin: only one of their own tenants.
        Raises 403/400 on violation."""
        req_tenant = str(req_tenant or "").strip()
        if _is_admin(sess):
            return req_tenant or access.shared_tenant_id() or ""
        own = ((sess or {}).get("user", {}).get("tenants")
               or [(sess or {}).get("user", {}).get("tenant_id")])
        own = [t for t in own if t]
        if req_tenant and req_tenant not in own:
            raise HTTPException(status_code=403, detail="You may only configure your own tenant")
        tid = req_tenant or (own[0] if own else "")
        if not tid:
            raise HTTPException(status_code=400, detail="No tenant resolved")
        return tid

    def _nw_scan_schedule(hub, tenant_id):
        """Per-tenant recurring-scan schedule from ``nw_tenant_cfg`` with defaults.
        ``interval_seconds`` 0/absent = off; ``dry_run`` true = preview only (no
        auto-add) even when the scan config allows adding."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        sc = (((gc.get("nw_tenant_cfg") or {}).get(tenant_id) or {}).get("scan_schedule") or {})
        return {
            "enabled": bool(sc.get("enabled", False)),
            "interval_seconds": int(sc.get("interval_seconds") or 0),
            "dry_run": bool(sc.get("dry_run", True)),
        }

    @app.get("/api/nw/tenant-config")
    async def get_nw_tenant_config(request: Request):
        """Tenant-facing NW config surface (Network → Scan tab): effective scan
        settings, poll jitter/caps/cadence, and the recurring-scan schedule for
        the caller's tenant, plus a flag per poll knob showing whether the tenant
        overrides the global admin default."""
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        tid = _nw_caller_tenant(sess, request.query_params.get("tenant"))
        gc = hub.state.system_state.get("global_config", {}) or {}
        poll_ov = (((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("poll") or {})
        eff = access.nw_poll_cfg_for_tenant(hub, tid)
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
        tenant-admin only their own). Answers "what scans are scheduled?"
        without having to switch tenant context and read one card at a time.

        Each row carries the schedule (enabled / interval / dry-run), a summary
        of the scan it will run (agent, credential sets, IP sources, auto-add),
        and the loop's runtime view (last run, next due, last outcome).

        The runtime fields are IN-MEMORY on the hub: a restart clears them and
        every schedule re-defers one full interval (anti-stampede), so a null
        ``last_run_at`` means "not since this hub started", not "never"."""
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        all_t = (getattr(hub.state, "tenant_state", {}) or {}).get("tenants", {}) or {}
        if _is_admin(sess):
            ids = list(all_t.keys())
        else:
            ids = [t for t in ((sess or {}).get("user", {}).get("tenants") or []) if t]
        runtime = getattr(hub, "nw_scan_runtime", {}) or {}
        gc = hub.state.system_state.get("global_config", {}) or {}
        all_sets = gc.get("nw_scan_credentials", []) or []
        by_id = {c.get("id"): c for c in all_sets if isinstance(c, dict)}
        rows = []
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
                "dry_run": bool(sched.get("dry_run", True)),
                "auto_add": bool(cfg.get("auto_add", False)),
                "ip_sources": list(cfg.get("ip_sources") or []),
                "max_targets": int(cfg.get("max_targets") or 0),
                "spoke_id": spoke_id,
                "spoke_connected": bool(
                    spoke_id and hub._primary_key(spoke_id) in hub.active_connections),
                "credential_names": [
                    (by_id.get(cid, {}) or {}).get("name") or cid for cid in cred_ids],
                # No credential sets selected → the scheduled run is a
                # discovery-only pass (reachability + open ports, no auto-add).
                "discovery_only": not cred_ids,
                "last_run_at": rt.get("last_run_at"),
                "next_due_at": rt.get("next_due_at"),
                "last_status": rt.get("last_status"),
                "last_added": int(rt.get("last_added") or 0),
                "last_identified": int(rt.get("last_identified") or 0),
                "last_error": rt.get("last_error") or "",
            })
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
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        data = await request.json()
        tid = _nw_caller_tenant(sess, data.get("tenant"))

        gc = hub.state.system_state.get("global_config", {})
        tmap = dict(gc.get("nw_tenant_cfg") or {})
        cur = dict(tmap.get(tid) or {})

        # ── scan (partial merge over the existing tenant scan override) ──
        if isinstance(data.get("scan"), dict):
            s = data["scan"]
            scan_ov = dict(cur.get("scan") or {})
            for k in ("enabled", "crawl", "auto_add", "try_snmp"):
                if k in s:
                    scan_ov[k] = bool(s[k])
            if "ip_sources" in s:
                scan_ov["ip_sources"] = [str(x) for x in (s["ip_sources"] or []) if str(x).strip()]
            if "credential_ids" in s:
                scan_ov["credential_ids"] = [str(x) for x in (s["credential_ids"] or []) if str(x).strip()]
            if "subnets" in s:
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
                ports = s["tcp_ports"]
                if isinstance(ports, str):
                    ports = [p.strip() for p in ports.split(",") if p.strip()]
                try:
                    scan_ov["tcp_ports"] = [int(p) for p in (ports or [])]
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="tcp_ports must be integers")
            if "max_targets" in s:
                scan_ov["max_targets"] = max(1, min(int(s["max_targets"] or 1024), 4096))
            if "concurrency" in s:
                scan_ov["concurrency"] = max(1, min(int(s["concurrency"] or 32), 128))
            if "spoke_id" in s:
                scan_ov["spoke_id"] = str(s["spoke_id"] or "").strip()
            cur["scan"] = scan_ov

        # ── poll (null a key → clear override so it inherits the global) ──
        if isinstance(data.get("poll"), dict):
            p = data["poll"]
            poll_ov = dict(cur.get("poll") or {})

            def _num_or_clear(key, cast, lo, hi):
                if key not in p:
                    return
                v = p[key]
                if v in (None, "", "null"):
                    poll_ov.pop(key, None)
                    return
                try:
                    poll_ov[key] = max(lo, min(cast(v), hi))
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail=f"{key} must be numeric or null")

            _num_or_clear("default_interval", int, 0, 604800)
            _num_or_clear("jitter_frac", float, 0.0, 0.9)
            _num_or_clear("max_per_tick", int, 1, 100)
            _num_or_clear("max_concurrency", int, 1, 50)
            cur["poll"] = poll_ov

        # ── scan_schedule ──
        if isinstance(data.get("scan_schedule"), dict):
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
        system = sess is None
        spoke_id = resolve_nw_scan_spoke(
            hub, tenant_id,
            str(data.get("spoke_id") or saved.get("spoke_id") or "").strip(),
            access.shared_tenant_id())
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
        chosen = [c for c in all_sets if isinstance(c, dict) and c.get("id") in set(cred_ids)]
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
        chosen = [c for c in chosen if access.in_tenant_scope(c.get("tenant_id"), owned)]
        if not system and not _is_admin(sess):
            chosen = [c for c in chosen
                      if access.spoke_visible_to_session(sess, c.get("tenant_id", ""))]
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
        overlaid = await instance_vault.overlay_many(hub, chosen, "nw_scan_credentials")
        push_creds = [{
            "id": c.get("id"), "name": c.get("name") or c.get("id"),
            "username": c.get("username") or c.get("user") or "",
            "password": c.get("password") or "",
            "enable_secret": c.get("enable_secret") or "",
            "snmp_community": c.get("snmp_community") or "",
        } for c in overlaid]

        ip_sources = data.get("ip_sources") or saved.get("ip_sources") or ["netbox"]
        # ``max_targets`` is the per-request BATCH size: a longer target list is
        # split into batches (run a few in parallel) rather than truncated. Only
        # the absolute ceiling below truncates.
        cap = max(1, min(int(data.get("max_targets") or saved.get("max_targets") or 1024), 4096))
        targets, per_source = await _aggregate_scan_targets(
            hub, tenant_id, ip_sources,
            data.get("subnets") or saved.get("subnets") or [],
            data.get("targets") or [], _NW_SCAN_MAX_TOTAL)
        logger.info("nw scan tenant=%s targets=%d sources=%s creds=%d",
                    tenant_id, len(targets), per_source, len(chosen))
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

        options = {
            "tcp_ports": saved.get("tcp_ports") or [22, 443, 80, 23],
            "try_snmp": bool(saved.get("try_snmp", True)),
            "use_nmap": use_nmap,
            "concurrency": int(saved.get("concurrency") or 32),
            "crawl": bool(data.get("crawl", saved.get("crawl", False))),
            "max_targets": cap,
            "max_depth": int(data.get("max_depth") or 2),
        }
        batches = [targets[i:i + cap] for i in range(0, len(targets), cap)]
        sem = asyncio.Semaphore(_NW_SCAN_PARALLEL_BATCHES)

        async def _run_batch(batch):
            async with sem:
                result = await hub.request_response(
                    spoke_id, "NW_SCAN",
                    {"targets": batch, "credentials": push_creds, "options": options,
                     "tenant": tenant_id},
                    timeout=max(60.0, min(len(batch) * 2.0, 900.0)))
                return access.unwrap_spoke(result)

        outcomes = await asyncio.gather(*(_run_batch(b) for b in batches),
                                        return_exceptions=True)
        failed = [o for o in outcomes if isinstance(o, BaseException)]
        if len(failed) == len(outcomes):
            e = failed[0]
            logger.error("nw scan failed (tenant=%s): %s", tenant_id, e)
            if system:
                return {"status": "error", "reason": str(e), "tenant": tenant_id,
                        "added": [], "identified": []}
            raise HTTPException(status_code=500, detail=f"scan failed: {e}")
        if failed:
            logger.warning("nw scan tenant=%s: %d of %d batch(es) failed: %s",
                           tenant_id, len(failed), len(outcomes), failed[0])
            per_source["failed_batches"] = len(failed)
        scans = [o for o in outcomes if isinstance(o, dict)]
        identified = [d for o in scans for d in (o.get("identified") or [])]
        # Hosts that answered a TCP probe but were not classified into a device
        # family. Always reported now — on a discovery-only (credential-free)
        # scan this IS the result, and even on a credentialed scan it is the
        # actionable "something is here that I can't manage yet" list.
        reachable = [d for o in scans for d in (o.get("reachable") or [])]
        scan = {"scanned": sum(int(o.get("scanned") or 0) for o in scans)}

        # Existing addresses for this tenant (dedup) — an identified device that
        # is already in the fleet (own or shared) is reported but not re-added.
        gc = hub.state.system_state.get("global_config", {})
        devices = gc.get("nw_devices", []) or []
        known = {str((d or {}).get("address", "")).strip()
                 for d in devices if isinstance(d, dict)
                 and (d.get("tenant_id", "") in (tenant_id, access.shared_tenant_id()))}
        by_cred = {c.get("id"): c for c in chosen}

        dry_run = bool(data.get("dry_run", True)) or not bool(
            data.get("auto_add", saved.get("auto_add", False)))
        # A credential-free pass is preview-only, as documented. Scan credentials
        # are optional now, and the spoke turns nmap service detection on when
        # none are supplied — nmap CAN classify a host into a manageable
        # object_type, so without this gate an auto-add scan would write fleet
        # entries with an empty username and no vault_credential behind them:
        # devices the fleet can never actually manage.
        discovery_only = not push_creds
        dry_run = dry_run or discovery_only
        added, preview = [], []
        for dev in identified:
            addr = str(dev.get("address", "")).strip()
            if not addr or addr in known:
                continue
            cred_set = by_cred.get(dev.get("credential_id")) or (chosen[0] if chosen else {})
            entry = {
                "name": dev.get("hostname") or addr,
                "object_type": dev.get("object_type"),
                "address": addr,
                "os": dev.get("os", ""),
                "method": dev.get("method"),
                "credential_id": dev.get("credential_id"),
            }
            if dev.get("object_type") not in _SCAN_OBJECT_TYPES:
                continue
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
            ref = cred_set.get("vault_credential")
            if ref:
                new_dev["vault_credential"] = ref
            devices.append(new_dev)
            known.add(addr)
            added.append(new_dev)

        if added:
            gc["nw_devices"] = devices
            hub.state.system_state["global_config"] = gc
            hub.state._mark_dirty()
            await _nw_push_fleet(hub, spoke_id)

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
        poll_ids = [d["id"] for d in added] + stale_ids
        if poll_ids:
            _nw_spawn_refresh(f"discovery-poll:{poll_ids[0]}",
                              lambda: _nw_poll_discovered(hub, poll_ids))

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
        }

    async def _run_nw_scheduled_scan(tenant_id):
        """System-initiated recurring scan for one tenant (called by the hub's
        run_nw_scan_schedule_loop). Uses the tenant's saved scan config +
        schedule; ``dry_run`` honors the schedule's preview flag (else the scan
        config's auto_add)."""
        saved = _nw_scan_config(hub, tenant_id)
        sched = _nw_scan_schedule(hub, tenant_id)
        data = {"dry_run": bool(sched.get("dry_run", True)),
                "auto_add": bool(saved.get("auto_add", False))}
        return await _execute_nw_scan(tenant_id, saved, sess=None, data=data)

    # Expose the system scan executor + schedule reader to the hub so the
    # background run_nw_scan_schedule_loop (a mixin method) can drive scans
    # without re-implementing the credential/target/add pipeline.
    # ── Tier 2: background supernet sweep ────────────────────────────────────
    # Slow, report-only, opt-in per tenant. Walks the address space of the
    # tenant's supernets MINUS anything the targeted scan already covers (DNS,
    # DHCP, NAC, child prefixes, user extras, fleet devices), a small batch per
    # tick with a persisted cursor, and records hosts that answer a light TCP
    # probe. It never adds devices and never blocks a scheduled scan.
    def _sweep_enabled(hub, tid):
        gc = hub.state.system_state.get("global_config", {}) or {}
        return bool((((gc.get("nw_tenant_cfg") or {}).get(tid) or {}).get("sweep") or {}).get("enabled", False))

    def _sweep_state(hub, tid):
        gc = hub.state.system_state.setdefault("global_config", {})
        return gc.setdefault("nw_sweep", {}).setdefault(tid, {
            "cursor": 0, "total": 0, "cycles": 0, "scanned": 0, "discovered": [],
            "last_run_at": None, "last_status": None, "last_error": ""})

    async def _nw_sweep_step(tid, *, force=False):
        """Probe the next batch of the tenant's sweep space. Returns the sweep
        state dict (or ``{"status": ...}`` when skipped)."""
        if not force and not _sweep_enabled(hub, tid):
            return {"status": "disabled"}
        saved = _nw_scan_config(hub, tid)
        spoke_id = resolve_nw_scan_spoke(
            hub, tid, str(saved.get("spoke_id") or "").strip(), access.shared_tenant_id())
        if not spoke_id:
            return {"status": "skipped", "reason": "no nw spoke connected"}
        st = _sweep_state(hub, tid)
        leaves, supers = await _nw_netbox_prefix_split(hub, tid)
        ranges = sweep_ranges(supers, leaves)
        if not ranges:
            st.update(total=0, cursor=0, last_status="no-supernets", last_run_at=time.time())
            hub.state._mark_dirty()
            return {"status": "no-supernets"}
        covered, _ps = await _aggregate_scan_targets(
            hub, tid, ["dns", "dhcp", "nac"], saved.get("subnets") or [], [], _NW_SCAN_MAX_TOTAL)
        gc = hub.state.system_state.get("global_config", {}) or {}
        covered = set(covered) | {str((d or {}).get("address", "")).strip()
                                  for d in (gc.get("nw_devices") or []) if isinstance(d, dict)}
        batch, cursor, total = sweep_take(ranges, st.get("cursor") or 0,
                                          _NW_SWEEP_BATCH, skip=frozenset(covered))
        options = {"tcp_ports": [22, 443, 80, 23], "try_snmp": False, "use_nmap": False,
                   "concurrency": 8, "crawl": False, "max_targets": _NW_SWEEP_BATCH,
                   "max_depth": 1}
        try:
            res = access.unwrap_spoke(await hub.request_response(
                spoke_id, "NW_SCAN",
                {"targets": batch, "credentials": [], "options": options, "tenant": tid},
                timeout=600.0)) if batch else {}
        except Exception as e:
            st.update(last_status="error", last_error=str(e), last_run_at=time.time())
            hub.state._mark_dirty()
            logger.warning("nw sweep tenant=%s batch failed: %s", tid, e)
            return {"status": "error", "reason": str(e)}
        now = time.time()
        found = {str(d.get("address")): d for d in (st.get("discovered") or []) if isinstance(d, dict)}
        for r in ((res or {}).get("reachable") or []) + ((res or {}).get("identified") or []):
            ip = str((r or {}).get("address") or "").strip()
            if not ip:
                continue
            prev = found.get(ip) or {"address": ip, "first_seen": now}
            prev.update(last_seen=now, open_ports=r.get("open_ports") or prev.get("open_ports") or [],
                        object_type=r.get("object_type") or prev.get("object_type"))
            found[ip] = prev
        wrapped = cursor == 0 and bool(batch)
        st.update(cursor=cursor, total=total, scanned=int(st.get("scanned") or 0) + len(batch),
                  discovered=sorted(found.values(), key=lambda d: -d.get("last_seen", 0))[:2000],
                  last_run_at=now, last_status="ok", last_error="",
                  cycles=int(st.get("cycles") or 0) + (1 if wrapped else 0))
        hub.state._mark_dirty()
        return {"status": "ok", "probed": len(batch), "discovered": len(found)}

    hub.run_nw_sweep_step = _nw_sweep_step
    hub.nw_sweep_enabled_for_tenant = lambda tid: _sweep_enabled(hub, tid)

    @app.get("/api/nw/sweep")
    async def get_nw_sweep(request: Request, tenant: str = ""):
        sess = _session_user(request)
        tid = _nw_caller_tenant(sess, tenant or None)
        st = dict(_sweep_state(hub, tid))
        known = {str((d or {}).get("address", "")).strip()
                 for d in ((hub.state.system_state.get("global_config", {}) or {}).get("nw_devices") or [])
                 if isinstance(d, dict)}
        st["discovered"] = [d for d in st.get("discovered", []) if d.get("address") not in known]
        st["enabled"] = _sweep_enabled(hub, tid)
        st["tenant"] = tid
        return st

    @app.post("/api/nw/sweep")
    async def post_nw_sweep(request: Request):
        """Body: ``tenant``, optional ``enabled`` (bool), ``run`` (bool, probe
        one batch now), ``reset`` (bool, restart the cycle + clear findings)."""
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
        data = await request.json()
        tid = _nw_caller_tenant(sess, data.get("tenant"))
        gc = hub.state.system_state.setdefault("global_config", {})
        if "enabled" in data:
            tmap = dict(gc.get("nw_tenant_cfg") or {})
            cur = dict(tmap.get(tid) or {})
            cur["sweep"] = {"enabled": bool(data["enabled"])}
            tmap[tid] = cur
            gc["nw_tenant_cfg"] = tmap
        if data.get("reset"):
            gc.setdefault("nw_sweep", {}).pop(tid, None)
        hub.state._mark_dirty()
        out = {"status": "ok", "enabled": _sweep_enabled(hub, tid)}
        if data.get("run"):
            out["run"] = await _nw_sweep_step(tid, force=True)
        return out

    hub.run_nw_scheduled_scan = _run_nw_scheduled_scan
    hub.nw_scan_schedule_for_tenant = lambda tid: _nw_scan_schedule(hub, tid)

    @app.post("/setup/nw-scan/run")
    async def run_nw_scan(request: Request):
        """Run a fingerprint scan on the nw spoke and (optionally) auto-add the
        identified manageable devices to the tenant fleet.

        Body (all optional; falls back to the saved ``nw_scan`` config):
          ``tenant``, ``credential_ids``, ``ip_sources``, ``subnets`` (CIDRs),
          ``targets`` (explicit IPs), ``crawl``, ``dry_run`` (default true —
          preview only), ``spoke_id``.

        Tenant-scoped: a tenant-admin scans only their own tenant (targets are
        aggregated from that tenant's inventory + they may only add devices bound
        to their tenant's spoke). Admin may scan any tenant / the shared tenant.
        Devices are added tagged ``source="scanned"`` with the winning scan
        credential's vault reference so future fleet pushes overlay the secret."""
        hub = app.state.hub
        sess = _session_user(request)
        if not (_is_admin(sess) or _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="admin or tenant-admin required")
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
        hub = app.state.hub
        try:
            data = await request.json()
            new_dev = data.get("device", {})
            if not new_dev.get("name") or not new_dev.get("object_type"):
                raise HTTPException(status_code=400, detail="Missing device name or object_type")
            _validate_nw_address(new_dev.get("address"))
            if new_dev.get("object_type") not in ("aos_switch", "cx_switch",
                                                   "ex_switch", "gateway"):
                raise HTTPException(status_code=400, detail="Invalid object_type")
            _enforce_tenant_bind(request, new_dev, "network device")
            await instance_vault.validate_ref(
                hub, new_dev, _session_user(request),
                is_admin=_is_admin(_session_user(request)), storage_key="nw_devices")
            instance_vault.strip_inline_secrets(new_dev, "nw_devices")
            if "id" not in new_dev:
                new_dev["id"] = str(uuid.uuid4())
            # A manually-added device is nw-owned (not a NetBox import) — tag it so
            # the NetBox→NW import loop never prunes it as a stale netbox record.
            new_dev.setdefault("source", "manual")

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
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("add_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/nw-devices/{device_id}")
    async def update_nw_device(device_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})

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

            devices[idx].update(update_data)
            await instance_vault.validate_ref(
                hub, devices[idx], _session_user(request),
                is_admin=_is_admin(_session_user(request)), storage_key="nw_devices")
            instance_vault.strip_inline_secrets(devices[idx], "nw_devices")
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            spoke_id = devices[idx].get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
            if pushed:
                return {"status": "ok",
                        "message": "Network device updated and pushed to spoke.",
                        "pushed": True}
            return {"status": "partial_success",
                    "message": "Configuration saved, but associated spoke is not connected.",
                    "pushed": False}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/nw-devices/{device_id}")
    async def delete_nw_device(device_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        devices = global_config.get("nw_devices", [])
        victim = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        original_len = len(devices)
        devices[:] = [d for d in devices if not (isinstance(d, dict) and d.get("id") == device_id)]
        if len(devices) == original_len:
            raise HTTPException(status_code=404, detail="Network device not found")

        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        # Re-push so the spoke drops the deleted device from its fleet.
        spoke_id = victim.get("spoke_id") if isinstance(victim, dict) else None
        pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
        return {"status": "ok", "message": f"Network device {device_id} deleted.",
                "pushed": pushed}

    # ─── Multi-instance product connections (mirror firewalls) ────────────────
    # NAC / IPAM / LDAP / DNS / DHCP each manage a LIST of connection instances
    # (one per bound spoke) instead of a single config object, so the Setup
    # page can show a table with Add / Edit / Delete like Firewalls.

    async def _push_instance_config(hub, instance: dict, payload_fn, storage_key=None):
        """Send UPDATE_CONFIG to the instance's bound spoke, if connected.
        `payload_fn(instance)` returns the spoke-side config dict (or None for
        save-only products like DNS/DHCP). Returns True when a message was sent."""
        if not payload_fn:
            return False
        spoke_id = instance.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # Overlay a Credential Vault secret (e.g. ClearPass client secret) onto a
        # copy just before projecting the spoke payload — the plaintext is never
        # persisted in global_config, only resolved on demand at push time.
        if storage_key:
            instance = await instance_vault.overlay(hub, instance, storage_key)
        payload = payload_fn(instance)
        if not payload:
            return False
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _vault_scan_sets(hub, tenant_id):
        """Synthetic scan credential sets for the tenant's own Credential Vault
        bucket (login/console secrets, automation-readable), so a vault login is
        selectable on the scan tab without hand-creating a set. Ids are
        ``vault:<bucket>:<name>`` and resolve at scan time via the normal overlay."""
        tid = str(tenant_id or "").strip()
        if not tid:
            return []
        bucket = next((b for b in (
            (((hub.state.system_state.get("global_config", {}) or {})
              .get("cred_vault", {}) or {}).get("secrets", {}) or {}))
            if str(b).casefold() == tid.casefold()), None)
        if bucket is None:
            return []
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
        hub = app.state.hub
        op = route_prefix.replace("-", "_")

        @app.get(f"/setup/{route_prefix}", operation_id=f"list_{op}")
        async def list_instances(request: Request):
            """List instances for this product (NAC/IPAM/Directory); folds in any legacy single-instance config."""
            global_config = hub.state.system_state.get("global_config", {})
            instances = list(global_config.get(storage_key, []))
            if legacy_key and legacy_to_instance:
                legacy = global_config.get(legacy_key)
                if isinstance(legacy, dict) and legacy:
                    inst = legacy_to_instance(legacy)
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
                data = await request.json()
                new_inst = dict(data.get("instance", {}))
                if not new_inst.get("name"):
                    raise HTTPException(status_code=400, detail="Missing instance name")
                worker_secret = str(new_inst.pop("worker_secret", "") or "")
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
                if "id" not in new_inst:
                    new_inst["id"] = str(uuid.uuid4())
                global_config = hub.state.system_state.get("global_config", {})
                instances = list(global_config.get(storage_key, []))
                candidate = [*instances, new_inst]
                pushed = (await topology_sync(
                    hub, candidate, new_inst.get("spoke_id"), worker_secret)
                    if topology_sync else
                    await _push_instance_config(
                        hub, new_inst, payload_fn, storage_key))
                instances.append(new_inst)
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                status = "ok" if pushed else "partial_success"
                msg = "Instance added and pushed to spoke." if pushed else "Instance added; spoke not connected."
                return {"status": status, "message": msg, "pushed": pushed, "instance": new_inst}
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("add_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.put(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"update_{op}")
        async def update_instance(instance_id: str, request: Request):
            """Update an instance and push to its spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                data = await request.json()
                update_data = dict(data.get("config", {}))
                worker_secret = str(update_data.pop("worker_secret", "") or "")
                global_config = hub.state.system_state.get("global_config", {})
                instances = list(global_config.get(storage_key, []))
                idx = next((i for i, x in enumerate(instances) if x.get("id") == instance_id), None)
                if idx is None:
                    raise HTTPException(status_code=404, detail="Instance not found")
                old_spoke = instances[idx].get("spoke_id")
                new_spoke = update_data.get("spoke_id")
                if new_spoke and new_spoke != old_spoke and route_prefix in PRODUCT_ROLE:
                    role, module_type = PRODUCT_ROLE[route_prefix]
                    update_data["spoke_id"] = await ensure_role_loaded(hub, new_spoke, role, module_type)
                updated = dict(instances[idx])
                updated.update(update_data)
                # Validate/strip a Credential Vault reference on the merged record.
                await instance_vault.validate_ref(
                    hub, updated, _session_user(request),
                    is_admin=_is_admin(_session_user(request)), storage_key=storage_key)
                instance_vault.strip_inline_secrets(updated, storage_key)
                instances[idx] = updated
                if topology_sync:
                    pushed = await topology_sync(
                        hub, instances, updated.get("spoke_id"), worker_secret)
                    if old_spoke and old_spoke != updated.get("spoke_id"):
                        old_pushed = await topology_sync(
                            hub, instances, old_spoke, "")
                        pushed = pushed and old_pushed
                else:
                    pushed = await _push_instance_config(
                        hub, updated, payload_fn, storage_key)
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                if route_prefix in PRODUCT_ROLE and old_spoke and old_spoke != updated.get("spoke_id"):
                    role, _mt = PRODUCT_ROLE[route_prefix]
                    await maybe_unload_orphaned_role(hub, old_spoke, role, instances)
                if pushed:
                    return {"status": "ok", "message": "Instance updated and pushed to spoke.", "pushed": True}
                return {"status": "partial_success", "message": "Instance saved; associated spoke not connected.", "pushed": False}
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("update_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.delete(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"delete_{op}")
        async def delete_instance(instance_id: str):
            """Delete an instance; the spoke keeps its last config until re-pushed."""
            global_config = hub.state.system_state.get("global_config", {})
            instances = list(global_config.get(storage_key, []))
            deleted = next((x for x in instances if x.get("id") == instance_id), None)
            if deleted is None:
                raise HTTPException(status_code=404, detail="Instance not found")
            candidate = [x for x in instances if x.get("id") != instance_id]
            pushed = (await topology_sync(
                hub, candidate, deleted.get("spoke_id"), "")
                if topology_sync else False)
            instances = candidate
            global_config[storage_key] = instances
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            spoke_id = (deleted or {}).get("spoke_id")
            if route_prefix in PRODUCT_ROLE and spoke_id:
                role, _mt = PRODUCT_ROLE[route_prefix]
                await maybe_unload_orphaned_role(hub, spoke_id, role, instances)
            return {"status": "ok", "message": f"Instance {instance_id} deleted.",
                    "pushed": pushed}

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
            data = _unwrap_spoke(result)
            if data.get("status") not in ("SUCCESS", "PARTIAL"):
                raise HTTPException(status_code=502,
                                    detail=data.get("message", "NetBox provisioning error"))
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ipam_apply_schema failed")
            raise HTTPException(status_code=500, detail=str(e))
    _instance_crud(
        "ldap-instances", "ldap_instances",
        lambda inst: {
            "LDAP_SERVER_URL": inst.get("server_url"),
            "LDAP_BASE_DN": inst.get("base_dn"),
            "LDAP_ADMIN_DN": inst.get("admin_dn"),
            "LDAP_ADMIN_PW": inst.get("admin_pw"),
        },
    )
    _instance_crud(
        "dns-instances", "dns_instances", None,
        topology_sync=sync_dns_instance_topology)
    _instance_crud("dhcp-instances", "dhcp_instances", None)
