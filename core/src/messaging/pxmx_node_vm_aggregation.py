"""Shared Proxmox node-stats / VM-list aggregation for ANY agent-hosting
control plane (pxmx's dedicated hypervisor spoke, a cs/simulation spoke
hosting its own Proxmox agent listener, or any future agent-hosting spoke
type).

Ported out of pxmx's ``ProxmoxSpoke`` (``_get_node_stats``/``_list_vms`` +
their helpers) — that copy operated on ``self.control_plane``; this one takes
the control plane (``cp``) as an explicit argument so ``BaseControlPlane.
handle_system_command`` can answer ``GET_NODE_STATS``/``PXMX_LIST_VMS``
directly for EVERY agent-hosting spoke, the same way it already answers
``GET_AGENTS`` — no per-product wiring needed. Before this, only a dedicated
pxmx spoke could answer these two commands; a cs spoke hosting a Proxmox
agent (the split-topology case) had no handler for them at all, so the hub's
fan-out (``get_all_hypervisor_spokes``) silently dropped its nodes/VMs from
the Hypervisors page even though the spoke itself was connected, approved,
and its agent was live.

``cp`` only needs the ``AgentHostingControlPlane`` contract: ``connected_agents``
(dict), ``send_to_agent()`` (coroutine), and optionally ``disk_cache`` (pxmx-only
last-known-data fallback; degrades to empty when absent, e.g. on a cs spoke).
"""
import asyncio
import logging
from typing import Any, Dict, List

try:
    from .. import pve_cmd_builder
except ImportError:  # imported off a stale path (messaging.* top-level, no repo root on sys.path)
    import pve_cmd_builder  # type: ignore

logger = logging.getLogger(__name__)


# ── Node stats ────────────────────────────────────────────────────────────

async def _node_stats_from_agent(cp, agent_id: str) -> Dict[str, Any]:
    """GET_NODE_STATS via multi-round-trip RUN_COMMAND.

    Reproduces the Agent's ``get_node_stats`` orchestration on the control
    plane so the Agent stays a dumb executor: primary ``pvesh get
    /cluster/resources`` (type==node) → one first-node ``/status`` for the
    cluster-wide pveversion; fallback ``pvesh get /nodes`` → per-node
    ``/status``. The ``cluster`` field is stamped from ``connected_agents``
    (the Agent used ``self.cluster_name``). On a total agent failure returns
    ``{nodes:[], error}`` (the Agent's outer-try shape); a pvesh error alone
    yields empty nodes (read-only, non-fatal), matching the Agent.
    """
    info = (cp.connected_agents or {}).get(agent_id, {}) if cp else {}
    cluster = info.get("cluster_name", agent_id)

    async def _send(cmd: str, timeout: float = 12.0):
        return await cp.send_to_agent(
            "RUN_COMMAND",
            {"command": cmd, "allow_shell": True, "timeout": timeout},
            agent_id=agent_id, timeout=15.0)

    try:
        # Primary: /cluster/resources filtered to type==node.
        res = await _send(pve_cmd_builder.cluster_resources_cmd())
        nodes = pve_cmd_builder.parse_cluster_resource_nodes(res, cluster)
        if nodes:
            # Best-effort cluster-wide pveversion from the first node.
            try:
                stat = await _send(pve_cmd_builder.node_status_cmd(nodes[0]["node"]))
                pve_ver = pve_cmd_builder.parse_pveversion(stat)
                if pve_ver:
                    for n in nodes:
                        n["proxmox_version"] = pve_ver
            except Exception as e:  # node-status trip failure is non-fatal
                logger.debug("GET_NODE_STATS pveversion for %s: %s", agent_id, e)
            return {"nodes": nodes, "cluster": cluster}

        # Fallback: /nodes listing → per-node /status.
        res = await _send(pve_cmd_builder.nodes_list_cmd())
        entries = pve_cmd_builder.parse_nodes_list_entries(res)
        nodes = []
        for nrec in entries:
            try:
                stat = await _send(pve_cmd_builder.node_status_cmd(nrec["node"]))
                nodes.append(pve_cmd_builder.node_from_status(stat, nrec, cluster))
            except Exception as e:  # one node's /status failing is non-fatal
                logger.debug("GET_NODE_STATS node %s: %s", nrec.get("node"), e)
        return {"nodes": nodes, "cluster": cluster}
    except Exception as e:
        # send_to_agent raised (agent unreachable) — Agent's total-failure shape.
        logger.warning("GET_NODE_STATS agent %s failed: %s", agent_id, e)
        return {"nodes": [], "error": str(e)}


async def get_node_stats(cp, data: Dict[str, Any]) -> Dict[str, Any]:
    if not cp:
        return {"status": "ERROR", "error": "Control plane not initialised"}

    agent_id = data.get("agent_id")
    if agent_id:
        # Multi-round-trip: build pvesh commands + send RUN_COMMAND to the
        # dumb Agent, orchestrating the parse/merge the Agent's
        # get_node_stats used to do. Returns the Agent's shape ({nodes,
        # cluster}) verbatim so the hub sees the same contract.
        return await _node_stats_from_agent(cp, agent_id)

    # Aggregate from all agents via telemetry cache (avoid hammering PVE API)
    all_nodes: List[Dict] = []
    for aid, info in cp.connected_agents.items():
        cluster = info.get("cluster_name", aid)
        for node in info.get("nodes", []):
            all_nodes.append({**node, "agent_id": aid, "cluster": cluster})

    if not all_nodes:
        # Telemetry not yet received — orchestrate per-agent RUN_COMMAND
        # round-trips (same helper as the pinned path) instead of the typed
        # GET_NODE_STATS the Agent used to answer. Best-effort per agent; an
        # agent that fails (unreachable/pvesh error) contributes no nodes.
        # All agents queried in PARALLEL (gather) — same bounded-fan-out
        # treatment as list_vms' live query.
        aids = list(cp.connected_agents or {})
        results = await asyncio.gather(
            *[_node_stats_from_agent(cp, a) for a in aids],
            return_exceptions=True)
        for aid, res in zip(aids, results):
            if isinstance(res, Exception) or not isinstance(res, dict):
                continue
            for node in res.get("nodes", []):
                all_nodes.append({**node, "agent_id": aid})

    if not all_nodes:
        # No agents connected — serve last-known data from disk cache
        # (pxmx only; a cs control plane has no disk_cache and degrades to {}).
        disk_cache = getattr(cp, "disk_cache", {})
        for aid, info in disk_cache.items():
            cluster = info.get("cluster_name", aid)
            for node in info.get("nodes", []):
                all_nodes.append({**node, "agent_id": aid, "cluster": cluster})
        if all_nodes:
            return {"status": "SUCCESS", "nodes": all_nodes, "stale": True}

    return {"status": "SUCCESS", "nodes": all_nodes}


# ── VM list (aggregated) ──────────────────────────────────────────────────

async def _pool_map_from_agent(cp, agent_id: str, _send, probe) -> Dict[Any, str]:
    """Best-effort ``{vmid: poolid}`` from ``/pools`` (+ per-pool detail).
    ``probe`` is the already-fetched ``/pools`` response (the reachability
    check round-trip is reused rather than re-sent). ``{}`` on any failure."""
    try:
        listing = pve_cmd_builder.parse_pools_listing_for_members(probe)
        details: Dict[str, List[Dict[str, Any]]] = {}
        for p in listing:
            if p.get("members") is None:
                details[p["poolid"]] = pve_cmd_builder.pool_detail_members(
                    await _send(pve_cmd_builder.pool_detail_cmd(p["poolid"])))
        return pve_cmd_builder.build_pool_map(listing, details)
    except Exception as e:  # pool map is best-effort — never sink the VM list
        logger.debug("pool map for %s unavailable: %s", agent_id, e)
        return {}


async def _vm_interfaces(_send, v: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Best-effort ``[{name, mac, ips}]`` for one VM/CT. Running → guest
    interfaces (QGA / lxc netns); stopped or empty → ``qm/pct config`` netN
    MACs. Mirrors the Agent's ``_vm_interfaces`` (4s per-call timeout)."""
    node, vmid = v.get("node", ""), v.get("vmid")
    kind = "qemu" if v.get("type") == "qemu" else "lxc"
    status = v.get("status")
    ifaces: List[Dict[str, Any]] = []
    if status == "running":
        try:
            r = await _send(pve_cmd_builder.vm_guest_ifaces_cmd(node, vmid, kind),
                            timeout=4.0)
            ifaces = pve_cmd_builder.parse_guest_ifaces(r)
        except Exception:
            ifaces = []
    if not ifaces:  # QGA absent / stopped / empty → configured MACs
        try:
            r = await _send(pve_cmd_builder.vm_config_cmd(node, vmid, kind),
                            timeout=4.0)
            ifaces = pve_cmd_builder.parse_config_nets(r)
        except Exception:
            ifaces = []
    return ifaces


async def _annotate_vm_interfaces(vms: List[Dict[str, Any]], _send) -> None:
    """Per-VM interface annotation in parallel — bounded by a 16-concurrent
    semaphore and a 12s deadline so a hung guest agent can't stall the list.
    Mirrors the Agent's ``_annotate_vm_interfaces`` (which the telemetry loop
    still uses internally). Best-effort: VMs not annotated before the deadline
    keep ``interfaces=[]``/``ips=[]`` (filled next telemetry tick)."""
    targets = [v for v in vms if v.get("node") and v.get("vmid") not in (None, "")]
    if not targets:
        return
    sem = asyncio.Semaphore(16)

    async def _one(v):
        async with sem:
            try:
                ifaces = await _vm_interfaces(_send, v)
            except Exception:  # one VM's annotation failure is non-fatal
                ifaces = []
            v["interfaces"] = ifaces
            v["ips"] = [ip for i in ifaces for ip in (i.get("ips") or [])]

    try:
        await asyncio.wait_for(
            asyncio.gather(*[_one(v) for v in targets], return_exceptions=True),
            timeout=12)
    except asyncio.TimeoutError:
        pass  # partial — un-annotated VMs keep interfaces=[]/ips=[]


async def _vms_from_agent(cp, agent_id: str) -> Dict[str, Any]:
    """PXMX_LIST_VMS via multi-round-trip RUN_COMMAND.

    Reproduces the Agent's ``get_vm_list`` on the control plane so the Agent
    is a dumb executor: (1) best-effort vmid→poolid map from ``/pools`` (+
    per-pool ``/pools/{pid}`` detail when members aren't inline); (2) base VM
    list — primary ``/cluster/resources`` filtered to qemu/lxc, fallback
    ``/nodes`` → per-node ``/qemu`` + ``/lxc``; (3) per-VM interface
    annotation issued CONCURRENTLY (send_to_agent multiplexes in-flight
    requests per agent) with a 16-concurrent semaphore + 12s deadline,
    mirroring the Agent's ``_annotate_vm_interfaces``. ``cluster`` is stamped
    from ``connected_agents`` (the Agent used ``self.cluster_name``). On an
    unreachable agent returns ``{status:ERROR, message}`` (so the pinned path
    surfaces it honestly, not as "0 VMs synced, success"); on a reachable-but-
    failed query returns the Agent's ``{vms:[], cluster, error}`` shape."""
    info = (cp.connected_agents or {}).get(agent_id, {}) if cp else {}
    cluster = info.get("cluster_name", agent_id)

    async def _send(cmd: str, timeout: float = 12.0):
        return await cp.send_to_agent(
            "RUN_COMMAND",
            {"command": cmd, "allow_shell": True, "timeout": timeout},
            agent_id=agent_id, timeout=15.0)

    # Reachability check: a RUN_COMMAND to an unreachable agent returns the
    # agent-level ERROR dict (not a runner dict). Surface it honestly so the
    # pinned sync records an 'error' status instead of an empty 'success'.
    probe = await _send(pve_cmd_builder.list_pools_cmd())
    if isinstance(probe, dict) and probe.get("status") == "ERROR":
        return {"status": "ERROR",
                "message": probe.get("message", f"agent {agent_id} unreachable")}

    try:
        pool_map = await _pool_map_from_agent(cp, agent_id, _send, probe)

        # Primary: /cluster/resources filtered to qemu/lxc.
        r = await _send(pve_cmd_builder.cluster_resources_cmd())
        vms = pve_cmd_builder.parse_cluster_resource_vms(r, cluster, pool_map)
        if not vms:
            # Fallback: /nodes → per-node /qemu + /lxc.
            rn = await _send(pve_cmd_builder.nodes_list_cmd())
            for node in pve_cmd_builder.node_names(rn):
                rq = await _send(pve_cmd_builder.node_qemu_cmd(node))
                vms += pve_cmd_builder.parse_node_vm_list(rq, node, "qemu", cluster, pool_map)
                rl = await _send(pve_cmd_builder.node_lxc_cmd(node))
                vms += pve_cmd_builder.parse_node_vm_list(rl, node, "lxc", cluster, pool_map)

        await _annotate_vm_interfaces(vms, _send)
        return {"vms": vms, "cluster": cluster}
    except Exception as e:
        logger.warning("PXMX_LIST_VMS agent %s failed: %s", agent_id, e)
        return {"vms": [], "cluster": cluster, "error": str(e)}


async def list_vms(cp, data: Dict[str, Any]) -> Dict[str, Any]:
    if not cp:
        return {"status": "ERROR", "error": "Control plane not initialised"}

    agent_id = data.get("agent_id")
    tag_filter = data.get("tag_filter", "").lower() or None

    # Single agent request (sync scoped to one pinned Proxmox server).
    # The tenant tag_filter still applies — pinning a server must NOT bypass
    # tenant scoping (otherwise every tenant's VMs on that server would sync).
    # If the pinned agent is unreachable, send_to_agent returns an ERROR dict;
    # surface it honestly so the hub records an 'error' sync status instead
    # of silently reading an empty vms list as "0 records synced, success".
    if agent_id:
        result = await _vms_from_agent(cp, agent_id)
        if not isinstance(result, dict) or result.get("status") == "ERROR":
            logger.warning("PXMX_LIST_VMS pinned agent %r unreachable: %s",
                           agent_id, result if isinstance(result, dict) else "non-dict")
            return result if isinstance(result, dict) else {"status": "ERROR",
                                                            "message": "agent returned no data"}
        cluster = result.get("cluster", agent_id)
        vms = []
        for vm in result.get("vms", []):
            vm = dict(vm) if isinstance(vm, dict) else {}
            vm["agent_id"] = agent_id
            vm.setdefault("cluster", cluster)
            vm.setdefault("unique_id", f"{cluster}/{vm.get('node','?')}/{vm.get('vmid','?')}")
            vms.append(vm)
        if tag_filter:
            vms = [v for v in vms
                   if tag_filter in [t.lower() for t in (v.get("tags") or [])]]
        logger.info("PXMX_LIST_VMS pinned agent=%s tag_filter=%r -> %d VMs",
                    agent_id, tag_filter, len(vms))
        return {"status": "SUCCESS", "vms": vms, "source": "pinned_agent",
                "agent_count": 1}

    # Aggregate from telemetry cache first (fast, no PVE API call)
    cached_vms: List[Dict] = []
    for aid, info in cp.connected_agents.items():
        cluster = info.get("cluster_name", aid)
        for vm in info.get("vms", []):
            vmid = vm.get("vmid", "?")
            node = vm.get("node", "?")
            cached_vms.append({
                **vm,
                "agent_id":  aid,
                "cluster":   vm.get("cluster", cluster),
                "unique_id": vm.get("unique_id", f"{cluster}/{node}/{vmid}"),
            })

    if tag_filter:
        cached_vms = [v for v in cached_vms
                      if tag_filter in [t.lower() for t in (v.get("tags") or [])]]

    if cached_vms:
        logger.info("PXMX_LIST_VMS aggregate tag_filter=%r -> %d VMs (telemetry_cache, %d agents)",
                    tag_filter, len(cached_vms), len(cp.connected_agents))
        return {"status": "SUCCESS", "vms": cached_vms,
                "source": "telemetry_cache",
                "agent_count": len(cp.connected_agents)}

    # No telemetry yet — live query all agents via the same RUN_COMMAND
    # orchestration as the pinned path (concurrent across agents; each
    # agent's annotation round-trips are concurrent within). An unreachable
    # agent returns {status:ERROR} and contributes nothing (honest skip).
    aids = list(cp.connected_agents or {})
    results = await asyncio.gather(
        *[_vms_from_agent(cp, a) for a in aids], return_exceptions=True)
    all_vms: List[Dict] = []
    for aid, res in zip(aids, results):
        if isinstance(res, Exception) or not isinstance(res, dict):
            continue
        if res.get("status") == "ERROR":
            continue  # unreachable agent — skip, don't sink the aggregate
        cluster = res.get("cluster", aid)
        for vm in res.get("vms", []):
            vmid = vm.get("vmid", "?")
            node = vm.get("node", "?")
            all_vms.append({
                **vm,
                "agent_id":  aid,
                "cluster":   vm.get("cluster", cluster),
                "unique_id": vm.get("unique_id", f"{cluster}/{node}/{vmid}"),
            })

    if tag_filter:
        all_vms = [v for v in all_vms
                   if tag_filter in [t.lower() for t in (v.get("tags") or [])]]

    if all_vms:
        logger.info("PXMX_LIST_VMS aggregate tag_filter=%r -> %d VMs (live_query, %d agents)",
                    tag_filter, len(all_vms), len(cp.connected_agents))
        return {"status": "SUCCESS", "vms": all_vms, "source": "live_query",
                "agent_count": len(cp.connected_agents)}

    # No agents connected — serve last-known data from disk cache (pxmx only;
    # a cs control plane has no disk_cache and degrades to empty here).
    disk_cache = getattr(cp, "disk_cache", {})
    if disk_cache:
        stale_vms: List[Dict] = []
        for aid, info in disk_cache.items():
            cluster = info.get("cluster_name", aid)
            for vm in info.get("vms", []):
                vmid = vm.get("vmid", "?")
                node = vm.get("node", "?")
                stale_vms.append({
                    **vm,
                    "agent_id":  aid,
                    "cluster":   vm.get("cluster", cluster),
                    "unique_id": vm.get("unique_id", f"{cluster}/{node}/{vmid}"),
                })
        if tag_filter:
            stale_vms = [v for v in stale_vms
                         if tag_filter in [t.lower() for t in (v.get("tags") or [])]]
        if stale_vms:
            return {"status": "SUCCESS", "vms": stale_vms, "source": "disk_cache",
                    "stale": True, "agent_count": 0}

    return {"status": "SUCCESS", "vms": all_vms, "source": "live_query",
            "agent_count": len(cp.connected_agents)}
