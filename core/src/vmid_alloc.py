"""LM hub Proxmox VMID auto-allocation (optional, OFF by default).

When the ``pxmx_auto_allocate_vmid.enabled`` config flag is ON, the hub picks
the next free Proxmox VMID inside the acting tenant's ``[vmid_start, vmid_end]``
range (read from NetBox custom fields on the tenant) before a create/clone,
instead of letting Proxmox pick a global ``/cluster/nextid``. The candidate is
verified against the live cluster (``PXMX_LIST_VMS``) so a VMID in use
out-of-band — e.g. by an untagged/other-tenant VM not yet reflected in NetBox —
is never handed out. This mirrors the operator's intent: pull the range from
NetBox for the assigned tenant, then verify the chosen VMID is not in use on
the cluster.

Returns the chosen int, or ``None`` to fall back to Proxmox ``nextid`` (no
tenant slug, no range set, range exhausted, or a spoke unavailable). The
create/clone routes only consult this when the knob is enabled AND the caller
did not supply an explicit ``new_vmid`` — so with the knob OFF (the default)
behavior is exactly today's.

Best-effort for a manually-triggered create/clone; a proper reservation lock is
out of scope until the knob is promoted (two concurrent creates could pick the
same VMID before either lands in NetBox — mitigated by the cluster check +
Proxmox rejecting a duplicate vmid on ``qm create``/``clone``).

Leaf module: imports only stdlib + typing. Uses the hub via duck typing
(``state`` / ``get_spoke_by_type`` / ``request_response``). Must not import
``api`` or ``main`` (no back-import — ``api`` imports this).

Audience: Hub developers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")

_VMID_ALLOC_CFG_KEY = "pxmx_auto_allocate_vmid"


def vmid_alloc_cfg(hub) -> Dict[str, Any]:
    """Read the auto-allocate config fresh (``{enabled: bool}``; default off)."""
    return (hub.state.system_state.get("global_config", {})
            .get(_VMID_ALLOC_CFG_KEY, {})) or {}


async def allocate_vmid(hub, tenant_id: str) -> Optional[int]:
    """Pick the lowest free VMID in the tenant's ``[vmid_start, vmid_end]`` range.

    Free = not already claimed by the tenant's VMs in NetBox AND not in use on
    the cluster (``PXMX_LIST_VMS``). Returns ``None`` when allocation isn't
    possible (no tenant slug, no range set, range exhausted, or a spoke
    unavailable) so the caller falls back to Proxmox ``/cluster/nextid``.
    """
    if not tenant_id:
        return None
    try:
        tcfg = hub.state.get_tenant(tenant_id) or {}
    except Exception:
        return None
    slug = str(tcfg.get("netbox_tenant_slug") or "").strip()
    if not slug:
        logger.debug("vmid-alloc tenant=%s: no netbox_tenant_slug — skip", tenant_id)
        return None

    netbox = hub.get_spoke_by_type("ipam")
    if not netbox:
        logger.debug("vmid-alloc tenant=%s: NetBox spoke down — skip", tenant_id)
        return None
    hyp = hub.get_spoke_by_type("hypervisor")
    if not hyp:
        logger.debug("vmid-alloc tenant=%s: hypervisor spoke down — skip", tenant_id)
        return None

    # 1) Range + NetBox-claimed VMIDs for this tenant.
    try:
        r = await hub.request_response(netbox, "NETBOX_TENANT_VMID_RANGE",
                                       {"tenant_slug": slug}, timeout=20.0)
        rd = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
    except Exception as e:
        logger.debug("vmid-alloc tenant=%s: range read failed: %s", tenant_id, e)
        return None
    if not isinstance(rd, dict) or str(rd.get("status", "")).upper() == "ERROR":
        logger.debug("vmid-alloc tenant=%s: range read ERROR: %s", tenant_id,
                     rd.get("message") if isinstance(rd, dict) else rd)
        return None
    start = rd.get("vmid_start")
    end = rd.get("vmid_end")
    if start is None or end is None:
        logger.info("vmid-alloc tenant=%s: no VMID range set in NetBox — "
                    "falling back to Proxmox nextid", tenant_id)
        return None
    try:
        start = int(start)
        end = int(end)
    except (TypeError, ValueError):
        logger.debug("vmid-alloc tenant=%s: non-integer range (%r-%r)", tenant_id, start, end)
        return None
    if start > end:
        logger.debug("vmid-alloc tenant=%s: range start>end (%d>%d)", tenant_id, start, end)
        return None
    used_nb = set()
    for v in (rd.get("used_vmids") or []):
        try:
            used_nb.add(int(v))
        except (TypeError, ValueError):
            pass

    # 2) Cluster in-use VMIDs (collision guard — a VMID may be in use
    #    out-of-band by a VM not yet reflected in NetBox).
    used_cluster = set()
    try:
        rv = await hub.request_response(hyp, "PXMX_LIST_VMS", {}, timeout=30.0)
        vd = rv.get("payload", {}).get("data", rv) if isinstance(rv, dict) else rv
        vms = (vd or {}).get("vms", []) if isinstance(vd, dict) else []
        for vm in vms or []:
            try:
                used_cluster.add(int((vm or {}).get("vmid")))
            except (TypeError, ValueError):
                pass
    except Exception as e:
        logger.debug("vmid-alloc tenant=%s: cluster list failed: %s", tenant_id, e)
        # Without cluster verification we can't honor the "verify not in use on
        # the cluster" requirement — fall back rather than guess.
        return None

    # 3) Lowest free in range not claimed by NetBox and not in cluster use.
    for candidate in range(start, end + 1):
        if candidate in used_nb or candidate in used_cluster:
            continue
        logger.info("vmid-alloc tenant=%s: allocated vmid=%d (range %d-%d)",
                    tenant_id, candidate, start, end)
        return candidate
    logger.info("vmid-alloc tenant=%s: range %d-%d exhausted — falling back to Proxmox nextid",
                tenant_id, start, end)
    return None