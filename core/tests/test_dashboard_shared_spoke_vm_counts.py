"""Regression tests for per-tenant VM counts on the Dashboard when a tenant's
Proxmox host lives on a SHARED hypervisor spoke.

``_compute_tenant_counts`` (routes/dashboard) originally queried only the SINGLE
spoke directly BOUND to the tenant (``get_hypervisor_spoke_for_tenant``). A
tenant (e.g. LRB) whose Proxmox host dials a SHARED pxmx spoke — pinned to LRB
but bound at the spoke level to the SHARED tenant — therefore had NO directly
bound spoke, so its VMs were never counted (Overview showed ~0/1) while they were
attributed to the SHARED row instead. The fix fans PXMX_LIST_VMS across the
PLURAL visible set (``get_hypervisor_spokes_for_tenant``, shared + pin aware),
merges/de-dupes by ``unique_id``, then subnet-filters — mirroring the
Hypervisors VM page (``get_pxmx_vms``).

These lock in:
* a tenant whose VMs live ONLY on a shared spoke (no bound spoke) is counted;
* the same VM reported by two visible spokes (cluster-mates / global overlap)
  is counted once (unique_id de-dupe);
* a VM outside the tenant's subnets is still excluded (no cross-tenant leak).
"""

import asyncio
import types

from routes.dashboard import register


class _State:
    def __init__(self, tenants, module_metadata, agent_config=None):
        self.system_state = {"active_tenant": "default",
                             "module_metadata": module_metadata,
                             "agent_config": agent_config or {}}
        self._tenants = tenants

    def get_tenant(self, tid):
        return self._tenants.get(tid)


class _Hub:
    def __init__(self, tenants, module_metadata, plural, global_spoke, responses,
                 agent_config=None, agent_spokes=None):
        self.state = _State(tenants, module_metadata, agent_config)
        self._plural = plural
        self._global = global_spoke
        self._responses = responses
        self._agent_spokes = agent_spokes or {}

    def get_spoke_by_type(self, t):
        return {"ipam": "ipam-1", "nac": "nac-1"}.get(t)

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        return self._agent_spokes.get(agent_id)

    def get_hypervisor_spokes_for_tenant(self, tid):
        return list(self._plural.get(tid, []))

    def get_hypervisor_spoke(self):
        return self._global

    async def request_response(self, spoke, cmd, payload=None, timeout=None):
        payload = payload or {}
        # A pinned-agent (whole-host) query is keyed by (spoke, cmd, agent_id).
        if payload.get("agent_id"):
            return self._responses.get(
                (spoke, cmd, payload["agent_id"]),
                self._responses.get((spoke, cmd), {}))
        return self._responses.get((spoke, cmd), {})


class _App:
    def __init__(self, hub):
        self.state = types.SimpleNamespace(hub=hub)
        self.routes = {}

    def get(self, path):
        def deco(fn):
            self.routes[("GET", path)] = fn
            return fn
        return deco

    def post(self, path):
        def deco(fn):
            self.routes[("POST", path)] = fn
            return fn
        return deco


def _ctx(prefixes):
    async def _resolve_prefixes_for_tenant(hub, tid):
        return list(prefixes.get(tid, []))

    return types.SimpleNamespace(
        _session_user=lambda request: {"tenant": "lrb", "admin": True},
        _is_admin=lambda sess: True,
        _resolve_tenant=lambda request, explicit=None: explicit or "lrb",
        _resolve_prefixes_for_tenant=_resolve_prefixes_for_tenant,
        _filter_enabled=lambda hub, module: True,
    )


def _summary(hub, ctx, tenant="lrb"):
    app = _App(hub)
    register(app, hub, ctx)
    handler = app.routes[("GET", "/api/dashboard/summary")]
    return asyncio.run(handler(types.SimpleNamespace(), tenant=tenant))


_TENANTS = {"lrb": {"netbox_tenant_slug": "lrb", "proxmox_tag": ""}}
_LRB_PREFIXES = {"lrb": ["10.10.0.0/24"]}


def _vm(vmid, ip, node="n1", cluster="c1", status="running"):
    return {"unique_id": f"{cluster}/{node}/{vmid}", "vmid": vmid, "node": node,
            "status": status, "ips": [ip] if ip else []}


def test_shared_spoke_vms_counted_for_tenant_without_bound_spoke():
    """LRB has no directly-bound hypervisor spoke; all its VMs live on a shared
    spoke visible via the plural resolver. They must be counted."""
    vms = [_vm(101, "10.10.0.11"), _vm(102, "10.10.0.12"), _vm(103, "10.10.0.13")]
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
        plural={"lrb": ["shared-pxmx"]},
        global_spoke="shared-pxmx",
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": vms}},
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["vms"] == 3


def test_same_vm_from_two_spokes_deduped():
    """A cluster-mate spoke (or the global-overlap fallback) re-reporting the
    same VM must not double-count — de-dupe is by unique_id."""
    shared_vms = [_vm(201, "10.10.0.21"), _vm(202, "10.10.0.22")]
    mate_vms = [_vm(202, "10.10.0.22"), _vm(203, "10.10.0.23")]  # 202 overlaps
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"},
                         "mate-pxmx": {"tenant_id": "shared"}},
        plural={"lrb": ["shared-pxmx", "mate-pxmx"]},
        global_spoke=None,
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": shared_vms},
                   ("mate-pxmx", "PXMX_LIST_VMS"): {"vms": mate_vms}},
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["vms"] == 3  # 201, 202, 203 — not 4


def test_vm_outside_tenant_subnet_excluded():
    """A shared-spoke VM whose IP is outside LRB's prefixes stays attributed
    elsewhere — the subnet filter still isolates it."""
    vms = [_vm(301, "10.10.0.31"), _vm(302, "192.168.9.9")]  # 302 not in lrb
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
        plural={"lrb": ["shared-pxmx"]},
        global_spoke=None,
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": vms}},
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["vms"] == 1


def test_tag_attributed_vm_off_subnet_counted():
    """The reported bug: on a SHARED host a tenant's VMs are attributed by
    Proxmox TAG, and their IPs are typically OFF the tenant's NetBox subnets.
    The Overview must count a VM tagged for the tenant even when its IP is not in
    the tenant's prefixes (the subnet-only filter dropped these → undercount).
    Mirrors the Hypervisors VM page (filter_hypervisor_vms tag override)."""
    vms = [
        _vm(401, "10.10.0.41"),                       # subnet match
        {**_vm(402, "192.168.50.2"), "tags": ["lrb"]},   # off-subnet, tagged lrb
        {**_vm(403, None), "tags": ["lrb"]},             # stopped/no-IP, tagged lrb
        _vm(404, "192.168.50.9"),                     # off-subnet, untagged → excluded
    ]
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
        plural={"lrb": ["shared-pxmx"]},
        global_spoke=None,
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": vms}},
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["vms"] == 3  # 401 (subnet) + 402/403 (tag) — 404 stays excluded


def test_pinned_agent_whole_host_vms_counted_off_subnet_untagged():
    """The LRB case: a Proxmox host is PINNED to the tenant on a SHARED spoke
    (agent_config[agent].client_simulation.tenant_id == 'lrb'). EVERY VM on that
    host is owned by LRB — even off-subnet AND untagged — via whole-host
    ownership. The per-spoke fan-out (subnet/tag filtered) keeps only the
    on-subnet VM; the agent-scoped query adds the rest unconditionally."""
    # Shared-spoke general fan-out: mixed VMs, only 501 is on LRB's subnet.
    spoke_vms = [_vm(501, "10.10.0.51"),
                 _vm(502, "192.168.7.2"),   # off-subnet, untagged
                 _vm(503, "192.168.7.3")]   # off-subnet, untagged
    # Agent-scoped (pinned host) query: all three are on LRB's pinned host.
    host_vms = [_vm(501, "10.10.0.51"), _vm(502, "192.168.7.2"), _vm(503, "192.168.7.3")]
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
        plural={"lrb": ["shared-pxmx"]},
        global_spoke=None,
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": spoke_vms},
                   ("shared-pxmx", "PXMX_LIST_VMS", "agent-lrb-1"): {"vms": host_vms}},
        agent_config={"agent-lrb-1": {"client_simulation": {"tenant_id": "lrb"}},
                      "agent-ra-1": {"client_simulation": {"tenant_id": "ra"}}},
        agent_spokes={"agent-lrb-1": "shared-pxmx", "agent-ra-1": "shared-pxmx"},
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["vms"] == 3  # 501 (subnet) + 502/503 (whole-host pinned) — all counted


def test_pinned_agent_stopped_vm_not_counted():
    """Whole-host ownership still only counts RUNNING VMs (Overview semantics).
    A stopped VM on the pinned host is owned but not counted as running."""
    host_vms = [_vm(601, "192.168.7.10"), _vm(602, "192.168.7.11", status="stopped")]
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
        plural={"lrb": ["shared-pxmx"]},
        global_spoke=None,
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": []},
                   ("shared-pxmx", "PXMX_LIST_VMS", "agent-lrb-1"): {"vms": host_vms}},
        agent_config={"agent-lrb-1": {"client_simulation": {"tenant_id": "lrb"}}},
        agent_spokes={"agent-lrb-1": "shared-pxmx"},
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["vms"] == 1  # only the running one
