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

from hub_spoke_registry import SpokeRegistryMixin, nac_push_key
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
        self.calls = []

    def get_spoke_by_type(self, t):
        return {"ipam": "ipam-1", "nac": "nac-1"}.get(t)

    def get_cppm_spoke_for_global(self):
        """Return the fixture's safe global NAC source."""
        return "nac-global"

    def get_cppm_spokes_for_tenant(self, tenant_id):
        """Return the fixture's tenant-visible NAC source."""
        return ["nac-shared"]

    # The real scope pick, over the two fixture sources above.
    get_cppm_spoke_for_scope = SpokeRegistryMixin.get_cppm_spoke_for_scope

    def _agent_relay_name(self, agent_id):
        return agent_id

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        return self._agent_spokes.get(agent_id)

    def get_hypervisor_spokes_for_tenant(self, tid):
        return list(self._plural.get(tid, []))

    def get_hypervisor_spoke(self):
        return self._global

    async def request_response(self, spoke, cmd, payload=None, timeout=None):
        payload = payload or {}
        self.calls.append((spoke, cmd, dict(payload)))
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


def test_pinned_agent_on_a_legacy_twin_tenant_not_counted(monkeypatch):
    """With "LRB" and "lrb" both stored, the access checks compare them by
    exact spelling: a host pinned to "LRB" is that tenant's, not lrb's. With
    one lrb tenant, a pin in another case is its own."""
    import access
    host_vms = [_vm(501, "10.10.0.51"), _vm(502, "192.168.7.2"), _vm(503, "192.168.7.3")]

    def _hub():
        """A shared spoke whose pinned host carries off-subnet VMs."""
        return _Hub(
            tenants=_TENANTS,
            module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
            plural={"lrb": ["shared-pxmx"]},
            global_spoke=None,
            responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": [_vm(501, "10.10.0.51")]},
                       ("shared-pxmx", "PXMX_LIST_VMS", "agent-lrb-1"): {"vms": host_vms}},
            agent_config={"agent-lrb-1": {"client_simulation": {"tenant_id": "LRB"}}},
            agent_spokes={"agent-lrb-1": "shared-pxmx"},
        )
    assert _summary(_hub(), _ctx(_LRB_PREFIXES))["vms"] == 3
    monkeypatch.setattr(access, "_AMBIGUOUS_TENANT_IDS", frozenset({"lrb"}))
    assert _summary(_hub(), _ctx(_LRB_PREFIXES))["vms"] == 1


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


def test_dashboard_tenant_summary_uses_tenant_visible_nac_source():
    """Tenant counts use the selected tenant's NAC source, not a global pick."""
    hub = _Hub(
        tenants=_TENANTS,
        module_metadata={},
        plural={"lrb": []},
        global_spoke=None,
        responses={
            ("nac-shared", "CPPM_GET_ACCESS_TRACKER"): {
                "sessions": [{"ip": "10.10.0.15"}],
            },
        },
    )
    out = _summary(hub, _ctx(_LRB_PREFIXES))
    assert out["sessions"] == 1
    assert ("nac-shared", "CPPM_GET_ACCESS_TRACKER", {}) in hub.calls


def test_dashboard_session_count_skips_rows_a_nested_tenant_owns(monkeypatch):
    """On the shared ClearPass a tenant on 10.0.0.0/8 does not count the
    sessions of a tenant on 10.10.0.0/16 inside it, as in the Access Tracker."""
    import access
    prefixes = {"lrb": ["10.0.0.0/8"], "inner": ["10.10.0.0/16"]}

    async def _fetch(hub, tid):
        """Each tenant's NetBox prefixes."""
        return prefixes.get(tid, [])

    monkeypatch.setattr(access, "fetch_tenant_prefixes", _fetch)
    tenants = dict(_TENANTS, inner={"netbox_tenant_slug": "inner", "proxmox_tag": ""})
    hub = _Hub(
        tenants=tenants,
        module_metadata={},
        plural={"lrb": [], "inner": []},
        global_spoke=None,
        responses={("nac-shared", "CPPM_GET_ACCESS_TRACKER"): {
            "sessions": [{"ip": "10.10.0.15"}, {"ip": "10.20.0.5"}]}},
    )
    hub.state.tenant_state = {"tenants": tenants}
    assert _summary(hub, _ctx(prefixes))["sessions"] == 1
    assert _summary(hub, _ctx(prefixes), tenant="inner")["sessions"] == 1


class _NacOwnerHub(_Hub):
    """The dashboard hub whose tenant NAC source is ``spoke``, owned as the
    real record-based ``get_nac_spoke_owner`` decides from ``records``."""

    get_nac_spoke_owner = SpokeRegistryMixin.get_nac_spoke_owner

    def __init__(self, spoke, records, sessions):
        super().__init__(
            tenants=_TENANTS,
            module_metadata={spoke: {"module_type": "nac", "tenant_id": ""}},
            plural={"lrb": []},
            global_spoke=None,
            responses={(spoke, "CPPM_GET_ACCESS_TRACKER"): {"sessions": sessions}},
        )
        self._nac = spoke
        gc = {"nac_instances": records}
        self.state.get_global_config = lambda: gc
        # Each record has a host and the spoke was sent the first one, so
        # it is not stale (hub_spoke_registry.nac_spoke_stale).
        for rec in records:
            rec.setdefault("host", "cp.example")
        self.state.system_state["nac_config_pushed"] = {spoke: nac_push_key(records[0])}
        self.state.get_spoke_tenant = lambda sid: ""

    def _primary_key(self, sid):
        return sid

    def get_cppm_spokes_for_tenant(self, tenant_id):
        """The tenant's NAC source is the fixture's spoke."""
        return [self._nac]


def test_dashboard_counts_an_own_clearpass_in_full_and_a_mixed_one_not_at_all():
    """A spoke serving only the tenant's own ClearPass record counts every
    session, including ones off the tenant's subnets, even when the spoke
    itself is unassigned. A spoke serving two tenants' records counts none
    for either tenant."""
    sessions = [{"ip": "10.10.0.15"}, {"ip": "192.168.5.9"}]
    own = _NacOwnerHub("nac-own", [{"id": "a", "spoke_id": "nac-own", "tenant_id": "lrb"}], sessions)
    assert _summary(own, _ctx(_LRB_PREFIXES))["sessions"] == 2
    mixed = _NacOwnerHub("nac-mixed", [
        {"id": "a", "spoke_id": "nac-mixed", "tenant_id": "lrb"},
        {"id": "b", "spoke_id": "nac-mixed", "tenant_id": "other"}], sessions)
    assert _summary(mixed, _ctx(_LRB_PREFIXES))["sessions"] == 0


def test_dashboard_default_summary_uses_safe_global_nac_source():
    """The admin/default dashboard uses only the explicit global NAC source."""
    tenants = dict(_TENANTS, default={"netbox_tenant_slug": "default", "proxmox_tag": ""})
    prefixes = dict(_LRB_PREFIXES, default=["10.10.0.0/24"])
    hub = _Hub(
        tenants=tenants,
        module_metadata={},
        plural={"default": []},
        global_spoke=None,
        responses={
            ("nac-global", "CPPM_GET_ACCESS_TRACKER"): {
                "sessions": [{"ip": "10.10.0.16"}],
            },
        },
    )
    out = _summary(hub, _ctx(prefixes), tenant="default")
    assert out["sessions"] == 1
    assert ("nac-global", "CPPM_GET_ACCESS_TRACKER", {}) in hub.calls


def test_pinned_agent_whole_host_vms_counted_for_default_tenant():
    """The reported bug: admin/default was special-cased OUT of both the
    plural hv_spokes resolver AND the whole-host pinned-agent merge, so a
    Proxmox host explicitly PINNED to "default" (per-agent Tenant button,
    e.g. the admin assigning a lab host to the ADMIN tenant) only ever
    contributed its on-subnet VMs — off-subnet/untagged VMs on that pinned
    host silently dropped off the Overview for admin/default, even though the
    identical scenario already worked for every other real tenant (lrb/ra/...).
    get_hypervisor_spokes_for_tenant("default") already scopes this safely
    (unassigned + default-pinned + shared only — never another tenant's
    dedicated spoke), so admin/default must get the same treatment."""
    spoke_vms = [_vm(701, "10.10.0.71"),
                 _vm(702, "192.168.9.2"),   # off-subnet, untagged
                 _vm(703, "192.168.9.3")]   # off-subnet, untagged
    host_vms = [_vm(701, "10.10.0.71"), _vm(702, "192.168.9.2"), _vm(703, "192.168.9.3")]
    tenants = dict(_TENANTS, default={"netbox_tenant_slug": "default", "proxmox_tag": ""})
    prefixes = dict(_LRB_PREFIXES, default=["10.10.0.0/24"])
    hub = _Hub(
        tenants=tenants,
        module_metadata={"shared-pxmx": {"tenant_id": "shared"}},
        plural={"default": ["shared-pxmx"]},
        global_spoke=None,
        responses={("shared-pxmx", "PXMX_LIST_VMS"): {"vms": spoke_vms},
                   ("shared-pxmx", "PXMX_LIST_VMS", "agent-default-1"): {"vms": host_vms}},
        agent_config={"agent-default-1": {"client_simulation": {"tenant_id": "default"}}},
        agent_spokes={"agent-default-1": "shared-pxmx"},
    )
    out = _summary(hub, _ctx(prefixes), tenant="default")
    assert out["vms"] == 3  # 701 (subnet) + 702/703 (whole-host pinned) — all counted
