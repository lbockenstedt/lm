"""Regression tests for ``routes.pxmx._merge_pinned_agent_vms`` — the
Hypervisors VM-list page's whole-host ownership merge.

``get_pxmx_vms`` fans PXMX_LIST_VMS across every spoke visible to a tenant and
then subnet/tag-filters the merged list (``_filter_tenant`` /
``filter_hypervisor_vms``). That correctly SPLITS a genuinely shared host's
VMs among tenants by IP/Proxmox-tag, but a host explicitly PINNED to one
tenant (per-agent Tenant button -> ``agent_config[agent].client_simulation.
tenant_id``) is WHOLLY that tenant's: every VM on it belongs regardless of
subnet/tag. Before this fix ``get_pxmx_vms`` had no such merge at all (unlike
the Dashboard's ``_compute_tenant_counts``, which already unions pinned-agent
VMs in for every tenant except "default") — an untagged/off-subnet VM on a
pinned-but-shared-spoke host silently dropped off the Hypervisors page for
ANY tenant, including the admin/default tenant the user reported.
"""
import asyncio
import os
import sys

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from routes.pxmx import _merge_pinned_agent_vms  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _vm(vmid, node="n1", cluster="c1"):
    return {"unique_id": f"{cluster}/{node}/{vmid}", "vmid": vmid, "node": node}


class _FakeHub:
    def __init__(self, agent_config, agent_spokes, responses):
        self.state = type("S", (), {"system_state": {"agent_config": agent_config}})()
        self._agent_spokes = agent_spokes
        self._responses = responses

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        return self._agent_spokes.get(agent_id)

    async def request_response(self, spoke, cmd, payload=None, timeout=None):
        payload = payload or {}
        return self._responses.get((spoke, cmd, payload.get("agent_id")), {})


def test_no_tid_returns_data_unchanged():
    hub = _FakeHub({}, {}, {})
    data = {"vms": [_vm(1)]}
    out = _run(_merge_pinned_agent_vms(hub, data, None, None))
    assert out is data


def test_no_pinned_agents_for_tenant_returns_data_unchanged():
    hub = _FakeHub(
        agent_config={"agent-ra-1": {"client_simulation": {"tenant_id": "ra"}}},
        agent_spokes={"agent-ra-1": "shared-pxmx"},
        responses={},
    )
    data = {"vms": [_vm(1)]}
    out = _run(_merge_pinned_agent_vms(hub, data, "default", None))
    assert out is data


def test_pinned_host_vms_unioned_in_unconditionally():
    """VM 2 and 3 are off-subnet/untagged (would be dropped by the subnet/tag
    filter upstream) but live on a host PINNED to "default" — they must be
    added back unconditionally."""
    filtered = {"vms": [_vm(1)]}  # only the on-subnet VM survived _filter_tenant
    hub = _FakeHub(
        agent_config={"agent-default-1": {"client_simulation": {"tenant_id": "default"}},
                      "agent-ra-1": {"client_simulation": {"tenant_id": "ra"}}},
        agent_spokes={"agent-default-1": "shared-pxmx", "agent-ra-1": "shared-pxmx"},
        responses={("shared-pxmx", "PXMX_LIST_VMS", "agent-default-1"):
                   {"vms": [_vm(1), _vm(2), _vm(3)]}},
    )
    out = _run(_merge_pinned_agent_vms(hub, filtered, "default", {"shared-pxmx"}))
    ids = sorted(v["vmid"] for v in out["vms"])
    assert ids == [1, 2, 3]


def test_restricted_to_visible_spokes():
    """A pinned agent on a spoke NOT in ``visible_spokes`` is skipped — the
    merge must never widen spoke-level tenant visibility."""
    filtered = {"vms": []}
    hub = _FakeHub(
        agent_config={"agent-default-1": {"client_simulation": {"tenant_id": "default"}}},
        agent_spokes={"agent-default-1": "other-pxmx"},
        responses={("other-pxmx", "PXMX_LIST_VMS", "agent-default-1"): {"vms": [_vm(9)]}},
    )
    out = _run(_merge_pinned_agent_vms(hub, filtered, "default", {"shared-pxmx"}))
    assert out["vms"] == []


def test_visible_spokes_none_means_no_restriction():
    filtered = {"vms": []}
    hub = _FakeHub(
        agent_config={"agent-default-1": {"client_simulation": {"tenant_id": "default"}}},
        agent_spokes={"agent-default-1": "any-pxmx"},
        responses={("any-pxmx", "PXMX_LIST_VMS", "agent-default-1"): {"vms": [_vm(9)]}},
    )
    out = _run(_merge_pinned_agent_vms(hub, filtered, "default", None))
    assert [v["vmid"] for v in out["vms"]] == [9]


def test_dedupe_by_unique_id_against_already_filtered_vm():
    """A VM already kept by the subnet/tag filter AND reported again by the
    pinned-agent query must not be duplicated."""
    filtered = {"vms": [_vm(1)]}
    hub = _FakeHub(
        agent_config={"agent-default-1": {"client_simulation": {"tenant_id": "default"}}},
        agent_spokes={"agent-default-1": "shared-pxmx"},
        responses={("shared-pxmx", "PXMX_LIST_VMS", "agent-default-1"): {"vms": [_vm(1), _vm(2)]}},
    )
    out = _run(_merge_pinned_agent_vms(hub, filtered, "default", {"shared-pxmx"}))
    assert sorted(v["vmid"] for v in out["vms"]) == [1, 2]
