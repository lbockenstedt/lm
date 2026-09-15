"""Regression: VM actions must reach the spoke that OWNS the VM.

The Hypervisors VM list is MERGED across every agent-hosting spoke
(``_merge_pxmx_list_vms`` fans ``PXMX_LIST_VMS`` out to all of them — a lab can
easily run three ``hypervisor`` spokes plus cs spokes hosting their own Proxmox
agents). VM ACTIONS, however, relayed to the single ``get_hypervisor_spoke()``.

So every start/stop/snapshot/**delete** on a VM owned by one of the OTHER spokes
was sent to a spoke whose agents don't host it. The receiving spoke's
``_resolve_agent_for_vm`` then fell back to its *first* connected agent, so the
command either failed or — worse — ran against the same vmid on the wrong
cluster. Identical shape to the DHCP cross-cluster write bug.

``resolve_vm_spoke`` resolves the owner from the explicit ``agent_id`` or the
VM's node hostname (the middle segment of ``<cluster>/<node>/<vmid>``) via the
hub's ``agent_info`` index, and the bulk route now fans ONE
``PXMX_VM_ACTION_BULK`` per owning spoke instead of one for the whole batch.
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx_vm


class _Store:
    def get_all_protected_vms(self):
        return set()


class _Hub:
    """Three agent-hosting spokes; records which spoke each relay went to."""

    def __init__(self):
        self.simulations_store = _Store()
        self.relayed = []   # [(spoke_id, cmd, payload)]
        # node hostname → owning spoke (what AGENT_RELAY_UP builds on the hub)
        self.agent_info = {
            "a-alpha": {"spoke_id": "pxmx-alpha", "agent_id": "a-alpha",
                        "hostname": "pve-alpha"},
            "a-bravo": {"spoke_id": "pxmx-bravo", "agent_id": "a-bravo",
                        "hostname": "pve-bravo"},
        }

    def get_hypervisor_spoke(self):
        return "pxmx-alpha"      # the historical single-spoke answer

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        info = self.agent_info.get(agent_id)
        if info:
            return info["spoke_id"]
        return self.get_hypervisor_spoke() if fallback_hypervisor else None

    async def request_response(self, sid, cmd, payload, timeout=35.0,
                               signing_secret=None):
        self.relayed.append((sid, cmd, payload))
        if cmd == "PXMX_VM_ACTION_BULK":
            rows = [{"vmid": it.get("vmid"), "ok": True}
                    for it in (payload.get("items") or [])]
            return {"payload": {"data": {"status": "SUCCESS", "results": rows}}}
        return {"payload": {"data": {"status": "SUCCESS", **payload}}}


def _build(hub):
    app = FastAPI()
    app.state.hub = hub
    pxmx_vm.register(app, hub, SimpleNamespace(
        _session_user=lambda request: {"user": {"tenant_id": "acme"}},
        _is_admin=lambda sess: True,
        _resolve_tenant=lambda request, explicit=None: explicit or "acme",
        _filter_tenant=lambda *a, **k: None,
        _trigger_vm_sync_after_pxmx_edit=lambda hub, request, body: None,
    ))
    return TestClient(app)


# ── pure resolver ────────────────────────────────────────────────────────────

def test_node_name_from_unique_id_when_node_absent():
    assert pxmx_vm._vm_node_name({"unique_id": "PXMX/pve-bravo/9001"}) == "pve-bravo"
    assert pxmx_vm._vm_node_name({"node": "pve-alpha"}) == "pve-alpha"
    assert pxmx_vm._vm_node_name({"unique_id": "bad"}) == ""
    assert pxmx_vm._vm_node_name({}) == ""


def test_resolve_prefers_explicit_agent_id():
    assert pxmx_vm.resolve_vm_spoke(_Hub(), {"agent_id": "a-bravo"}) == "pxmx-bravo"


def test_resolve_by_node_hostname():
    hub = _Hub()
    assert pxmx_vm.resolve_vm_spoke(hub, {"node": "pve-bravo"}) == "pxmx-bravo"
    assert pxmx_vm.resolve_vm_spoke(hub, {"node": "PVE-BRAVO"}) == "pxmx-bravo"
    assert pxmx_vm.resolve_vm_spoke(
        hub, {"unique_id": "PXMX/pve-bravo/9001"}) == "pxmx-bravo"


def test_resolve_none_for_unknown_node_so_caller_falls_back():
    assert pxmx_vm.resolve_vm_spoke(_Hub(), {"node": "pve-ghost"}) is None


def test_resolve_tolerates_hub_without_agent_index():
    # A hub that hasn't indexed any agent yet must not raise — the action route
    # falls back to get_hypervisor_spoke().
    assert pxmx_vm.resolve_vm_spoke(SimpleNamespace(), {"node": "pve1"}) is None


# ── single-VM route ──────────────────────────────────────────────────────────

def test_single_action_routes_to_owning_spoke():
    hub = _Hub()
    r = _build(hub).post("/api/pxmx/vm-action", json={
        "unique_id": "PXMX/pve-bravo/9001", "vmid": 9001, "node": "pve-bravo",
        "type": "qemu", "action": "destroy"})
    assert r.status_code == 200
    assert hub.relayed[0][0] == "pxmx-bravo"


def test_single_action_falls_back_to_default_spoke():
    hub = _Hub()
    r = _build(hub).post("/api/pxmx/vm-action", json={
        "unique_id": "PXMX/pve-ghost/9001", "vmid": 9001, "node": "pve-ghost",
        "type": "qemu", "action": "stop"})
    assert r.status_code == 200
    assert hub.relayed[0][0] == "pxmx-alpha"


# ── bulk route ───────────────────────────────────────────────────────────────

def test_bulk_fans_one_request_per_owning_spoke():
    hub = _Hub()
    r = _build(hub).post("/api/pxmx/vm-action-bulk", json={
        "action": "destroy",
        "items": [
            {"unique_id": "PXMX/pve-alpha/9001", "vmid": 9001, "node": "pve-alpha", "type": "qemu"},
            {"unique_id": "PXMX/pve-bravo/9002", "vmid": 9002, "node": "pve-bravo", "type": "qemu"},
            {"unique_id": "PXMX/pve-bravo/9003", "vmid": 9003, "node": "pve-bravo", "type": "qemu"},
        ]})
    assert r.status_code == 200
    by_spoke = {sid: payload for sid, cmd, payload in hub.relayed
                if cmd == "PXMX_VM_ACTION_BULK"}
    assert set(by_spoke) == {"pxmx-alpha", "pxmx-bravo"}
    assert [it["vmid"] for it in by_spoke["pxmx-alpha"]["items"]] == [9001]
    assert [it["vmid"] for it in by_spoke["pxmx-bravo"]["items"]] == [9002, 9003]
    # Every VM is accounted for exactly once in the merged result.
    body = r.json()
    assert body["total"] == 3 and body["ok"] == 3
    assert sorted(row["vmid"] for row in body["results"]) == [9001, 9002, 9003]


def test_bulk_unknown_node_group_uses_default_spoke():
    hub = _Hub()
    r = _build(hub).post("/api/pxmx/vm-action-bulk", json={
        "action": "stop",
        "items": [{"unique_id": "PXMX/pve-ghost/9009", "vmid": 9009,
                   "node": "pve-ghost", "type": "qemu"}]})
    assert r.status_code == 200
    assert hub.relayed[0][0] == "pxmx-alpha"


def test_bulk_one_spoke_failing_does_not_sink_the_other():
    hub = _Hub()
    orig = hub.request_response

    async def _rr(sid, cmd, payload, timeout=35.0, signing_secret=None):
        if sid == "pxmx-bravo":
            raise RuntimeError("spoke offline")
        return await orig(sid, cmd, payload, timeout=timeout)

    hub.request_response = _rr
    r = _build(hub).post("/api/pxmx/vm-action-bulk", json={
        "action": "destroy",
        "items": [
            {"unique_id": "PXMX/pve-alpha/9001", "vmid": 9001, "node": "pve-alpha", "type": "qemu"},
            {"unique_id": "PXMX/pve-bravo/9002", "vmid": 9002, "node": "pve-bravo", "type": "qemu"},
        ]})
    rows = {row["vmid"]: row for row in r.json()["results"]}
    assert rows[9001]["ok"] is True
    assert rows[9002]["ok"] is False and "offline" in rows[9002]["error"]
