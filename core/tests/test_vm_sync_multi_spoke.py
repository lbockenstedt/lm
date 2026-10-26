"""``sync_all_vms`` across several hypervisor spokes.

Each pxmx spoke fronts a different Proxmox cluster. The sync must list ALL of
them before a replace-delete, otherwise each run deletes the other clusters'
VMs from NetBox (seen live: 213 <-> 25 VMs flapping every run).
"""
import asyncio

from vm_sync import VmSyncMixin, _dedupe_by_cluster_vmid


class _Store:
    async def set_vm_sync_status(self, tid, st):
        pass


class _State:
    system_state = {"global_config": {}}
    tenant_state = {"tenants": {}}


class _Hub(VmSyncMixin):
    def __init__(self, lists):
        self.state = _State()
        self.simulations_store = _Store()
        self._lists = lists  # spoke id -> list of VMs, or Exception
        self.pushed = None

    def get_spoke_by_type(self, t):
        if t == "hypervisor":
            return next(iter(self._lists))
        return "netbox-1"

    def refresh_module_cache(self, name):
        pass

    def get_all_spokes_by_type(self, t):
        return list(self._lists)

    async def request_response(self, sid, cmd, payload, timeout=30.0):
        if cmd == "PXMX_LIST_VMS":
            r = self._lists[sid]
            if isinstance(r, Exception):
                raise r
            return {"payload": {"data": {"status": "SUCCESS", "vms": r}}}
        self.pushed = payload
        return {"payload": {"data": {"status": "SUCCESS",
                                     "pushed": len(payload["vms"])}}}


def _vm(cluster, node, vmid, name, ts=0):
    return {"unique_id": f"{cluster}/{node}/{vmid}", "cluster": cluster,
            "node": node, "vmid": vmid, "name": name, "telemetry_ts": ts}


def _run(hub):
    return asyncio.new_event_loop().run_until_complete(hub.sync_all_vms())


def test_lists_every_hypervisor_spoke_and_replaces():
    hub = _Hub({"pxmx-a": [_vm("A", "n1", 100, "a1")],
                "pxmx-b": [_vm("B", "n1", 200, "b1"), _vm("B", "n2", 201, "b2")]})
    _run(hub)
    assert sorted(v["name"] for v in hub.pushed["vms"]) == ["a1", "b1", "b2"]
    assert hub.pushed["replace"] is True


def test_failed_spoke_disables_replace_delete():
    hub = _Hub({"pxmx-a": [_vm("A", "n1", 100, "a1")],
                "pxmx-b": RuntimeError("timed out")})
    _run(hub)
    assert [v["name"] for v in hub.pushed["vms"]] == ["a1"]
    assert hub.pushed["replace"] is False


def test_every_spoke_failing_pushes_nothing():
    hub = _Hub({"pxmx-a": RuntimeError("down")})
    out = _run(hub)
    assert out["status"] == "error"
    assert hub.pushed is None


def test_migrated_vm_reported_on_two_nodes_is_sent_once():
    hub = _Hub({"pxmx-a": [_vm("A", "old", 100, "web", ts=10)],
                "pxmx-b": [_vm("A", "new", 100, "web", ts=20)]})
    _run(hub)
    assert [v["node"] for v in hub.pushed["vms"]] == ["new"]


def test_dedupe_keeps_rows_without_cluster_or_vmid():
    rows = [{"unique_id": "x", "name": "x"}, _vm("A", "n", 1, "a"), _vm("A", "m", 1, "a", ts=5)]
    out = _dedupe_by_cluster_vmid(rows)
    assert len(out) == 2
    assert {"unique_id": "x", "name": "x"} in out
    assert any(v.get("node") == "m" for v in out)
