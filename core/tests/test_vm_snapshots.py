"""vm_snapshots — the shared VM snapshot service (scheduled snapshots and OS
Updates' pre-patch snapshots)."""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import vm_snapshots  # noqa: E402

_VMS = [
    {"unique_id": "C/pve1/101", "name": "spoke-a", "vmid": 101, "node": "pve1", "type": "qemu",
     "ips": ["10.0.0.11"], "tags": ["lab"], "pool": "infra"},
    {"unique_id": "C/pve2/102", "name": "spoke-b.lab.local", "vmid": 102, "node": "pve2",
     "type": "qemu", "ips": ["10.0.0.12"], "tags": [], "pool": ""},
    {"unique_id": "C/pve2/103", "name": "dup", "vmid": 103, "node": "pve2", "ips": ["10.0.0.13"]},
    {"unique_id": "C/pve1/104", "name": "dup", "vmid": 104, "node": "pve1", "ips": ["10.0.0.14"]},
    {"unique_id": "C/pve1/900", "name": "tmpl", "vmid": 900, "node": "pve1", "template": 1},
]


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}, "subnet_filter_modules": {"hypervisor": False}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, vms=_VMS, snapshots=None, fail=()):
        self.state = _State()
        self.vms = vms
        self.agent_info = {"g1": {"spoke_id": "px", "agent_id": "agent-pve1", "hostname": "pve1"},
                           "g2": {"spoke_id": "px", "agent_id": "agent-pve2", "hostname": "pve2.lab"}}
        self.snapshots = list(snapshots or [])
        self.fail = set(fail)
        self.calls = []

    # Tenant "t1" sees VM 101 through its spokes/tag; tenant "t2" sees nothing.
    scoped = {"t1": [_VMS[0]], "t2": []}

    def warm_get(self, ns, key):
        assert ns == "pxmx_vms"
        scope = key.split("|")[0]
        return {"vms": self.vms if scope == "_all_" else self.scoped.get(scope, [])}

    def get_hypervisor_spoke(self):
        return "px"

    async def request_response(self, spoke, cmd, data, timeout=None):
        self.calls.append((spoke, data.get("agent_id"), data["action"], data.get("snapshot_name")))
        if data["action"] in self.fail:
            return {"payload": {"data": {"status": "ERROR", "message": "boom"}}}
        if data["action"] == "snapshot":
            self.snapshots.append({"name": data["snapshot_name"], "snaptime": 9_999_999_999})
        if data["action"] == "list_snapshots":
            return {"payload": {"data": {"status": "SUCCESS", "snapshots": self.snapshots}}}
        if data["action"] == "delete_snapshot":
            self.snapshots = [s for s in self.snapshots if s["name"] != data["snapshot_name"]]
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_all_vms_skips_templates():
    assert 900 not in [vm["vmid"] for vm in vm_snapshots.all_vms(_Hub())]


@pytest.mark.parametrize("names, ips, vmid", [
    (["SPOKE-A"], [], 101),
    (["spoke-b"], [], 102),                     # VM name is an FQDN
    (["dup"], ["10.0.0.14"], 104),              # IP breaks a hostname tie
    (["nope"], ["10.0.0.11"], None),            # an IP alone is never enough
    (["dup"], [], None),                        # never guess between two
])
def test_find_vm(names, ips, vmid):
    vm, why = vm_snapshots.find_vm(_Hub(), names, ips)
    assert (vm or {}).get("vmid") == vmid
    assert bool(why) == (vmid is None)


def test_snapshot_runs_on_the_vms_own_node_and_prunes_only_its_prefix():
    hub = _Hub(snapshots=[{"name": "lm-prepatch-1", "snaptime": 1},
                          {"name": "manual", "snaptime": 2},
                          {"name": "lm-prepatch-2", "snaptime": 3}])
    res = _run(vm_snapshots.take_snapshot(hub, _VMS[1], "lm-prepatch-", keep=2))
    assert res["status"] == "SUCCESS" and res["snapshot"].startswith("lm-prepatch-")
    assert res["pruned"] == ["lm-prepatch-1"]
    assert [s["name"] for s in hub.snapshots] == ["manual", "lm-prepatch-2", res["snapshot"]]
    assert {(c[0], c[1]) for c in hub.calls} == {("px", "agent-pve2")}


def test_failed_snapshot_is_an_error_and_prunes_nothing():
    hub = _Hub(snapshots=[{"name": "lm-prepatch-1", "snaptime": 1}], fail={"snapshot"})
    res = _run(vm_snapshots.take_snapshot(hub, _VMS[0], "lm-prepatch-", keep=1))
    assert res["status"] == "ERROR" and [c[2] for c in hub.calls] == ["snapshot"]


def test_failed_prune_does_not_fail_the_snapshot():
    hub = _Hub(snapshots=[{"name": "x-1", "snaptime": 1}], fail={"delete_snapshot"})
    res = _run(vm_snapshots.take_snapshot(hub, _VMS[0], "x-", keep=1))
    assert res["status"] == "SUCCESS" and "could not delete x-1" in res["message"]


def test_bad_prefix_is_refused():
    res = _run(vm_snapshots.take_snapshot(_Hub(), _VMS[0], "1 bad;", keep=1))
    assert res["status"] == "ERROR"


@pytest.mark.parametrize("body", [
    {"every_hours": 24, "keep": 3, "vms": ["C/pve1/101"]},                 # no name
    {"name": "x", "every_hours": 0.5, "keep": 3, "vms": ["C/pve1/101"]},   # too often
    {"name": "x", "every_hours": 24, "keep": 0, "vms": ["C/pve1/101"]},
    {"name": "x", "every_hours": 24, "keep": 3},                           # no targets
])
def test_bad_schedules_are_refused(body):
    with pytest.raises(ValueError):
        vm_snapshots.save_schedule(_Hub(), body)


def test_schedule_picks_vms_by_id_tag_or_pool():
    s = {"vms": ["C/pve2/102"], "tags": ["lab"], "pools": []}
    assert [vm["vmid"] for vm in vm_snapshots.schedule_vms(s, _VMS)] == [101, 102]
    s = {"vms": [], "tags": [], "pools": ["infra"]}
    assert [vm["vmid"] for vm in vm_snapshots.schedule_vms(s, _VMS)] == [101]


def test_schedule_runs_when_due_and_records_the_result():
    hub = _Hub()
    s = vm_snapshots.save_schedule(hub, {"name": "Lab", "every_hours": 24, "keep": 2,
                                         "tags": ["lab"]})
    assert vm_snapshots.due_schedules(hub, 100_000.0) == [s["id"]]
    res = _run(vm_snapshots.run_schedule(hub, s["id"]))
    assert res["status"] == "SUCCESS" and res["ok"] == 1
    assert hub.calls[0][2] == "snapshot" and hub.calls[0][3].startswith(f"lms-{s['id']}-")
    last = vm_snapshots.list_schedules(hub)[0]["last_run"]
    assert vm_snapshots.due_schedules(hub, last + 3600) == []
    assert vm_snapshots.due_schedules(hub, last + 24 * 3600) == [s["id"]]


def test_schedule_waits_for_the_vm_list():
    hub = _Hub(vms=[])
    s = vm_snapshots.save_schedule(hub, {"name": "Lab", "every_hours": 1, "keep": 1,
                                         "vms": ["C/pve1/101"]})
    assert _run(vm_snapshots.run_schedule(hub, s["id"]))["status"] == "ERROR"
    assert vm_snapshots.list_schedules(hub)[0]["last_run"] == 0.0   # retried next tick


def test_editing_a_schedule_keeps_its_prefix_and_history():
    hub = _Hub()
    s = vm_snapshots.save_schedule(hub, {"name": "Lab", "every_hours": 24, "keep": 2,
                                         "tags": ["lab"]})
    _run(vm_snapshots.run_schedule(hub, s["id"]))
    s2 = vm_snapshots.save_schedule(hub, {"name": "Lab 2", "every_hours": 12, "keep": 5,
                                          "tags": ["lab"]}, s["id"])
    assert s2["prefix"] == s["prefix"] and s2["last_run"] > 0 and s2["keep"] == 5


# ── routes ────────────────────────────────────────────────────────────────────

def _client(is_admin=True):
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routes import vm_snapshots as routes
    app, hub = FastAPI(), _Hub()
    routes.register(app, hub, SimpleNamespace(_session_user=lambda r: {"username": "admin"},
                                              _is_admin=lambda s: is_admin))
    return TestClient(app), hub


def test_schedule_routes_crud():
    c, _ = _client()
    r = c.post("/api/vm-snapshots/schedules",
               json={"name": "Lab", "every_hours": 24, "keep": 3, "tags": ["lab"]})
    assert r.status_code == 200
    sid = r.json()["id"]
    listing = c.get("/api/vm-snapshots/schedules").json()
    assert listing["tags"] == ["lab"] and listing["pools"] == ["infra"]
    assert listing["schedules"][0]["vm_count"] == 1
    assert c.put(f"/api/vm-snapshots/schedules/{sid}",
                 json={"name": "Lab", "every_hours": 0, "keep": 3, "tags": ["lab"]}).status_code == 400
    assert c.delete(f"/api/vm-snapshots/schedules/{sid}").status_code == 200
    assert c.delete(f"/api/vm-snapshots/schedules/{sid}").status_code == 404


def test_schedule_routes_are_global_admin_only():
    c, _ = _client(is_admin=False)
    assert c.get("/api/vm-snapshots/schedules").status_code == 403
    assert c.post("/api/vm-snapshots/schedules", json={}).status_code == 403


# ── tenant scope ──────────────────────────────────────────────────────────────

def test_tenant_vms_are_its_own_plus_every_vm_on_a_host_pinned_to_it():
    hub = _Hub()
    assert [vm["vmid"] for vm in _run(vm_snapshots.tenant_vms(hub, "t1"))] == [101]
    hub.state.system_state["agent_config"] = {"g2": {"client_simulation": {"tenant_id": "T1"}}}
    hub.agent_info["g2"]["hostname"] = "pve2"
    assert sorted(vm["vmid"] for vm in _run(vm_snapshots.tenant_vms(hub, "t1"))) == [101, 102, 103]


def test_a_schedule_only_snapshots_its_tenants_vms():
    hub = _Hub()
    s = vm_snapshots.save_schedule(hub, {"name": "all lab", "every_hours": 1, "keep": 1,
                                         "vms": ["C/pve2/102"], "tags": ["lab"]}, tenant="t1")
    res = _run(vm_snapshots.run_schedule(hub, s["id"]))
    assert [r["vmid"] for r in res["results"]] == [101]


def test_schedules_are_per_tenant_in_the_api():
    c, _ = _client()
    body = {"name": "Lab", "every_hours": 24, "keep": 3, "tags": ["lab"]}
    sid = c.post("/api/vm-snapshots/schedules?tenant=t1", json=body).json()["id"]
    t1 = c.get("/api/vm-snapshots/schedules?tenant=t1").json()
    assert [s["id"] for s in t1["schedules"]] == [sid] and [v["vmid"] for v in t1["vms"]] == [101]
    t2 = c.get("/api/vm-snapshots/schedules?tenant=t2").json()
    assert t2["schedules"] == [] and t2["vms"] == []
    assert c.put(f"/api/vm-snapshots/schedules/{sid}?tenant=t2", json=body).status_code == 404
    assert c.post(f"/api/vm-snapshots/schedules/{sid}/run?tenant=t2").status_code == 404
    assert c.delete(f"/api/vm-snapshots/schedules/{sid}?tenant=t2").status_code == 404
    assert c.delete(f"/api/vm-snapshots/schedules/{sid}?tenant=t1").status_code == 200
