"""Delete-protection safeguard tests for the pxmx VM-action routes
(``routes/pxmx_vm.py``).

A Global Admin can mark VMs non-deletable from Setup → Hypervisors (stored
per-tenant as ``protected_vms``, enforced as the UNION across all tenants via
``simulations_store.get_all_protected_vms``). These lock in:

* a single-VM ``destroy`` of a protected VM is rejected 403 before the relay;
* a single-VM ``destroy`` of a non-protected VM is relayed (PXMX_VM_ACTION,
  action=destroy) and succeeds;
* a bulk ``destroy`` skips protected VMs (ok=False, clear error) while the
  free VMs in the same batch still run;
* ``destroy``/``delete`` are accepted action names (no 400 "unknown action").
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx_vm


# ── Fakes ────────────────────────────────────────────────────────────────────

class _Store:
    def __init__(self, protected=None):
        self._protected = set(protected or [])

    def get_all_protected_vms(self):
        return set(self._protected)


class _Hub:
    """Minimal hub: hypervisor spoke + recorded PXMX_VM_ACTION(_BULK) relays."""

    def __init__(self, protected=None, connected=True):
        self.simulations_store = _Store(protected=protected)
        self._spoke = "pxmx-1" if connected else None
        self.relayed = []     # [(cmd, payload)] for single actions
        self.bulked = []      # [{"action", "items"}] for bulk

    def get_hypervisor_spoke(self):
        return self._spoke

    async def request_response(self, sid, cmd, payload, timeout=35.0,
                               signing_secret=None):
        if cmd == "PXMX_VM_ACTION":
            self.relayed.append((cmd, payload))
            return {"payload": {"data": {"status": "SUCCESS", **payload}}}
        if cmd == "PXMX_VM_ACTION_BULK":
            self.bulked.append({"action": payload.get("action"),
                                "items": payload.get("items")})
            # One ok row per relayed item.
            rows = [{"vmid": it.get("vmid"), "ok": True} for it in (payload.get("items") or [])]
            return {"payload": {"data": {"status": "SUCCESS", "results": rows}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _ctx(admin=True):
    return SimpleNamespace(
        _session_user=lambda request: {"user": {"tenant_id": "acme"},
                                       "tenant_id": "acme"},
        _is_admin=lambda sess: admin,
        _resolve_tenant=lambda request, explicit=None: explicit or "acme",
        _filter_tenant=lambda *a, **k: None,  # not exercised by the action routes
        _trigger_vm_sync_after_pxmx_edit=lambda hub, request, body: None,
    )


def _build(hub, admin=True):
    app = FastAPI()
    app.state.hub = hub
    pxmx_vm.register(app, hub, _ctx(admin=admin))
    return TestClient(app)


# ── Single-VM destroy ────────────────────────────────────────────────────────

def test_destroy_protected_vm_rejected_403():
    hub = _Hub(protected={"px/px/100"})
    c = _build(hub)
    r = c.post("/api/pxmx/vm-action", json={
        "unique_id": "px/px/100", "vmid": 100, "node": "px",
        "type": "qemu", "action": "destroy"})
    assert r.status_code == 403
    assert "protected" in r.json()["detail"].lower()
    assert hub.relayed == []   # never reached the spoke


def test_destroy_free_vm_relayed():
    hub = _Hub(protected={"px/px/999"})  # a different VM is protected
    c = _build(hub)
    r = c.post("/api/pxmx/vm-action", json={
        "unique_id": "px/px/100", "vmid": 100, "node": "px",
        "type": "qemu", "action": "destroy"})
    assert r.status_code == 200
    assert hub.relayed and hub.relayed[0][0] == "PXMX_VM_ACTION"
    assert hub.relayed[0][1]["action"] == "destroy"


def test_delete_alias_accepted():
    """``delete`` is an accepted alias for ``destroy`` (no 400 unknown action)."""
    hub = _Hub()
    c = _build(hub)
    r = c.post("/api/pxmx/vm-action", json={
        "unique_id": "px/px/100", "vmid": 100, "node": "px",
        "type": "qemu", "action": "delete"})
    assert r.status_code == 200
    assert hub.relayed[0][1]["action"] == "delete"


# ── Bulk destroy ─────────────────────────────────────────────────────────────

def test_bulk_destroy_skips_protected_keeps_free():
    hub = _Hub(protected={"px/px/100"})
    c = _build(hub)
    r = c.post("/api/pxmx/vm-action-bulk", json={
        "action": "destroy",
        "items": [
            {"unique_id": "px/px/100", "vmid": 100, "node": "px", "type": "qemu"},
            {"unique_id": "px/px/101", "vmid": 101, "node": "px", "type": "qemu"},
        ]})
    assert r.status_code == 200
    body = r.json()
    by_vmid = {row["vmid"]: row for row in body["results"]}
    # protected VM → skipped with an error, never relayed
    assert by_vmid[100]["ok"] is False
    assert "protected" in by_vmid[100]["error"].lower()
    # free VM → relayed + ok
    assert by_vmid[101]["ok"] is True
    # only the free VM reached the spoke
    assert hub.bulked and len(hub.bulked[0]["items"]) == 1
    assert hub.bulked[0]["items"][0]["vmid"] == 101