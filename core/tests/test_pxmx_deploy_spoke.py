"""One-click spoke-deploy route tests (``routes/pxmx_vm.py``).

The ``/api/pxmx/deploy-spoke`` easy button clones a golden spoke template,
auto-names the clone ``<prefix>-0N`` (next free number), tags it for the acting
tenant, and STARTS it so it boots + self-onboards. These lock in:

* the pure next-number picker (``_next_spoke_number``) skips taken VM names AND
  taken spoke hostnames (with/without the ``agent-`` prefix, any zero-padding);
* the route clones with the computed name then relays a ``start`` action, and
  reports the spoke id the box will self-register under;
* ``start: false`` clones without starting.
"""
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx_vm


# ── Pure next-number picker ───────────────────────────────────────────────────

def test_next_spoke_number_empty_is_one():
    assert pxmx_vm._next_spoke_number("CS-SVR", [], []) == 1


def test_next_spoke_number_skips_taken_vm_names():
    # CS-SVR-01/02/03 taken → next is 04 (case + padding insensitive).
    names = ["cs-svr-01", "CS-SVR-2", "CS-SVR-03", "other-05"]
    assert pxmx_vm._next_spoke_number("CS-SVR", names, []) == 4


def test_next_spoke_number_skips_taken_spoke_hostnames():
    # A spoke already registered as agent-cs-svr-05 must not be reused even
    # though no VM named CS-SVR-05 exists in the cache.
    hostnames = ["agent-cs-svr-05", "cs-svr-01"]
    assert pxmx_vm._next_spoke_number("CS-SVR", [], hostnames) == 2
    # fill 2..4 → the agent-cs-svr-05 keeps 5 taken → 6
    assert pxmx_vm._next_spoke_number(
        "CS-SVR", ["CS-SVR-02", "CS-SVR-03", "CS-SVR-04"], hostnames) == 6


def test_next_spoke_number_ignores_other_prefixes():
    assert pxmx_vm._next_spoke_number("CS-SVR", ["PXMX-CS-SVR-09", "web-01"], []) == 1


# ── Route: clone + auto-name + start ─────────────────────────────────────────

class _Hub:
    def __init__(self, vms):
        self._vms = vms
        self.relayed = []          # (cmd, payload)
        self.state = SimpleNamespace(
            get_tenant=lambda tid: {"name": "Acme"},
            system_state={"known_modules": [], "module_names": {}, "module_metadata": {}},
        )

    def get_hypervisor_spoke(self):
        return "pxmx-1"

    async def request_response(self, sid, cmd, payload, timeout=35.0, signing_secret=None):
        self.relayed.append((cmd, payload))
        if cmd == "PXMX_LIST_VMS":
            return {"payload": {"data": {"vms": self._vms}}}
        if cmd == "PXMX_CLONE_VM":
            return {"payload": {"data": {
                "status": "SUCCESS",
                "unique_id": f"cl/px/{payload.get('new_vmid') or 900}",
                "vmid": payload.get("new_vmid") or 900,
                "node": "px", "type": "qemu", "name": payload.get("name"),
            }}}
        if cmd == "PXMX_VM_ACTION":
            return {"payload": {"data": {"status": "SUCCESS", **payload}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _ctx():
    return SimpleNamespace(
        _session_user=lambda request: {"user": {"tenant_id": "acme"}, "tenant_id": "acme"},
        _is_admin=lambda sess: True,
        _resolve_tenant=lambda request, explicit=None: explicit or "acme",
        _filter_tenant=lambda *a, **k: None,
        _trigger_vm_sync_after_pxmx_edit=lambda hub, request, body: None,
    )


@pytest.fixture
def patched(monkeypatch):
    # Neutralize the api-backed deps so the route runs standalone.
    monkeypatch.setattr(pxmx_vm, "access", SimpleNamespace(
        has_edit_access=lambda sess: True,
        _template_pools=lambda hub: [],          # no configured pools → guard passes
    ))
    monkeypatch.setattr(pxmx_vm, "get_tenant_scoping", lambda hub, tid: {"proxmox_tag": "acme"})
    monkeypatch.setattr(pxmx_vm, "vmid_alloc",
                        SimpleNamespace(vmid_alloc_cfg=lambda hub: {"enabled": False}))
    monkeypatch.setattr(pxmx_vm, "_cache_entry", lambda tid, mod: None)
    monkeypatch.setattr(pxmx_vm, "_refresh_module_all_tenants", lambda hub, mod: None)


def _build(hub):
    app = FastAPI()
    app.state.hub = hub
    pxmx_vm.register(app, hub, _ctx())
    return TestClient(app)


def test_deploy_spoke_autoname_and_start(patched):
    # A template plus one existing CS-SVR-01 → next name CS-SVR-02.
    hub = _Hub(vms=[
        {"unique_id": "cl/px/100", "name": "cs-golden", "type": "qemu", "pool": ""},
        {"unique_id": "cl/px/200", "name": "CS-SVR-01", "type": "qemu", "pool": ""},
    ])
    c = _build(hub)
    r = c.post("/api/pxmx/deploy-spoke", json={"template_unique_id": "cl/px/100"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deployed_name"] == "CS-SVR-02"
    assert body["spoke_id"] == "agent-cs-svr-02"
    assert body["started"] is True
    cmds = [c for c, _ in hub.relayed]
    assert "PXMX_CLONE_VM" in cmds and "PXMX_VM_ACTION" in cmds
    clone = next(p for cmd, p in hub.relayed if cmd == "PXMX_CLONE_VM")
    assert clone["name"] == "CS-SVR-02"
    start = next(p for cmd, p in hub.relayed if cmd == "PXMX_VM_ACTION")
    assert start["action"] == "start"


def test_deploy_spoke_no_start(patched):
    hub = _Hub(vms=[{"unique_id": "cl/px/100", "name": "cs-golden", "type": "qemu", "pool": ""}])
    c = _build(hub)
    r = c.post("/api/pxmx/deploy-spoke",
               json={"template_unique_id": "cl/px/100", "start": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deployed_name"] == "CS-SVR-01"
    assert body["started"] is False
    assert "PXMX_VM_ACTION" not in [c for c, _ in hub.relayed]


def test_deploy_spoke_explicit_number(patched):
    hub = _Hub(vms=[{"unique_id": "cl/px/100", "name": "cs-golden", "type": "qemu", "pool": ""}])
    c = _build(hub)
    r = c.post("/api/pxmx/deploy-spoke",
               json={"template_unique_id": "cl/px/100", "number": 7})
    assert r.status_code == 200, r.text
    assert r.json()["deployed_name"] == "CS-SVR-07"
