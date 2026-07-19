"""Backup-config tenant-resolution tests for ``routes/pxmx_vm.py``.

Setup → Hypervisors stores the vzdump config (``backup_storage`` default +
``per_host[host].backup_storage`` override) **per-tenant**, keyed by the UI's
selected tenant (the settings route resolves it via ``get_tenant_id`` →
``?tenant_id=``). The VM-action routes must read that SAME tenant's config:

* a non-admin's session carries their own tenant (``sess["user"]["tenant_id"]``);
* a Global Admin (no session tenant) passes the selected tenant in the body
  (``tenant``) so the right config is read.

Pre-fix the routes read ``sess.get("tenant_id")`` — but the session has NO
top-level ``tenant_id`` (it lives at ``sess["user"]["tenant_id"]``), so it was
always ``""`` → the empty-tenant config → ``backup_storage`` always ``""`` →
every backup failed with "No backup storage configured for host '…'", even
when the admin had just set one in Setup → Hypervisors. These lock in the fix
and use a REALISTIC session shape (no top-level ``tenant_id``) so the old bug
would actually be caught.
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx_vm


# ── Fakes ────────────────────────────────────────────────────────────────────

class _Store:
    """Per-tenant hypervisors config + the delete-protection union surface."""

    def __init__(self, configs=None, protected=None):
        self._configs = configs or {}      # {tenant_id: {backup_storage, per_host}}
        self._protected = set(protected or [])

    async def get_hypervisors_config(self, tenant_id):
        return dict(self._configs.get(tenant_id, {})) or {}

    def get_all_protected_vms(self):
        return set(self._protected)


class _Hub:
    def __init__(self, configs=None, protected=None, connected=True):
        self.simulations_store = _Store(configs=configs, protected=protected)
        self._spoke = "pxmx-1" if connected else None
        self.relayed = []
        self.bulked = []

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
            rows = [{"vmid": it.get("vmid"), "ok": True}
                    for it in (payload.get("items") or [])]
            return {"payload": {"data": {"status": "SUCCESS", "results": rows}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _ctx(admin=True, session_tenant=None):
    """Realistic session: tenant_id lives under ``user``, NOT at the top level
    (the bug was that the route read the non-existent top-level key)."""
    sess = {"user": {"tenant_id": session_tenant} if session_tenant else {}}
    return SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: admin,
        _resolve_tenant=lambda request, explicit=None: explicit or session_tenant,
        _filter_tenant=lambda *a, **k: None,
        _trigger_vm_sync_after_pxmx_edit=lambda hub, request, body: None,
    )


def _build(hub, admin=True, session_tenant=None):
    app = FastAPI()
    app.state.hub = hub
    pxmx_vm.register(app, hub, _ctx(admin=admin, session_tenant=session_tenant))
    return TestClient(app)


# ── Single-VM backup ─────────────────────────────────────────────────────────

def test_admin_backup_uses_body_tenant_config():
    """A Global Admin (no session tenant) backs up a VM in tenant 'acme'; the
    body carries the selected tenant so acme's configured storage is injected
    (not the empty default → no spurious 'No backup storage configured')."""
    hub = _Hub(configs={"acme": {"backup_storage": "local-backup"}})
    c = _build(hub, admin=True)  # admin, no session tenant
    r = c.post("/api/pxmx/vm-action", json={
        "unique_id": "px/px/100", "vmid": 100, "node": "px",
        "type": "qemu", "action": "backup", "tenant": "acme"})
    assert r.status_code == 200
    relayed = hub.relayed[0][1]
    assert relayed["action"] == "backup"
    assert relayed["backup"]["storage"] == "local-backup"


def test_admin_backup_no_storage_for_selected_tenant_is_400():
    """Admin selects a tenant that has NO backup_storage configured → clear 400
    (not a silent fallback to another tenant's storage)."""
    hub = _Hub(configs={"acme": {"backup_storage": ""}})
    c = _build(hub, admin=True)
    r = c.post("/api/pxmx/vm-action", json={
        "unique_id": "px/px/100", "vmid": 100, "node": "px",
        "type": "qemu", "action": "backup", "tenant": "acme"})
    assert r.status_code == 400
    assert "No backup storage configured" in r.json()["detail"]
    assert hub.relayed == []   # never relayed


def test_per_host_override_wins_over_default():
    """per_host[node].backup_storage overrides the tenant default."""
    hub = _Hub(configs={"acme": {"backup_storage": "default-disk",
                                 "per_host": {"px": {"backup_storage": "nfs-px"}}}})
    c = _build(hub, admin=True)
    r = c.post("/api/pxmx/vm-action", json={
        "unique_id": "px/px/100", "vmid": 100, "node": "px",
        "type": "qemu", "action": "backup", "tenant": "acme"})
    assert r.status_code == 200
    assert hub.relayed[0][1]["backup"]["storage"] == "nfs-px"


# ── Bulk backup ──────────────────────────────────────────────────────────────

def test_bulk_backup_admin_uses_body_tenant_storage():
    """Bulk backup under an admin injects the selected tenant's storage into
    every relayed item (the old code read sess.get('tenant_id')='' → 400-skipped
    every item with 'No backup storage configured')."""
    hub = _Hub(configs={"acme": {"backup_storage": "local-backup"}})
    c = _build(hub, admin=True)
    r = c.post("/api/pxmx/vm-action-bulk", json={
        "action": "backup", "tenant": "acme",
        "items": [
            {"unique_id": "px/px/100", "vmid": 100, "node": "px", "type": "qemu"},
            {"unique_id": "px/px/101", "vmid": 101, "node": "px", "type": "qemu"},
        ]})
    assert r.status_code == 200
    items = hub.bulked[0]["items"]
    assert len(items) == 2
    assert all(it["backup"]["storage"] == "local-backup" for it in items)
    by_vmid = {row["vmid"]: row for row in r.json()["results"]}
    assert all(row["ok"] for row in by_vmid.values())