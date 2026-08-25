"""``POST /tenant/templates/backup`` — the tenant-gated mirror of the Global
Admin ``/setup/templates/backup``. A tenant-admin has no Setup/Hypervisors nav,
so this is their only way to seed a live-VM template backup from the Simulations
module. Same agent/vmid resolution + pending record + START_BACKUP relay as the
admin endpoint, but gated by tenant OWNERSHIP of the resolved host (anti-IDOR)
instead of ``_require_admin``:

  * own-tenant caller succeeds (agent/vmid resolved, pending record created +
    START_BACKUP relayed);
  * a host in a tenant the caller doesn't own / an unassigned host → 403;
  * missing agent/vmid (can't resolve the owning host) → 400;
  * Global Admin may back up a host in ANY tenant.
"""
import os
import sys
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes.templates import register  # noqa: E402
from template_repo import TemplateRepo  # noqa: E402


class FakeHub:
    def __init__(self, tmp):
        self.template_repo = TemplateRepo(str(tmp))
        # Two hosts bound to two different tenants — agent-1 → acme, agent-2 →
        # other. agent-3 has no tenant binding (unassigned).
        self.agent_info = {
            "agent-1": {"hostname": "pxmx-acme"},
            "agent-2": {"hostname": "pxmx-other"},
            "agent-3": {"hostname": "pxmx-orphan"},
        }
        self.forwarded = []
        self.state = SimpleNamespace(
            system_state={"agent_config": {
                "agent-1": {"client_simulation": {"tenant_id": "acme"}},
                "agent-2": {"client_simulation": {"tenant_id": "other"}},
                "agent-3": {"client_simulation": {}},
            }},
            get_spoke_tenant=lambda sid: "",
            get_tenant=lambda tid: {"name": "Acme Corp"} if tid == "acme" else None,
        )

    async def request_response(self, sid, cmd, payload, timeout=8.0):
        self.forwarded.append((sid, cmd, payload))
        return {"payload": {"data": {"status": "ACCEPTED"}}}

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=False):
        return "cs-spoke-1"

    def get_hypervisor_spoke(self):
        return "cs-spoke-1"

    def _primary_key(self, spoke_id):
        return spoke_id

    def _agent_primary_key(self, agent_id):
        return agent_id

    def _agent_relay_name(self, agent_id):
        return agent_id


def _build(tmp, *, is_admin=False, tenants=("acme",)):
    app = FastAPI()
    hub = FakeHub(tmp)
    sess = {"username": "operator", "user": {"tenants": list(tenants)}}
    ctx = SimpleNamespace(
        _session_user=lambda req: sess,
        _is_admin=lambda s: is_admin,
    )
    register(app, hub, ctx)
    return TestClient(app), hub


def test_tenant_backup_own_tenant_succeeds(tmp_path):
    c, hub = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/backup", json={
        "agent_id": "agent-1", "vmid": 90025, "node": "pxmx-acme",
        "name": "t2-golden", "storage": "nfs-backup",
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "SUCCESS"
    # A pending record was created and stamped to the resolved tenant.
    rec = hub.template_repo.get(d["id"])
    assert rec is not None
    assert rec["source_vmid"] == 90025
    assert rec["source_node"] == "pxmx-acme"
    assert rec["tenant_id"] == "acme"
    assert rec["tenant"] == "Acme Corp"
    # START_BACKUP was relayed to the owning agent with the chosen storage.
    sid, cmd, payload = hub.forwarded[-1]
    assert cmd == "SPOKE_RELAY"
    assert payload["command"] == "START_BACKUP"
    assert payload["target_agent_id"] == "agent-1"
    assert payload["data"]["vmid"] == 90025
    assert payload["data"]["storage"] == "nfs-backup"
    assert payload["data"]["upload_url"].endswith(
        "/api/templates/" + payload["data"]["template_id"] + "/upload")


def test_tenant_backup_resolves_agent_by_node(tmp_path):
    """No agent_id given → resolve the owning agent by node hostname (like the
    admin endpoint), then enforce ownership on that resolved host."""
    c, hub = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/backup", json={
        "vmid": 90025, "node": "pxmx-acme", "name": "t2-golden",
    })
    assert r.status_code == 200, r.text
    _, _, payload = hub.forwarded[-1]
    assert payload["target_agent_id"] == "agent-1"
    # storage omitted → empty (agent tempdir fallback)
    assert payload["data"]["storage"] == ""


def test_tenant_backup_foreign_tenant_forbidden(tmp_path):
    """A tenant-admin cannot back up a host bound to a tenant they don't own."""
    c, hub = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/backup", json={
        "agent_id": "agent-2", "vmid": 90050, "node": "pxmx-other", "name": "x",
    })
    assert r.status_code == 403
    # Nothing was relayed for the forbidden request.
    assert hub.forwarded == []


def test_tenant_backup_unassigned_host_forbidden(tmp_path):
    """A host with no tenant binding is not ownable by a tenant-admin → 403."""
    c, _ = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/backup", json={
        "agent_id": "agent-3", "vmid": 90099, "node": "pxmx-orphan", "name": "x",
    })
    assert r.status_code == 403


def test_tenant_backup_missing_agent_vmid_bad_request(tmp_path):
    """Can't resolve the owning agent/vmid → 400 (not a 403/500)."""
    c, _ = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/backup", json={"name": "x"})
    assert r.status_code == 400


def test_admin_can_backup_any_tenant(tmp_path):
    """Global Admin passes _owns_tenant for any tenant — including 'other'."""
    c, hub = _build(tmp_path, is_admin=True, tenants=())
    r = c.post("/tenant/templates/backup", json={
        "agent_id": "agent-2", "vmid": 90050, "node": "pxmx-other", "name": "adm",
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "SUCCESS"
    _, _, payload = hub.forwarded[-1]
    assert payload["target_agent_id"] == "agent-2"
