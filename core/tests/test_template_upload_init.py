"""``POST /tenant/templates/upload-init`` — the MANUAL (browser) template upload
entry point used from the Simulations UI. It mints a pending record + one-time
upload token (no source host/agent) so a tenant-admin's (or admin's) browser can
PUT a vzdump archive straight to the existing token-authed
``/api/templates/{id}/upload`` endpoint. Used when the source Proxmox host is
offline or only the archive file is available. Tenant-admins are confined to the
tenants they own (anti-IDOR).
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
        self.agent_info = {}
        self.state = SimpleNamespace(
            system_state={"agent_config": {}},
            get_spoke_tenant=lambda sid: "",
            get_tenant=lambda tid: {"name": "Acme Corp"} if tid == "acme" else None,
        )

    def _primary_key(self, spoke_id):
        return spoke_id

    def _agent_primary_key(self, agent_id):
        return agent_id

    def _agent_relay_name(self, agent_id):
        return agent_id


def _build(tmp, *, is_admin=False, tenants=("acme",)):
    """Build a test client. ``is_admin`` → Global Admin (owns any tenant);
    otherwise a tenant-admin confined to ``tenants``."""
    app = FastAPI()
    hub = FakeHub(tmp)
    sess = {"username": "operator", "user": {"tenants": list(tenants)}}
    ctx = SimpleNamespace(
        _session_user=lambda req: sess,
        _is_admin=lambda s: is_admin,
    )
    register(app, hub, ctx)
    return TestClient(app), hub


def test_tenant_upload_init_mints_token_and_url(tmp_path):
    c, hub = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/upload-init", json={
        "name": "offline-golden", "os": "Debian 12", "version": "v3",
        "purpose": "manual", "tenant_id": "acme",
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "SUCCESS"
    tid, token = d["id"], d["upload_token"]
    assert token
    assert d["upload_url"].endswith(f"/api/templates/{tid}/upload")

    rec = hub.template_repo.get(tid)
    assert rec["name"] == "offline-golden"
    assert rec["status"] == "pending"
    # no source host/agent for a manual upload
    assert rec["source_vmid"] is None
    assert rec["source_node"] == ""
    assert rec["source_agent"] == ""
    # metadata persisted
    assert rec["os"] == "Debian 12"
    assert rec["version"] == "v3"
    assert rec["purpose"] == "manual"
    # tenant display name resolved via get_tenant
    assert rec["tenant"] == "Acme Corp"
    assert rec["tenant_id"] == "acme"


def test_tenant_upload_init_requires_name(tmp_path):
    c, _ = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/upload-init", json={"tenant_id": "acme", "os": "Debian 12"})
    assert r.status_code == 400


def test_tenant_upload_init_rejects_foreign_tenant(tmp_path):
    """A tenant-admin cannot stamp an upload to a tenant they don't own."""
    c, _ = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/upload-init", json={"name": "x", "tenant_id": "other"})
    assert r.status_code == 403


def test_tenant_upload_init_rejects_unassigned_for_tenant_admin(tmp_path):
    """A tenant-admin must supply an owned tenant (empty tenant_id → 403)."""
    c, _ = _build(tmp_path, tenants=("acme",))
    r = c.post("/tenant/templates/upload-init", json={"name": "x"})
    assert r.status_code == 403


def test_admin_upload_init_any_tenant(tmp_path):
    """Global Admin may stamp any tenant, including unassigned."""
    c, hub = _build(tmp_path, is_admin=True, tenants=())
    r = c.post("/tenant/templates/upload-init", json={"name": "adm", "tenant_id": ""})
    assert r.status_code == 200, r.text
    rec = hub.template_repo.get(r.json()["id"])
    assert rec["tenant"] == ""
    assert rec["tenant_id"] == ""


def test_tenant_upload_init_then_put_completes(tmp_path):
    """End-to-end: init → PUT the file to the returned url with the token →
    the existing upload endpoint finalizes it to complete."""
    c, hub = _build(tmp_path, tenants=("acme",))
    d = c.post("/tenant/templates/upload-init", json={"name": "e2e", "tenant_id": "acme"}).json()
    tid, token = d["id"], d["upload_token"]
    body = b"fake-vzdump-archive-bytes"
    r = c.put(f"/api/templates/{tid}/upload", content=body,
              headers={"x-upload-token": token})
    assert r.status_code == 200, r.text
    rec = hub.template_repo.get(tid)
    assert rec["status"] == "complete"
    assert rec["size"] == len(body)
    assert rec["sha256"]
