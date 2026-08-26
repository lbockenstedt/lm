"""The template REFRESH path forwards an optional destination ``target_storage``
to the agent's REFRESH_TEMPLATE as ``data['storage']`` (the agent runs
``qmrestore --storage``). This lets an operator redirect the restored disks onto
a storage that exists on the DESTINATION host — the fix for cross-host restores
failing when the backup's recorded storage id is absent on the target.

Covers the self-restore endpoint (``/setup/templates/{tid}/refresh``) and the
fleet seed-distribute endpoint (``/tenant/templates/refresh-hosts``), plus the
back-compat default (no storage → no ``storage`` key) and validation.
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
        self.agent_info = {"agent-1": {"hostname": "pxmx-node", "spoke_id": "cs-spoke-1"}}
        self.active_connections = {"cs-spoke-1": object()}
        self.forwarded = []
        self.state = SimpleNamespace(
            system_state={"agent_config": {"agent-1":
                         {"client_simulation": {"tenant_id": "acme",
                                                "usb_config": {"image1_template_id": 9000}}}}},
            get_spoke_tenant=lambda sid: "acme",
            get_tenant=lambda tid: None,
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


def _complete_template(hub):
    rec = hub.template_repo.create_pending(
        name="golden", source_vmid=100, source_node="pxmx-node",
        source_agent="agent-1", source_spoke="cs-spoke-1", created_by="admin",
        tenant="Acme", tenant_id="acme")
    hub.template_repo.finalize(rec["id"], size=10, sha256="abc")
    return rec["id"]


def _build(tmp):
    app = FastAPI()
    hub = FakeHub(tmp)
    ctx = SimpleNamespace(
        _session_user=lambda req: {"user": {"permissions": {"role": "admin"},
                                            "tenants": ["acme"]},
                                   "username": "admin"},
        _is_admin=lambda sess: True,
    )
    register(app, hub, ctx)
    return TestClient(app), hub


def _last_refresh(hub):
    for sid, cmd, payload in reversed(hub.forwarded):
        if payload.get("command") == "REFRESH_TEMPLATE":
            return payload
    raise AssertionError("no REFRESH_TEMPLATE forwarded")


def test_self_refresh_forwards_storage(tmp_path):
    c, hub = _build(tmp_path)
    tid = _complete_template(hub)
    r = c.post(f"/setup/templates/{tid}/refresh", json={"target_storage": "local-lvm"})
    assert r.status_code == 200, r.text
    payload = _last_refresh(hub)
    assert payload["data"]["storage"] == "local-lvm"


def test_self_refresh_omits_storage_by_default(tmp_path):
    c, hub = _build(tmp_path)
    tid = _complete_template(hub)
    r = c.post(f"/setup/templates/{tid}/refresh", json={})
    assert r.status_code == 200, r.text
    # No storage → key absent → agent keeps the backup's recorded storage.
    assert "storage" not in _last_refresh(hub)["data"]


def test_fleet_refresh_forwards_storage_to_every_target(tmp_path):
    c, hub = _build(tmp_path)
    tid = _complete_template(hub)
    r = c.post("/tenant/templates/refresh-hosts", json={
        "host_ids": ["pxmx-node"], "template_id": tid,
        "target_storage": "ssd-pool", "target_vmid": 200,
    })
    assert r.status_code == 200, r.text
    payload = _last_refresh(hub)
    assert payload["data"]["storage"] == "ssd-pool"
    assert payload["data"]["template_vmid"] == 200


def test_invalid_storage_rejected(tmp_path):
    c, hub = _build(tmp_path)
    tid = _complete_template(hub)
    r = c.post(f"/setup/templates/{tid}/refresh", json={"target_storage": "bad name!"})
    assert r.status_code == 400
    # Nothing was forwarded to the agent.
    assert not any(p.get("command") == "REFRESH_TEMPLATE" for _, _, p in hub.forwarded)
