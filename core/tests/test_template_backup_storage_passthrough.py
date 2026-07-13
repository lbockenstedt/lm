"""``POST /setup/templates/backup`` forwards the chosen vzdump ``storage`` to
the agent's START_BACKUP (the cs spoke relays it verbatim). Empty/missing
storage → legacy tempdir mode on the agent (back-compat with an older WebUI).
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
        self.agent_info = {"agent-1": {"hostname": "pxmx-node"}}
        self.forwarded = []
        self.state = SimpleNamespace(
            system_state={"agent_config": {"agent-1":
                         {"client_simulation": {"tenant_id": "acme"}}}},
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


def _build(tmp):
    app = FastAPI()
    hub = FakeHub(tmp)
    ctx = SimpleNamespace(
        _session_user=lambda req: {"username": "admin"},
        _is_admin=lambda sess: True,
    )
    register(app, hub, ctx)
    return TestClient(app), hub


def test_storage_is_forwarded_in_start_backup_data(tmp_path):
    c, hub = _build(tmp_path)
    r = c.post("/setup/templates/backup", json={
        "agent_id": "agent-1", "vmid": 90025, "node": "pxmx-node",
        "name": "t2-golden", "storage": "nfs-backup",
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "SUCCESS"
    sid, cmd, payload = hub.forwarded[-1]
    assert cmd == "SPOKE_RELAY"
    assert payload["target_agent_id"] == "agent-1"
    assert payload["command"] == "START_BACKUP"
    assert payload["data"]["storage"] == "nfs-backup"          # the new field
    assert payload["data"]["vmid"] == 90025
    assert payload["data"]["upload_url"].endswith("/api/templates/" + payload["data"]["template_id"] + "/upload")


def test_storage_defaults_empty_when_not_provided(tmp_path):
    """Older WebUI (no storage in payload) → empty string → agent tempdir mode."""
    c, hub = _build(tmp_path)
    r = c.post("/setup/templates/backup", json={
        "agent_id": "agent-1", "vmid": 90025, "node": "pxmx-node",
        "name": "t2-golden",
    })
    assert r.status_code == 200, r.text
    _, _, payload = hub.forwarded[-1]
    assert payload["data"]["storage"] == ""