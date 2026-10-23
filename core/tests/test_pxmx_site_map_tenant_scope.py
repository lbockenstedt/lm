"""Config → Sites "Server to Site Assignments" is tenant-scoped.

A pxmx server that moved to ANOTHER tenant leaves a stale site-map entry /
offline row on this tenant's cs spokes. GET /sim/api/{tenant}/pxmx-site-map
hides hosts a different tenant's spoke is relaying live, and the Delete action
(DELETE /sim/api/proxmox/host/{h}) purges the record on EVERY tenant cs spoke.
"""

import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations.routes import register_simulations_routes


class _State:
    def __init__(self, tenants):
        self._t = tenants

    def get_spoke_tenant(self, sid):
        return self._t.get(sid)


class _Hub:
    def __init__(self):
        now = time.time()
        self.spokes = ["cs-a", "cs-b"]
        self.state = _State({"cs-a": "10", "cs-b": "10", "lrb": "20", "orphan": None})
        self.simulations_cache = {
            "cs-a": {"proxmox_hosts": [{"hostname": "pxmx-cs-svr-01", "proxmox": {"last_seen": now}}]},
            "lrb": {"proxmox_hosts": [{"hostname": "pxmx-cs-svr-05", "proxmox": {"last_seen": now}}]},
            # An unbound spoke's frozen copy is not ownership evidence.
            "orphan": {"proxmox_hosts": [{"hostname": "pxmx-cs-svr-06", "proxmox": {"last_seen": now}}]},
        }
        self.simulations_store = type("_Store", (), {"__getattr__": lambda s, n: (lambda *a, **k: None)})()
        self.calls = []

    def get_client_sim_spokes(self, tenant_id):
        return list(self.spokes)

    async def request_response(self, sid, cmd_type, payload, timeout=8.0):
        self.calls.append((sid, cmd_type, dict(payload)))
        if cmd_type == "CS_GET_PXMX_SITE_MAP":
            return {"status": "SUCCESS",
                    "pxmx_site_map": {"pxmx-cs-svr-01": "BAR",
                                      "pxmx-cs-svr-05": "Tenant-Wide Pool",
                                      "pxmx-cs-svr-06": "Tenant-Wide Pool"},
                    "agents": [{"agent_id": "pxmx-cs-svr-01", "status": "connected"},
                               {"agent_id": "pxmx-cs-svr-05", "status": "offline"}]}
        return {"status": "SUCCESS", "removed": True}


def _client(hub):
    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: {"username": "admin", "role": "admin"},
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return TestClient(app)


def test_get_hides_servers_owned_by_another_tenant():
    hub = _Hub()
    body = _client(hub).get("/sim/api/10/pxmx-site-map?tenant_id=10").json()
    assert "pxmx-cs-svr-05" not in body["pxmx_site_map"]
    assert all(a["agent_id"] != "pxmx-cs-svr-05" for a in body["agents"])
    # Own server stays; an orphan-claimed stale host stays (deletable) — not foreign.
    assert body["pxmx_site_map"]["pxmx-cs-svr-01"] == "BAR"
    assert "pxmx-cs-svr-06" in body["pxmx_site_map"]


def test_delete_purges_on_every_tenant_spoke():
    hub = _Hub()
    r = _client(hub).delete("/sim/api/proxmox/host/pxmx-cs-svr-06?tenant_id=10")
    assert r.status_code == 200, r.text
    assert r.json()["spoke_notified"] is True
    purged = sorted(sid for sid, cmd, p in hub.calls
                    if cmd == "CS_PURGE_HOST" and p == {"hostname": "pxmx-cs-svr-06"})
    assert purged == ["cs-a", "cs-b"]
