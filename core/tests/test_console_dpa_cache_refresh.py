"""A DPA save must re-cache the spoke's port list before returning.

The Console page is served from the hub's console_ports warm cache (refreshed
every ~30s). Pre-fix, enabling DPA (or pinning a port) and then reloading the
page kept serving the pre-change snapshot, so the "🔐 DPA host:port" badge
didn't appear until the next background refresh — looking like DPA was broken.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import console
from test_console_ports_warm_cache import _FakeAccess, _Hub, _ctx

import pytest


@pytest.fixture(autouse=True)
def _stub_access(monkeypatch):
    monkeypatch.setattr(console, "access", _FakeAccess)


class _DpaHub(_Hub):
    def __init__(self):
        super().__init__(connected=["c1"])
        self.dpa_on = False
        self.refreshed = []

    async def request_response(self, sid, cmd, payload, timeout=15.0, signing_secret=None):
        self._rr_calls.append((sid, cmd))
        if cmd == "CONSOLE_SET_DPA":
            self.dpa_on = bool(payload.get("enabled"))
            return {"payload": {"data": {"status": "SUCCESS", "config": {}, "runtime": {}}}}
        if cmd == "CONSOLE_SET_DPA_PORT":
            return {"payload": {"data": {"status": "SUCCESS", "port": payload.get("port")}}}
        dpa = {"host": "10.0.0.5", "ssh_port": 3002, "proto": "ssh"} if self.dpa_on else None
        return {"payload": {"data": {"status": "SUCCESS",
                                     "ports": [{"port_id": "p1", "device": "/dev/ttyUSB0", "dpa": dpa}]}}}

    async def refresh_console_ports_cache(self, sids=None, timeout=None):
        self.refreshed.append(list(sids))
        for sid in sids:
            r = await self.request_response(sid, "CONSOLE_LIST_PORTS", {})
            await self.warm_set("console_ports", sid, r["payload"]["data"]["ports"])
        return set(sids)


def _client(hub):
    app = FastAPI()
    app.state.hub = hub
    console.register(app, hub, _ctx())
    return TestClient(app)


def test_enabling_dpa_shows_badge_on_next_page_load():
    hub = _DpaHub()
    c = _client(hub)
    first = c.get("/api/console/ports").json()["ports"]
    assert first[0]["dpa"] is None                      # warm cache now holds "off"

    assert c.post("/api/console/dpa", json={"spoke_id": "c1", "enabled": True}).status_code == 200
    assert hub.refreshed == [["c1"]]

    after = c.get("/api/console/ports").json()["ports"]
    assert after[0]["dpa"] == {"host": "10.0.0.5", "ssh_port": 3002, "proto": "ssh"}


def test_port_override_refreshes_cache():
    hub = _DpaHub()
    c = _client(hub)
    r = c.post("/api/console/dpa-port", json={"spoke_id": "c1", "port_id": "p1", "proto": "ssh", "port": 4000})
    assert r.status_code == 200
    assert hub.refreshed == [["c1"]]
